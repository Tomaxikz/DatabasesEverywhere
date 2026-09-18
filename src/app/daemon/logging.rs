use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, IsTerminal, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

use anyhow::Context;
use tracing::{Event, Level, Subscriber};
use tracing_appender::non_blocking::{NonBlockingBuilder, WorkerGuard};
use tracing_subscriber::{
    EnvFilter, fmt,
    layer::{Context as LayerContext, Layer, SubscriberExt},
    util::SubscriberInitExt,
};

use crate::{config::Config, constants};

const LOG_BYTES: u64 = 10 * 1024 * 1024;
const LOG_ARCHIVES: usize = 4;
const LOG_QUEUE_LINES: usize = 2048;
const LOG_WRITE_BUFFER_BYTES: usize = 64 * 1024;
const LOG_EVENTS_PER_SECOND: u32 = 250;

struct LogWindow {
    started: Instant,
    events: u32,
}

impl LogWindow {
    fn allows(&mut self, level: &Level, now: Instant) -> bool {
        if now.duration_since(self.started) >= Duration::from_secs(1) {
            self.started = now;
            self.events = 0;
        }
        // Count suppressed INFO too, but never suppress other levels.
        self.events = self.events.saturating_add(1);
        *level != Level::INFO || self.events <= LOG_EVENTS_PER_SECOND
    }
}

struct InfoRateLimit {
    window: Mutex<LogWindow>,
}

impl InfoRateLimit {
    fn new() -> Self {
        Self {
            window: Mutex::new(LogWindow {
                started: Instant::now(),
                events: 0,
            }),
        }
    }
}

impl<S: Subscriber> Layer<S> for InfoRateLimit {
    fn event_enabled(&self, event: &Event<'_>, _ctx: LayerContext<'_, S>) -> bool {
        let mut window = self
            .window
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // Count actual events, not spans or enabled! probes. Read time under the
        // lock so concurrent callers cannot reset the window out of order.
        window.allows(event.metadata().level(), Instant::now())
    }
}

fn log_queue() -> NonBlockingBuilder {
    // The library's 128,000 slots are excessive for a daemon, even when idle.
    // Keep its non-blocking/lossy behavior; stdout still goes to the journal.
    NonBlockingBuilder::default().buffered_lines_limit(LOG_QUEUE_LINES)
}

fn log_filter() -> EnvFilter {
    EnvFilter::try_from_env(constants::RUST_LOG_ENV)
        .unwrap_or_else(|_| EnvFilter::new("databases_everywhere=info,tower_http=info"))
}

pub(crate) fn init_stdout_logging() {
    let _ = tracing_subscriber::registry()
        .with(InfoRateLimit::new())
        .with(log_filter())
        .with(fmt::layer().with_ansi(io::stdout().is_terminal()))
        .try_init();
}

/// Callers hold the daemon lock and keep this guard until shutdown so queued
/// records are flushed before the lock is released (statics are never dropped).
pub(super) fn init_logging(config: &Config) -> anyhow::Result<WorkerGuard> {
    let directory = Path::new(&config.paths.logs);
    super::create_runtime_dirs(directory)?;
    super::harden_runtime_dir(directory)?;
    let writer = RollingLog::new(directory, LOG_BYTES)
        .with_context(|| format!("failed to initialize log file in {}", directory.display()))?;
    let (file_writer, guard) = log_queue().finish(writer);

    tracing_subscriber::registry()
        // The outer EnvFilter runs first; both outputs share this event budget.
        .with(InfoRateLimit::new())
        .with(log_filter())
        .with(fmt::layer().with_ansi(io::stdout().is_terminal()))
        .with(fmt::layer().with_ansi(false).with_writer(file_writer))
        .try_init()
        .context("failed to initialize logging")?;
    tracing::info!(
        path = %directory.join("dbev.log").display(),
        max_file_bytes = LOG_BYTES,
        retained_files = LOG_ARCHIVES + 1,
        write_buffer_bytes = LOG_WRITE_BUFFER_BYTES,
        "daemon file logging ready; old dated logs are left untouched"
    );
    Ok(guard)
}

/// Size rotation runs on tracing's existing worker thread, not API tasks.
/// Buffer inside the rotating writer so record boundaries and size accounting
/// remain intact. The worker flushes after draining a queue batch and at shutdown;
/// a full buffer also flushes during a sustained burst, without a polling timer.
/// Only these five exact filenames are managed; no directory scans or glob deletes.
struct RollingLog {
    directory: PathBuf,
    file: Option<BufWriter<File>>,
    bytes: u64,
    max_bytes: u64,
}

impl RollingLog {
    fn new(directory: &Path, max_bytes: u64) -> io::Result<Self> {
        let mut writer = Self {
            directory: directory.to_owned(),
            file: None,
            bytes: 0,
            max_bytes,
        };
        if max_bytes == 0 {
            return Err(io::Error::other("log size limit must be positive"));
        }
        writer.check_paths()?;
        writer.open()?;
        Ok(writer)
    }

    fn path(&self, index: usize) -> PathBuf {
        self.directory.join(if index == 0 {
            "dbev.log".to_owned()
        } else {
            format!("dbev.log.{index}")
        })
    }

    fn check_paths(&self) -> io::Result<()> {
        for index in 0..=LOG_ARCHIVES {
            match fs::symlink_metadata(self.path(index)) {
                Ok(metadata) => check_log(&metadata)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn open(&mut self) -> io::Result<()> {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.path(0))?;
        let metadata = file.metadata()?;
        check_log(&metadata)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        self.bytes = metadata.len();
        self.file = Some(BufWriter::with_capacity(LOG_WRITE_BUFFER_BYTES, file));
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        self.check_paths()?;
        // Propagate flush errors before closing or renaming any files. Dropping
        // BufWriter alone would silently ignore them and lose pending records.
        self.flush()?;
        self.file.take();
        match fs::remove_file(self.path(LOG_ARCHIVES)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        for index in (0..LOG_ARCHIVES).rev() {
            match fs::rename(self.path(index), self.path(index + 1)) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        self.open()
    }
}

fn check_log(metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(io::Error::other(
            "log path must be an owned regular file, not a symlink or hard link",
        ));
    }
    Ok(())
}

impl Write for RollingLog {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        // Reopen on the next write if a previous rotation could not create its file.
        if self.file.is_none() {
            self.open()?;
        }
        if self.bytes > 0 && self.bytes.saturating_add(buffer.len() as u64) > self.max_bytes {
            self.rotate()?;
        }
        // Normal records stay together. Oversized writes are split by write_all
        // so even one huge record cannot exceed the per-file byte limit.
        let length = buffer.len().min((self.max_bytes - self.bytes) as usize);
        let written = self
            .file
            .as_mut()
            .expect("log file is open")
            .write(&buffer[..length])?;
        self.bytes += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.file.as_mut() {
            Some(file) => file.flush(),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_limit_resets_at_one_second_and_preserves_other_levels() {
        let started = Instant::now();
        let mut window = LogWindow { started, events: 0 };
        for _ in 0..LOG_EVENTS_PER_SECOND {
            assert!(window.allows(&Level::INFO, started));
        }
        assert!(!window.allows(&Level::INFO, started));
        for level in [Level::WARN, Level::ERROR, Level::DEBUG, Level::TRACE] {
            assert!(window.allows(&level, started));
        }
        assert!(!window.allows(&Level::INFO, started + Duration::from_millis(999)));
        assert!(window.allows(&Level::INFO, started + Duration::from_secs(1)));
        assert_eq!(window.events, 1);
        window.events = u32::MAX;
        assert!(!window.allows(&Level::INFO, started + Duration::from_secs(1)));
        assert_eq!(window.events, u32::MAX);
    }

    #[test]
    fn other_levels_count_toward_the_info_budget() {
        let started = Instant::now();
        let mut window = LogWindow { started, events: 0 };
        for _ in 0..LOG_EVENTS_PER_SECOND {
            assert!(window.allows(&Level::WARN, started));
        }
        assert!(!window.allows(&Level::INFO, started));
    }

    #[test]
    fn limiter_filters_both_outputs_after_env_filter_without_counting_probes() {
        #[derive(Clone)]
        struct Capture(std::sync::Arc<Mutex<Vec<u8>>>);

        impl Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let first = Capture(std::sync::Arc::new(Mutex::new(Vec::new())));
        let second = Capture(std::sync::Arc::new(Mutex::new(Vec::new())));
        let first_writer = first.clone();
        let second_writer = second.clone();
        // Pin the window in the future to avoid wall-clock-dependent resets.
        let limiter = InfoRateLimit {
            window: Mutex::new(LogWindow {
                started: Instant::now() + Duration::from_secs(3600),
                events: LOG_EVENTS_PER_SECOND - 1,
            }),
        };
        let subscriber = tracing_subscriber::registry()
            .with(limiter)
            .with(EnvFilter::new("info,ignored=off"))
            .with(
                fmt::layer()
                    .without_time()
                    .with_ansi(false)
                    .with_writer(move || first_writer.clone()),
            )
            .with(
                fmt::layer()
                    .without_time()
                    .with_ansi(false)
                    .with_writer(move || second_writer.clone()),
            );
        tracing::subscriber::with_default(subscriber, || {
            assert!(tracing::enabled!(Level::INFO));
            let _span = tracing::info_span!("not_an_event").entered();
            tracing::info!(target: "ignored", "filtered");
            tracing::info!("allowed");
            tracing::info!("suppressed");
            tracing::warn!("warning");
            tracing::error!("error");
        });
        let first = first.0.lock().unwrap();
        assert_eq!(*first, *second.0.lock().unwrap());
        let output = std::str::from_utf8(&first).unwrap();
        assert_eq!(output.lines().count(), 3);
        assert!(output.contains("allowed"));
        assert!(output.contains("warning"));
        assert!(output.contains("error"));
        assert!(!output.contains("suppressed"));
        assert!(!output.contains("filtered"));
    }

    #[test]
    fn file_queue_stays_bounded_when_disk_writes_stall() {
        use std::sync::{Arc, Mutex, mpsc};
        struct StalledWriter {
            started: Option<mpsc::SyncSender<()>>,
            resume: mpsc::Receiver<()>,
            output: Arc<Mutex<Vec<u8>>>,
        }
        impl Write for StalledWriter {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if let Some(started) = self.started.take() {
                    started.send(()).map_err(io::Error::other)?;
                    self.resume.recv().map_err(io::Error::other)?;
                }
                self.output.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (started, waiting) = mpsc::sync_channel(1);
        let (resume, paused) = mpsc::sync_channel(1);
        let output = Arc::new(Mutex::new(Vec::new()));
        let (mut writer, guard) = log_queue().finish(StalledWriter {
            started: Some(started),
            resume: paused,
            output: output.clone(),
        });
        writer.write_all(b"first\n").unwrap();
        let ready = waiting.recv_timeout(std::time::Duration::from_secs(3));
        if ready.is_ok() {
            for _ in 0..=LOG_QUEUE_LINES {
                writer.write_all(b"line\n").unwrap();
            }
        }
        let dropped = writer.error_counter().dropped_lines();
        resume.send(()).unwrap();
        drop(guard);
        ready.unwrap();
        assert_eq!(dropped, 1);
        assert_eq!(
            output.lock().unwrap().len(),
            b"first\n".len() + LOG_QUEUE_LINES * b"line\n".len()
        );
    }

    fn contents(directory: &Path, max_bytes: u64) -> String {
        (0..=LOG_ARCHIVES)
            .rev()
            .filter_map(|index| {
                let name = if index == 0 {
                    "dbev.log".to_owned()
                } else {
                    format!("dbev.log.{index}")
                };
                let path = directory.join(name);
                let metadata = fs::metadata(&path).ok()?;
                assert!(metadata.len() <= max_bytes);
                assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
                Some(fs::read_to_string(path).unwrap())
            })
            .collect()
    }

    #[test]
    fn rotation_retains_latest_records_across_restarts() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("dbev.log.2026-09-04"), "old log").unwrap();
        fs::write(directory.path().join("dbev.log.notes"), "notes").unwrap();
        fs::create_dir(directory.path().join("instances")).unwrap();
        for batch in 0..3 {
            let (mut writer, guard) =
                log_queue().finish(RollingLog::new(directory.path(), 10).unwrap());
            for record in batch * 4..batch * 4 + 4 {
                writer
                    .write_all(format!("line-{record:02}\n").as_bytes())
                    .unwrap();
            }
            drop(guard);
        }
        assert_eq!(
            contents(directory.path(), 10),
            "line-07\nline-08\nline-09\nline-10\nline-11\n"
        );
        assert_eq!(
            fs::read_to_string(directory.path().join("dbev.log.2026-09-04")).unwrap(),
            "old log"
        );
        assert_eq!(
            fs::read_to_string(directory.path().join("dbev.log.notes")).unwrap(),
            "notes"
        );
        assert!(directory.path().join("instances").is_dir());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 8);
    }

    #[test]
    fn oversized_records_and_full_files_stay_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let mut writer = RollingLog::new(directory.path(), 10).unwrap();
        let record = "1234567890".repeat(8) + "end";
        writer.write_all(record.as_bytes()).unwrap();
        writer.flush().unwrap();
        assert_eq!(contents(directory.path(), 10), record[40..]);
        writer.write_all(b"1234567").unwrap();
        writer.flush().unwrap();
        assert_eq!(fs::metadata(writer.path(0)).unwrap().len(), 10);
        writer.write_all(b"").unwrap();
        writer.write_all(b"next").unwrap();
        writer.flush().unwrap();
        assert_eq!(fs::read(writer.path(0)).unwrap(), b"next");
    }

    #[test]
    fn small_records_are_batched_and_the_write_buffer_stays_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let mut writer = RollingLog::new(directory.path(), LOG_BYTES).unwrap();
        let record = b"one small log record\n";
        for _ in 0..1000 {
            writer.write_all(record).unwrap();
        }
        let file = writer.file.as_ref().unwrap();
        assert_eq!(file.get_ref().metadata().unwrap().len(), 0);
        assert_eq!(file.buffer().len(), record.len() * 1000);

        for _ in 1000..10_000 {
            writer.write_all(record).unwrap();
            assert!(writer.file.as_ref().unwrap().buffer().len() <= LOG_WRITE_BUFFER_BYTES);
        }
        assert!(
            writer
                .file
                .as_ref()
                .unwrap()
                .get_ref()
                .metadata()
                .unwrap()
                .len()
                > 0
        );
        writer.flush().unwrap();
        assert_eq!(fs::read(writer.path(0)).unwrap(), record.repeat(10_000));
        assert!(writer.file.as_ref().unwrap().buffer().is_empty());
    }

    #[test]
    fn idle_worker_flushes_without_waiting_for_guard_drop() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dbev.log");
        let (mut writer, guard) =
            log_queue().finish(RollingLog::new(directory.path(), LOG_BYTES).unwrap());
        writer.write_all(b"visible while idle\n").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while fs::metadata(&path).unwrap().len() == 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(fs::read(&path).unwrap(), b"visible while idle\n");
        writer.write_all(b"last record before shutdown\n").unwrap();
        drop(guard);
        assert_eq!(
            fs::read(path).unwrap(),
            b"visible while idle\nlast record before shutdown\n"
        );
    }

    #[test]
    fn flush_failure_does_not_rotate_or_discard_buffered_records() {
        let directory = tempfile::tempdir().unwrap();
        let mut writer = RollingLog::new(directory.path(), 4).unwrap();
        // A read-only descriptor deterministically rejects the eventual flush.
        writer.file = Some(BufWriter::with_capacity(
            LOG_WRITE_BUFFER_BYTES,
            File::open(writer.path(0)).unwrap(),
        ));
        writer.write_all(b"full").unwrap();
        assert!(writer.write_all(b"next").is_err());
        assert_eq!(writer.bytes, 4);
        assert_eq!(writer.file.as_ref().unwrap().buffer(), b"full");
        assert!(!writer.path(1).exists());
    }

    #[test]
    fn rotation_refuses_non_regular_or_linked_paths() {
        for index in [0, LOG_ARCHIVES] {
            for kind in ["symlink", "hardlink", "directory"] {
                let directory = tempfile::tempdir().unwrap();
                let mut writer = RollingLog::new(directory.path(), 4).unwrap();
                writer.write_all(b"full").unwrap();
                let target = directory.path().join("keep");
                fs::write(&target, "unchanged").unwrap();
                let path = writer.path(index);
                if path.exists() {
                    fs::remove_file(&path).unwrap();
                }
                match kind {
                    "symlink" => std::os::unix::fs::symlink(&target, &path).unwrap(),
                    "hardlink" => fs::hard_link(&target, &path).unwrap(),
                    _ => fs::create_dir(&path).unwrap(),
                }
                assert!(writer.write_all(b"next").is_err(), "{kind} at {index}");
                assert!(RollingLog::new(directory.path(), 4).is_err());
                assert_eq!(fs::read_to_string(target).unwrap(), "unchanged");
            }
        }
    }
}
