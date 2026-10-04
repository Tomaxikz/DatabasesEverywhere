use std::{
    io::Error,
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::io::AsyncReadExt;

use tokio::{
    process::Command,
    time::{sleep, timeout},
};

use super::{
    MAX_HELPER_CMDLINE_BYTES, UNMOUNT_COMMAND_TIMEOUT, UNMOUNT_CONFIRM_TIMEOUT,
    UNMOUNT_POLL_INTERVAL,
};
use crate::server::disk::{DiskLimitError, mounts};

pub(super) async fn unmount(mount_path: &Path) -> Result<(), DiskLimitError> {
    if !mounts::is_mountpoint(mount_path)? {
        return Ok(());
    }

    let mut failures = Vec::new();
    let attempts: [(&'static str, &[&str]); 3] = [
        ("fusermount3", &["-u"]),
        ("fusermount", &["-u"]),
        ("umount", &[]),
    ];
    for (program, args) in attempts {
        match run_unmount_command(program, args, mount_path).await {
            Ok(Some(status)) if !status.success() => {
                failures.push(format!("{program} exited with {status}"));
            }
            Ok(_) => {}
            Err(error) => failures.push(error.to_string()),
        }
        if wait_until_unmounted(mount_path, UNMOUNT_CONFIRM_TIMEOUT).await? {
            return Ok(());
        }
    }

    Err(DiskLimitError::FuseSocket(format!(
        "failed to confirm unmount of {}: {}",
        mount_path.display(),
        failures.join("; ")
    )))
}

async fn run_unmount_command(
    program: &'static str,
    args: &[&str],
    mount_path: &Path,
) -> Result<Option<std::process::ExitStatus>, DiskLimitError> {
    let mut command = Command::new(program);
    command
        .args(args)
        .arg(mount_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    match timeout(UNMOUNT_COMMAND_TIMEOUT, command.status()).await {
        Ok(Ok(status)) => Ok(Some(status)),
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Ok(Err(source)) => Err(DiskLimitError::CommandIo {
            command: program,
            source,
        }),
        Err(_) => Err(DiskLimitError::CommandIo {
            command: program,
            source: std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("{program} exceeded the 10 second timeout"),
            ),
        }),
    }
}

async fn wait_until_unmounted(mount_path: &Path, wait: Duration) -> Result<bool, DiskLimitError> {
    let started = Instant::now();
    loop {
        if !mounts::is_mountpoint(mount_path)? {
            return Ok(true);
        }
        if started.elapsed() >= wait {
            return Ok(false);
        }
        sleep(UNMOUNT_POLL_INTERVAL).await;
    }
}

pub(super) async fn helper_cache_is_safe(pid: i32) -> bool {
    let Ok(cmdline) = read_helper_cmdline(pid).await else {
        return false;
    };
    cmdline.len() <= MAX_HELPER_CMDLINE_BYTES && has_nocache_arg(&cmdline)
}

pub(super) async fn read_helper_cmdline(pid: i32) -> Result<Vec<u8>, Error> {
    let file = tokio::fs::File::open(format!("/proc/{pid}/cmdline")).await?;
    let mut bytes = Vec::new();
    file.take((MAX_HELPER_CMDLINE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    Ok(bytes)
}

pub(super) fn has_nocache_arg(cmdline: &[u8]) -> bool {
    cmdline.ends_with(&[0])
        && cmdline
            .split(|byte| *byte == 0)
            .skip(1)
            .take_while(|arg| *arg != b"--")
            .any(|arg| arg == b"--nocache")
}

pub(super) fn mount_args() -> [&'static str; 6] {
    // Each libfuse worker retains its receive buffer (up to 4 MiB plus header).
    // The helper defaults to ten persistent workers per mount. Two keep I/O
    // concurrent without multiplying that idle footprint across every engine.
    [
        // The pinned helper's create path leaves O_WRONLY descriptors unable
        // to serve kernel writeback-cache reads after a partial-page append.
        // Keep backing-filesystem caching, but disable unsafe FUSE writeback.
        "--nocache",
        "--nopassthrough",
        "--nosplice",
        "--clone-fd",
        "--num-threads",
        "2",
    ]
}

pub(super) fn stderr_string(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr).trim().to_string()
}
