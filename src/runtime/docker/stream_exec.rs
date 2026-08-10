use std::{
    collections::HashSet,
    io::{Error as IoError, ErrorKind},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bollard::{
    container::LogOutput,
    errors::Error as BollardError,
    exec::{CreateExecOptions, StartExecOptions, StartExecResults},
};
use futures::{Stream, StreamExt};
use secrecy::{ExposeSecret, SecretString};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::oneshot,
};

use super::{DockerError, DockerRuntime};
use crate::shared::protocol::Protocol;

const EXEC_STREAM_BUFFER_BYTES: usize = 64 * 1024;
const EXEC_STREAM_DECODER_CAPACITY: usize = 64 * 1024;
const EXEC_STREAM_RECOVERY_READINESS_TIMEOUT: Duration = Duration::from_secs(30);
const STREAM_OPERATION: &str = "streaming exec [command and environment redacted]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecStreamResult {
    pub transferred_bytes: u64,
}

#[derive(Debug, Clone)]
enum ExecStreamDirection {
    Input { path: PathBuf, max_bytes: u64 },
    Output { path: PathBuf, max_bytes: u64 },
}

struct CancellationSignal(Option<oneshot::Sender<()>>);

impl CancellationSignal {
    fn disarm(&mut self) {
        self.0.take();
    }
}

impl Drop for CancellationSignal {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

impl DockerRuntime {
    /// Streams a private regular host file to the stdin of a native command.
    ///
    /// The source is opened without following its final symlink, its descriptor
    /// length is bounded before exec creation, and growth or truncation while it
    /// is being read fails the operation. Secret values exist only in the exec
    /// environment and are never included in diagnostics.
    #[allow(clippy::too_many_arguments)]
    pub async fn exec_with_file_stdin_and_secret_env(
        &self,
        protocol: Protocol,
        instance_id: &str,
        command: Vec<String>,
        environment: &[(&str, &SecretString)],
        input_path: &Path,
        max_input_bytes: u64,
        timeout: Duration,
    ) -> Result<ExecStreamResult, DockerError> {
        self.exec_streaming(
            protocol,
            instance_id,
            command,
            environment,
            ExecStreamDirection::Input {
                path: input_path.to_path_buf(),
                max_bytes: max_input_bytes,
            },
            timeout,
        )
        .await
    }

    /// Shell counterpart of [`Self::exec_with_file_stdin_and_secret_env`].
    #[allow(clippy::too_many_arguments)]
    pub async fn exec_shell_with_file_stdin_and_secret_env(
        &self,
        protocol: Protocol,
        instance_id: &str,
        script: &str,
        environment: &[(&str, &SecretString)],
        input_path: &Path,
        max_input_bytes: u64,
        timeout: Duration,
    ) -> Result<ExecStreamResult, DockerError> {
        self.exec_with_file_stdin_and_secret_env(
            protocol,
            instance_id,
            vec!["sh".to_string(), "-c".to_string(), script.to_string()],
            environment,
            input_path,
            max_input_bytes,
            timeout,
        )
        .await
    }

    /// Streams a native command's stdout to a new private regular host file.
    ///
    /// The destination is create-new and mode 0600. It is removed through its
    /// already-open parent descriptor unless the command exits successfully,
    /// stays within `max_output_bytes`, and the file and directory are synced.
    #[allow(clippy::too_many_arguments)]
    pub async fn exec_to_file_with_secret_env(
        &self,
        protocol: Protocol,
        instance_id: &str,
        command: Vec<String>,
        environment: &[(&str, &SecretString)],
        output_path: &Path,
        max_output_bytes: u64,
        timeout: Duration,
    ) -> Result<ExecStreamResult, DockerError> {
        self.exec_streaming(
            protocol,
            instance_id,
            command,
            environment,
            ExecStreamDirection::Output {
                path: output_path.to_path_buf(),
                max_bytes: max_output_bytes,
            },
            timeout,
        )
        .await
    }

    /// Shell counterpart of [`Self::exec_to_file_with_secret_env`].
    #[allow(clippy::too_many_arguments)]
    pub async fn exec_shell_to_file_with_secret_env(
        &self,
        protocol: Protocol,
        instance_id: &str,
        script: &str,
        environment: &[(&str, &SecretString)],
        output_path: &Path,
        max_output_bytes: u64,
        timeout: Duration,
    ) -> Result<ExecStreamResult, DockerError> {
        self.exec_to_file_with_secret_env(
            protocol,
            instance_id,
            vec!["sh".to_string(), "-c".to_string(), script.to_string()],
            environment,
            output_path,
            max_output_bytes,
            timeout,
        )
        .await
    }

    async fn exec_streaming(
        &self,
        protocol: Protocol,
        instance_id: &str,
        command: Vec<String>,
        environment: &[(&str, &SecretString)],
        direction: ExecStreamDirection,
        timeout: Duration,
    ) -> Result<ExecStreamResult, DockerError> {
        if timeout.is_zero() {
            return Err(DockerError::InvalidExecTimeout);
        }
        validate_exec_command(&command)?;
        let environment = encode_secret_environment(environment)?;
        let container = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let instance_id = instance_id.to_string();
        let runtime = self.clone();
        let (cancel_sender, cancel_receiver) = oneshot::channel();
        let mut cancellation = CancellationSignal(Some(cancel_sender));
        let task = tokio::spawn(async move {
            runtime
                .run_streaming_exec(
                    protocol,
                    &instance_id,
                    &container,
                    command,
                    environment,
                    direction,
                    timeout,
                    cancel_receiver,
                )
                .await
        });

        let result = task
            .await
            .map_err(|error| DockerError::ExecStreamTask(error.to_string()))?;
        cancellation.disarm();
        result
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_streaming_exec(
        &self,
        protocol: Protocol,
        instance_id: &str,
        container: &str,
        command: Vec<String>,
        environment: Vec<String>,
        direction: ExecStreamDirection,
        timeout: Duration,
        cancel_receiver: oneshot::Receiver<()>,
    ) -> Result<ExecStreamResult, DockerError> {
        let active = Arc::new(AtomicBool::new(false));
        let execution = self.execute_streaming_exec(
            container,
            command,
            environment,
            direction,
            Arc::clone(&active),
        );
        tokio::pin!(execution);
        let deadline = tokio::time::Instant::now() + timeout;
        let result = tokio::select! {
            _ = cancel_receiver => Err(DockerError::ExecStreamCancelled {
                container: container.to_string(),
            }),
            result = tokio::time::timeout_at(deadline, &mut execution) => match result {
                Ok(result) => result,
                Err(_) => Err(DockerError::ExecTimedOut {
                    container: container.to_string(),
                    operation: STREAM_OPERATION.to_string(),
                    timeout_seconds: timeout.as_secs(),
                }),
            },
        };

        if result.is_err() && active.load(Ordering::Acquire) {
            self.recover_interrupted_exec(
                protocol,
                instance_id,
                container,
                STREAM_OPERATION,
                EXEC_STREAM_RECOVERY_READINESS_TIMEOUT,
            )
            .await?;
        }
        result
    }

    async fn execute_streaming_exec(
        &self,
        container: &str,
        command: Vec<String>,
        environment: Vec<String>,
        direction: ExecStreamDirection,
        active: Arc<AtomicBool>,
    ) -> Result<ExecStreamResult, DockerError> {
        let mut input_file = None;
        let mut output_file = None;
        let attach_stdin = matches!(direction, ExecStreamDirection::Input { .. });
        match &direction {
            ExecStreamDirection::Input { path, max_bytes } => {
                input_file = Some(open_private_input(path, *max_bytes)?);
            }
            ExecStreamDirection::Output { path, .. } => {
                output_file = Some(PrivateOutputFile::create(path)?);
            }
        }

        let exec = self
            .docker
            .create_exec(
                container,
                streaming_exec_options(command, environment, attach_stdin),
            )
            .await?;

        // Once start is attempted, cancellation or an ambiguous transport
        // failure must recover the whole managed container: Docker has no API
        // for reliably killing one exec process.
        active.store(true, Ordering::Release);
        let started = self
            .docker
            .start_exec(
                &exec.id,
                Some(StartExecOptions {
                    detach: false,
                    tty: false,
                    output_capacity: Some(EXEC_STREAM_DECODER_CAPACITY),
                }),
            )
            .await?;
        let StartExecResults::Attached { output, input } = started else {
            return Err(DockerError::ExecStreamDetached {
                container: container.to_string(),
            });
        };

        let transferred_bytes = match direction {
            ExecStreamDirection::Input { path, max_bytes } => {
                let (file, expected_bytes) = input_file
                    .take()
                    .expect("input direction always opens an input descriptor");
                let transfer = pump_private_input(file, input, expected_bytes, max_bytes);
                let drain = discard_exec_output(output);
                let (transferred, ()) = tokio::try_join!(
                    async {
                        transfer.await.map_err(|source| DockerError::ExecStreamIo {
                            direction: "input",
                            path: path.display().to_string(),
                            source,
                        })
                    },
                    async { drain.await.map_err(DockerError::from) }
                )?;
                transferred
            }
            ExecStreamDirection::Output { path, max_bytes } => {
                drop(input);
                let output_file = output_file
                    .as_mut()
                    .expect("output direction always opens an output descriptor");
                match drain_exec_output(output, output_file.file_mut(), max_bytes).await {
                    Ok(bytes) => bytes,
                    Err(OutputDrainError::Api(error)) => return Err(error.into()),
                    Err(OutputDrainError::Io(source)) => {
                        return Err(DockerError::ExecStreamIo {
                            direction: "output",
                            path: path.display().to_string(),
                            source,
                        });
                    }
                    Err(OutputDrainError::Limit) => {
                        return Err(DockerError::ExecStreamOutputTooLarge {
                            path: path.display().to_string(),
                            max_bytes,
                        });
                    }
                }
            }
        };

        let exit_code = self.wait_for_streaming_exec_exit(&exec.id, &active).await?;
        if exit_code != 0 {
            return Err(DockerError::ExecStreamFailed {
                container: container.to_string(),
                exit_code,
            });
        }
        if let Some(output_file) = output_file {
            output_file.commit().await?;
        }
        Ok(ExecStreamResult { transferred_bytes })
    }

    async fn wait_for_streaming_exec_exit(
        &self,
        exec_id: &str,
        active: &AtomicBool,
    ) -> Result<i64, DockerError> {
        loop {
            let inspection = self.docker.inspect_exec(exec_id).await?;
            if inspection.running == Some(false)
                || (inspection.running.is_none() && inspection.exit_code.is_some())
            {
                active.store(false, Ordering::Release);
                return inspection
                    .exit_code
                    .ok_or(DockerError::ExecExitStatusUnavailable);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

fn validate_exec_command(command: &[String]) -> Result<(), DockerError> {
    if command.is_empty() || command.iter().any(|argument| argument.contains('\0')) {
        return Err(DockerError::InvalidExecCommand);
    }
    Ok(())
}

fn streaming_exec_options(
    command: Vec<String>,
    environment: Vec<String>,
    attach_stdin: bool,
) -> CreateExecOptions<String> {
    CreateExecOptions {
        attach_stdin: Some(attach_stdin),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        tty: Some(false),
        cmd: Some(command),
        env: (!environment.is_empty()).then_some(environment),
        privileged: Some(false),
        ..Default::default()
    }
}

fn encode_secret_environment(
    environment: &[(&str, &SecretString)],
) -> Result<Vec<String>, DockerError> {
    let mut names = HashSet::with_capacity(environment.len());
    let mut encoded = Vec::with_capacity(environment.len());
    for (name, value) in environment {
        let valid_name = !name.is_empty()
            && name.bytes().enumerate().all(|(index, byte)| match byte {
                b'A'..=b'Z' | b'_' => true,
                b'a'..=b'z' if index == 0 => true,
                b'a'..=b'z' | b'0'..=b'9' if index > 0 => true,
                _ => false,
            });
        if !valid_name || !names.insert(*name) {
            return Err(DockerError::InvalidExecEnvironment);
        }
        let value = value.expose_secret();
        if value.contains('\0') {
            return Err(DockerError::InvalidExecEnvironment);
        }
        encoded.push(format!("{name}={value}"));
    }
    Ok(encoded)
}

async fn pump_private_input<R, W>(
    mut reader: R,
    mut writer: W,
    expected_bytes: u64,
    max_bytes: u64,
) -> Result<u64, IoError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut transferred = 0_u64;
    let mut buffer = vec![0_u8; EXEC_STREAM_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        transferred = transferred
            .checked_add(read as u64)
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "exec input size overflow"))?;
        if transferred > max_bytes || transferred > expected_bytes {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "exec input changed size or exceeded its byte limit",
            ));
        }
        writer.write_all(&buffer[..read]).await?;
    }
    if transferred != expected_bytes {
        return Err(IoError::new(
            ErrorKind::UnexpectedEof,
            "exec input changed size while it was streamed",
        ));
    }
    writer.shutdown().await?;
    Ok(transferred)
}

async fn discard_exec_output<S>(mut output: S) -> Result<(), BollardError>
where
    S: Stream<Item = Result<LogOutput, BollardError>> + Unpin,
{
    while let Some(chunk) = output.next().await {
        let _ = chunk?;
    }
    Ok(())
}

#[derive(Debug)]
enum OutputDrainError {
    Api(BollardError),
    Io(IoError),
    Limit,
}

async fn drain_exec_output<S, W>(
    mut output: S,
    writer: &mut W,
    max_bytes: u64,
) -> Result<u64, OutputDrainError>
where
    S: Stream<Item = Result<LogOutput, BollardError>> + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut transferred = 0_u64;
    while let Some(chunk) = output.next().await {
        let chunk = chunk.map_err(OutputDrainError::Api)?;
        let message = match chunk {
            LogOutput::StdOut { message } | LogOutput::Console { message } => message,
            LogOutput::StdErr { .. } | LogOutput::StdIn { .. } => continue,
        };
        transferred = transferred
            .checked_add(message.len() as u64)
            .ok_or(OutputDrainError::Limit)?;
        if transferred > max_bytes {
            return Err(OutputDrainError::Limit);
        }
        writer
            .write_all(&message)
            .await
            .map_err(OutputDrainError::Io)?;
    }
    writer.flush().await.map_err(OutputDrainError::Io)?;
    Ok(transferred)
}

#[cfg(unix)]
fn open_private_input(path: &Path, max_bytes: u64) -> Result<(tokio::fs::File, u64), DockerError> {
    use std::{fs::File, os::fd::OwnedFd};

    use rustix::fs::{Mode, OFlags};

    let (directory, file_name) = open_parent_directory(path, "input")?;
    let descriptor: OwnedFd = rustix::fs::openat(
        &directory,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| DockerError::ExecStreamIo {
        direction: "input",
        path: path.display().to_string(),
        source: IoError::from(source),
    })?;
    let file = File::from(descriptor);
    let metadata = file
        .metadata()
        .map_err(|source| DockerError::ExecStreamIo {
            direction: "input",
            path: path.display().to_string(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(DockerError::InvalidExecStreamFile {
            direction: "input",
            path: path.display().to_string(),
        });
    }
    if metadata.len() > max_bytes {
        return Err(DockerError::ExecStreamInputTooLarge {
            path: path.display().to_string(),
            size: metadata.len(),
            max_bytes,
        });
    }
    Ok((tokio::fs::File::from_std(file), metadata.len()))
}

#[cfg(not(unix))]
fn open_private_input(path: &Path, _max_bytes: u64) -> Result<(tokio::fs::File, u64), DockerError> {
    Err(DockerError::ExecStreamIo {
        direction: "input",
        path: path.display().to_string(),
        source: IoError::new(
            ErrorKind::Unsupported,
            "private no-follow exec input is only available on Unix",
        ),
    })
}

#[cfg(unix)]
struct PrivateOutputFile {
    file: Option<tokio::fs::File>,
    directory: std::os::fd::OwnedFd,
    file_name: std::ffi::OsString,
    path: PathBuf,
    committed: bool,
}

#[cfg(unix)]
impl PrivateOutputFile {
    fn create(path: &Path) -> Result<Self, DockerError> {
        use std::{fs::File, os::fd::OwnedFd};

        use rustix::fs::{Mode, OFlags};

        let (directory, file_name) = open_parent_directory(path, "output")?;
        let descriptor: OwnedFd = rustix::fs::openat(
            &directory,
            &file_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|source| DockerError::ExecStreamIo {
            direction: "output",
            path: path.display().to_string(),
            source: IoError::from(source),
        })?;
        rustix::fs::fchmod(&descriptor, Mode::RUSR | Mode::WUSR).map_err(|source| {
            let _ = rustix::fs::unlinkat(&directory, &file_name, rustix::fs::AtFlags::empty());
            let _ = sync_directory(&directory);
            DockerError::ExecStreamIo {
                direction: "output",
                path: path.display().to_string(),
                source: IoError::from(source),
            }
        })?;
        Ok(Self {
            file: Some(tokio::fs::File::from_std(File::from(descriptor))),
            directory,
            file_name,
            path: path.to_path_buf(),
            committed: false,
        })
    }

    fn file_mut(&mut self) -> &mut tokio::fs::File {
        self.file
            .as_mut()
            .expect("uncommitted output always owns its descriptor")
    }

    async fn commit(mut self) -> Result<(), DockerError> {
        let file = self
            .file
            .take()
            .expect("uncommitted output always owns its descriptor");
        file.sync_all()
            .await
            .map_err(|source| DockerError::ExecStreamIo {
                direction: "output",
                path: self.path.display().to_string(),
                source,
            })?;
        drop(file);
        sync_directory(&self.directory).map_err(|source| DockerError::ExecStreamIo {
            direction: "output",
            path: self.path.display().to_string(),
            source,
        })?;
        self.committed = true;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for PrivateOutputFile {
    fn drop(&mut self) {
        if !self.committed {
            self.file.take();
            let _ = rustix::fs::unlinkat(
                &self.directory,
                &self.file_name,
                rustix::fs::AtFlags::empty(),
            );
            let _ = sync_directory(&self.directory);
        }
    }
}

#[cfg(not(unix))]
struct PrivateOutputFile;

#[cfg(not(unix))]
impl PrivateOutputFile {
    fn create(path: &Path) -> Result<Self, DockerError> {
        Err(DockerError::ExecStreamIo {
            direction: "output",
            path: path.display().to_string(),
            source: IoError::new(
                ErrorKind::Unsupported,
                "private no-follow exec output is only available on Unix",
            ),
        })
    }

    fn file_mut(&mut self) -> &mut tokio::fs::File {
        unreachable!("unsupported output creation never returns a value")
    }

    async fn commit(self) -> Result<(), DockerError> {
        unreachable!("unsupported output creation never returns a value")
    }
}

#[cfg(unix)]
fn open_parent_directory(
    path: &Path,
    direction: &'static str,
) -> Result<(std::os::fd::OwnedFd, std::ffi::OsString), DockerError> {
    use rustix::fs::{Mode, OFlags};

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| DockerError::InvalidExecStreamFile {
            direction,
            path: path.display().to_string(),
        })?;
    let file_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| DockerError::InvalidExecStreamFile {
            direction,
            path: path.display().to_string(),
        })?
        .to_os_string();
    let directory = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|source| DockerError::ExecStreamIo {
        direction,
        path: path.display().to_string(),
        source: IoError::from(source),
    })?;
    Ok((directory, file_name))
}

#[cfg(unix)]
fn sync_directory(directory: &impl std::os::fd::AsFd) -> Result<(), IoError> {
    match rustix::fs::fsync(directory) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::INVAL | rustix::io::Errno::OPNOTSUPP) => Ok(()),
        Err(error) => Err(IoError::from(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use secrecy::SecretString;

    #[test]
    fn secret_environment_is_validated_without_echoing_values() {
        let secret = SecretString::from("correct horse battery staple");
        assert_eq!(
            encode_secret_environment(&[("PGPASSWORD", &secret)]).unwrap(),
            vec!["PGPASSWORD=correct horse battery staple"]
        );
        assert!(
            encode_secret_environment(&[("BAD=KEY", &secret)])
                .unwrap_err()
                .to_string()
                .contains("environment")
        );
        assert!(
            encode_secret_environment(&[("PGPASSWORD", &secret), ("PGPASSWORD", &secret)]).is_err()
        );
        let nul = SecretString::from("secret\0tail");
        let error = encode_secret_environment(&[("PGPASSWORD", &nul)]).unwrap_err();
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn streaming_exec_is_attached_non_tty_and_never_privileged() {
        let options = streaming_exec_options(
            vec!["database-client".to_string()],
            vec!["PASSWORD=redacted".to_string()],
            true,
        );

        assert_eq!(options.attach_stdin, Some(true));
        assert_eq!(options.attach_stdout, Some(true));
        assert_eq!(options.attach_stderr, Some(true));
        assert_eq!(options.tty, Some(false));
        assert_eq!(options.privileged, Some(false));
        assert_eq!(
            options.cmd.as_deref(),
            Some(["database-client".to_string()].as_slice())
        );
        assert!(options.env.is_some());
    }

    #[tokio::test]
    async fn input_pump_obeys_backpressure_and_preserves_bytes() {
        let contents = vec![b'x'; EXEC_STREAM_BUFFER_BYTES * 3 + 17];
        let (writer, mut reader) = tokio::io::duplex(7);
        let expected = contents.clone();
        let consumer = tokio::spawn(async move {
            let mut received = Vec::new();
            reader.read_to_end(&mut received).await.unwrap();
            received
        });

        let transferred = pump_private_input(
            std::io::Cursor::new(contents),
            writer,
            expected.len() as u64,
            expected.len() as u64,
        )
        .await
        .unwrap();

        assert_eq!(transferred, expected.len() as u64);
        assert_eq!(consumer.await.unwrap(), expected);
    }

    #[tokio::test]
    async fn input_pump_rejects_growth_and_truncation() {
        let growth = pump_private_input(std::io::Cursor::new(b"too long"), tokio::io::sink(), 3, 8)
            .await
            .unwrap_err();
        assert_eq!(growth.kind(), ErrorKind::InvalidData);

        let truncated = pump_private_input(std::io::Cursor::new(b"short"), tokio::io::sink(), 8, 8)
            .await
            .unwrap_err();
        assert_eq!(truncated.kind(), ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn output_drain_writes_only_stdout_and_console() {
        let output = futures::stream::iter(vec![
            Ok(LogOutput::StdOut {
                message: Bytes::from_static(b"dump"),
            }),
            Ok(LogOutput::StdErr {
                message: Bytes::from_static(b"not part of dump"),
            }),
            Ok(LogOutput::Console {
                message: Bytes::from_static(b"-tail"),
            }),
        ]);
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let drain = tokio::spawn(async move {
            let bytes = drain_exec_output(output, &mut writer, 9).await.unwrap();
            writer.shutdown().await.unwrap();
            bytes
        });
        let mut contents = Vec::new();
        reader.read_to_end(&mut contents).await.unwrap();

        assert_eq!(drain.await.unwrap(), 9);
        assert_eq!(contents, b"dump-tail");
    }

    #[tokio::test]
    async fn output_drain_stops_before_writing_past_limit() {
        let output = futures::stream::iter(vec![Ok(LogOutput::StdOut {
            message: Bytes::from_static(b"oversized"),
        })]);
        let error = drain_exec_output(output, &mut tokio::io::sink(), 4)
            .await
            .unwrap_err();
        assert!(matches!(error, OutputDrainError::Limit));
    }

    #[cfg(unix)]
    #[test]
    fn private_input_rejects_symlinks_and_oversized_files() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let regular = directory.path().join("dump.sql");
        let linked = directory.path().join("linked.sql");
        std::fs::write(&regular, b"contents").unwrap();
        symlink(&regular, &linked).unwrap();

        assert_eq!(open_private_input(&regular, 8).unwrap().1, 8);
        assert!(matches!(
            open_private_input(&regular, 7).unwrap_err(),
            DockerError::ExecStreamInputTooLarge { .. }
        ));
        assert!(open_private_input(&linked, 8).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn private_output_is_create_new_private_and_durable_on_commit() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let output_path = directory.path().join("dump.sql");
        let mut output = PrivateOutputFile::create(&output_path).unwrap();
        output.file_mut().write_all(b"contents").await.unwrap();
        output.commit().await.unwrap();

        assert_eq!(std::fs::read(&output_path).unwrap(), b"contents");
        assert_eq!(
            std::fs::metadata(&output_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(PrivateOutputFile::create(&output_path).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn output_limit_removes_partial_private_file() {
        let directory = tempfile::tempdir().unwrap();
        let output_path = directory.path().join("partial.sql");
        let output = futures::stream::iter(vec![
            Ok(LogOutput::StdOut {
                message: Bytes::from_static(b"part"),
            }),
            Ok(LogOutput::StdOut {
                message: Bytes::from_static(b"too-much"),
            }),
        ]);
        let mut file = PrivateOutputFile::create(&output_path).unwrap();

        let error = drain_exec_output(output, file.file_mut(), 4)
            .await
            .unwrap_err();
        assert!(matches!(error, OutputDrainError::Limit));
        drop(file);
        assert!(!output_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn dropping_uncommitted_output_removes_only_the_created_file() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let output_path = directory.path().join("partial.sql");
        let victim = directory.path().join("victim");
        std::fs::write(&victim, b"safe").unwrap();
        drop(PrivateOutputFile::create(&output_path).unwrap());
        assert!(!output_path.exists());

        symlink(&victim, &output_path).unwrap();
        assert!(PrivateOutputFile::create(&output_path).is_err());
        assert_eq!(std::fs::read(victim).unwrap(), b"safe");
    }

    #[tokio::test]
    async fn cancellation_signal_notifies_the_detached_worker() {
        let (sender, receiver) = oneshot::channel();
        drop(CancellationSignal(Some(sender)));
        receiver.await.unwrap();
    }
}
