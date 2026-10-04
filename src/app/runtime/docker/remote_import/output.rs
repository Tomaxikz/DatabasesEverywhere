use crate::{
    runtime::docker::{
        command::CommandOutput,
        error::DockerError,
        remote_import::{
            HELPER_LOG_TAIL_CHARS, MAX_WORK_DIRECTORY_DEPTH, MAX_WORK_DIRECTORY_ENTRIES,
        },
        transfer::CappedExecOutput,
    },
    utils::{logs::truncate_log_tail, redaction},
};
use std::{
    io::{Error as IoError, ErrorKind},
    path::Path,
    time::Duration,
};

pub(super) async fn measure_work_directory(
    path: &Path,
    stop_after: u64,
) -> Result<u64, DockerError> {
    let path = path.to_path_buf();
    let error_path = path.display().to_string();
    tokio::task::spawn_blocking(move || measure_work_dir_sync(&path, stop_after))
        .await
        .map_err(|error| DockerError::RemoteImportHelperTask(error.to_string()))?
        .map_err(|source| DockerError::RemoteImportHelperIo {
            path: error_path,
            source,
        })
}

pub(super) fn measure_work_dir_sync(root: &Path, stop_after: u64) -> Result<u64, IoError> {
    let mut total = 0_u64;
    let mut entries = 0_usize;
    let mut pending = vec![(root.to_path_buf(), 0_usize)];

    while let Some((directory, depth)) = pending.pop() {
        if depth > MAX_WORK_DIRECTORY_DEPTH {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                "remote import work directory nesting is too deep",
            ));
        }
        for entry in std::fs::read_dir(directory)? {
            entries += 1;
            if entries > MAX_WORK_DIRECTORY_ENTRIES {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "remote import work directory has too many entries",
                ));
            }
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "remote import work directory contains a symbolic link",
                ));
            }
            if file_type.is_dir() {
                pending.push((entry.path(), depth + 1));
            } else if file_type.is_file() {
                total = total.checked_add(metadata.len()).ok_or_else(|| {
                    IoError::new(
                        ErrorKind::InvalidData,
                        "remote import work directory size overflow",
                    )
                })?;
                if total > stop_after {
                    return Ok(total);
                }
            } else {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "remote import work directory contains a special file",
                ));
            }
        }
    }
    Ok(total)
}

pub(super) fn sanitized_helper_output(
    stdout: CappedExecOutput,
    stderr: CappedExecOutput,
    secret_values: &[String],
) -> CommandOutput {
    CommandOutput {
        stdout: truncate_log_tail(
            &redact_helper_output(&stdout.into_string(), secret_values),
            HELPER_LOG_TAIL_CHARS,
        ),
        stderr: truncate_log_tail(
            &redact_helper_output(&stderr.into_string(), secret_values),
            HELPER_LOG_TAIL_CHARS,
        ),
    }
}

pub(super) fn redact_helper_output(output: &str, secret_values: &[String]) -> String {
    redaction::redact_exact_secrets(output, secret_values)
}

pub(super) fn invalid_helper_spec(reason: impl Into<String>) -> DockerError {
    DockerError::InvalidRemoteImportHelperSpec {
        reason: reason.into(),
    }
}

pub(super) fn helper_timeout(timeout: Duration) -> DockerError {
    DockerError::RemoteImportHelperTimedOut {
        timeout_seconds: timeout.as_secs().max(1),
    }
}
