use super::*;

pub(super) async fn wait_for_socket(socket_path: &Path) -> Result<(), DiskLimitError> {
    let started = Instant::now();
    let mut last_error = String::new();
    while started.elapsed() < SOCKET_READY_TIMEOUT {
        match send_command_detailed(socket_path, "get quota_used", None).await {
            Ok(response) => {
                set_helper_nofile_limit(response.peer_pid).await?;
                return Ok(());
            }
            Err(error) => {
                last_error = error.to_string();
                sleep(SOCKET_READY_POLL_INTERVAL).await;
            }
        }
    }
    Err(DiskLimitError::FuseSocket(format!(
        "fusequota control socket did not become ready at {}: {last_error}",
        socket_path.display()
    )))
}

pub(super) async fn send_command(
    socket_path: &Path,
    command: &str,
) -> Result<Vec<String>, DiskLimitError> {
    send_command_detailed(socket_path, command, None)
        .await
        .map(|response| response.lines)
}

pub(super) async fn send_command_detailed(
    socket_path: &Path,
    command: &str,
    expected_pid: Option<i32>,
) -> Result<FuseControlResponse, DiskLimitError> {
    if command.len() > MAX_CONTROL_COMMAND_BYTES || command.contains(['\r', '\n']) {
        return Err(DiskLimitError::FuseSocket(
            "invalid fusequota control command".to_string(),
        ));
    }
    validate_control_socket(socket_path)?;

    timeout(
        CONTROL_IO_TIMEOUT,
        send_command_bounded(socket_path, command, expected_pid),
    )
    .await
    .map_err(|_| {
        DiskLimitError::FuseSocket(format!(
            "fusequota control I/O timed out at {}",
            socket_path.display()
        ))
    })?
}

async fn send_command_bounded(
    socket_path: &Path,
    command: &str,
    expected_pid: Option<i32>,
) -> Result<FuseControlResponse, DiskLimitError> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .map_err(path_io_error(socket_path))?;
    let peer_pid = verify_control_peer(&stream, socket_path, expected_pid)?;

    stream
        .write_all(format!("{command}\n").as_bytes())
        .await
        .map_err(path_io_error(socket_path))?;
    stream
        .shutdown()
        .await
        .map_err(path_io_error(socket_path))?;

    let mut response = Vec::with_capacity(MAX_CONTROL_RESPONSE_BYTES.min(4096));
    stream
        .take((MAX_CONTROL_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .await
        .map_err(path_io_error(socket_path))?;
    let lines = parse_control_response(&response, command)?;
    Ok(FuseControlResponse { lines, peer_pid })
}

fn verify_control_peer(
    stream: &UnixStream,
    socket_path: &Path,
    expected_pid: Option<i32>,
) -> Result<i32, DiskLimitError> {
    let peer = stream.peer_cred().map_err(path_io_error(socket_path))?;
    let expected_uid = rustix::process::geteuid().as_raw();
    if peer.uid() != expected_uid {
        return Err(DiskLimitError::FuseSocket(format!(
            "fusequota control peer at {} is owned by uid {}, expected uid {expected_uid}",
            socket_path.display(),
            peer.uid()
        )));
    }
    let peer_pid = peer.pid().filter(|pid| *pid > 0).ok_or_else(|| {
        DiskLimitError::FuseSocket(format!(
            "fusequota control peer at {} did not expose a valid process id",
            socket_path.display()
        ))
    })?;
    if expected_pid.is_some_and(|expected| peer_pid != expected) {
        return Err(DiskLimitError::FuseRequiresRestart(
            socket_path.to_path_buf(),
        ));
    }
    Ok(peer_pid)
}

fn parse_control_response(response: &[u8], command: &str) -> Result<Vec<String>, DiskLimitError> {
    if response.len() > MAX_CONTROL_RESPONSE_BYTES {
        return Err(DiskLimitError::FuseSocket(format!(
            "fusequota control response exceeded {MAX_CONTROL_RESPONSE_BYTES} bytes"
        )));
    }
    let response = std::str::from_utf8(response)
        .map_err(|_| DiskLimitError::FuseSocket("fusequota response was not UTF-8".to_string()))?;
    let mut lines = Vec::new();
    for line in response.lines() {
        if lines.len() >= MAX_CONTROL_RESPONSE_LINES {
            return Err(DiskLimitError::FuseSocket(format!(
                "fusequota control response exceeded {MAX_CONTROL_RESPONSE_LINES} lines"
            )));
        }
        if line.len() > MAX_CONTROL_RESPONSE_LINE_BYTES {
            return Err(DiskLimitError::FuseSocket(format!(
                "fusequota control response line exceeded {MAX_CONTROL_RESPONSE_LINE_BYTES} bytes"
            )));
        }
        lines.push(line.trim().to_string());
    }

    if lines.iter().any(|line| line.starts_with("ERROR")) {
        return Err(DiskLimitError::FuseSocket(lines.join("; ")));
    }
    if !lines.iter().any(|line| line.starts_with("OK")) {
        return Err(DiskLimitError::FuseSocket(format!(
            "unexpected response to {command}: {}",
            lines.join("; ")
        )));
    }

    Ok(lines)
}

pub(super) fn validate_control_socket(socket_path: &Path) -> Result<(), DiskLimitError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = fs::symlink_metadata(socket_path).map_err(path_io_error(socket_path))?;
    let expected_uid = rustix::process::geteuid().as_raw();
    let mode = metadata.mode() & 0o777;
    if !metadata.file_type().is_socket() || metadata.uid() != expected_uid || mode & 0o022 != 0 {
        return Err(DiskLimitError::FuseSocket(format!(
            "fusequota control path {} must be a real socket owned by uid {expected_uid} and not writable by group or others (mode {mode:o})",
            socket_path.display()
        )));
    }
    Ok(())
}

pub(super) async fn remove_control_socket(socket_path: &Path) -> Result<(), DiskLimitError> {
    match fs::symlink_metadata(socket_path) {
        Ok(_) => validate_control_socket(socket_path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(path_io_error(socket_path)(source)),
    }
    match tokio::fs::remove_file(socket_path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(path_io_error(socket_path)(source)),
    }
}

pub(super) fn parse_quota_usage(lines: &[String]) -> Result<u64, DiskLimitError> {
    for line in lines {
        if let Some(value) = line.strip_prefix("quota_used =") {
            return value
                .trim()
                .parse::<u64>()
                .map_err(|error| DiskLimitError::FuseSocket(error.to_string()));
        }
    }

    Err(DiskLimitError::FuseSocket(format!(
        "fuse quota socket did not return quota_used: {}",
        lines.join("; ")
    )))
}
