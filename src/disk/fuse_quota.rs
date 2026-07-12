use std::{
    fs::{self, File},
    io::{Error, ErrorKind, Read},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    process::Command,
    time::{sleep, timeout},
};

use super::{DiskLimitError, mounts};

#[derive(Debug, Clone)]
struct FuseQuotaPaths {
    root_path: PathBuf,
    mount_path: PathBuf,
    socket_path: PathBuf,
}

const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CONTROL_COMMAND_BYTES: usize = 256;
const MAX_CONTROL_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_CONTROL_RESPONSE_LINES: usize = 64;
const MAX_CONTROL_RESPONSE_LINE_BYTES: usize = 1024;
const UNMOUNT_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const UNMOUNT_CONFIRM_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) async fn verify_startup(
    binary: &str,
    binary_sha256: &str,
    fuse_root: Option<&Path>,
) -> Result<(), DiskLimitError> {
    if tokio::fs::metadata("/dev/fuse").await.is_err() {
        return Err(DiskLimitError::FuseDeviceUnavailable);
    }

    let fuse_conf = tokio::fs::read_to_string("/etc/fuse.conf")
        .await
        .unwrap_or_default();
    let allow_other_enabled = fuse_conf.lines().any(|line| {
        let line = line.trim();
        !line.starts_with('#') && line == "user_allow_other"
    });
    if !allow_other_enabled {
        return Err(DiskLimitError::FuseAllowOtherDisabled);
    }

    if let Some(fuse_root) = fuse_root {
        ensure_private_fuse_directories(fuse_root)?;
    }

    let binary_path = resolve_binary(binary, binary_sha256, fuse_root).await?;
    let output = Command::new(&binary_path)
        .arg("--help")
        .output()
        .await
        .map_err(|source| DiskLimitError::FuseBinaryIo {
            binary: display_binary(binary, &binary_path),
            source,
        })?;
    if !output.status.success() {
        return Err(DiskLimitError::FuseBinaryFailed {
            binary: display_binary(binary, &binary_path),
            stderr: stderr_string(&output.stderr),
        });
    }

    Ok(())
}

pub(super) async fn apply_with_root(
    data_path: &Path,
    fuse_root: Option<&Path>,
    disk_mib: u64,
    binary: &str,
    binary_sha256: &str,
    rescan_interval_seconds: u64,
) -> Result<PathBuf, DiskLimitError> {
    let paths = fuse_paths_with_root(data_path, fuse_root)?;
    ensure_private_fuse_directories(&paths.root_path)?;
    tokio::fs::create_dir_all(data_path)
        .await
        .map_err(|source| DiskLimitError::PathIo {
            path: data_path.display().to_string(),
            source,
        })?;
    if let Some(parent) = paths.mount_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|source| DiskLimitError::PathIo {
                path: parent.display().to_string(),
                source,
            })?;
    }
    if let Some(parent) = paths.socket_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|source| DiskLimitError::PathIo {
                path: parent.display().to_string(),
                source,
            })?;
    }
    tokio::fs::create_dir_all(&paths.mount_path)
        .await
        .map_err(|source| DiskLimitError::PathIo {
            path: paths.mount_path.display().to_string(),
            source,
        })?;

    let expected_owner = path_owner(data_path).await?;

    if send_command(
        &paths.socket_path,
        &format!("set quota = {}", mib_to_bytes(disk_mib)),
    )
    .await
    .is_ok()
    {
        if mount_owner_matches(&paths.mount_path, expected_owner).await {
            return Ok(paths.mount_path);
        }

        tracing::warn!(
            data_path = %data_path.display(),
            mount_path = %paths.mount_path.display(),
            uid = expected_owner.0,
            gid = expected_owner.1,
            "fuse quota mount owner does not match data path owner; restarting mount"
        );
        destroy_with_root(data_path, fuse_root).await?;
    } else if mounts::is_mountpoint(&paths.mount_path)? {
        tracing::warn!(
            data_path = %data_path.display(),
            mount_path = %paths.mount_path.display(),
            "stale fuse quota mount has no responsive control socket; tearing it down before restart"
        );
        destroy_with_root(data_path, fuse_root).await?;
    }

    remove_control_socket(&paths.socket_path).await?;

    let (uid, gid) = expected_owner;
    let binary_path = resolve_binary(binary, binary_sha256, fuse_root).await?;
    Command::new(&binary_path)
        .arg("--quota")
        .arg(mib_to_bytes(disk_mib).to_string())
        .arg("--quota-rescan-interval")
        .arg(rescan_interval_seconds.to_string())
        .arg("--communication-socket-path")
        .arg(&paths.socket_path)
        .arg("--uid")
        .arg(uid.to_string())
        .arg("--gid")
        .arg(gid.to_string())
        .args(database_safe_mount_args())
        .arg("-o")
        .arg("allow_other")
        .arg(data_path)
        .arg(&paths.mount_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|source| DiskLimitError::FuseBinaryIo {
            binary: display_binary(binary, &binary_path),
            source,
        })?;

    wait_for_socket(&paths.socket_path).await?;
    Ok(paths.mount_path)
}

pub(super) async fn destroy_with_root(
    data_path: &Path,
    fuse_root: Option<&Path>,
) -> Result<(), DiskLimitError> {
    let paths = fuse_paths_with_root(data_path, fuse_root)?;
    let graceful_error = match fs::symlink_metadata(&paths.socket_path) {
        Ok(_) => send_command(&paths.socket_path, "do end").await.err(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(source) => {
            return Err(DiskLimitError::PathIo {
                path: paths.socket_path.display().to_string(),
                source,
            });
        }
    };

    unmount(&paths.mount_path).await?;
    remove_control_socket(&paths.socket_path).await?;
    match tokio::fs::remove_dir(&paths.mount_path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(DiskLimitError::PathIo {
                path: paths.mount_path.display().to_string(),
                source,
            });
        }
    }
    if let Some(error) = graceful_error {
        tracing::warn!(
            mount_path = %paths.mount_path.display(),
            socket_path = %paths.socket_path.display(),
            %error,
            "fusequota graceful shutdown failed, but unmount was independently confirmed"
        );
    }
    Ok(())
}

pub(super) fn mount_path_with_root(
    data_path: &Path,
    fuse_root: Option<&Path>,
) -> Result<PathBuf, DiskLimitError> {
    Ok(fuse_paths_with_root(data_path, fuse_root)?.mount_path)
}

pub(super) async fn quota_used_with_root(
    data_path: &Path,
    fuse_root: Option<&Path>,
) -> Result<u64, DiskLimitError> {
    let paths = fuse_paths_with_root(data_path, fuse_root)?;
    let response = send_command(&paths.socket_path, "get quota_used").await?;
    parse_quota_used_response(&response)
}

pub(super) async fn runtime_is_healthy(
    data_path: &Path,
    fuse_root: Option<&Path>,
) -> Result<bool, DiskLimitError> {
    let paths = fuse_paths_with_root(data_path, fuse_root)?;
    if !mounts::is_mountpoint(&paths.mount_path)? {
        return Ok(false);
    }
    let expected_owner = match path_owner(data_path).await {
        Ok(owner) => owner,
        Err(DiskLimitError::PathIo { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    if !mount_owner_matches(&paths.mount_path, expected_owner).await {
        return Ok(false);
    }
    Ok(send_command(&paths.socket_path, "get quota_used")
        .await
        .is_ok())
}

async fn wait_for_socket(socket_path: &Path) -> Result<(), DiskLimitError> {
    let started = Instant::now();
    let mut last_error = String::new();
    while started.elapsed() < Duration::from_secs(10) {
        match send_command(socket_path, "get quota_used").await {
            Ok(_) => return Ok(()),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_millis(200)).await;
            }
        }
    }
    Err(DiskLimitError::FuseSocket(format!(
        "fusequota control socket did not become ready at {}: {last_error}",
        socket_path.display()
    )))
}

async fn send_command(socket_path: &Path, command: &str) -> Result<Vec<String>, DiskLimitError> {
    if command.len() > MAX_CONTROL_COMMAND_BYTES || command.contains(['\r', '\n']) {
        return Err(DiskLimitError::FuseSocket(
            "invalid fusequota control command".to_string(),
        ));
    }
    validate_control_socket(socket_path)?;

    timeout(
        CONTROL_IO_TIMEOUT,
        send_command_bounded(socket_path, command),
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
) -> Result<Vec<String>, DiskLimitError> {
    let mut stream =
        UnixStream::connect(socket_path)
            .await
            .map_err(|source| DiskLimitError::PathIo {
                path: socket_path.display().to_string(),
                source,
            })?;
    let peer = stream
        .peer_cred()
        .map_err(|source| DiskLimitError::PathIo {
            path: socket_path.display().to_string(),
            source,
        })?;
    let expected_uid = rustix::process::geteuid().as_raw();
    if peer.uid() != expected_uid {
        return Err(DiskLimitError::FuseSocket(format!(
            "fusequota control peer at {} is owned by uid {}, expected uid {expected_uid}",
            socket_path.display(),
            peer.uid()
        )));
    }

    stream
        .write_all(format!("{command}\n").as_bytes())
        .await
        .map_err(|source| DiskLimitError::PathIo {
            path: socket_path.display().to_string(),
            source,
        })?;
    stream
        .shutdown()
        .await
        .map_err(|source| DiskLimitError::PathIo {
            path: socket_path.display().to_string(),
            source,
        })?;

    let mut response = Vec::with_capacity(MAX_CONTROL_RESPONSE_BYTES.min(4096));
    stream
        .take((MAX_CONTROL_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .await
        .map_err(|source| DiskLimitError::PathIo {
            path: socket_path.display().to_string(),
            source,
        })?;
    if response.len() > MAX_CONTROL_RESPONSE_BYTES {
        return Err(DiskLimitError::FuseSocket(format!(
            "fusequota control response exceeded {MAX_CONTROL_RESPONSE_BYTES} bytes"
        )));
    }
    let response = std::str::from_utf8(&response)
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

    if lines
        .iter()
        .any(|line| line.starts_with("ERROR:") || line.starts_with("ERROR"))
    {
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

fn ensure_private_fuse_directories(fuse_root: &Path) -> Result<(), DiskLimitError> {
    for path in [
        fuse_root.to_path_buf(),
        fuse_root.join("instances"),
        fuse_root.join("mounts"),
    ] {
        fs::create_dir_all(&path).map_err(|source| DiskLimitError::PathIo {
            path: path.display().to_string(),
            source,
        })?;
        secure_fuse_directory(&path)?;
    }
    Ok(())
}

fn secure_fuse_directory(path: &Path) -> Result<(), DiskLimitError> {
    use rustix::fs::{FileType, Mode, OFlags};

    let directory = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .map_err(|source| DiskLimitError::PathIo {
        path: path.display().to_string(),
        source,
    })?;
    let stat = rustix::fs::fstat(&directory)
        .map_err(std::io::Error::from)
        .map_err(|source| DiskLimitError::PathIo {
            path: path.display().to_string(),
            source,
        })?;
    let expected_uid = rustix::process::geteuid().as_raw();
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory || stat.st_uid != expected_uid {
        return Err(DiskLimitError::FuseSocket(format!(
            "fusequota runtime directory {} must be a real directory owned by uid {expected_uid}",
            path.display()
        )));
    }
    rustix::fs::fchmod(&directory, Mode::RWXU)
        .map_err(std::io::Error::from)
        .map_err(|source| DiskLimitError::PathIo {
            path: path.display().to_string(),
            source,
        })?;
    Ok(())
}

fn validate_control_socket(socket_path: &Path) -> Result<(), DiskLimitError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        let metadata =
            fs::symlink_metadata(socket_path).map_err(|source| DiskLimitError::PathIo {
                path: socket_path.display().to_string(),
                source,
            })?;
        let expected_uid = rustix::process::geteuid().as_raw();
        let mode = metadata.mode() & 0o777;
        if !metadata.file_type().is_socket() || metadata.uid() != expected_uid || mode & 0o022 != 0
        {
            return Err(DiskLimitError::FuseSocket(format!(
                "fusequota control path {} must be a real socket owned by uid {expected_uid} and not writable by group or others (mode {mode:o})",
                socket_path.display()
            )));
        }
    }
    Ok(())
}

async fn remove_control_socket(socket_path: &Path) -> Result<(), DiskLimitError> {
    match fs::symlink_metadata(socket_path) {
        Ok(_) => validate_control_socket(socket_path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(DiskLimitError::PathIo {
                path: socket_path.display().to_string(),
                source,
            });
        }
    }
    match tokio::fs::remove_file(socket_path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(DiskLimitError::PathIo {
            path: socket_path.display().to_string(),
            source,
        }),
    }
}

async fn unmount(mount_path: &Path) -> Result<(), DiskLimitError> {
    if !mounts::is_mountpoint(mount_path)? {
        return Ok(());
    }

    let mut failures = Vec::new();
    for program in ["fusermount3", "fusermount"] {
        match run_unmount_command(program, &["-u"], mount_path).await {
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

    match run_unmount_command("umount", &[], mount_path).await {
        Ok(Some(status)) if !status.success() => {
            failures.push(format!("umount exited with {status}"));
        }
        Ok(_) => {}
        Err(error) => failures.push(error.to_string()),
    }
    if wait_until_unmounted(mount_path, UNMOUNT_CONFIRM_TIMEOUT).await? {
        return Ok(());
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
        sleep(Duration::from_millis(100)).await;
    }
}

async fn path_owner(path: &Path) -> Result<(u32, u32), DiskLimitError> {
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|source| DiskLimitError::PathIo {
            path: path.display().to_string(),
            source,
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        Ok((metadata.uid(), metadata.gid()))
    }

    #[cfg(not(unix))]
    {
        let _ = metadata;
        Ok((0, 0))
    }
}

#[cfg(unix)]
async fn mount_owner_matches(mount_path: &Path, expected: (u32, u32)) -> bool {
    path_owner(mount_path)
        .await
        .map(|actual| actual == expected)
        .unwrap_or(false)
}

#[cfg(not(unix))]
async fn mount_owner_matches(_mount_path: &Path, _expected: (u32, u32)) -> bool {
    true
}

fn fuse_paths_with_root(
    data_path: &Path,
    fuse_root: Option<&Path>,
) -> Result<FuseQuotaPaths, DiskLimitError> {
    let instance_id = data_path.file_name().ok_or_else(|| {
        DiskLimitError::FuseSocket("instance data path has no basename".to_string())
    })?;
    let fuse_root = match fuse_root {
        Some(root) => root.to_path_buf(),
        None => {
            let instances_dir = data_path.parent().ok_or_else(|| {
                DiskLimitError::FuseSocket("instance data path has no parent directory".to_string())
            })?;
            let data_root = instances_dir.parent().ok_or_else(|| {
                DiskLimitError::FuseSocket("instance data path has no data root".to_string())
            })?;
            data_root.join("fuse")
        }
    };

    let mount_name = fuse_mount_name(data_path, instance_id);

    Ok(FuseQuotaPaths {
        root_path: fuse_root.clone(),
        mount_path: fuse_root.join("instances").join(&mount_name),
        socket_path: fuse_root
            .join("mounts")
            .join(mount_name)
            .with_extension("sock"),
    })
}

fn fuse_mount_name(data_path: &Path, instance_id: &std::ffi::OsStr) -> String {
    let mut hash = Sha256::new();
    hash.update(data_path.as_os_str().as_encoded_bytes());
    let digest = hash.finalize();
    let encoded = hex_prefix(&digest, 24);
    let readable = instance_id
        .to_string_lossy()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
        .take(24)
        .collect::<String>();
    if readable.is_empty() {
        encoded
    } else {
        format!("{readable}-{encoded}")
    }
}

fn hex_prefix(bytes: &[u8], chars: usize) -> String {
    let mut output = String::with_capacity(chars);
    for byte in bytes {
        if output.len() >= chars {
            break;
        }
        output.push_str(&format!("{byte:02x}"));
    }
    output.truncate(chars);
    output
}

fn mib_to_bytes(mib: u64) -> u64 {
    mib.saturating_mul(1024).saturating_mul(1024)
}

fn database_safe_mount_args() -> [&'static str; 3] {
    ["--nopassthrough", "--nosplice", "--clone-fd"]
}

fn parse_quota_used_response(lines: &[String]) -> Result<u64, DiskLimitError> {
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

fn stderr_string(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr).trim().to_string()
}

async fn resolve_binary(
    binary: &str,
    binary_sha256: &str,
    runtime_root: Option<&Path>,
) -> Result<PathBuf, DiskLimitError> {
    if binary.trim().eq_ignore_ascii_case("embedded") {
        let runtime_root = runtime_root.ok_or_else(|| DiskLimitError::FuseBinaryIo {
            binary: "embedded".to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "embedded fusequota requires a configured private runtime root",
            ),
        })?;
        return crate::bins::get_fusequota_bin_path(runtime_root)
            .await
            .map_err(|source| DiskLimitError::FuseBinaryIo {
                binary: "embedded".to_string(),
                source,
            });
    }
    let binary_path = PathBuf::from(binary.trim());
    let checked_path = binary_path.clone();
    let expected_digest = binary_sha256.trim().to_string();
    tokio::task::spawn_blocking(move || verify_external_binary(&checked_path, &expected_digest))
        .await
        .map_err(|source| DiskLimitError::FuseBinaryIo {
            binary: binary.to_string(),
            source: Error::other(source),
        })?
        .map_err(|source| DiskLimitError::FuseBinaryIo {
            binary: binary.to_string(),
            source,
        })?;
    Ok(binary_path)
}

fn verify_external_binary(path: &Path, expected_digest: &str) -> Result<(), Error> {
    use rustix::fs::{FileType, Mode, OFlags};

    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "external fuse quota helper must use an absolute path without parent segments",
        ));
    }
    if expected_digest.len() != 64
        || !expected_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "external fuse quota helper requires a lowercase SHA-256 digest",
        ));
    }

    let parent = path.parent().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "external fuse quota helper has no parent directory",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "external fuse quota helper has no file name",
        )
    })?;
    let directory = open_trusted_root_owned_directory(parent)?;
    let binary = rustix::fs::openat(
        &directory,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(Error::other)?;
    let stat = rustix::fs::fstat(&binary).map_err(Error::other)?;
    validate_external_binary_metadata(
        FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile,
        stat.st_uid,
        stat.st_nlink,
        stat.st_mode,
    )?;

    let mut file = File::from(binary);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual_digest = format!("{:x}", hasher.finalize());
    if actual_digest != expected_digest {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "external fuse quota helper {} failed SHA-256 verification",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn open_trusted_root_owned_directory(path: &Path) -> Result<rustix::fd::OwnedFd, Error> {
    use rustix::fs::{FileType, Mode, OFlags};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = rustix::fs::open("/", flags, Mode::empty()).map_err(Error::other)?;
    for component in path.components() {
        match component {
            std::path::Component::RootDir => continue,
            std::path::Component::Normal(name) => {
                let next = rustix::fs::openat(&directory, name, flags, Mode::empty())
                    .map_err(Error::other)?;
                let stat = rustix::fs::fstat(&next).map_err(Error::other)?;
                if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
                    || stat.st_uid != 0
                    || stat.st_mode & 0o022 != 0
                {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        format!(
                            "external fuse quota helper parent {} must be a root-owned directory not writable by group or others",
                            path.display()
                        ),
                    ));
                }
                directory = next;
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "external fuse quota helper path contains an unsupported component",
                ));
            }
        }
    }
    Ok(directory)
}

fn validate_external_binary_metadata(
    is_regular_file: bool,
    uid: u32,
    link_count: u64,
    mode: u32,
) -> Result<(), Error> {
    if !is_regular_file || uid != 0 || link_count != 1 || mode & 0o022 != 0 || mode & 0o111 == 0 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "external fuse quota helper must be a root-owned, singly-linked executable regular file not writable by group or others",
        ));
    }
    Ok(())
}

fn display_binary(configured: &str, resolved: &Path) -> String {
    if configured.trim().eq_ignore_ascii_case("embedded") {
        format!("embedded ({})", resolved.display())
    } else {
        configured.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};

    use super::*;

    #[test]
    fn fuse_quota_uses_database_safe_mount_args() {
        let args = database_safe_mount_args();

        assert!(args.contains(&"--nopassthrough"));
        assert!(args.contains(&"--nosplice"));
        assert!(args.contains(&"--clone-fd"));
        assert!(!args.contains(&"--nocache"));
    }

    #[test]
    fn external_helper_metadata_must_be_root_owned_and_immutable_to_unprivileged_users() {
        assert!(validate_external_binary_metadata(true, 0, 1, 0o100755).is_ok());
        assert!(validate_external_binary_metadata(true, 1000, 1, 0o100755).is_err());
        assert!(validate_external_binary_metadata(true, 0, 2, 0o100755).is_err());
        assert!(validate_external_binary_metadata(true, 0, 1, 0o100775).is_err());
        assert!(validate_external_binary_metadata(true, 0, 1, 0o100644).is_err());
        assert!(validate_external_binary_metadata(false, 0, 1, 0o100755).is_err());
    }

    #[test]
    fn parses_quota_used_response() {
        let lines = vec!["quota_used = 12345".to_string(), "OK".to_string()];
        assert_eq!(parse_quota_used_response(&lines).unwrap(), 12345);
    }

    #[test]
    fn fuse_paths_keep_socket_path_short_for_long_instance_ids() {
        let data_path = Path::new(
            "/var/lib/dbev/volumes/dbe_upgrade_tmp_9689dc77d5ce499c80e4ae5beaec4217_inst_node_db_agent_1_1_mongodb_s1_testt",
        );
        let fuse_root = Path::new("/var/lib/dbev/fuse");

        let paths = fuse_paths_with_root(data_path, Some(fuse_root)).unwrap();

        assert!(paths.socket_path.to_string_lossy().len() < 100);
        assert!(
            paths
                .socket_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("dbe_upgrade_tmp_9689dc77")
        );
    }

    #[test]
    fn fuse_runtime_directories_are_private() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("fuse");

        ensure_private_fuse_directories(&root).unwrap();

        for path in [root.clone(), root.join("instances"), root.join("mounts")] {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
    }

    #[test]
    fn control_socket_must_not_be_group_writable() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("control.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o620)).unwrap();

        let error = validate_control_socket(&socket).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("not writable by group or others")
        );
    }

    #[tokio::test]
    async fn control_response_is_size_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("control.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut command = Vec::new();
            stream.read_to_end(&mut command).await.unwrap();
            stream
                .write_all(&vec![b'x'; MAX_CONTROL_RESPONSE_BYTES + 1])
                .await
                .unwrap();
        });

        let error = send_command(&socket, "get quota_used").await.unwrap_err();
        server.await.unwrap();

        assert!(error.to_string().contains("response exceeded"));
    }

    #[tokio::test]
    async fn teardown_removes_only_confirmed_unmounted_runtime_paths() {
        let temp = tempfile::tempdir().unwrap();
        let fuse_root = temp.path().join("fuse");
        let data_path = temp.path().join("volumes").join("instance-one");
        let paths = fuse_paths_with_root(&data_path, Some(&fuse_root)).unwrap();
        fs::create_dir_all(&paths.mount_path).unwrap();
        fs::create_dir_all(paths.socket_path.parent().unwrap()).unwrap();

        destroy_with_root(&data_path, Some(&fuse_root))
            .await
            .unwrap();

        assert!(!paths.mount_path.exists());
        assert!(!paths.socket_path.exists());
    }

    #[tokio::test]
    async fn teardown_preserves_invalid_control_path() {
        let temp = tempfile::tempdir().unwrap();
        let fuse_root = temp.path().join("fuse");
        let data_path = temp.path().join("volumes").join("instance-one");
        let paths = fuse_paths_with_root(&data_path, Some(&fuse_root)).unwrap();
        fs::create_dir_all(&paths.mount_path).unwrap();
        fs::create_dir_all(paths.socket_path.parent().unwrap()).unwrap();
        fs::write(&paths.socket_path, b"not a socket").unwrap();

        assert!(
            destroy_with_root(&data_path, Some(&fuse_root))
                .await
                .is_err()
        );
        assert!(paths.mount_path.exists());
        assert!(paths.socket_path.exists());
    }
}
