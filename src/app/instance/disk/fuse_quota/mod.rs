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

use crate::utils::limits::mib_to_bytes;

use super::{DiskLimitError, mounts, path_io_error};

pub(crate) mod cleanup;

mod binary;
mod control;
mod mount;
mod nofile;
mod paths;
#[cfg(test)]
mod tests;

use self::binary::*;
use self::control::*;
use self::mount::*;
use self::nofile::*;
use self::paths::*;

#[derive(Debug, Clone)]
struct FuseQuotaPaths {
    root_path: PathBuf,
    mount_path: PathBuf,
    socket_path: PathBuf,
}

#[derive(Debug)]
struct FuseControlResponse {
    lines: Vec<String>,
    peer_pid: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NofileLimits {
    current: Option<u64>,
    maximum: Option<u64>,
}

const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CONTROL_COMMAND_BYTES: usize = 256;
const MAX_CONTROL_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_CONTROL_RESPONSE_LINES: usize = 64;
const MAX_CONTROL_RESPONSE_LINE_BYTES: usize = 1024;
const MINIMUM_FUSEQUOTA_NOFILE: u64 = 65_536;
const TARGET_FUSEQUOTA_NOFILE: u64 = 1_048_576;
const UNMOUNT_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const UNMOUNT_CONFIRM_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HELPER_CMDLINE_BYTES: usize = 16 * 1024;
const SOCKET_READY_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKET_READY_POLL_INTERVAL: Duration = Duration::from_millis(200);
const UNMOUNT_POLL_INTERVAL: Duration = Duration::from_millis(100);
const EMBEDDED_BINARY: &str = "embedded";
const SHA256_HEX_LENGTH: usize = 64;
const HASH_BUFFER_BYTES: usize = 64 * 1024;

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
    let allow_other_enabled = fuse_conf
        .lines()
        .any(|line| line.trim() == "user_allow_other");
    if !allow_other_enabled {
        return Err(DiskLimitError::FuseAllowOtherDisabled);
    }

    if let Some(fuse_root) = fuse_root {
        prepare_fuse_dirs(fuse_root)?;
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
    prepare_fuse_dirs(&paths.root_path)?;
    create_runtime_directories(data_path, &paths).await?;

    let expected_owner = path_owner(data_path).await?;

    if let Ok(response) = send_command_detailed(&paths.socket_path, "get quota_used", None).await {
        return resize_running_helper(paths, response.peer_pid, expected_owner, disk_mib).await;
    }
    if mounts::is_mountpoint(&paths.mount_path)? {
        // Live resize, password and image preflights also use this function.
        // Only the lifecycle owner may stop the database and then detach it.
        return Err(DiskLimitError::FuseRequiresRestart(paths.mount_path));
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
        .args(mount_args())
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

async fn create_runtime_directories(
    data_path: &Path,
    paths: &FuseQuotaPaths,
) -> Result<(), DiskLimitError> {
    create_directory_all(data_path).await?;
    if let Some(parent) = paths.mount_path.parent() {
        create_directory_all(parent).await?;
    }
    if let Some(parent) = paths.socket_path.parent() {
        create_directory_all(parent).await?;
    }
    create_directory_all(&paths.mount_path).await
}

async fn create_directory_all(path: &Path) -> Result<(), DiskLimitError> {
    tokio::fs::create_dir_all(path)
        .await
        .map_err(path_io_error(path))
}

async fn resize_running_helper(
    paths: FuseQuotaPaths,
    helper_pid: i32,
    expected_owner: (u32, u32),
    disk_mib: u64,
) -> Result<PathBuf, DiskLimitError> {
    if !mounts::is_mountpoint(&paths.mount_path)?
        || !helper_cache_is_safe(helper_pid).await
        || !mount_owner_matches(&paths.mount_path, expected_owner).await
    {
        return Err(DiskLimitError::FuseRequiresRestart(paths.mount_path));
    }
    set_helper_nofile_limit(helper_pid).await?;
    send_command_detailed(
        &paths.socket_path,
        &format!("set quota = {}", mib_to_bytes(disk_mib)),
        Some(helper_pid),
    )
    .await?;
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
        Err(source) => return Err(path_io_error(&paths.socket_path)(source)),
    };

    unmount(&paths.mount_path).await?;
    remove_control_socket(&paths.socket_path).await?;
    match tokio::fs::remove_dir(&paths.mount_path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => return Err(path_io_error(&paths.mount_path)(source)),
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
    parse_quota_usage(&response)
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
    let response = match send_command_detailed(&paths.socket_path, "get quota_used", None).await {
        Ok(response) => response,
        Err(_) => return Ok(false),
    };
    if !helper_cache_is_safe(response.peer_pid).await
        || !mount_owner_matches(&paths.mount_path, expected_owner).await
    {
        return Ok(false);
    }
    if let Err(error) = set_helper_nofile_limit(response.peer_pid).await {
        tracing::warn!(
            mount_path = %paths.mount_path.display(),
            helper_pid = response.peer_pid,
            %error,
            "fusequota helper has an unsafe open-file limit; its mount will be recreated"
        );
        return Ok(false);
    }
    Ok(true)
}
