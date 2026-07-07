use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    process::Command,
    time::sleep,
};

use super::DiskLimitError;

#[derive(Debug, Clone)]
struct FuseQuotaPaths {
    mount_path: PathBuf,
    socket_path: PathBuf,
}

pub(super) async fn verify_startup(binary: &str) -> Result<(), DiskLimitError> {
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

    let binary_path = resolve_binary(binary).await?;
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
    rescan_interval_seconds: u64,
) -> Result<PathBuf, DiskLimitError> {
    let paths = fuse_paths_with_root(data_path, fuse_root)?;
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
        let _ = destroy_with_root(data_path, fuse_root).await;
    }

    match tokio::fs::remove_file(&paths.socket_path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(DiskLimitError::PathIo {
                path: paths.socket_path.display().to_string(),
                source,
            });
        }
    }

    let (uid, gid) = expected_owner;
    let binary_path = resolve_binary(binary).await?;
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
    let _ = send_command(&paths.socket_path, "do end").await;
    let _ = unmount(&paths.mount_path).await;
    match tokio::fs::remove_file(&paths.socket_path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(DiskLimitError::PathIo {
                path: paths.socket_path.display().to_string(),
                source,
            });
        }
    }
    match tokio::fs::remove_dir(&paths.mount_path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
        Err(source) => {
            return Err(DiskLimitError::PathIo {
                path: paths.mount_path.display().to_string(),
                source,
            });
        }
    }
    Ok(())
}

pub(super) fn mount_path_with_root(
    data_path: &Path,
    fuse_root: Option<&Path>,
) -> Result<PathBuf, DiskLimitError> {
    Ok(fuse_paths_with_root(data_path, fuse_root)?.mount_path)
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
    let stream =
        UnixStream::connect(socket_path)
            .await
            .map_err(|source| DiskLimitError::PathIo {
                path: socket_path.display().to_string(),
                source,
            })?;
    let mut stream = BufReader::new(stream);
    stream
        .get_mut()
        .write_all(format!("{command}\n").as_bytes())
        .await
        .map_err(|source| DiskLimitError::PathIo {
            path: socket_path.display().to_string(),
            source,
        })?;
    stream
        .get_mut()
        .shutdown()
        .await
        .map_err(|source| DiskLimitError::PathIo {
            path: socket_path.display().to_string(),
            source,
        })?;

    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        let bytes = stream
            .read_line(&mut line)
            .await
            .map_err(|source| DiskLimitError::PathIo {
                path: socket_path.display().to_string(),
                source,
            })?;
        if bytes == 0 {
            break;
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

async fn unmount(mount_path: &Path) -> Result<(), DiskLimitError> {
    for program in ["fusermount3", "fusermount"] {
        let output = Command::new(program)
            .arg("-u")
            .arg(mount_path)
            .output()
            .await;
        match output {
            Ok(output) if output.status.success() => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(DiskLimitError::CommandIo {
                    command: "fusermount",
                    source,
                });
            }
        }
    }

    let output = Command::new("umount").arg(mount_path).output().await;
    match output {
        Ok(output) if output.status.success() => return Ok(()),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(DiskLimitError::CommandIo {
                command: "umount",
                source,
            });
        }
    }
    Ok(())
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

    Ok(FuseQuotaPaths {
        mount_path: fuse_root.join("instances").join(instance_id),
        socket_path: fuse_root
            .join("mounts")
            .join(instance_id)
            .with_extension("sock"),
    })
}

fn mib_to_bytes(mib: u64) -> u64 {
    mib.saturating_mul(1024).saturating_mul(1024)
}

fn database_safe_mount_args() -> [&'static str; 3] {
    ["--nopassthrough", "--nosplice", "--clone-fd"]
}

fn stderr_string(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr).trim().to_string()
}

async fn resolve_binary(binary: &str) -> Result<PathBuf, DiskLimitError> {
    if binary.trim().eq_ignore_ascii_case("embedded") {
        return crate::bins::get_fusequota_bin_path()
            .await
            .map_err(|source| DiskLimitError::FuseBinaryIo {
                binary: "embedded".to_string(),
                source,
            });
    }
    Ok(PathBuf::from(binary))
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
    use super::*;

    #[test]
    fn fuse_quota_uses_database_safe_mount_args() {
        let args = database_safe_mount_args();

        assert!(args.contains(&"--nopassthrough"));
        assert!(args.contains(&"--nosplice"));
        assert!(args.contains(&"--clone-fd"));
        assert!(!args.contains(&"--nocache"));
    }
}
