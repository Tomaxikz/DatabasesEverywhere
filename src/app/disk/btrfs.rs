use std::path::{Path, PathBuf};

use super::{DiskLimitError, displayed_privileged_command, privileged_command};

pub(super) async fn verify_startup(mount: &Path) -> Result<(), DiskLimitError> {
    ensure_quota_enabled(mount).await
}

pub(super) async fn apply(
    data_path: &Path,
    disk_mib: u64,
    mount: &Path,
) -> Result<String, DiskLimitError> {
    ensure_quota_enabled(mount).await?;
    ensure_subvolume(data_path).await?;
    run_limit(data_path, disk_mib).await?;
    Ok("host_btrfs_qgroup".to_string())
}

pub(super) async fn destroy(data_path: &Path) -> Result<(), DiskLimitError> {
    if !is_subvolume(data_path).await? {
        return Ok(());
    }
    run(
        data_path,
        &["subvolume", "delete"],
        "btrfs subvolume delete",
    )
    .await
}

async fn ensure_quota_enabled(mount: &Path) -> Result<(), DiskLimitError> {
    if qgroups_available(mount).await? {
        return Ok(());
    }
    run(mount, &["quota", "enable"], "btrfs quota enable").await?;
    if qgroups_available(mount).await? {
        Ok(())
    } else {
        Err(DiskLimitError::CommandFailed {
            command: format!("btrfs qgroup show {}", mount.display()),
            stderr: "qgroups are still unavailable after enabling btrfs quotas".to_string(),
        })
    }
}

async fn qgroups_available(mount: &Path) -> Result<bool, DiskLimitError> {
    let output = privileged_command("btrfs")
        .arg("qgroup")
        .arg("show")
        .arg(mount)
        .output()
        .await
        .map_err(|source| DiskLimitError::CommandIo {
            command: "btrfs",
            source,
        })?;
    Ok(output.status.success())
}

async fn ensure_subvolume(path: &Path) -> Result<(), DiskLimitError> {
    if is_subvolume(path).await? {
        return Ok(());
    }

    let path = path.to_path_buf();
    let path = tokio::task::spawn_blocking(move || -> Result<PathBuf, DiskLimitError> {
        if path.exists() {
            let mut entries =
                std::fs::read_dir(&path).map_err(|source| DiskLimitError::PathIo {
                    path: path.display().to_string(),
                    source,
                })?;
            if entries
                .next()
                .transpose()
                .map_err(|source| DiskLimitError::PathIo {
                    path: path.display().to_string(),
                    source,
                })?
                .is_some()
            {
                return Err(DiskLimitError::DataPathNotEmpty(path));
            }
            std::fs::remove_dir(&path).map_err(|source| DiskLimitError::PathIo {
                path: path.display().to_string(),
                source,
            })?;
        }
        Ok(path)
    })
    .await
    .map_err(|error| DiskLimitError::Task(error.to_string()))??;

    run(&path, &["subvolume", "create"], "btrfs subvolume create").await
}

async fn is_subvolume(path: &Path) -> Result<bool, DiskLimitError> {
    let output = privileged_command("btrfs")
        .arg("subvolume")
        .arg("show")
        .arg(path)
        .output()
        .await
        .map_err(|source| DiskLimitError::CommandIo {
            command: "btrfs",
            source,
        })?;
    Ok(output.status.success())
}

async fn run_limit(path: &Path, disk_mib: u64) -> Result<(), DiskLimitError> {
    let limit = format!("{disk_mib}M");
    let output = privileged_command("btrfs")
        .arg("qgroup")
        .arg("limit")
        .arg(&limit)
        .arg(path)
        .output()
        .await
        .map_err(|source| DiskLimitError::CommandIo {
            command: "btrfs",
            source,
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(DiskLimitError::CommandFailed {
            command: displayed_privileged_command(
                "btrfs",
                format!("qgroup limit {limit} {}", path.display()),
            ),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

async fn run(path: &Path, args: &[&str], command_name: &'static str) -> Result<(), DiskLimitError> {
    let output = privileged_command("btrfs")
        .args(args)
        .arg(path)
        .output()
        .await
        .map_err(|source| DiskLimitError::CommandIo {
            command: "btrfs",
            source,
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(DiskLimitError::CommandFailed {
            command: displayed_privileged_command(command_name, path.display().to_string()),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}
