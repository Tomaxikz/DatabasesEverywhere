use std::path::Path;

use super::{
    DiskLimitError, displayed_privileged_command,
    helpers::{remove_empty_data_directory, restore_replaced_directory},
    privileged_command,
};

mod quota;
pub(super) use quota::verify_startup;

pub(super) async fn apply(data_path: &Path, disk_mib: u64) -> Result<String, DiskLimitError> {
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

async fn ensure_subvolume(path: &Path) -> Result<(), DiskLimitError> {
    if is_subvolume(path).await? {
        return Ok(());
    }

    let path = path.to_path_buf();
    let removed = path.clone();
    let replaced = tokio::task::spawn_blocking(move || remove_empty_data_directory(&removed))
        .await
        .map_err(|error| DiskLimitError::Task(error.to_string()))??;

    run(&path, &["subvolume", "create"], "btrfs subvolume create").await?;
    // Files inherit NOCOW at creation. Existing subvolumes keep their attributes.
    let result = privileged_command("chattr")
        .arg("+C")
        .arg(&path)
        .output()
        .await;
    match result {
        Ok(output) if !output.status.success() => tracing::warn!(
            path = %path.display(), stderr = %String::from_utf8_lossy(&output.stderr).trim(),
            "could not set NOCOW on new Btrfs volume"
        ),
        Err(error) => tracing::warn!(path = %path.display(), %error, "could not run chattr +C"),
        Ok(_) => {}
    }
    tokio::task::spawn_blocking(move || restore_replaced_directory(&path, replaced))
        .await
        .map_err(|error| DiskLimitError::Task(error.to_string()))?
}

pub(super) async fn is_subvolume(path: &Path) -> Result<bool, DiskLimitError> {
    #[cfg(target_os = "linux")]
    {
        // "subvolume show" also lists snapshots. Check the root inode directly
        // so deletes and resizes do not enumerate snapshots on a busy filesystem.
        let target = path.to_owned();
        let result = tokio::task::spawn_blocking(move || is_subvolume_root(&target))
            .await
            .map_err(|error| DiskLimitError::Task(error.to_string()))?;
        match result {
            Ok(found) => return Ok(found),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            // Preserve the privileged probe for root-owned volume paths.
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(error) => return Err(super::path_io_error(path)(error)),
        }
    }
    let output = privileged_command("btrfs")
        .args(["subvolume", "show"])
        .arg(path)
        .output()
        .await
        .map_err(|source| DiskLimitError::CommandIo {
            command: "btrfs",
            source,
        })?;
    Ok(output.status.success())
}

#[cfg(target_os = "linux")]
fn is_subvolume_root(path: &Path) -> std::io::Result<bool> {
    use linux_raw_sys::btrfs::BTRFS_FIRST_FREE_OBJECTID;
    use rustix::fs::{FileType, Mode, OFlags, fstat, fstatfs, open};

    let fd = open(
        path,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let stat = fstat(&fd)?;
    Ok(FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_ino == u64::from(BTRFS_FIRST_FREE_OBJECTID)
        && fstatfs(&fd)?.f_type == linux_raw_sys::general::BTRFS_SUPER_MAGIC as rustix::fs::FsWord)
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
