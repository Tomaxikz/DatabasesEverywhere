use std::path::Path;

use super::{
    DiskLimitError, NativeProjectQuotaFs, displayed_privileged_command, privileged_command,
    project_id, project_tree, project_usage, real_directory_exists,
};
use crate::shared::limits::mib_to_bytes;

pub(super) async fn verify_startup(
    data_root: &Path,
    mount: &Path,
    source: &str,
    fstype: &str,
    options: &[String],
) -> Result<(), DiskLimitError> {
    require_project_quota(data_root, mount, source, fstype, options)?;
    require_command("quotaon").await?;
    require_command("setquota").await?;
    run_quotaon_state(mount).await
}

pub(super) async fn apply_in(
    owner_id: &str,
    data_path: &Path,
    registry_root: &Path,
    disk_mib: u64,
    project_id_base: u32,
    mount: &Path,
) -> Result<String, DiskLimitError> {
    let project_id = project_id::allocate_in(owner_id, registry_root, project_id_base).await?;
    // Keep the pending project bounded before the first inode leaves the
    // aggregate/root project. If relabeling is interrupted, retrying the
    // pending claim remains safe and the partial tree is still capped.
    set_project_quota(mount, project_id, disk_mib).await?;
    project_tree::assign(data_path, project_id).await?;
    project_id::activate_in(owner_id, registry_root, project_id).await?;
    Ok("host_linux_project_quota".to_string())
}

pub(super) async fn update_in(
    owner_id: &str,
    data_path: &Path,
    registry_root: &Path,
    disk_mib: u64,
    project_id_base: u32,
    mount: &Path,
) -> Result<String, DiskLimitError> {
    let project_id = project_id::find_active_in(owner_id, registry_root, project_id_base)
        .await?
        .ok_or_else(|| DiskLimitError::ProjectIdNotFound {
            owner_id: owner_id.to_string(),
            registry_root: registry_root.to_path_buf(),
        })?;
    // Updates and boot restoration are constant-time: adoption already
    // verified the whole tree, while inheritance makes future descendants
    // correct. Refuse an active claim whose root boundary was altered.
    project_tree::verify_root(data_path, project_id).await?;
    set_project_quota(mount, project_id, disk_mib).await?;
    Ok("host_linux_project_quota".to_string())
}

pub(super) async fn remove_in(
    owner_id: &str,
    data_path: &Path,
    registry_root: &Path,
    project_id_base: u32,
    mount: &Path,
) -> Result<(), DiskLimitError> {
    let Some(claim) = project_id::find_claim_in(owner_id, registry_root, project_id_base).await?
    else {
        return Ok(());
    };
    if claim.state == project_id::ProjectIdState::Released {
        return Ok(());
    }
    // Keep the project cap in place until every reachable inode has left the
    // claim. A pending adoption can contain both the trusted source ID and the
    // new target ID, so restore it to that source rather than applying the
    // stricter active-boundary clear.
    if real_directory_exists(data_path)? {
        match claim.state {
            project_id::ProjectIdState::Pending => {
                project_tree::rollback_pending(data_path, claim.id).await?
            }
            project_id::ProjectIdState::Active => project_tree::clear(data_path, claim.id).await?,
            project_id::ProjectIdState::Released => unreachable!("released claims return above"),
        }
    }
    project_usage::verify_unused(NativeProjectQuotaFs::Ext4, mount, claim.id).await?;
    set_project_quota(mount, claim.id, 0).await?;
    project_id::release_in(owner_id, registry_root, project_id_base).await?;
    Ok(())
}

async fn require_command(command: &'static str) -> Result<(), DiskLimitError> {
    privileged_command(command)
        .output()
        .await
        .map(|_| ())
        .map_err(|source| DiskLimitError::CommandIo { command, source })
}

fn require_project_quota(
    data_root: &Path,
    mount: &Path,
    source: &str,
    fstype: &str,
    options: &[String],
) -> Result<(), DiskLimitError> {
    let enabled = options
        .iter()
        .any(|option| matches!(option.as_str(), "prjquota" | "pquota"));
    if enabled {
        return Ok(());
    }

    Err(DiskLimitError::ProjectQuotaNotEnabled {
        data_root: data_root.to_path_buf(),
        mountpoint: mount.to_path_buf(),
        device: source.to_string(),
        fstype: fstype.to_string(),
        options: if options.is_empty() {
            "-".to_string()
        } else {
            options.join(",")
        },
    })
}

async fn run_quotaon_state(mount: &Path) -> Result<(), DiskLimitError> {
    let output = privileged_command("quotaon")
        .arg("-P")
        .arg("-p")
        .arg(mount)
        .output()
        .await
        .map_err(|source| DiskLimitError::CommandIo {
            command: "quotaon",
            source,
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(DiskLimitError::CommandFailed {
            command: displayed_privileged_command("quotaon", format!("-P -p {}", mount.display())),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

async fn set_project_quota(
    mount: &Path,
    project_id: u32,
    disk_mib: u64,
) -> Result<(), DiskLimitError> {
    let blocks_1k = disk_mib.saturating_mul(1024);
    let output = privileged_command("setquota")
        .arg("-P")
        .arg(project_id.to_string())
        .arg(blocks_1k.to_string())
        .arg(blocks_1k.to_string())
        .arg("0")
        .arg("0")
        .arg(mount)
        .output()
        .await
        .map_err(|source| DiskLimitError::CommandIo {
            command: "setquota",
            source,
        })?;
    if output.status.success() {
        // ext4 and F2FS use the same VFS project-quota record format. Do not
        // trust the helper's exit status until the kernel returns the exact
        // hard limit that was requested (including zero during teardown).
        project_usage::verify_hard_limit(
            NativeProjectQuotaFs::Ext4,
            mount,
            project_id,
            mib_to_bytes(disk_mib),
        )
        .await
    } else {
        Err(DiskLimitError::CommandFailed {
            command: displayed_privileged_command(
                "setquota",
                format!(
                    "-P {project_id} {blocks_1k} {blocks_1k} 0 0 {}",
                    mount.display()
                ),
            ),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_mount_without_project_quota_option() {
        let error = require_project_quota(
            Path::new("/var/lib/databases-everywhere"),
            Path::new("/"),
            "/dev/vda3",
            "ext4",
            &["rw".to_string(), "errors=remount-ro".to_string()],
        )
        .unwrap_err();

        assert!(matches!(
            error,
            DiskLimitError::ProjectQuotaNotEnabled { .. }
        ));
    }

    #[test]
    fn accepts_project_quota_mount_option_aliases() {
        require_project_quota(
            Path::new("/var/lib/databases-everywhere"),
            Path::new("/"),
            "/dev/vda3",
            "ext4",
            &["rw".to_string(), "prjquota".to_string()],
        )
        .unwrap();
        require_project_quota(
            Path::new("/var/lib/databases-everywhere"),
            Path::new("/"),
            "/dev/vda3",
            "f2fs",
            &["rw".to_string(), "pquota".to_string()],
        )
        .unwrap();
    }
}
