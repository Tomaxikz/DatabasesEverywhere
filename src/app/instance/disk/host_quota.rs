use std::path::Path;

use tokio::process::Command;

use super::{DiskLimitError, btrfs, canonical_path, linux_project, mounts, xfs, zfs};

pub(super) fn privileged_command(program: &'static str) -> Command {
    if should_use_sudo() {
        let mut command = Command::new("sudo");
        command.arg("-n").arg(program);
        command
    } else {
        Command::new(program)
    }
}

pub(super) fn displayed_privileged_command(program: &str, args: impl AsRef<str>) -> String {
    let args = args.as_ref();
    if should_use_sudo() {
        format!("sudo -n {program} {args}")
    } else {
        format!("{program} {args}")
    }
}

fn should_use_sudo() -> bool {
    matches!(
        std::env::var("DBE_USE_SUDO").as_deref(),
        Ok("1" | "true" | "yes")
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HostQuotaChange {
    Apply,
    Update,
}

pub(super) async fn set_host_quota(
    instance_id: &str,
    data_path: &Path,
    disk_mib: u64,
    project_id_base: u32,
    change: HostQuotaChange,
) -> Result<String, DiskLimitError> {
    let data_path = canonical_path(data_path)?;
    let mount = mounts::find_mount(&data_path)?;
    let registry_root = super::project_id::default_registry_root(&data_path)?.to_path_buf();
    match mount.fstype.as_str() {
        "xfs" => match change {
            HostQuotaChange::Apply => {
                xfs::apply_in(
                    instance_id,
                    &data_path,
                    &registry_root,
                    disk_mib,
                    project_id_base,
                    &mount.mountpoint,
                )
                .await
            }
            HostQuotaChange::Update => {
                xfs::update_in(
                    instance_id,
                    &data_path,
                    &registry_root,
                    disk_mib,
                    project_id_base,
                    &mount.mountpoint,
                )
                .await
            }
        },
        "btrfs" => btrfs::apply(&data_path, disk_mib, &mount.mountpoint).await,
        "zfs" => zfs::apply(instance_id, &data_path, disk_mib).await,
        "ext4" | "f2fs" => match change {
            HostQuotaChange::Apply => {
                linux_project::apply_in(
                    instance_id,
                    &data_path,
                    &registry_root,
                    disk_mib,
                    project_id_base,
                    &mount.mountpoint,
                )
                .await
            }
            HostQuotaChange::Update => {
                linux_project::update_in(
                    instance_id,
                    &data_path,
                    &registry_root,
                    disk_mib,
                    project_id_base,
                    &mount.mountpoint,
                )
                .await
            }
        },
        fstype => Err(DiskLimitError::UnsupportedFilesystem {
            mountpoint: mount.mountpoint,
            fstype: fstype.to_string(),
        }),
    }
}
