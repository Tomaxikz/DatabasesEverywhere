//! Atomic, read-only snapshots of one instance volume on Btrfs or ZFS.
//!
//! With native quotas on those filesystems every instance data directory is
//! its own subvolume or dataset, so one snapshot captures exactly that
//! instance at a single instant while it keeps running. The copy is
//! crash-consistent: the engine recovers it from its own journal, as after a
//! power loss. Snapshot names always carry a backup job tag so cleanup never
//! touches anything else.

use std::path::{Path, PathBuf};

use super::{DiskLimitError, btrfs, privileged_command, zfs};

/// `disk_enforcement_method` values whose volumes support snapshots.
const BTRFS_METHOD: &str = "host_btrfs_qgroup";
const ZFS_METHOD: &str = "host_zfs_refquota";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SnapshotBackend {
    Btrfs,
    Zfs,
}

impl SnapshotBackend {
    /// The backend of an instance whose disk limit uses a native subvolume or
    /// dataset, or `None` for directories without atomic snapshots.
    pub(crate) fn for_enforcement_method(method: &str) -> Option<Self> {
        match method {
            BTRFS_METHOD => Some(Self::Btrfs),
            ZFS_METHOD => Some(Self::Zfs),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Btrfs => "btrfs",
            Self::Zfs => "zfs",
        }
    }
}

/// A snapshot that exists until [`destroy`] removes it.
#[derive(Debug, Clone)]
pub(crate) struct VolumeSnapshot {
    /// Read-only tree of the volume as it was at the snapshot instant.
    pub read_root: PathBuf,
}

/// Btrfs snapshots live beside the volume, hidden, never inside it where the
/// database would see them.
fn btrfs_snapshot_path(data_path: &Path, name: &str) -> Result<PathBuf, DiskLimitError> {
    let parent = data_path
        .parent()
        .ok_or_else(|| DiskLimitError::MountpointNotFound(data_path.to_path_buf()))?;
    Ok(parent.join(format!(".{name}")))
}

fn valid_name(name: &str) -> bool {
    name.starts_with("dbev_bk_")
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn invalid_name(name: &str) -> DiskLimitError {
    DiskLimitError::CommandFailed {
        command: "volume snapshot".to_string(),
        stderr: format!("{name} is not a backup snapshot name"),
    }
}

/// Takes an atomic read-only snapshot of the instance volume at `data_path`.
pub(crate) async fn create(
    backend: SnapshotBackend,
    data_path: &Path,
    name: &str,
) -> Result<VolumeSnapshot, DiskLimitError> {
    if !valid_name(name) {
        return Err(invalid_name(name));
    }
    match backend {
        SnapshotBackend::Btrfs => {
            if !btrfs::is_subvolume(data_path).await? {
                return Err(DiskLimitError::CommandFailed {
                    command: "btrfs subvolume show".to_string(),
                    stderr: format!("{} is not a Btrfs subvolume", data_path.display()),
                });
            }
            let target = btrfs_snapshot_path(data_path, name)?;
            run(
                "btrfs",
                &[
                    "subvolume".as_ref(),
                    "snapshot".as_ref(),
                    "-r".as_ref(),
                    data_path.as_os_str(),
                    target.as_os_str(),
                ],
            )
            .await?;
            Ok(VolumeSnapshot { read_root: target })
        }
        SnapshotBackend::Zfs => {
            let dataset = exact_dataset(data_path).await?;
            let snapshot = format!("{}@{name}", dataset.name);
            zfs::run_zfs(&["snapshot", &snapshot], format!("zfs snapshot {snapshot}")).await?;
            Ok(VolumeSnapshot {
                read_root: data_path.join(".zfs").join("snapshot").join(name),
            })
        }
    }
}

/// Removes the named snapshot of the volume at `data_path`. A snapshot that is
/// already gone counts as removed.
pub(crate) async fn destroy(
    backend: SnapshotBackend,
    data_path: &Path,
    name: &str,
) -> Result<(), DiskLimitError> {
    if !valid_name(name) {
        return Err(invalid_name(name));
    }
    match backend {
        SnapshotBackend::Btrfs => {
            let target = btrfs_snapshot_path(data_path, name)?;
            if !btrfs::is_subvolume(&target).await? {
                return Ok(());
            }
            run(
                "btrfs",
                &["subvolume".as_ref(), "delete".as_ref(), target.as_os_str()],
            )
            .await
        }
        SnapshotBackend::Zfs => {
            let Ok(dataset) = exact_dataset(data_path).await else {
                // The volume itself is gone, and its snapshots with it.
                return Ok(());
            };
            let snapshot = format!("{}@{name}", dataset.name);
            let exists = privileged_command("zfs")
                .args(["list", "-H", "-t", "snapshot", &snapshot])
                .output()
                .await
                .map_err(|source| DiskLimitError::CommandIo {
                    command: "zfs",
                    source,
                })?
                .status
                .success();
            if !exists {
                return Ok(());
            }
            zfs::run_zfs(&["destroy", &snapshot], format!("zfs destroy {snapshot}")).await
        }
    }
}

async fn exact_dataset(data_path: &Path) -> Result<zfs::ZfsDataset, DiskLimitError> {
    let datasets = zfs::list_datasets().await?;
    zfs::dataset_for_exact_mount(data_path, &datasets)
        .ok_or_else(|| DiskLimitError::MountpointNotFound(data_path.to_path_buf()))
}

async fn run(program: &'static str, args: &[&std::ffi::OsStr]) -> Result<(), DiskLimitError> {
    let output = privileged_command(program)
        .args(args)
        .output()
        .await
        .map_err(|source| DiskLimitError::CommandIo {
            command: program,
            source,
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(DiskLimitError::CommandFailed {
            command: super::displayed_privileged_command(
                program,
                args.iter()
                    .map(|arg| arg.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" "),
            ),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_native_subvolume_and_dataset_quotas_snapshot() {
        assert_eq!(
            SnapshotBackend::for_enforcement_method("host_btrfs_qgroup"),
            Some(SnapshotBackend::Btrfs)
        );
        assert_eq!(
            SnapshotBackend::for_enforcement_method("host_zfs_refquota"),
            Some(SnapshotBackend::Zfs)
        );
        for method in [
            "host_xfs_project",
            "fuse_quota",
            "soft_scanner",
            "not_supported",
        ] {
            assert_eq!(
                SnapshotBackend::for_enforcement_method(method),
                None,
                "{method}"
            );
        }
    }

    #[test]
    fn btrfs_snapshots_are_hidden_siblings_of_the_volume() {
        assert_eq!(
            btrfs_snapshot_path(
                Path::new("/var/lib/dbev/volumes/inst_one"),
                "dbev_bk_ab_snapshot"
            )
            .unwrap(),
            Path::new("/var/lib/dbev/volumes/.dbev_bk_ab_snapshot")
        );
    }

    #[test]
    fn snapshot_names_must_be_backup_job_names() {
        assert!(valid_name(
            "dbev_bk_0123456789abcdef0123456789abcdef_snapshot"
        ));
        for name in ["", "data", "dbev_bk_../x", "dbev_bk_a b", "dbev_bk_a@b"] {
            assert!(!valid_name(name), "{name}");
        }
    }
}
