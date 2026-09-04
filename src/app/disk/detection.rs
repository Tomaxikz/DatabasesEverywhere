use std::path::PathBuf;

use crate::config::{DiskLimitMode, DiskLimitSelection, PathConfig};

use super::{DiskLimitError, mounts};

#[derive(Debug, Clone)]
pub struct FilesystemInspection {
    pub field: &'static str,
    pub path: PathBuf,
    pub mountpoint: PathBuf,
    pub source: String,
    pub fstype: String,
    pub options: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DiskModeDetection {
    pub mode: DiskLimitMode,
    pub reason: &'static str,
    pub filesystems: Vec<FilesystemInspection>,
}

pub fn detect_disk_mode(
    paths: &PathConfig,
    selection: DiskLimitSelection,
) -> Result<DiskModeDetection, DiskLimitError> {
    let roots = [
        ("paths.data", paths.data.clone()),
        ("paths.metadata", paths.metadata_root()),
        ("paths.volumes", paths.volumes_root()),
        ("paths.backups", paths.backups_root()),
        ("paths.sockets", paths.sockets.clone()),
        ("paths.locks", paths.locks.clone()),
        ("paths.logs", paths.logs.clone()),
        ("paths.artifacts", paths.artifacts.clone()),
        ("paths.exports", paths.exports_root()),
        ("paths.imports", paths.imports_root()),
        ("paths.fuse", paths.fuse_root()),
        ("paths.tmp", paths.tmp_root()),
    ];
    let mut filesystems = Vec::with_capacity(roots.len());
    for (field, configured_path) in roots {
        let path = PathBuf::from(configured_path);
        let mount = mounts::find_mount(&path)?;
        filesystems.push(FilesystemInspection {
            field,
            path,
            mountpoint: mount.mountpoint,
            source: mount.source,
            fstype: mount.fstype,
            options: mount.options,
        });
    }
    let volumes = filesystems
        .iter()
        .find(|inspection| inspection.field == "paths.volumes")
        .expect("paths.volumes is always inspected");
    let (mode, reason) = select_disk_mode(&volumes.fstype, &volumes.options, selection);
    Ok(DiskModeDetection {
        mode,
        reason,
        filesystems,
    })
}

pub(super) fn select_disk_mode(
    fstype: &str,
    options: &[String],
    selection: DiskLimitSelection,
) -> (DiskLimitMode, &'static str) {
    match selection {
        DiskLimitSelection::FuseQuota => (
            DiskLimitMode::FuseQuota,
            "FuseQuota was selected explicitly",
        ),
        DiskLimitSelection::SoftScanner => (
            DiskLimitMode::SoftScanner,
            "soft scanner enforcement was selected explicitly",
        ),
        DiskLimitSelection::ProjectQuota => (
            DiskLimitMode::ProjectQuota,
            "native project quota enforcement was selected explicitly",
        ),
        DiskLimitSelection::Auto => auto_mode(fstype, options),
    }
}

fn auto_mode(fstype: &str, options: &[String]) -> (DiskLimitMode, &'static str) {
    let project_quota_mounted = options
        .iter()
        .any(|option| matches!(option.as_str(), "prjquota" | "pquota"));
    match fstype {
        "btrfs" => (
            DiskLimitMode::ProjectQuota,
            "Btrfs supports native per-subvolume qgroup limits",
        ),
        "zfs" => (
            DiskLimitMode::ProjectQuota,
            "ZFS supports native per-dataset refquota limits",
        ),
        "xfs" if project_quota_mounted => (
            DiskLimitMode::ProjectQuota,
            "XFS is mounted with project quotas enabled",
        ),
        "ext4" | "f2fs" if project_quota_mounted => (
            DiskLimitMode::ProjectQuota,
            "Linux filesystem is mounted with project quotas enabled",
        ),
        _ => (
            DiskLimitMode::FuseQuota,
            "the volumes filesystem has no detected native quota facility",
        ),
    }
}
