use std::path::{Path, PathBuf};

use procfs::process::MountInfo as ProcMountInfo;

use super::DiskLimitError;
use crate::io::cgroup::unescape_mountinfo;

const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MountInfo {
    pub mountpoint: PathBuf,
    pub fstype: String,
    pub source: String,
    pub options: Vec<String>,
}

pub(super) fn find_mount(path: &Path) -> Result<MountInfo, DiskLimitError> {
    let path = path
        .canonicalize()
        .map_err(|source| DiskLimitError::PathIo {
            path: path.display().to_string(),
            source,
        })?;
    let mounts = read_mountinfo()?;
    find_mount_in(&path, &mounts).ok_or(DiskLimitError::MountpointNotFound(path))
}

pub(super) fn is_mountpoint(path: &Path) -> Result<bool, DiskLimitError> {
    if !path.is_absolute() {
        return Err(DiskLimitError::PathIo {
            path: path.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "mountpoint path must be absolute",
            ),
        });
    }
    let path = path
        .components()
        .filter(|component| !matches!(component, std::path::Component::CurDir))
        .collect::<PathBuf>();
    let mounts = read_mountinfo()?;
    Ok(is_mountpoint_in(&path, &mounts))
}

fn read_mountinfo() -> Result<Vec<ProcMountInfo>, DiskLimitError> {
    let mountinfo = std::fs::read_to_string(MOUNTINFO_PATH).map_err(DiskLimitError::Io)?;
    Ok(parse_mountinfo(&mountinfo))
}

/// Parses each line on its own so one malformed entry is skipped instead of
/// hiding every other mount.
fn parse_mountinfo(mountinfo: &str) -> Vec<ProcMountInfo> {
    mountinfo
        .lines()
        .filter_map(|line| ProcMountInfo::from_line(line).ok())
        .collect()
}

fn mountpoint_path(mount: &ProcMountInfo) -> PathBuf {
    PathBuf::from(unescape_mountinfo(&mount.mount_point.to_string_lossy()))
}

fn is_mountpoint_in(path: &Path, mounts: &[ProcMountInfo]) -> bool {
    mounts.iter().any(|mount| mountpoint_path(mount) == path)
}

fn find_mount_in(path: &Path, mounts: &[ProcMountInfo]) -> Option<MountInfo> {
    let mut best: Option<MountInfo> = None;
    for mount in mounts.iter().map(mount_info) {
        let is_more_specific = best.as_ref().is_none_or(|current| {
            mount.mountpoint.as_os_str().len() > current.mountpoint.as_os_str().len()
        });
        if path.starts_with(&mount.mountpoint) && is_more_specific {
            best = Some(mount);
        }
    }
    best
}

fn mount_info(mount: &ProcMountInfo) -> MountInfo {
    // procfs keeps super options in a map, so sort them for a stable order.
    let mut options = mount
        .super_options
        .iter()
        .filter(|(name, _)| !name.is_empty())
        .map(|(name, value)| match value {
            Some(value) => format!("{name}={value}"),
            None => name.clone(),
        })
        .collect::<Vec<_>>();
    options.sort();
    MountInfo {
        mountpoint: mountpoint_path(mount),
        fstype: mount.fs_type.clone(),
        source: mount
            .mount_source
            .clone()
            .unwrap_or_else(|| "none".to_string()),
        options,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_most_specific_mount_with_filesystem_type() {
        let mountinfo = "\
1 0 0:1 / / rw - btrfs /dev/sda rw
2 1 0:2 / /var/lib/databases-everywhere rw - xfs /dev/sdb rw
";

        let mount = find_mount_in(
            Path::new("/var/lib/databases-everywhere/instances/inst_1"),
            &parse_mountinfo(mountinfo),
        )
        .unwrap();

        assert_eq!(
            mount.mountpoint,
            PathBuf::from("/var/lib/databases-everywhere")
        );
        assert_eq!(mount.fstype, "xfs");
        assert_eq!(mount.source, "/dev/sdb");
    }

    #[test]
    fn includes_mount_options() {
        let mountinfo = "\
1 0 0:1 / / rw,relatime - ext4 /dev/vda3 rw,relatime,prjquota,errors=remount-ro
";

        let mount = find_mount_in(
            Path::new("/var/lib/databases-everywhere"),
            &parse_mountinfo(mountinfo),
        )
        .unwrap();

        assert_eq!(
            mount.options,
            vec!["errors=remount-ro", "prjquota", "relatime", "rw"]
        );
    }

    #[test]
    fn identifies_only_exact_mountpoints() {
        let mountinfo = "\
1 0 0:1 / / rw - ext4 /dev/sda rw
2 1 0:2 / /var/lib/dbev/fuse/instances/db\\040one rw - fuse.fusequota fusequota rw
";

        assert!(is_mountpoint_in(
            Path::new("/var/lib/dbev/fuse/instances/db one"),
            &parse_mountinfo(mountinfo)
        ));
        assert!(!is_mountpoint_in(
            Path::new("/var/lib/dbev/fuse/instances/db one/data"),
            &parse_mountinfo(mountinfo)
        ));
    }
}
