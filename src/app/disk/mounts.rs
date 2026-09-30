use std::path::{Path, PathBuf};

use super::DiskLimitError;
use crate::shared::cgroup::unescape_mountinfo;

const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";
const MOUNTPOINT_FIELD: usize = 4;

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
    let mountinfo = std::fs::read_to_string(MOUNTINFO_PATH).map_err(DiskLimitError::Io)?;
    find_mount_in(&path, &mountinfo).ok_or(DiskLimitError::MountpointNotFound(path))
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
    let mountinfo = std::fs::read_to_string(MOUNTINFO_PATH).map_err(DiskLimitError::Io)?;
    Ok(is_mountpoint_in(&path, &mountinfo))
}

fn is_mountpoint_in(path: &Path, mountinfo: &str) -> bool {
    mountinfo.lines().any(|line| {
        let Some((before_separator, _)) = line.split_once(" - ") else {
            return false;
        };
        before_separator
            .split_whitespace()
            .nth(MOUNTPOINT_FIELD)
            .is_some_and(|mountpoint| Path::new(&unescape_mountinfo(mountpoint)) == path)
    })
}

fn find_mount_in(path: &Path, mountinfo: &str) -> Option<MountInfo> {
    let mut best: Option<MountInfo> = None;
    for mount in mountinfo.lines().filter_map(parse_mountinfo_line) {
        let is_more_specific = best.as_ref().is_none_or(|current| {
            mount.mountpoint.as_os_str().len() > current.mountpoint.as_os_str().len()
        });
        if path.starts_with(&mount.mountpoint) && is_more_specific {
            best = Some(mount);
        }
    }
    best
}

fn parse_mountinfo_line(line: &str) -> Option<MountInfo> {
    let (before_separator, after_separator) = line.split_once(" - ")?;
    let mountpoint = before_separator.split_whitespace().nth(MOUNTPOINT_FIELD)?;
    let mut filesystem_fields = after_separator.split_whitespace();
    let fstype = filesystem_fields.next()?;
    let source = filesystem_fields.next().unwrap_or("-").to_string();
    let options = filesystem_fields
        .next()
        .unwrap_or_default()
        .split(',')
        .filter(|option| !option.is_empty())
        .map(ToString::to_string)
        .collect();
    Some(MountInfo {
        mountpoint: PathBuf::from(unescape_mountinfo(mountpoint)),
        fstype: fstype.to_string(),
        source,
        options,
    })
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
            mountinfo,
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

        let mount = find_mount_in(Path::new("/var/lib/databases-everywhere"), mountinfo).unwrap();

        assert_eq!(
            mount.options,
            vec!["rw", "relatime", "prjquota", "errors=remount-ro"]
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
            mountinfo
        ));
        assert!(!is_mountpoint_in(
            Path::new("/var/lib/dbev/fuse/instances/db one/data"),
            mountinfo
        ));
    }
}
