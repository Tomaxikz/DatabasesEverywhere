use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use super::{
    DiskEnforcement,
    error::DiskLimitError,
    mounts,
    native::{NativeProjectQuota, inspect_native_project_quota, native_project_quota_fs},
    path_io_error,
};
use crate::config::DiskLimitMode;

pub(super) fn check_project_quota_restore(
    data_path: &Path,
    fstype: &str,
) -> Result<(), DiskLimitError> {
    if matches!(fstype, "xfs" | "ext4" | "f2fs") {
        return Ok(());
    }
    Err(DiskLimitError::UnsupportedPhysicalDataReplacement {
        path: data_path.to_path_buf(),
        fstype: fstype.to_string(),
    })
}

pub(super) fn canonical_path(path: &Path) -> Result<PathBuf, DiskLimitError> {
    path.canonicalize().map_err(path_io_error(path))
}

pub(super) fn invalid_path_input(path: &Path, message: &'static str) -> DiskLimitError {
    path_io_error(path)(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

/// Owner and mode of an empty data directory that a subvolume or dataset
/// replaces. Instance creation already gave it to the container user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReplacedDirectory {
    uid: u32,
    gid: u32,
    mode: u32,
}

/// Removes the empty data directory so a subvolume or dataset can take its
/// place, returning what [`restore_replaced_directory`] needs.
pub(super) fn remove_empty_data_directory(
    path: &Path,
) -> Result<Option<ReplacedDirectory>, DiskLimitError> {
    use std::os::unix::fs::MetadataExt;

    if !path.exists() {
        return Ok(None);
    }
    let metadata = std::fs::symlink_metadata(path).map_err(path_io_error(path))?;
    let replaced = ReplacedDirectory {
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o7777,
    };
    let mut entries = std::fs::read_dir(path).map_err(path_io_error(path))?;
    let has_entries = entries
        .next()
        .transpose()
        .map_err(path_io_error(path))?
        .is_some();
    if has_entries {
        return Err(DiskLimitError::DataPathNotEmpty(path.to_path_buf()));
    }
    std::fs::remove_dir(path).map_err(path_io_error(path))?;
    Ok(Some(replaced))
}

/// Gives a new subvolume or dataset the owner and mode of the directory it
/// replaced; it is created root-owned, which the container user cannot use.
pub(super) fn restore_replaced_directory(
    path: &Path,
    replaced: Option<ReplacedDirectory>,
) -> Result<(), DiskLimitError> {
    use std::os::unix::fs::PermissionsExt;

    let Some(replaced) = replaced else {
        return Ok(());
    };
    std::os::unix::fs::chown(path, Some(replaced.uid), Some(replaced.gid))
        .map_err(path_io_error(path))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(replaced.mode))
        .map_err(path_io_error(path))
}

pub(super) fn require_native_project_quota(
    path: &Path,
) -> Result<NativeProjectQuota, DiskLimitError> {
    inspect_native_project_quota(path)?.ok_or_else(|| {
        DiskLimitError::NativeProjectQuotaUnavailable {
            path: path.to_path_buf(),
        }
    })
}

pub(super) fn require_native_project_quota_for_remove(
    path: &Path,
) -> Result<NativeProjectQuota, DiskLimitError> {
    match inspect_native_project_quota(path) {
        Ok(Some(target)) => Ok(target),
        Ok(None) => Err(DiskLimitError::NativeProjectQuotaUnavailable {
            path: path.to_path_buf(),
        }),
        Err(DiskLimitError::PathIo { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            let (resolved_path, existing_ancestor) = resolve_missing_path(path)?;
            let mount = mounts::find_mount(&existing_ancestor)?;
            let filesystem =
                native_project_quota_fs(&mount.fstype, &mount.options).ok_or_else(|| {
                    DiskLimitError::NativeProjectQuotaUnavailable {
                        path: resolved_path.clone(),
                    }
                })?;
            Ok(NativeProjectQuota {
                path: resolved_path,
                mountpoint: mount.mountpoint,
                filesystem,
            })
        }
        Err(error) => Err(error),
    }
}

fn resolve_missing_path(path: &Path) -> Result<(PathBuf, PathBuf), DiskLimitError> {
    const NO_EXISTING_ANCESTOR: &str = "missing quota path has no existing ancestor";

    if !path.is_absolute() {
        return Err(invalid_path_input(
            path,
            "missing quota path must be absolute",
        ));
    }

    let mut ancestor = path;
    let mut missing_components = Vec::<OsString>::new();
    let existing_ancestor = loop {
        match ancestor.canonicalize() {
            Ok(existing) => break existing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = ancestor
                    .file_name()
                    .ok_or_else(|| invalid_path_input(path, NO_EXISTING_ANCESTOR))?;
                if name == "." || name == ".." {
                    return Err(invalid_path_input(
                        path,
                        "missing quota path must not contain dot components",
                    ));
                }
                missing_components.push(name.to_os_string());
                ancestor = ancestor
                    .parent()
                    .ok_or_else(|| invalid_path_input(path, NO_EXISTING_ANCESTOR))?;
            }
            Err(source) => return Err(path_io_error(ancestor)(source)),
        }
    };
    let mut resolved_path = existing_ancestor.clone();
    for component in missing_components.into_iter().rev() {
        resolved_path.push(component);
    }
    Ok((resolved_path, existing_ancestor))
}

pub(super) fn soft_path_enforcement() -> DiskEnforcement {
    DiskEnforcement {
        enforced: false,
        method: DiskLimitMode::SoftScanner.method().to_string(),
        container_data_path: None,
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum PathQuotaChange {
    Adopt,
    Update,
}

pub(super) fn should_apply_native_path(mode: DiskLimitMode, existing_native: bool) -> bool {
    existing_native || mode == DiskLimitMode::ProjectQuota
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;

    #[test]
    fn a_replacement_volume_keeps_the_replaced_directory_owner_and_mode() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        std::fs::create_dir(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o750)).unwrap();
        let owner = std::fs::metadata(&data).unwrap();

        let replaced = remove_empty_data_directory(&data).unwrap();
        assert!(replaced.is_some());
        assert!(!data.exists());

        // Stands in for `btrfs subvolume create` / `zfs create`.
        std::fs::create_dir(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
        restore_replaced_directory(&data, replaced).unwrap();
        let restored = std::fs::metadata(&data).unwrap();
        assert_eq!(restored.permissions().mode() & 0o7777, 0o750);
        assert_eq!((restored.uid(), restored.gid()), (owner.uid(), owner.gid()));

        restore_replaced_directory(&data, None).unwrap();
        assert_eq!(
            remove_empty_data_directory(&root.path().join("missing")).unwrap(),
            None
        );
    }

    #[test]
    fn a_data_directory_with_files_is_never_replaced() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("PG_VERSION"), b"18").unwrap();
        assert!(matches!(
            remove_empty_data_directory(root.path()),
            Err(DiskLimitError::DataPathNotEmpty(_))
        ));
    }
}
