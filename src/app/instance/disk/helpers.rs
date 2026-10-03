use super::*;

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

pub(super) fn remove_empty_data_directory(path: &Path) -> Result<(), DiskLimitError> {
    if !path.exists() {
        return Ok(());
    }
    let mut entries = std::fs::read_dir(path).map_err(path_io_error(path))?;
    let has_entries = entries
        .next()
        .transpose()
        .map_err(path_io_error(path))?
        .is_some();
    if has_entries {
        return Err(DiskLimitError::DataPathNotEmpty(path.to_path_buf()));
    }
    std::fs::remove_dir(path).map_err(path_io_error(path))
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
