use super::*;

pub(super) fn native_project_quota_fs(
    fstype: &str,
    options: &[String],
) -> Option<NativeProjectQuotaFs> {
    if !has_project_quota_option(options) {
        return None;
    }
    match fstype {
        "xfs" => Some(NativeProjectQuotaFs::Xfs),
        "ext4" => Some(NativeProjectQuotaFs::Ext4),
        "f2fs" => Some(NativeProjectQuotaFs::F2fs),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeProjectQuotaFs {
    Xfs,
    Ext4,
    F2fs,
}

impl NativeProjectQuotaFs {
    pub(super) fn method(self) -> &'static str {
        match self {
            Self::Xfs => "host_xfs_project_quota",
            Self::Ext4 | Self::F2fs => "host_linux_project_quota",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeProjectQuota {
    pub path: PathBuf,
    pub mountpoint: PathBuf,
    pub filesystem: NativeProjectQuotaFs,
}

/// Inspect a concrete path without changing quota state. `None` means the
/// path is not on an XFS/ext4/F2FS mount advertising project quotas, so a
/// shared tenant must use the soft limiter instead of pretending it has a
/// native hard limit.
pub(crate) fn inspect_native_project_quota(
    path: &Path,
) -> Result<Option<NativeProjectQuota>, DiskLimitError> {
    if !real_directory_exists(path)? {
        return Err(DiskLimitError::PathIo {
            path: path.display().to_string(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "quota path does not exist"),
        });
    }
    let path = canonical_path(path)?;
    let mount = mounts::find_mount(&path)?;
    let Some(filesystem) = native_project_quota_fs(&mount.fstype, &mount.options) else {
        return Ok(None);
    };
    Ok(Some(NativeProjectQuota {
        path,
        mountpoint: mount.mountpoint,
        filesystem,
    }))
}
