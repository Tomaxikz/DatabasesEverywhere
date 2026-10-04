mod btrfs;
pub(crate) mod capacity;
mod detection;
mod fuse_quota;
pub(crate) use fuse_quota::cleanup::cleanup_unused_helpers;
mod host_quota;
mod linux_project;
mod mounts;
mod project_id;
#[cfg(test)]
mod project_quota_integration_tests;
mod project_tree;
mod project_usage;
pub mod soft;
pub mod usage;
mod xfs;
mod zfs;

#[cfg(test)]
mod detection_tests;
mod error;
mod helpers;
mod instance_limit;
mod native;
mod path_quota;
mod teardown;

pub use self::error::DiskLimitError;
#[cfg(test)]
use self::helpers::check_project_quota_restore;
use self::helpers::invalid_path_input;
#[cfg(test)]
use self::native::native_project_quota_fs;
pub(crate) use self::native::{NativeProjectQuota, NativeProjectQuotaFs};

use std::path::{Path, PathBuf};

use crate::{
    config::{DiskConfig, DiskLimitMode},
    databases::protocol::Protocol,
};

#[cfg(test)]
use detection::select_disk_mode;
pub use detection::{DiskModeDetection, FilesystemInspection, detect_disk_mode};
use host_quota::{displayed_privileged_command, privileged_command};

pub(super) fn has_project_quota_option(options: &[String]) -> bool {
    options
        .iter()
        .any(|option| matches!(option.as_str(), "prjquota" | "pquota"))
}

#[derive(Debug, Clone)]
pub struct DiskLimiter {
    config: DiskConfig,
    fuse_root: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct DiskEnforcement {
    pub enforced: bool,
    pub method: String,
    pub container_data_path: Option<PathBuf>,
}

impl DiskLimiter {
    pub fn new(config: DiskConfig) -> Self {
        Self {
            config,
            fuse_root: None,
        }
    }

    pub fn with_fuse_root(config: DiskConfig, fuse_root: impl Into<PathBuf>) -> Self {
        Self {
            config,
            fuse_root: Some(fuse_root.into()),
        }
    }

    pub fn mode(&self) -> DiskLimitMode {
        self.config.mode
    }

    /// Resolve the per-instance mode. Qdrant explicitly rejects FUSE-backed
    /// storage because its mmap/cache assumptions can corrupt vector data, so
    /// it uses the predictive scanner whenever the node fallback is FuseQuota.
    pub fn mode_for_protocol(&self, protocol: Protocol) -> DiskLimitMode {
        if protocol.engine().fuse_quota_unsupported()
            && self.config.mode == DiskLimitMode::FuseQuota
        {
            DiskLimitMode::SoftScanner
        } else {
            self.config.mode
        }
    }

    pub fn for_protocol(&self, protocol: Protocol) -> Self {
        let mut limiter = self.clone();
        limiter.config.mode = self.mode_for_protocol(protocol);
        limiter
    }

    /// Build a limiter for an already-mounted legacy FuseQuota runtime.
    ///
    /// This deliberately ignores the node's current selection. It is used
    /// only while a safe container migration is deferred or rolled back, so
    /// boot reconciliation continues to verify the enforcement the container
    /// is actually bound to instead of claiming the newly configured mode.
    pub fn legacy_fuse_limiter(&self) -> Self {
        let mut limiter = self.clone();
        limiter.config.mode = DiskLimitMode::FuseQuota;
        limiter
    }

    /// Resolve the actual method for an existing instance. New Qdrant
    /// instances never use FUSE, but a pre-exclusion container whose safe
    /// migration was deferred must remain truthfully attached to, verified
    /// against, and updated through its legacy mount until migration succeeds.
    pub fn for_persisted_protocol(&self, protocol: Protocol, persisted_method: &str) -> Self {
        if protocol.engine().fuse_quota_unsupported()
            && DiskLimitMode::from_persisted_method(persisted_method)
                == Some(DiskLimitMode::FuseQuota)
        {
            self.legacy_fuse_limiter()
        } else {
            self.for_protocol(protocol)
        }
    }

    /// Resolve persisted enforcement without applying current selection
    /// policy. Destructive cleanup and rollback use this so mode changes do
    /// not orphan old Fuse helpers/mounts or native quota artifacts.
    pub fn for_persisted_method(&self, persisted_method: &str) -> Self {
        let mut limiter = self.clone();
        let Some(mode) = DiskLimitMode::from_persisted_method(persisted_method) else {
            return limiter;
        };
        limiter.config.mode = mode;
        limiter
    }

    /// Validate method changes that share the same raw bind path. A native
    /// project quota remains active until explicitly removed; relabelling it
    /// as soft enforcement would be false telemetry and surprising policy.
    pub fn check_method_change(&self, persisted_method: &str) -> Result<(), DiskLimitError> {
        if DiskLimitMode::from_persisted_method(persisted_method)
            == Some(DiskLimitMode::ProjectQuota)
            && self.mode() == DiskLimitMode::SoftScanner
        {
            return Err(DiskLimitError::UnsafeMethodTransition {
                from: persisted_method.to_string(),
                to: self.mode().method().to_string(),
            });
        }
        Ok(())
    }

    pub fn container_data_path(&self, data_path: &Path) -> Result<PathBuf, DiskLimitError> {
        match self.config.mode {
            DiskLimitMode::FuseQuota => {
                fuse_quota::mount_path_with_root(data_path, self.fuse_root.as_deref())
            }
            DiskLimitMode::ProjectQuota => Ok(data_path.to_path_buf()),
            DiskLimitMode::SoftScanner => Ok(data_path.to_path_buf()),
        }
    }
}

pub(super) fn path_io_error(path: &Path) -> impl FnOnce(std::io::Error) -> DiskLimitError + '_ {
    move |source| DiskLimitError::PathIo {
        path: path.display().to_string(),
        source,
    }
}

pub(super) fn real_directory_exists(path: &Path) -> Result<bool, DiskLimitError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(path_io_error(path)(source)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid_path_input(
            path,
            "quota path must be a real directory",
        ));
    }
    Ok(true)
}
