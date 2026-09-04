mod btrfs;
mod detection;
mod fuse_quota;
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

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use crate::{
    config::{DiskConfig, DiskLimitMode},
    shared::protocol::Protocol,
};

#[cfg(test)]
use detection::select_disk_mode;
pub use detection::{DiskModeDetection, FilesystemInspection, detect_disk_mode};
use host_quota::{HostQuotaChange, set_host_quota};
use host_quota::{displayed_privileged_command, privileged_command};

fn native_project_quota_fs(fstype: &str, options: &[String]) -> Option<NativeProjectQuotaFs> {
    let enabled = options
        .iter()
        .any(|option| matches!(option.as_str(), "prjquota" | "pquota"));
    if !enabled {
        return None;
    }
    match fstype {
        "xfs" => Some(NativeProjectQuotaFs::Xfs),
        "ext4" => Some(NativeProjectQuotaFs::Ext4),
        "f2fs" => Some(NativeProjectQuotaFs::F2fs),
        _ => None,
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeProjectQuotaFs {
    Xfs,
    Ext4,
    F2fs,
}

impl NativeProjectQuotaFs {
    fn method(self) -> &'static str {
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
        if protocol == Protocol::Qdrant && self.config.mode == DiskLimitMode::FuseQuota {
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
        if protocol == Protocol::Qdrant
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

    pub async fn verify_startup(&self, data_root: &Path) -> Result<(), DiskLimitError> {
        match self.config.mode {
            DiskLimitMode::FuseQuota => {
                fuse_quota::verify_startup(
                    self.config.fuse_quota_binary(),
                    &self.config.fuse_quota_binary_sha256,
                    self.fuse_root.as_deref(),
                )
                .await
            }
            DiskLimitMode::ProjectQuota => {
                let mount = mounts::find_mount(data_root)?;
                match mount.fstype.as_str() {
                    "xfs" => xfs::verify_startup(&mount.mountpoint).await,
                    "btrfs" => btrfs::verify_startup(&mount.mountpoint).await,
                    "zfs" => zfs::verify_startup().await,
                    "ext4" | "f2fs" => {
                        linux_project::verify_startup(
                            data_root,
                            &mount.mountpoint,
                            &mount.source,
                            &mount.fstype,
                            &mount.options,
                        )
                        .await
                    }
                    fstype => Err(DiskLimitError::UnsupportedFilesystem {
                        mountpoint: mount.mountpoint,
                        fstype: fstype.to_string(),
                    }),
                }
            }
            DiskLimitMode::SoftScanner => Ok(()),
        }
    }

    pub async fn apply_instance_limit(
        &self,
        instance_id: &str,
        data_path: &Path,
        disk_mib: u64,
    ) -> Result<DiskEnforcement, DiskLimitError> {
        match self.config.mode {
            DiskLimitMode::FuseQuota => {
                let mount_path = fuse_quota::apply_with_root(
                    data_path,
                    self.fuse_root.as_deref(),
                    disk_mib,
                    self.config.fuse_quota_binary(),
                    &self.config.fuse_quota_binary_sha256,
                    self.config.fuse_quota_rescan_interval_seconds,
                )
                .await?;
                Ok(DiskEnforcement {
                    enforced: true,
                    method: DiskLimitMode::FuseQuota.method().to_string(),
                    container_data_path: Some(mount_path),
                })
            }
            DiskLimitMode::ProjectQuota => {
                let method = set_host_quota(
                    instance_id,
                    data_path,
                    disk_mib,
                    self.config.project_id_base,
                    HostQuotaChange::Apply,
                )
                .await?;
                Ok(DiskEnforcement {
                    enforced: true,
                    method,
                    container_data_path: None,
                })
            }
            DiskLimitMode::SoftScanner => Ok(DiskEnforcement {
                // `enforced` is the legacy hard-quota bit. Keep it false while
                // reporting the actual active method separately.
                enforced: false,
                method: DiskLimitMode::SoftScanner.method().to_string(),
                container_data_path: None,
            }),
        }
    }

    /// Reports whether the per-instance enforcement runtime can be reused
    /// without interrupting its container. Non-FUSE modes have no persistent
    /// helper process to recover.
    pub async fn runtime_is_healthy(&self, data_path: &Path) -> Result<bool, DiskLimitError> {
        match self.config.mode {
            DiskLimitMode::FuseQuota => {
                fuse_quota::runtime_is_healthy(data_path, self.fuse_root.as_deref()).await
            }
            DiskLimitMode::ProjectQuota => Ok(true),
            DiskLimitMode::SoftScanner => Ok(true),
        }
    }

    /// Detect a legacy FuseQuota mount independently of the per-protocol
    /// effective mode. This is used to migrate Qdrant containers that predate
    /// its FUSE safety exclusion without guessing from metadata.
    pub fn has_legacy_fuse_mount(&self, data_path: &Path) -> Result<bool, DiskLimitError> {
        let mount_path = fuse_quota::mount_path_with_root(data_path, self.fuse_root.as_deref())?;
        mounts::is_mountpoint(&mount_path)
    }

    pub fn legacy_fuse_container_path(&self, data_path: &Path) -> Result<PathBuf, DiskLimitError> {
        fuse_quota::mount_path_with_root(data_path, self.fuse_root.as_deref())
    }

    pub async fn unmount_legacy_fuse(&self, data_path: &Path) -> Result<(), DiskLimitError> {
        fuse_quota::destroy_with_root(data_path, self.fuse_root.as_deref()).await
    }

    pub async fn set_legacy_fuse_limit(
        &self,
        data_path: &Path,
        disk_mib: u64,
    ) -> Result<PathBuf, DiskLimitError> {
        fuse_quota::apply_with_root(
            data_path,
            self.fuse_root.as_deref(),
            disk_mib,
            self.config.fuse_quota_binary(),
            &self.config.fuse_quota_binary_sha256,
            self.config.fuse_quota_rescan_interval_seconds,
        )
        .await
    }

    pub async fn update_instance_limit(
        &self,
        instance_id: &str,
        data_path: &Path,
        disk_mib: u64,
    ) -> Result<(), DiskLimitError> {
        self.apply_instance_limit(instance_id, data_path, disk_mib)
            .await
            .map(|_| ())
    }

    /// Update the aggregate limit of an existing shared engine without
    /// recursively adopting its nested tenant paths. Dedicated restore paths
    /// must keep using [`Self::update_instance_limit`] so moved files are
    /// adopted into the dedicated instance project.
    pub(crate) async fn update_shared_pool_limit(
        &self,
        runtime_id: &str,
        data_path: &Path,
        disk_mib: u64,
    ) -> Result<(), DiskLimitError> {
        match self.config.mode {
            DiskLimitMode::FuseQuota => fuse_quota::apply_with_root(
                data_path,
                self.fuse_root.as_deref(),
                disk_mib,
                self.config.fuse_quota_binary(),
                &self.config.fuse_quota_binary_sha256,
                self.config.fuse_quota_rescan_interval_seconds,
            )
            .await
            .map(|_| ()),
            DiskLimitMode::ProjectQuota => set_host_quota(
                runtime_id,
                data_path,
                disk_mib,
                self.config.project_id_base,
                HostQuotaChange::Update,
            )
            .await
            .map(|_| ()),
            DiskLimitMode::SoftScanner => Ok(()),
        }
    }

    /// Adopt a shared tenant directory into a native filesystem project and
    /// apply its hard byte limit. XFS and Linux project-quota backends adopt
    /// existing descendants; ext4/F2FS reject symlinks, special files, and
    /// nested mounts rather than leaving uncharged data behind.
    pub(crate) async fn apply_path_quota(
        &self,
        owner_id: &str,
        data_path: &Path,
        registry_root: &Path,
        disk_mib: u64,
    ) -> Result<DiskEnforcement, DiskLimitError> {
        let active_native =
            project_id::find_active_in(owner_id, registry_root, self.config.project_id_base)
                .await?
                .is_some();
        let pending_native =
            project_id::find_pending_in(owner_id, registry_root, self.config.project_id_base)
                .await?
                .is_some();
        let existing_native = active_native || pending_native;
        if !should_apply_native_path(self.config.mode, existing_native) {
            return Ok(soft_path_enforcement());
        }
        let target = match inspect_native_project_quota(data_path)? {
            Some(target) => target,
            None if !existing_native => return Ok(soft_path_enforcement()),
            None => {
                return Err(DiskLimitError::NativeProjectQuotaUnavailable {
                    path: data_path.to_path_buf(),
                });
            }
        };
        let registry_root = canonical_path(registry_root)?;
        let method = if active_native {
            self.update_path_quota(owner_id, &target.path, &registry_root, disk_mib)
                .await?;
            target.filesystem.method().to_string()
        } else {
            self.set_native_path_quota(
                owner_id,
                &target,
                &registry_root,
                disk_mib,
                PathQuotaChange::Adopt,
            )
            .await?
        };
        Ok(DiskEnforcement {
            enforced: true,
            method,
            container_data_path: None,
        })
    }

    /// Update only the quota value for an already-adopted path. In
    /// particular, XFS does not rerun recursive `project -s`, so resizing or
    /// recovering a shared pool cannot overwrite nested tenant project IDs.
    pub(crate) async fn update_path_quota(
        &self,
        owner_id: &str,
        data_path: &Path,
        registry_root: &Path,
        disk_mib: u64,
    ) -> Result<(), DiskLimitError> {
        let existing_native =
            project_id::find_active_in(owner_id, registry_root, self.config.project_id_base)
                .await?
                .is_some();
        if !should_apply_native_path(self.config.mode, existing_native) {
            return Ok(());
        }
        let target = require_native_project_quota(data_path)?;
        let registry_root = canonical_path(registry_root)?;
        self.set_native_path_quota(
            owner_id,
            &target,
            &registry_root,
            disk_mib,
            PathQuotaChange::Update,
        )
        .await
        .map(|_| ())
    }

    /// Read an active per-path project's kernel-accounted byte usage without
    /// walking the tenant directory. Pending, released, missing, or
    /// differently-owned claims are rejected before the filesystem query.
    pub(crate) async fn path_quota_usage_bytes(
        &self,
        owner_id: &str,
        data_path: &Path,
        registry_root: &Path,
    ) -> Result<u64, DiskLimitError> {
        let registry_root = canonical_path(registry_root)?;
        let project_id =
            project_id::find_active_in(owner_id, &registry_root, self.config.project_id_base)
                .await?
                .ok_or_else(|| DiskLimitError::ProjectIdNotFound {
                    owner_id: owner_id.to_string(),
                    registry_root: registry_root.clone(),
                })?;
        let target = require_native_project_quota(data_path)?;
        let usage = project_usage::usage_bytes(&target, &registry_root, project_id).await?;

        // A concurrent drop zeroes the kernel quota before tombstoning its
        // claim. Recheck after the syscall so that transient zero is never
        // published as current tenant telemetry.
        let current =
            project_id::find_active_in(owner_id, &registry_root, self.config.project_id_base)
                .await?;
        if current != Some(project_id) {
            return Err(DiskLimitError::ProjectIdNotFound {
                owner_id: owner_id.to_string(),
                registry_root,
            });
        }
        Ok(usage)
    }

    async fn set_native_path_quota(
        &self,
        owner_id: &str,
        target: &NativeProjectQuota,
        registry_root: &Path,
        disk_mib: u64,
        change: PathQuotaChange,
    ) -> Result<String, DiskLimitError> {
        match (target.filesystem, change) {
            (NativeProjectQuotaFs::Xfs, PathQuotaChange::Adopt) => {
                xfs::apply_in(
                    owner_id,
                    &target.path,
                    registry_root,
                    disk_mib,
                    self.config.project_id_base,
                    &target.mountpoint,
                )
                .await
            }
            (NativeProjectQuotaFs::Xfs, PathQuotaChange::Update) => {
                xfs::update_in(
                    owner_id,
                    &target.path,
                    registry_root,
                    disk_mib,
                    self.config.project_id_base,
                    &target.mountpoint,
                )
                .await
            }
            (NativeProjectQuotaFs::Ext4 | NativeProjectQuotaFs::F2fs, PathQuotaChange::Adopt) => {
                linux_project::apply_in(
                    owner_id,
                    &target.path,
                    registry_root,
                    disk_mib,
                    self.config.project_id_base,
                    &target.mountpoint,
                )
                .await
            }
            (NativeProjectQuotaFs::Ext4 | NativeProjectQuotaFs::F2fs, PathQuotaChange::Update) => {
                linux_project::update_in(
                    owner_id,
                    &target.path,
                    registry_root,
                    disk_mib,
                    self.config.project_id_base,
                    &target.mountpoint,
                )
                .await
            }
        }
    }

    /// Remove a shared path quota safely and idempotently. Labels are restored
    /// while the old cap remains active, then the limit is zeroed and the
    /// project-ID claim is tombstoned. The ID is never reused, so an uncertain
    /// old inode cannot later become charged to a different tenant.
    pub(crate) async fn remove_path_quota(
        &self,
        owner_id: &str,
        data_path: &Path,
        registry_root: &Path,
    ) -> Result<(), DiskLimitError> {
        let Some(claim) =
            project_id::find_claim_in(owner_id, registry_root, self.config.project_id_base).await?
        else {
            return Ok(());
        };
        if claim.state == project_id::ProjectIdState::Released {
            return Ok(());
        }
        let target = require_native_project_quota_for_remove(data_path)?;
        let registry_root = canonical_path(registry_root)?;
        match target.filesystem {
            NativeProjectQuotaFs::Xfs => {
                xfs::remove_in(
                    owner_id,
                    &target.path,
                    &registry_root,
                    self.config.project_id_base,
                    &target.mountpoint,
                )
                .await
            }
            NativeProjectQuotaFs::Ext4 | NativeProjectQuotaFs::F2fs => {
                linux_project::remove_in(
                    owner_id,
                    &target.path,
                    &registry_root,
                    self.config.project_id_base,
                    &target.mountpoint,
                )
                .await
            }
        }
    }

    /// Release every storage object owned by an instance before its data
    /// directory is deleted. Unlike [`Self::purge_instance_data`], this also
    /// removes XFS/ext4/F2FS project labels, kernel limits, and registry
    /// claims. Pending and active claims must be removed successfully before
    /// callers may delete the backing path.
    pub(crate) async fn release_instance_storage(
        &self,
        owner_id: &str,
        data_path: &Path,
    ) -> Result<(), DiskLimitError> {
        if self.config.mode == DiskLimitMode::ProjectQuota {
            let registry_root = project_id::default_registry_root(data_path)?;
            self.remove_path_quota(owner_id, data_path, registry_root)
                .await?;
        }
        self.purge_instance_data(data_path).await
    }

    pub async fn purge_instance_data(&self, data_path: &Path) -> Result<(), DiskLimitError> {
        if self.config.mode == DiskLimitMode::FuseQuota {
            return self.teardown_instance_mount(data_path).await;
        }
        if self.config.mode == DiskLimitMode::SoftScanner {
            return Ok(());
        }
        if self.config.mode != DiskLimitMode::ProjectQuota || !data_path.exists() {
            return Ok(());
        }

        let mount = mounts::find_mount(data_path)?;
        match mount.fstype.as_str() {
            "btrfs" => btrfs::destroy(data_path).await,
            "zfs" => zfs::destroy(data_path).await,
            "xfs" | "ext4" | "f2fs" => Ok(()),
            fstype => Err(DiskLimitError::UnsupportedFilesystem {
                mountpoint: mount.mountpoint,
                fstype: fstype.to_string(),
            }),
        }
    }

    /// Stop the per-instance quota helper and unmount its runtime filesystem.
    /// The persistent backing directory and its database files are retained.
    pub async fn teardown_instance_mount(&self, data_path: &Path) -> Result<(), DiskLimitError> {
        if self.config.mode == DiskLimitMode::FuseQuota {
            fuse_quota::destroy_with_root(data_path, self.fuse_root.as_deref()).await?;
        }
        Ok(())
    }

    /// Verify that the generic directory-rename cutover used by major image
    /// upgrades is safe for this instance's storage layout.
    ///
    /// Native quota backends attach enforcement identity to projects,
    /// subvolumes, or datasets rather than only to a directory name. A generic
    /// rename can retain the temporary upgrade identity, leave stale quota
    /// registry entries, or fail outright for a mounted dataset. Fail before
    /// export or old-container removal until each backend has a transactional
    /// native cutover.
    pub fn check_upgrade_cutover(&self, data_path: &Path) -> Result<(), DiskLimitError> {
        if self.config.mode != DiskLimitMode::ProjectQuota {
            return Ok(());
        }
        Err(DiskLimitError::UnsupportedMajorUpgradeCutover {
            path: data_path.to_path_buf(),
            method: "native project quota".to_string(),
        })
    }

    /// Verify that a physical archive can replace the contents of this data
    /// directory without losing native quota identity.
    ///
    /// The restore transaction stages files in a sibling directory and then
    /// renames them into the instance directory. XFS/ext4/F2FS reapply the
    /// project ID to every existing regular file and set inheritance on every
    /// directory without following symlinks or crossing filesystems. Btrfs
    /// and ZFS attach enforcement to a subvolume/dataset boundary, so those
    /// layouts still reject a generic directory cutover.
    pub fn check_restore_layout(&self, data_path: &Path) -> Result<(), DiskLimitError> {
        if self.config.mode != DiskLimitMode::ProjectQuota {
            return Ok(());
        }
        let mount = mounts::find_mount(data_path)?;
        check_project_quota_restore(data_path, &mount.fstype)
    }

    pub async fn instance_usage_bytes(
        &self,
        data_path: &Path,
    ) -> Result<Option<u64>, DiskLimitError> {
        match self.config.mode {
            DiskLimitMode::FuseQuota => {
                fuse_quota::quota_used_with_root(data_path, self.fuse_root.as_deref())
                    .await
                    .map(Some)
            }
            DiskLimitMode::ProjectQuota => Ok(None),
            DiskLimitMode::SoftScanner => Ok(None),
        }
    }
}

fn check_project_quota_restore(data_path: &Path, fstype: &str) -> Result<(), DiskLimitError> {
    if matches!(fstype, "xfs" | "ext4" | "f2fs") {
        return Ok(());
    }
    Err(DiskLimitError::UnsupportedPhysicalDataReplacement {
        path: data_path.to_path_buf(),
        fstype: fstype.to_string(),
    })
}

fn canonical_path(path: &Path) -> Result<PathBuf, DiskLimitError> {
    path.canonicalize()
        .map_err(|source| DiskLimitError::PathIo {
            path: path.display().to_string(),
            source,
        })
}

pub(super) fn real_directory_exists(path: &Path) -> Result<bool, DiskLimitError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(DiskLimitError::PathIo {
                path: path.display().to_string(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DiskLimitError::PathIo {
            path: path.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "quota path must be a real directory",
            ),
        });
    }
    Ok(true)
}

fn require_native_project_quota(path: &Path) -> Result<NativeProjectQuota, DiskLimitError> {
    inspect_native_project_quota(path)?.ok_or_else(|| {
        DiskLimitError::NativeProjectQuotaUnavailable {
            path: path.to_path_buf(),
        }
    })
}

fn require_native_project_quota_for_remove(
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
    if !path.is_absolute() {
        return Err(DiskLimitError::PathIo {
            path: path.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing quota path must be absolute",
            ),
        });
    }

    let mut ancestor = path;
    let mut suffix = Vec::<OsString>::new();
    let existing_ancestor = loop {
        match ancestor.canonicalize() {
            Ok(existing) => break existing,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let name = ancestor.file_name().ok_or_else(|| DiskLimitError::PathIo {
                    path: path.display().to_string(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "missing quota path has no existing ancestor",
                    ),
                })?;
                if name == "." || name == ".." {
                    return Err(DiskLimitError::PathIo {
                        path: path.display().to_string(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "missing quota path must not contain dot components",
                        ),
                    });
                }
                suffix.push(name.to_os_string());
                ancestor = ancestor.parent().ok_or_else(|| DiskLimitError::PathIo {
                    path: path.display().to_string(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "missing quota path has no existing ancestor",
                    ),
                })?;
            }
            Err(source) => {
                return Err(DiskLimitError::PathIo {
                    path: ancestor.display().to_string(),
                    source,
                });
            }
        }
    };
    let mut resolved_path = existing_ancestor.clone();
    for component in suffix.into_iter().rev() {
        resolved_path.push(component);
    }
    Ok((resolved_path, existing_ancestor))
}

fn soft_path_enforcement() -> DiskEnforcement {
    DiskEnforcement {
        enforced: false,
        method: DiskLimitMode::SoftScanner.method().to_string(),
        container_data_path: None,
    }
}

#[derive(Debug, Clone, Copy)]
enum PathQuotaChange {
    Adopt,
    Update,
}

fn should_apply_native_path(mode: DiskLimitMode, existing_native: bool) -> bool {
    existing_native || mode == DiskLimitMode::ProjectQuota
}

#[derive(Debug, thiserror::Error)]
pub enum DiskLimitError {
    #[error(
        "disk enforcement cannot transition in place from {from} to {to}: the existing hard quota must be removed through a safe recreation or migration before metadata can change"
    )]
    UnsafeMethodTransition { from: String, to: String },
    #[error(
        "major image upgrade cannot safely use a directory-rename cutover while {method} owns {}; use a fresh instance/import workflow until a transactional native-quota cutover is available",
        path.display()
    )]
    UnsupportedMajorUpgradeCutover { path: PathBuf, method: String },
    #[error(
        "physical archive replacement cannot safely preserve native project-quota identity on {fstype} at {}; use an XFS project-quota volume, switch through a safe recreation to soft/FUSE enforcement, or restore into a fresh instance",
        path.display()
    )]
    UnsupportedPhysicalDataReplacement { path: PathBuf, fstype: String },
    #[error("disk limiter command {command} failed: {stderr}")]
    CommandFailed { command: String, stderr: String },
    #[error("failed to run disk limiter command {command}: {source}")]
    CommandIo {
        command: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("disk limiter project file {path} failed: {source}")]
    ProjectFile {
        path: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("disk limiter project id registry {path} failed: {source}")]
    ProjectIdRegistry {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("disk limiter could not allocate a unique project id at or above {base}")]
    ProjectIdExhausted { base: u32 },
    #[error(
        "disk limiter has no project id claim for owner {owner_id} in registry root {}",
        registry_root.display()
    )]
    ProjectIdNotFound {
        owner_id: String,
        registry_root: PathBuf,
    },
    #[error(
        "native per-path project quotas are unavailable for {}; use the shared soft disk limiter on this filesystem",
        path.display()
    )]
    NativeProjectQuotaUnavailable { path: PathBuf },
    #[error(
        "project quota {project_id} data path {} and registry root {} are on different filesystems",
        data_path.display(),
        registry_root.display()
    )]
    ProjectQuotaFilesystemMismatch {
        project_id: u32,
        data_path: PathBuf,
        registry_root: PathBuf,
    },
    #[error(
        "failed to read project quota {project_id} usage through {}: {source}",
        path.display()
    )]
    ProjectQuotaUsageIo {
        project_id: u32,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "project quota {project_id} on {} returned invalid usage: {reason}",
        mountpoint.display()
    )]
    InvalidProjectQuotaUsage {
        project_id: u32,
        mountpoint: PathBuf,
        reason: String,
    },
    #[error(
        "project quota {project_id} on {} still accounts {used_bytes} bytes after its boundary was removed; keeping its hard limit and claim until open files are released",
        mountpoint.display()
    )]
    ProjectQuotaStillUsed {
        project_id: u32,
        mountpoint: PathBuf,
        used_bytes: u64,
    },
    #[error("disk limiter path {path} failed: {source}")]
    PathIo {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to read mount information: {0}")]
    Io(std::io::Error),
    #[error("could not determine mountpoint for {}", .0.display())]
    MountpointNotFound(PathBuf),
    #[error("disk strict mode does not support filesystem {fstype} at {}", mountpoint.display())]
    UnsupportedFilesystem { mountpoint: PathBuf, fstype: String },
    #[error(
        "project quotas are not enabled for {fstype} mount {mountpoint} ({device}); current mount options: {options}. Add prjquota to the matching /etc/fstab entry, reboot, then verify with: findmnt -T {data_root} -o TARGET,SOURCE,FSTYPE,OPTIONS"
    )]
    ProjectQuotaNotEnabled {
        data_root: PathBuf,
        mountpoint: PathBuf,
        device: String,
        fstype: String,
        options: String,
    },
    #[error("strict disk limits require an empty unmanaged instance data directory before quota setup: {}", .0.display())]
    DataPathNotEmpty(PathBuf),
    #[error("fuse quota requires /dev/fuse to exist and be accessible")]
    FuseDeviceUnavailable,
    #[error("fuse quota requires /etc/fuse.conf to contain user_allow_other")]
    FuseAllowOtherDisabled,
    #[error("fuse quota control socket failed: {0}")]
    FuseSocket(String),
    #[error("failed to run fuse quota binary {binary}: {source}")]
    FuseBinaryIo {
        binary: String,
        #[source]
        source: std::io::Error,
    },
    #[error("fuse quota binary {binary} failed: {stderr}")]
    FuseBinaryFailed { binary: String, stderr: String },
    #[error("disk limiter task failed: {0}")]
    Task(String),
}

#[cfg(test)]
mod detection_tests {
    use super::*;
    use crate::config::DiskLimitSelection;

    #[test]
    fn auto_selects_the_available_quota_backend() {
        for (fstype, options, expected) in [
            ("ext4", vec!["rw"], DiskLimitMode::FuseQuota),
            ("btrfs", vec!["rw"], DiskLimitMode::ProjectQuota),
            ("zfs", vec!["rw"], DiskLimitMode::ProjectQuota),
        ] {
            assert_eq!(
                select_disk_mode(
                    fstype,
                    &options.into_iter().map(String::from).collect::<Vec<_>>(),
                    DiskLimitSelection::Auto
                )
                .0,
                expected
            );
        }
        for fstype in ["xfs", "ext4", "f2fs"] {
            for option in ["prjquota", "pquota"] {
                let options = ["rw".to_string(), option.to_string()];
                assert_eq!(
                    select_disk_mode(fstype, &options, DiskLimitSelection::Auto).0,
                    DiskLimitMode::ProjectQuota
                );
            }
        }
    }

    #[test]
    fn shared_native_quota_detection_requires_supported_filesystem_and_mount_option() {
        for (fs, options, expected) in [
            (
                "xfs",
                vec!["rw", "prjquota"],
                Some(NativeProjectQuotaFs::Xfs),
            ),
            ("ext4", vec!["pquota"], Some(NativeProjectQuotaFs::Ext4)),
            ("xfs", vec!["rw"], None),
            ("btrfs", vec!["prjquota"], None),
        ] {
            let options = options.into_iter().map(String::from).collect::<Vec<_>>();
            assert_eq!(native_project_quota_fs(fs, &options), expected);
        }
    }

    #[tokio::test]
    async fn non_project_modes_fall_back_before_touching_the_tenant_path() {
        let limiter = DiskLimiter::new(DiskConfig::default());
        let enforcement = limiter
            .apply_path_quota(
                "tenant",
                Path::new("/definitely/missing/tenant"),
                Path::new("/definitely/missing/registry"),
                1024,
            )
            .await
            .unwrap();

        assert!(!enforcement.enforced);
        assert_eq!(enforcement.method, DiskLimitMode::SoftScanner.method());
    }

    #[tokio::test]
    async fn path_usage_accepts_only_the_exact_active_owner_claim() {
        let temporary = tempfile::tempdir().unwrap();
        let registry_root = temporary.path();
        let data_path = registry_root.join("tenant-data");
        std::fs::create_dir(&data_path).unwrap();
        let config = DiskConfig {
            mode: DiskLimitMode::ProjectQuota,
            ..DiskConfig::default()
        };
        let project_id_base = config.project_id_base;
        let limiter = DiskLimiter::new(config);

        let project_id = project_id::allocate_in("tenant-a", registry_root, project_id_base)
            .await
            .unwrap();
        let pending = limiter
            .path_quota_usage_bytes("tenant-a", &data_path, registry_root)
            .await
            .unwrap_err();
        assert!(matches!(
            pending,
            DiskLimitError::ProjectIdNotFound { owner_id, .. } if owner_id == "tenant-a"
        ));

        project_id::activate_in("tenant-a", registry_root, project_id)
            .await
            .unwrap();
        let wrong_owner = limiter
            .path_quota_usage_bytes("tenant-b", &data_path, registry_root)
            .await
            .unwrap_err();
        assert!(matches!(
            wrong_owner,
            DiskLimitError::ProjectIdNotFound { owner_id, .. } if owner_id == "tenant-b"
        ));

        project_id::release_in("tenant-a", registry_root, project_id_base)
            .await
            .unwrap();
        let released = limiter
            .path_quota_usage_bytes("tenant-a", &data_path, registry_root)
            .await
            .unwrap_err();
        assert!(matches!(
            released,
            DiskLimitError::ProjectIdNotFound { owner_id, .. } if owner_id == "tenant-a"
        ));
    }

    #[test]
    fn explicit_soft_scanner_overrides_a_native_quota_filesystem() {
        assert_eq!(
            select_disk_mode(
                "xfs",
                &["rw".to_string(), "prjquota".to_string()],
                DiskLimitSelection::SoftScanner,
            )
            .0,
            DiskLimitMode::SoftScanner
        );
    }

    #[test]
    fn qdrant_never_resolves_to_fuse_quota() {
        let limiter = DiskLimiter::new(DiskConfig::default());
        assert_eq!(
            limiter.mode_for_protocol(Protocol::Qdrant),
            DiskLimitMode::SoftScanner
        );
        assert_eq!(
            limiter.mode_for_protocol(Protocol::Postgres),
            DiskLimitMode::FuseQuota
        );
    }

    #[test]
    fn native_project_quota_cannot_be_silently_relabelled_soft() {
        let config = DiskConfig {
            mode: DiskLimitMode::SoftScanner,
            ..DiskConfig::default()
        };
        let limiter = DiskLimiter::new(config);

        for method in [
            "host_filesystem_quota",
            "host_xfs_project_quota",
            "host_linux_project_quota",
            "host_btrfs_qgroup",
            "host_zfs_refquota",
        ] {
            assert!(
                limiter.check_method_change(method).is_err(),
                "{method} must remain a native project-quota mode"
            );
            assert_eq!(
                limiter.for_persisted_method(method).mode(),
                DiskLimitMode::ProjectQuota
            );
        }
        assert!(limiter.check_method_change("soft_scanner").is_ok());
    }

    #[test]
    fn physical_replacement_accepts_recursive_project_quota_backends() {
        let data = Path::new("/srv/dbev/volumes/inst_1");

        for fstype in ["xfs", "ext4", "f2fs"] {
            assert!(check_project_quota_restore(data, fstype).is_ok());
        }
        for fstype in ["btrfs", "zfs"] {
            let error = check_project_quota_restore(data, fstype).unwrap_err();
            assert!(matches!(
                error,
                DiskLimitError::UnsupportedPhysicalDataReplacement {
                    path,
                    fstype: rejected,
                } if path == data && rejected == fstype
            ));
        }
    }

    #[test]
    fn every_native_quota_backend_requires_a_transactional_major_upgrade_cutover() {
        let data = Path::new("/var/lib/dbev/volumes/instance-one");
        let limiter = DiskLimiter::new(DiskConfig {
            mode: DiskLimitMode::ProjectQuota,
            ..DiskConfig::default()
        });

        let error = limiter.check_upgrade_cutover(data).unwrap_err();
        assert!(error.to_string().contains("transactional native-quota"));
    }

    #[tokio::test]
    async fn project_quota_runtime_teardown_preserves_staged_data() {
        let temporary = tempfile::tempdir().unwrap();
        let marker = temporary.path().join("imported-data");
        std::fs::write(&marker, b"preserve me").unwrap();
        let limiter = DiskLimiter::new(DiskConfig {
            mode: DiskLimitMode::ProjectQuota,
            ..DiskConfig::default()
        });

        limiter
            .teardown_instance_mount(temporary.path())
            .await
            .unwrap();

        assert_eq!(std::fs::read(marker).unwrap(), b"preserve me");
    }

    #[tokio::test]
    async fn instance_release_fails_closed_with_an_unremovable_pending_claim() {
        let temporary = tempfile::tempdir_in("/dev/shm").unwrap();
        let data_path = temporary.path().join("instance-data");
        std::fs::create_dir(&data_path).unwrap();
        let config = DiskConfig {
            mode: DiskLimitMode::ProjectQuota,
            ..DiskConfig::default()
        };
        let project_id_base = config.project_id_base;
        let limiter = DiskLimiter::new(config);
        project_id::allocate_in("instance-one", temporary.path(), project_id_base)
            .await
            .unwrap();

        let error = limiter
            .release_instance_storage("instance-one", &data_path)
            .await
            .expect_err("a live project claim must not be skipped");

        assert!(matches!(
            error,
            DiskLimitError::NativeProjectQuotaUnavailable { path } if path == data_path
        ));
        let claim = project_id::find_claim_in("instance-one", temporary.path(), project_id_base)
            .await
            .unwrap()
            .expect("failed cleanup must retain the claim");
        assert_eq!(claim.state, project_id::ProjectIdState::Pending);
    }

    #[tokio::test]
    async fn missing_instance_path_still_checks_its_project_claim() {
        let temporary = tempfile::tempdir_in("/dev/shm").unwrap();
        let data_path = temporary.path().join("missing-instance-data");
        let config = DiskConfig {
            mode: DiskLimitMode::ProjectQuota,
            ..DiskConfig::default()
        };
        let project_id_base = config.project_id_base;
        let limiter = DiskLimiter::new(config);
        project_id::allocate_in("instance-two", temporary.path(), project_id_base)
            .await
            .unwrap();

        let error = limiter
            .release_instance_storage("instance-two", &data_path)
            .await
            .expect_err(
                "a missing data path must not turn a pending quota claim into a successful purge",
            );
        assert!(matches!(
            error,
            DiskLimitError::NativeProjectQuotaUnavailable { path } if path == data_path
        ));
        let claim = project_id::find_claim_in("instance-two", temporary.path(), project_id_base)
            .await
            .unwrap()
            .expect("failed cleanup must retain the pending claim");
        assert_eq!(claim.state, project_id::ProjectIdState::Pending);
    }
}
