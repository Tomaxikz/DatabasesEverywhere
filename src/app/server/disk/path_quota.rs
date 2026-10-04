use std::path::Path;

use super::{
    DiskEnforcement, DiskLimiter,
    error::DiskLimitError,
    helpers::{
        PathQuotaChange, canonical_path, require_native_project_quota,
        require_native_project_quota_for_remove, should_apply_native_path, soft_path_enforcement,
    },
    linux_project,
    native::{NativeProjectQuota, NativeProjectQuotaFs, inspect_native_project_quota},
    project_id, project_usage, xfs,
};

impl DiskLimiter {
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
}
