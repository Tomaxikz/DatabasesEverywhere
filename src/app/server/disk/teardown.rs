use std::path::Path;

use super::{
    DiskLimiter, btrfs, error::DiskLimitError, fuse_quota, helpers::check_project_quota_restore,
    mounts, project_id, zfs,
};
use crate::config::DiskLimitMode;

impl DiskLimiter {
    /// Releases every storage object owned by an instance, including project labels, kernel limits and registry claims, before its data directory is deleted.
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
        match self.config.mode {
            DiskLimitMode::FuseQuota => return self.teardown_instance_mount(data_path).await,
            DiskLimitMode::SoftScanner => return Ok(()),
            DiskLimitMode::ProjectQuota => {}
        }
        if !data_path.exists() {
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

    /// Stops the quota helper and unmounts its runtime filesystem; backing files are kept.
    pub async fn teardown_instance_mount(&self, data_path: &Path) -> Result<(), DiskLimitError> {
        if self.config.mode == DiskLimitMode::FuseQuota {
            fuse_quota::destroy_with_root(data_path, self.fuse_root.as_deref()).await?;
        }
        Ok(())
    }

    /// Checks that the generic directory-rename cutover of major image upgrades is safe for this layout;
    /// native quota identity is attached to projects/subvolumes/datasets, not directory names.
    pub fn check_upgrade_cutover(&self, data_path: &Path) -> Result<(), DiskLimitError> {
        if self.config.mode != DiskLimitMode::ProjectQuota {
            return Ok(());
        }
        Err(DiskLimitError::UnsupportedMajorUpgradeCutover {
            path: data_path.to_path_buf(),
            method: "native project quota".to_string(),
        })
    }

    /// Checks that a physical archive can replace this data directory without losing native quota identity;
    /// Btrfs and ZFS still reject a generic directory cutover.
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
