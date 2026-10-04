use std::path::{Path, PathBuf};

use super::host_quota::{HostQuotaChange, set_host_quota};

use super::{
    DiskEnforcement, DiskLimiter, btrfs, error::DiskLimitError, fuse_quota, linux_project, mounts,
    xfs, zfs,
};
use crate::config::DiskLimitMode;

impl DiskLimiter {
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
                let mount_path = self.apply_fuse_limit(data_path, disk_mib).await?;
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
        self.apply_fuse_limit(data_path, disk_mib).await
    }

    async fn apply_fuse_limit(
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
            DiskLimitMode::FuseQuota => {
                self.apply_fuse_limit(data_path, disk_mib).await.map(|_| ())
            }
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
}
