pub mod docker;

use crate::config::DiskLimitMode;

pub const FUSE_QUOTA_STORAGE_GUIDANCE: &str = "Qdrant does not support FUSE-backed storage because its mmap caching semantics can corrupt stored vectors. Enable native project quotas for paths.volumes (ext4, f2fs, or XFS mounted with prjquota, or Btrfs/ZFS), restart dbev so it selects host_filesystem_quota, then retry";

pub fn fuse_quota_storage_is_unsupported(mode: DiskLimitMode) -> bool {
    mode == DiskLimitMode::FuseQuota
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qdrant_requires_native_storage_instead_of_fuse_quota() {
        assert!(fuse_quota_storage_is_unsupported(DiskLimitMode::FuseQuota));
        assert!(!fuse_quota_storage_is_unsupported(
            DiskLimitMode::ProjectQuota
        ));
        assert!(FUSE_QUOTA_STORAGE_GUIDANCE.contains("mmap"));
        assert!(FUSE_QUOTA_STORAGE_GUIDANCE.contains("prjquota"));
    }
}
