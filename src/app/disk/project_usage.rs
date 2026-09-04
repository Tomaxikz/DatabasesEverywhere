use std::path::Path;

use super::{DiskLimitError, NativeProjectQuota, NativeProjectQuotaFs, project_tree};

pub(super) async fn usage_bytes(
    target: &NativeProjectQuota,
    registry_root: &Path,
    project_id: u32,
) -> Result<u64, DiskLimitError> {
    // A project counter is authoritative only while this directory is still
    // the verified inheritance boundary for the active claim. Check on both
    // sides of the syscall so a concurrent relabel cannot publish a plausible
    // counter for a boundary that no longer constrains new files.
    project_tree::verify_root(&target.path, project_id).await?;
    let target = target.clone();
    let registry_root = registry_root.to_path_buf();
    let path = target.path.clone();
    let usage =
        tokio::task::spawn_blocking(move || usage_bytes_sync(&target, &registry_root, project_id))
            .await
            .map_err(|error| DiskLimitError::Task(error.to_string()))??;
    project_tree::verify_root(&path, project_id).await?;
    Ok(usage)
}

/// Read the quota record back from the kernel and require the requested hard
/// byte limit. Command success alone is insufficient: quota tooling can exit
/// successfully while enforcement is disabled or a different record remains
/// installed.
pub(super) async fn verify_hard_limit(
    filesystem: NativeProjectQuotaFs,
    mountpoint: &Path,
    project_id: u32,
    expected_bytes: u64,
) -> Result<(), DiskLimitError> {
    let mountpoint = mountpoint.to_path_buf();
    tokio::task::spawn_blocking(move || {
        verify_hard_limit_sync(filesystem, &mountpoint, project_id, expected_bytes)
    })
    .await
    .map_err(|error| DiskLimitError::Task(error.to_string()))?
}

/// Require the kernel project record to account no remaining blocks before
/// its hard limit and durable claim are removed. This deliberately queries by
/// mount and project ID without requiring the boundary path: an unlinked file
/// can remain charged after that path has safely disappeared.
pub(super) async fn verify_unused(
    filesystem: NativeProjectQuotaFs,
    mountpoint: &Path,
    project_id: u32,
) -> Result<(), DiskLimitError> {
    let mountpoint = mountpoint.to_path_buf();
    tokio::task::spawn_blocking(move || verify_unused_sync(filesystem, &mountpoint, project_id))
        .await
        .map_err(|error| DiskLimitError::Task(error.to_string()))?
}

fn usage_bytes_sync(
    target: &NativeProjectQuota,
    registry_root: &Path,
    project_id: u32,
) -> Result<u64, DiskLimitError> {
    linux::usage_bytes(target, registry_root, project_id)
}

fn verify_hard_limit_sync(
    filesystem: NativeProjectQuotaFs,
    mountpoint: &Path,
    project_id: u32,
    expected_bytes: u64,
) -> Result<(), DiskLimitError> {
    linux::verify_hard_limit(filesystem, mountpoint, project_id, expected_bytes)
}

fn verify_unused_sync(
    filesystem: NativeProjectQuotaFs,
    mountpoint: &Path,
    project_id: u32,
) -> Result<(), DiskLimitError> {
    linux::verify_unused(filesystem, mountpoint, project_id)
}

mod linux {
    use std::{
        fmt,
        os::fd::AsRawFd,
        path::{Path, PathBuf},
    };

    use rustix::fs::{Mode, OFlags, fstat, open};

    use super::super::{DiskLimitError, NativeProjectQuota, NativeProjectQuotaFs};

    const PROJECT_QUOTA: u32 = 2;
    const COMMAND_SHIFT: u32 = 8;
    const COMMAND_TYPE_MASK: u32 = 0xff;
    const XFS_COMMAND_PREFIX: u32 = (b'X' as u32) << 8;
    const XFS_GET_QUOTA: u32 = XFS_COMMAND_PREFIX + 3;
    const XFS_GET_QUOTA_STATE: u32 = XFS_COMMAND_PREFIX + 8;
    const XFS_QUOTA_VERSION: i8 = 1;
    const XFS_PROJECT_QUOTA: i8 = 1 << 1;
    const XFS_QUOTA_STATE_VERSION: i8 = 1;
    const XFS_PROJECT_ACCOUNTING: u16 = 1 << 4;
    const XFS_PROJECT_ENFORCEMENT: u16 = 1 << 5;
    const XFS_BLOCK_BYTES: u64 = 512;
    const VFS_BLOCK_BYTES: u64 = 1024;

    #[repr(C)]
    #[derive(Debug, Default)]
    struct XfsDiskQuota {
        d_version: i8,
        d_flags: i8,
        d_fieldmask: u16,
        d_id: u32,
        d_blk_hardlimit: u64,
        d_blk_softlimit: u64,
        d_ino_hardlimit: u64,
        d_ino_softlimit: u64,
        d_bcount: u64,
        d_icount: u64,
        d_itimer: i32,
        d_btimer: i32,
        d_iwarns: u16,
        d_bwarns: u16,
        d_itimer_hi: i8,
        d_btimer_hi: i8,
        d_rtbtimer_hi: i8,
        d_padding2: i8,
        d_rtb_hardlimit: u64,
        d_rtb_softlimit: u64,
        d_rtbcount: u64,
        d_rtbtimer: i32,
        d_rtbwarns: u16,
        d_padding3: i16,
        d_padding4: [u8; 8],
    }

    #[repr(C)]
    #[derive(Debug, Default)]
    struct XfsQuotaFileState {
        inode: u64,
        blocks: u64,
        extents: u32,
        padding: u32,
    }

    #[repr(C)]
    #[derive(Debug, Default)]
    struct XfsQuotaState {
        version: i8,
        padding1: u8,
        flags: u16,
        in_core_records: u32,
        user: XfsQuotaFileState,
        group: XfsQuotaFileState,
        project: XfsQuotaFileState,
        block_time_limit: i32,
        inode_time_limit: i32,
        realtime_block_time_limit: i32,
        block_warn_limit: u16,
        inode_warn_limit: u16,
        realtime_block_warn_limit: u16,
        padding3: u16,
        padding4: u32,
        padding2: [u64; 7],
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum InvalidUsage {
        MissingSpaceCounter,
        MissingBlockLimits,
        XfsVersion(i8),
        XfsStateVersion(i8),
        XfsQuotaType(i8),
        XfsProjectAccountingDisabled,
        XfsProjectEnforcementDisabled,
        XfsProjectId { expected: u32, actual: u32 },
        XfsBlockCountOverflow,
        HardLimitOverflow,
        HardLimitMismatch { expected: u64, actual: u64 },
    }

    enum QuotaBuffer<'a> {
        Vfs(&'a mut libc::dqblk),
        Xfs(&'a mut XfsDiskQuota),
        XfsState(&'a mut XfsQuotaState),
    }

    impl fmt::Display for InvalidUsage {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::MissingSpaceCounter => {
                    formatter.write_str("kernel did not mark the space counter valid")
                }
                Self::MissingBlockLimits => {
                    formatter.write_str("kernel did not mark the block limits valid")
                }
                Self::XfsVersion(version) => write!(
                    formatter,
                    "XFS returned quota record version {version}, expected {XFS_QUOTA_VERSION}"
                ),
                Self::XfsStateVersion(version) => write!(
                    formatter,
                    "XFS returned quota-state version {version}, expected {XFS_QUOTA_STATE_VERSION}"
                ),
                Self::XfsQuotaType(flags) => write!(
                    formatter,
                    "XFS returned quota type flags {flags:#x}, expected project quota"
                ),
                Self::XfsProjectAccountingDisabled => {
                    formatter.write_str("XFS project quota accounting is disabled")
                }
                Self::XfsProjectEnforcementDisabled => {
                    formatter.write_str("XFS project hard-limit enforcement is disabled")
                }
                Self::XfsProjectId { expected, actual } => write!(
                    formatter,
                    "XFS returned project id {actual}, expected {expected}"
                ),
                Self::XfsBlockCountOverflow => {
                    formatter.write_str("XFS project block usage exceeds u64 byte capacity")
                }
                Self::HardLimitOverflow => {
                    formatter.write_str("project hard limit exceeds u64 byte capacity")
                }
                Self::HardLimitMismatch { expected, actual } => write!(
                    formatter,
                    "kernel retained hard limit {actual} bytes, expected {expected} bytes"
                ),
            }
        }
    }

    pub(super) fn usage_bytes(
        target: &NativeProjectQuota,
        registry_root: &Path,
        project_id: u32,
    ) -> Result<u64, DiskLimitError> {
        let data = open_dir(&target.path, project_id)?;
        let registry = open_dir(registry_root, project_id)?;
        let data_device = fstat(&data)
            .map_err(std::io::Error::from)
            .map_err(|source| io_error(project_id, &target.path, source))?
            .st_dev;
        let registry_device = fstat(&registry)
            .map_err(std::io::Error::from)
            .map_err(|source| io_error(project_id, registry_root, source))?
            .st_dev;
        if data_device != registry_device {
            return Err(DiskLimitError::ProjectQuotaFilesystemMismatch {
                project_id,
                data_path: target.path.clone(),
                registry_root: registry_root.to_path_buf(),
            });
        }

        quota_state(target.filesystem, &target.mountpoint, project_id)
            .map(|state| state.usage_bytes)
    }

    pub(super) fn verify_hard_limit(
        filesystem: NativeProjectQuotaFs,
        mountpoint: &Path,
        project_id: u32,
        expected_bytes: u64,
    ) -> Result<(), DiskLimitError> {
        let state = quota_state(filesystem, mountpoint, project_id)?;
        validate_hard_limit(state.hard_limit_bytes, expected_bytes)
            .map_err(|error| invalid(project_id, mountpoint, error))
    }

    pub(super) fn verify_unused(
        filesystem: NativeProjectQuotaFs,
        mountpoint: &Path,
        project_id: u32,
    ) -> Result<(), DiskLimitError> {
        let state = quota_state(filesystem, mountpoint, project_id)?;
        validate_unused(state.usage_bytes).map_err(|used_bytes| {
            DiskLimitError::ProjectQuotaStillUsed {
                project_id,
                mountpoint: mountpoint.to_path_buf(),
                used_bytes,
            }
        })
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct QuotaState {
        usage_bytes: u64,
        hard_limit_bytes: u64,
    }

    fn quota_state(
        filesystem: NativeProjectQuotaFs,
        mountpoint: &Path,
        project_id: u32,
    ) -> Result<QuotaState, DiskLimitError> {
        let mount = open_dir(mountpoint, project_id)?;
        match filesystem {
            NativeProjectQuotaFs::Xfs => {
                let mut state = XfsQuotaState {
                    version: XFS_QUOTA_STATE_VERSION,
                    ..XfsQuotaState::default()
                };
                query(
                    mount.as_raw_fd(),
                    project_id,
                    QuotaBuffer::XfsState(&mut state),
                )
                .map_err(|source| io_error(project_id, mountpoint, source))?;
                validate_xfs_enforcement(&state)
                    .map_err(|error| invalid(project_id, mountpoint, error))?;
                let mut quota = XfsDiskQuota::default();
                query(mount.as_raw_fd(), project_id, QuotaBuffer::Xfs(&mut quota))
                    .map_err(|source| io_error(project_id, mountpoint, source))?;
                xfs_state(&quota, project_id)
                    .map_err(|error| invalid(project_id, mountpoint, error))
            }
            NativeProjectQuotaFs::Ext4 | NativeProjectQuotaFs::F2fs => {
                let mut quota = empty_vfs_quota();
                query(mount.as_raw_fd(), project_id, QuotaBuffer::Vfs(&mut quota))
                    .map_err(|source| io_error(project_id, mountpoint, source))?;
                vfs_state(&quota).map_err(|error| invalid(project_id, mountpoint, error))
            }
        }
    }

    fn open_dir(path: &Path, project_id: u32) -> Result<rustix::fd::OwnedFd, DiskLimitError> {
        open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)
        .map_err(|source| io_error(project_id, path, source))
    }

    fn quota_command(command: u32, quota_type: u32) -> u32 {
        (command << COMMAND_SHIFT) | (quota_type & COMMAND_TYPE_MASK)
    }

    fn query(
        mount_fd: libc::c_int,
        project_id: libc::c_uint,
        quota: QuotaBuffer<'_>,
    ) -> Result<(), std::io::Error> {
        let (command, address) = match quota {
            QuotaBuffer::Vfs(record) => (
                quota_command(libc::Q_GETQUOTA as u32, PROJECT_QUOTA),
                record as *mut libc::dqblk as *mut libc::c_void,
            ),
            QuotaBuffer::Xfs(record) => (
                quota_command(XFS_GET_QUOTA, PROJECT_QUOTA),
                record as *mut XfsDiskQuota as *mut libc::c_void,
            ),
            QuotaBuffer::XfsState(record) => (
                quota_command(XFS_GET_QUOTA_STATE, PROJECT_QUOTA),
                record as *mut XfsQuotaState as *mut libc::c_void,
            ),
        };
        // SAFETY: `mount_fd` remains open for the call, the command selects a
        // kernel UAPI structure paired by `QuotaBuffer`, and `address` points
        // to initialized, writable, correctly aligned storage that lives until
        // the syscall returns.
        let result = unsafe {
            libc::syscall(
                libc::SYS_quotactl_fd,
                mount_fd,
                command,
                project_id,
                address,
            )
        };
        if result == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn empty_vfs_quota() -> libc::dqblk {
        libc::dqblk {
            dqb_bhardlimit: 0,
            dqb_bsoftlimit: 0,
            dqb_curspace: 0,
            dqb_ihardlimit: 0,
            dqb_isoftlimit: 0,
            dqb_curinodes: 0,
            dqb_btime: 0,
            dqb_itime: 0,
            dqb_valid: 0,
        }
    }

    fn vfs_state(quota: &libc::dqblk) -> Result<QuotaState, InvalidUsage> {
        if quota.dqb_valid & libc::QIF_SPACE == 0 {
            return Err(InvalidUsage::MissingSpaceCounter);
        }
        if quota.dqb_valid & libc::QIF_BLIMITS == 0 {
            return Err(InvalidUsage::MissingBlockLimits);
        }
        Ok(QuotaState {
            usage_bytes: quota.dqb_curspace,
            hard_limit_bytes: quota
                .dqb_bhardlimit
                .checked_mul(VFS_BLOCK_BYTES)
                .ok_or(InvalidUsage::HardLimitOverflow)?,
        })
    }

    fn xfs_state(quota: &XfsDiskQuota, project_id: u32) -> Result<QuotaState, InvalidUsage> {
        if quota.d_version != XFS_QUOTA_VERSION {
            return Err(InvalidUsage::XfsVersion(quota.d_version));
        }
        if quota.d_flags & XFS_PROJECT_QUOTA == 0 {
            return Err(InvalidUsage::XfsQuotaType(quota.d_flags));
        }
        if quota.d_id != project_id {
            return Err(InvalidUsage::XfsProjectId {
                expected: project_id,
                actual: quota.d_id,
            });
        }
        let usage_bytes = quota
            .d_bcount
            .checked_add(quota.d_rtbcount)
            .and_then(|blocks| blocks.checked_mul(XFS_BLOCK_BYTES))
            .ok_or(InvalidUsage::XfsBlockCountOverflow)?;
        let hard_limit_bytes = quota
            .d_blk_hardlimit
            .checked_mul(XFS_BLOCK_BYTES)
            .ok_or(InvalidUsage::HardLimitOverflow)?;
        Ok(QuotaState {
            usage_bytes,
            hard_limit_bytes,
        })
    }

    fn validate_xfs_enforcement(state: &XfsQuotaState) -> Result<(), InvalidUsage> {
        if state.version != XFS_QUOTA_STATE_VERSION {
            return Err(InvalidUsage::XfsStateVersion(state.version));
        }
        if state.flags & XFS_PROJECT_ACCOUNTING == 0 {
            return Err(InvalidUsage::XfsProjectAccountingDisabled);
        }
        if state.flags & XFS_PROJECT_ENFORCEMENT == 0 {
            return Err(InvalidUsage::XfsProjectEnforcementDisabled);
        }
        Ok(())
    }

    fn validate_hard_limit(actual: u64, expected: u64) -> Result<(), InvalidUsage> {
        if actual == expected {
            Ok(())
        } else {
            Err(InvalidUsage::HardLimitMismatch { expected, actual })
        }
    }

    fn validate_unused(actual: u64) -> Result<(), u64> {
        if actual == 0 { Ok(()) } else { Err(actual) }
    }

    fn io_error(project_id: u32, path: &Path, source: std::io::Error) -> DiskLimitError {
        DiskLimitError::ProjectQuotaUsageIo {
            project_id,
            path: path.to_path_buf(),
            source,
        }
    }

    fn invalid(project_id: u32, mountpoint: &Path, error: InvalidUsage) -> DiskLimitError {
        DiskLimitError::InvalidProjectQuotaUsage {
            project_id,
            mountpoint: PathBuf::from(mountpoint),
            reason: error.to_string(),
        }
    }

    #[cfg(test)]
    mod tests {
        use std::mem::{offset_of, size_of};

        use super::*;
        use crate::shared::limits::mib_to_bytes;

        #[test]
        fn linux_quota_commands_match_uapi_macros() {
            assert_eq!(
                quota_command(libc::Q_GETQUOTA as u32, PROJECT_QUOTA),
                0x8000_0702
            );
            assert_eq!(XFS_GET_QUOTA, 0x5803);
            assert_eq!(quota_command(XFS_GET_QUOTA, PROJECT_QUOTA), 0x0058_0302);
            assert_eq!(XFS_GET_QUOTA_STATE, 0x5808);
            assert_eq!(
                quota_command(XFS_GET_QUOTA_STATE, PROJECT_QUOTA),
                0x0058_0802
            );
        }

        #[test]
        fn xfs_record_layout_matches_linux_uapi() {
            assert_eq!(size_of::<XfsDiskQuota>(), 112);
            assert_eq!(offset_of!(XfsDiskQuota, d_id), 4);
            assert_eq!(offset_of!(XfsDiskQuota, d_bcount), 40);
            assert_eq!(offset_of!(XfsDiskQuota, d_rtbcount), 88);
            assert_eq!(offset_of!(XfsDiskQuota, d_padding4), 104);
            assert_eq!(size_of::<XfsQuotaFileState>(), 24);
            assert_eq!(size_of::<XfsQuotaState>(), 160);
            assert_eq!(offset_of!(XfsQuotaState, flags), 2);
            assert_eq!(offset_of!(XfsQuotaState, project), 56);
            assert_eq!(offset_of!(XfsQuotaState, padding2), 104);
        }

        #[test]
        fn vfs_state_requires_valid_usage_and_limit_fields() {
            let mut quota = empty_vfs_quota();
            quota.dqb_curspace = 42;
            quota.dqb_bhardlimit = 1024;
            assert_eq!(vfs_state(&quota), Err(InvalidUsage::MissingSpaceCounter));

            quota.dqb_valid = libc::QIF_SPACE;
            assert_eq!(vfs_state(&quota), Err(InvalidUsage::MissingBlockLimits));

            quota.dqb_valid |= libc::QIF_BLIMITS;
            assert_eq!(
                vfs_state(&quota),
                Ok(QuotaState {
                    usage_bytes: 42,
                    hard_limit_bytes: 1024 * VFS_BLOCK_BYTES,
                })
            );
        }

        #[test]
        fn xfs_usage_validates_identity_and_checked_block_conversion() {
            let mut quota = XfsDiskQuota {
                d_version: XFS_QUOTA_VERSION,
                d_flags: XFS_PROJECT_QUOTA,
                d_id: 17,
                d_bcount: 10,
                d_rtbcount: 2,
                ..XfsDiskQuota::default()
            };
            quota.d_blk_hardlimit = 2048;
            assert_eq!(
                xfs_state(&quota, 17),
                Ok(QuotaState {
                    usage_bytes: 12 * XFS_BLOCK_BYTES,
                    hard_limit_bytes: 2048 * XFS_BLOCK_BYTES,
                })
            );

            quota.d_id = 18;
            assert_eq!(
                xfs_state(&quota, 17),
                Err(InvalidUsage::XfsProjectId {
                    expected: 17,
                    actual: 18,
                })
            );
            quota.d_id = 17;
            quota.d_bcount = u64::MAX;
            assert_eq!(
                xfs_state(&quota, 17),
                Err(InvalidUsage::XfsBlockCountOverflow)
            );
        }

        #[test]
        fn xfs_state_requires_project_accounting_and_enforcement() {
            let mut state = XfsQuotaState {
                version: XFS_QUOTA_STATE_VERSION,
                flags: XFS_PROJECT_ACCOUNTING | XFS_PROJECT_ENFORCEMENT,
                ..XfsQuotaState::default()
            };
            assert_eq!(validate_xfs_enforcement(&state), Ok(()));

            state.flags = XFS_PROJECT_ENFORCEMENT;
            assert_eq!(
                validate_xfs_enforcement(&state),
                Err(InvalidUsage::XfsProjectAccountingDisabled)
            );
            state.flags = XFS_PROJECT_ACCOUNTING;
            assert_eq!(
                validate_xfs_enforcement(&state),
                Err(InvalidUsage::XfsProjectEnforcementDisabled)
            );
            state.flags = XFS_PROJECT_ACCOUNTING | XFS_PROJECT_ENFORCEMENT;
            state.version = 2;
            assert_eq!(
                validate_xfs_enforcement(&state),
                Err(InvalidUsage::XfsStateVersion(2))
            );
        }

        #[test]
        fn hard_limit_readback_rejects_silent_tooling_mismatches() {
            let four_mib = mib_to_bytes(4);
            assert_eq!(validate_hard_limit(four_mib, four_mib), Ok(()));
            assert_eq!(
                validate_hard_limit(0, four_mib),
                Err(InvalidUsage::HardLimitMismatch {
                    expected: four_mib,
                    actual: 0,
                })
            );
            assert_eq!(
                validate_hard_limit(four_mib, 0),
                Err(InvalidUsage::HardLimitMismatch {
                    expected: 0,
                    actual: four_mib,
                })
            );
        }

        #[test]
        fn teardown_rejects_project_records_with_open_deleted_bytes() {
            assert_eq!(validate_unused(0), Ok(()));
            assert_eq!(validate_unused(4096), Err(4096));
        }
    }
}
