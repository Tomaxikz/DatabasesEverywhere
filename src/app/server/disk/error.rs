use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum DiskLimitError {
    #[error("FuseQuota mount {} requires an offline recovery or cache-policy update; stop the database before remounting (daemon boot performs this safely)", .0.display())]
    FuseRequiresRestart(PathBuf),
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
