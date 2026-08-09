mod btrfs;
mod fuse_quota;
mod linux_project;
mod mounts;
mod project_id;
pub mod soft;
pub mod usage;
mod xfs;
mod zfs;

use std::path::{Path, PathBuf};

use tokio::process::Command;

use crate::{
    config::{DiskConfig, DiskLimitMode, DiskLimitSelection, PathConfig},
    shared::protocol::Protocol,
};

#[derive(Debug, Clone)]
pub struct FilesystemInspection {
    pub field: &'static str,
    pub path: PathBuf,
    pub mountpoint: PathBuf,
    pub source: String,
    pub fstype: String,
    pub options: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DiskModeDetection {
    pub mode: DiskLimitMode,
    pub reason: &'static str,
    pub filesystems: Vec<FilesystemInspection>,
}

pub fn detect_disk_mode(
    paths: &PathConfig,
    selection: DiskLimitSelection,
) -> Result<DiskModeDetection, DiskLimitError> {
    let roots = [
        ("paths.data", paths.data.clone()),
        ("paths.metadata", paths.metadata_root()),
        ("paths.volumes", paths.volumes_root()),
        ("paths.backups", paths.backups_root()),
        ("paths.sockets", paths.sockets.clone()),
        ("paths.locks", paths.locks.clone()),
        ("paths.logs", paths.logs.clone()),
        ("paths.artifacts", paths.artifacts.clone()),
        ("paths.exports", paths.exports_root()),
        ("paths.imports", paths.imports_root()),
        ("paths.fuse", paths.fuse_root()),
        ("paths.tmp", paths.tmp_root()),
    ];
    let mut filesystems = Vec::with_capacity(roots.len());
    for (field, configured_path) in roots {
        let path = PathBuf::from(configured_path);
        let mount = mounts::find_mount(&path)?;
        filesystems.push(FilesystemInspection {
            field,
            path,
            mountpoint: mount.mountpoint,
            source: mount.source,
            fstype: mount.fstype,
            options: mount.options,
        });
    }
    let volumes = filesystems
        .iter()
        .find(|inspection| inspection.field == "paths.volumes")
        .expect("paths.volumes is always inspected");
    let (mode, reason) = select_disk_mode(&volumes.fstype, &volumes.options, selection);
    Ok(DiskModeDetection {
        mode,
        reason,
        filesystems,
    })
}

fn select_disk_mode(
    fstype: &str,
    options: &[String],
    selection: DiskLimitSelection,
) -> (DiskLimitMode, &'static str) {
    match selection {
        DiskLimitSelection::FuseQuota => {
            return (
                DiskLimitMode::FuseQuota,
                "FuseQuota was selected explicitly",
            );
        }
        DiskLimitSelection::SoftScanner => {
            return (
                DiskLimitMode::SoftScanner,
                "soft scanner enforcement was selected explicitly",
            );
        }
        DiskLimitSelection::ProjectQuota => {
            return (
                DiskLimitMode::ProjectQuota,
                "native project quota enforcement was selected explicitly",
            );
        }
        DiskLimitSelection::Auto => {}
    }
    let project_quota_mounted = options
        .iter()
        .any(|option| matches!(option.as_str(), "prjquota" | "pquota"));
    match fstype {
        "btrfs" => (
            DiskLimitMode::ProjectQuota,
            "Btrfs supports native per-subvolume qgroup limits",
        ),
        "zfs" => (
            DiskLimitMode::ProjectQuota,
            "ZFS supports native per-dataset refquota limits",
        ),
        "xfs" if project_quota_mounted => (
            DiskLimitMode::ProjectQuota,
            "XFS is mounted with project quotas enabled",
        ),
        "ext4" | "f2fs" if project_quota_mounted => (
            DiskLimitMode::ProjectQuota,
            "Linux filesystem is mounted with project quotas enabled",
        ),
        _ => (
            DiskLimitMode::FuseQuota,
            "the volumes filesystem has no detected native quota facility",
        ),
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
    pub fn validate_persisted_method_transition(
        &self,
        persisted_method: &str,
    ) -> Result<(), DiskLimitError> {
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
                let method = apply_host_quota(
                    instance_id,
                    data_path,
                    disk_mib,
                    self.config.project_id_base,
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
    pub async fn instance_runtime_is_healthy(
        &self,
        data_path: &Path,
    ) -> Result<bool, DiskLimitError> {
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
    pub fn legacy_fuse_mount_is_present(&self, data_path: &Path) -> Result<bool, DiskLimitError> {
        let mount_path = fuse_quota::mount_path_with_root(data_path, self.fuse_root.as_deref())?;
        mounts::is_mountpoint(&mount_path)
    }

    pub fn legacy_fuse_container_path(&self, data_path: &Path) -> Result<PathBuf, DiskLimitError> {
        fuse_quota::mount_path_with_root(data_path, self.fuse_root.as_deref())
    }

    pub async fn teardown_legacy_fuse_mount(&self, data_path: &Path) -> Result<(), DiskLimitError> {
        fuse_quota::destroy_with_root(data_path, self.fuse_root.as_deref()).await
    }

    pub async fn apply_legacy_fuse_limit(
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
            DiskLimitMode::ProjectQuota => apply_host_quota(
                instance_id,
                data_path,
                disk_mib,
                self.config.project_id_base,
            )
            .await
            .map(|_| ()),
            DiskLimitMode::SoftScanner => Ok(()),
        }
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
    pub fn verify_major_upgrade_directory_cutover(
        &self,
        data_path: &Path,
    ) -> Result<(), DiskLimitError> {
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
    /// renames them into the instance directory. XFS's `project -s` operation
    /// recursively adopts those moved inodes when the limiter is reapplied.
    /// ext4/F2FS `chattr -p +P` only labels the directory itself, while Btrfs
    /// and ZFS attach enforcement to a subvolume/dataset boundary. Reject
    /// those layouts before any data is moved rather than silently admitting
    /// uncharged restored files or relying on a cross-boundary rename.
    pub fn verify_physical_data_replacement(&self, data_path: &Path) -> Result<(), DiskLimitError> {
        if self.config.mode != DiskLimitMode::ProjectQuota {
            return Ok(());
        }
        let mount = mounts::find_mount(data_path)?;
        verify_project_quota_physical_replacement(data_path, &mount.fstype)
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

pub(super) fn privileged_command(program: &'static str) -> Command {
    if use_sudo_for_disk_commands() {
        let mut command = Command::new("sudo");
        command.arg("-n").arg(program);
        command
    } else {
        Command::new(program)
    }
}

fn verify_project_quota_physical_replacement(
    data_path: &Path,
    fstype: &str,
) -> Result<(), DiskLimitError> {
    if fstype == "xfs" {
        return Ok(());
    }
    Err(DiskLimitError::UnsupportedPhysicalDataReplacement {
        path: data_path.to_path_buf(),
        fstype: fstype.to_string(),
    })
}

pub(super) fn displayed_privileged_command(program: &str, args: impl AsRef<str>) -> String {
    let args = args.as_ref();
    if use_sudo_for_disk_commands() {
        format!("sudo -n {program} {args}")
    } else {
        format!("{program} {args}")
    }
}

fn use_sudo_for_disk_commands() -> bool {
    matches!(
        std::env::var("DBE_USE_SUDO").as_deref(),
        Ok("1" | "true" | "yes")
    )
}

async fn apply_host_quota(
    instance_id: &str,
    data_path: &Path,
    disk_mib: u64,
    project_id_base: u32,
) -> Result<String, DiskLimitError> {
    let data_path = data_path
        .canonicalize()
        .map_err(|source| DiskLimitError::PathIo {
            path: data_path.display().to_string(),
            source,
        })?;
    let mount = mounts::find_mount(&data_path)?;
    match mount.fstype.as_str() {
        "xfs" => {
            xfs::apply(
                instance_id,
                &data_path,
                disk_mib,
                project_id_base,
                &mount.mountpoint,
            )
            .await
        }
        "btrfs" => btrfs::apply(&data_path, disk_mib, &mount.mountpoint).await,
        "zfs" => zfs::apply(instance_id, &data_path, disk_mib).await,
        "ext4" | "f2fs" => {
            linux_project::apply(
                instance_id,
                &data_path,
                disk_mib,
                project_id_base,
                &mount.mountpoint,
            )
            .await
        }
        fstype => Err(DiskLimitError::UnsupportedFilesystem {
            mountpoint: mount.mountpoint,
            fstype: fstype.to_string(),
        }),
    }
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

    #[test]
    fn plain_ext4_selects_fuse_quota() {
        assert_eq!(
            select_disk_mode("ext4", &["rw".to_string()], DiskLimitSelection::Auto).0,
            DiskLimitMode::FuseQuota
        );
    }

    #[test]
    fn project_quota_mount_options_select_native_quota() {
        for fstype in ["xfs", "ext4", "f2fs"] {
            assert_eq!(
                select_disk_mode(
                    fstype,
                    &["rw".to_string(), "prjquota".to_string()],
                    DiskLimitSelection::Auto,
                )
                .0,
                DiskLimitMode::ProjectQuota
            );
            assert_eq!(
                select_disk_mode(
                    fstype,
                    &["rw".to_string(), "pquota".to_string()],
                    DiskLimitSelection::Auto,
                )
                .0,
                DiskLimitMode::ProjectQuota
            );
        }
    }

    #[test]
    fn dataset_filesystems_select_native_quota() {
        assert_eq!(
            select_disk_mode("btrfs", &["rw".to_string()], DiskLimitSelection::Auto).0,
            DiskLimitMode::ProjectQuota
        );
        assert_eq!(
            select_disk_mode("zfs", &["rw".to_string()], DiskLimitSelection::Auto).0,
            DiskLimitMode::ProjectQuota
        );
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
                limiter
                    .validate_persisted_method_transition(method)
                    .is_err(),
                "{method} must remain a native project-quota mode"
            );
            assert_eq!(
                limiter.for_persisted_method(method).mode(),
                DiskLimitMode::ProjectQuota
            );
        }
        assert!(
            limiter
                .validate_persisted_method_transition("soft_scanner")
                .is_ok()
        );
    }

    #[test]
    fn physical_replacement_rejects_non_recursive_native_quota_backends() {
        let data = Path::new("/srv/dbev/volumes/inst_1");

        assert!(verify_project_quota_physical_replacement(data, "xfs").is_ok());
        for fstype in ["ext4", "f2fs", "btrfs", "zfs"] {
            let error = verify_project_quota_physical_replacement(data, fstype).unwrap_err();
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

        let error = limiter
            .verify_major_upgrade_directory_cutover(data)
            .unwrap_err();
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
}
