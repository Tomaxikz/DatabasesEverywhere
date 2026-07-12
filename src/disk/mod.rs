mod btrfs;
mod fuse_quota;
mod linux_project;
mod mounts;
mod project_id;
mod xfs;
mod zfs;

use std::path::{Path, PathBuf};

use tokio::process::Command;

use crate::config::{DiskConfig, DiskLimitMode, PathConfig};

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

pub fn detect_disk_mode(paths: &PathConfig) -> Result<DiskModeDetection, DiskLimitError> {
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
    let (mode, reason) = select_disk_mode(&volumes.fstype, &volumes.options);
    Ok(DiskModeDetection {
        mode,
        reason,
        filesystems,
    })
}

fn select_disk_mode(fstype: &str, options: &[String]) -> (DiskLimitMode, &'static str) {
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

    pub fn container_data_path(&self, data_path: &Path) -> Result<PathBuf, DiskLimitError> {
        match self.config.mode {
            DiskLimitMode::FuseQuota => {
                fuse_quota::mount_path_with_root(data_path, self.fuse_root.as_deref())
            }
            DiskLimitMode::ProjectQuota => Ok(data_path.to_path_buf()),
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
        }
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
        }
    }

    pub async fn purge_instance_data(&self, data_path: &Path) -> Result<(), DiskLimitError> {
        if self.config.mode == DiskLimitMode::FuseQuota {
            return self.teardown_instance_mount(data_path).await;
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
            select_disk_mode("ext4", &["rw".to_string()]).0,
            DiskLimitMode::FuseQuota
        );
    }

    #[test]
    fn project_quota_mount_options_select_native_quota() {
        for fstype in ["xfs", "ext4", "f2fs"] {
            assert_eq!(
                select_disk_mode(fstype, &["rw".to_string(), "prjquota".to_string()]).0,
                DiskLimitMode::ProjectQuota
            );
            assert_eq!(
                select_disk_mode(fstype, &["rw".to_string(), "pquota".to_string()]).0,
                DiskLimitMode::ProjectQuota
            );
        }
    }

    #[test]
    fn dataset_filesystems_select_native_quota() {
        assert_eq!(
            select_disk_mode("btrfs", &["rw".to_string()]).0,
            DiskLimitMode::ProjectQuota
        );
        assert_eq!(
            select_disk_mode("zfs", &["rw".to_string()]).0,
            DiskLimitMode::ProjectQuota
        );
    }
}
