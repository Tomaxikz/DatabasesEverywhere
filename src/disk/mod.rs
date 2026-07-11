mod btrfs;
mod fuse_quota;
mod linux_project;
mod mounts;
mod project_id;
mod xfs;
mod zfs;

use std::path::{Path, PathBuf};

use tokio::process::Command;

use crate::config::{DiskConfig, DiskLimitMode};

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

    pub fn uses_docker_storage_opt(&self) -> bool {
        self.config.mode.uses_docker_storage_opt()
    }

    pub fn container_data_path(&self, data_path: &Path) -> Result<PathBuf, DiskLimitError> {
        match self.config.mode {
            DiskLimitMode::FuseQuota => {
                fuse_quota::mount_path_with_root(data_path, self.fuse_root.as_deref())
            }
            DiskLimitMode::Advisory
            | DiskLimitMode::DockerStorageOpt
            | DiskLimitMode::ProjectQuota => Ok(data_path.to_path_buf()),
        }
    }

    pub async fn verify_startup(&self, data_root: &Path) -> Result<(), DiskLimitError> {
        match self.config.mode {
            DiskLimitMode::Advisory | DiskLimitMode::DockerStorageOpt => Ok(()),
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
            DiskLimitMode::Advisory => Ok(DiskEnforcement {
                enforced: false,
                method: DiskLimitMode::Advisory.method().to_string(),
                container_data_path: None,
            }),
            DiskLimitMode::DockerStorageOpt => Ok(DiskEnforcement {
                enforced: true,
                method: DiskLimitMode::DockerStorageOpt.method().to_string(),
                container_data_path: None,
            }),
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
            DiskLimitMode::Advisory | DiskLimitMode::DockerStorageOpt => {
                Err(DiskLimitError::UnsupportedUpdate(self.config.mode.method()))
            }
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
            DiskLimitMode::Advisory
            | DiskLimitMode::DockerStorageOpt
            | DiskLimitMode::ProjectQuota => Ok(None),
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
    #[error("disk limit updates are not supported in {0} mode")]
    UnsupportedUpdate(&'static str),
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
