mod backup_helper;
mod cgroup_stats;
mod command;
mod container_config;
mod cpu_burst;
mod create;
mod engine;
mod error;
mod events;
mod helpers;
pub(crate) mod host_paths;
mod image_probe;
mod inspection;
mod lifecycle;
mod mounts;
mod podman_api;
mod remote_import;
pub(crate) mod rootless_preflight;
mod security;
mod spec;
mod startup;
mod stream_exec;
mod transfer;

pub use backup_helper::{
    BACKUP_HELPER_STAGING, BackupHelperError, BackupHelperSocket, BackupHelperSpec,
};
pub use error::DockerError;
use helpers::is_rootless_security_option;
use transfer::CappedExecOutput;

pub(crate) use cgroup_stats::CgroupCounters;
pub use command::{CommandOutput, ExecRecovery};
pub(crate) use cpu_burst::CpuBurstPolicyStatus;
pub use engine::{DaemonEngineConnection, rootless_uid_from_socket};
pub use events::{ManagedContainerAction, ManagedContainerEvent};
pub use remote_import::{
    IMPORT_HELPER_INPUT_PATH, ImportHelperInput, ImportHelperNetwork, RemoteImportHelperSpec,
};
pub use security::DockerSecurityPolicy;
pub use spec::{DockerEnv, DockerInstanceSpec, DockerMount};
pub use stream_exec::{ExecInputFile, ExecStreamResult, ShellExec};

use std::time::Duration;

use bollard::{Docker, models::SystemInfoCgroupVersionEnum};

use crate::{
    config::{DaemonConfig, DaemonEngine},
    databases::protocol::Protocol,
    io::ownership::HostOwner,
    utils::ids::sanitize_docker_suffix,
};

const MAX_CONTAINER_TRANSFER_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_EXEC_OUTPUT_BYTES_PER_CHANNEL: usize = 1024 * 1024;
const FILE_TRANSFER_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const EXEC_OUTPUT_TRUNCATION_MARKER: &str = "[... earlier output truncated ...]\n";
const CONTAINER_STOP_TIMEOUT_SECONDS: i64 = 30;

#[derive(Debug, Clone)]
pub struct DockerInstanceInspection {
    pub status: DockerContainerStatus,
    pub oom_killed: bool,
    pub memory_limit_bytes: Option<u64>,
    pub network_mode: Option<String>,
    pub health: Option<String>,
    pub image: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagedContainerIdentity {
    pub id: String,
    /// A stop/start keeps the container ID but changes this value.
    pub started_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagedContainerCompatibilityIdentity {
    pub id: String,
    pub image_id: String,
}

/// Recreated after an engine error so a restart cannot leave the sampler polling a stale container ID.
///
/// Reads the container's local cgroup directly when the engine runs on this host and falls back
/// to the engine's one-shot stats API otherwise, retrying the direct path periodically.
#[derive(Debug)]
pub(crate) struct ManagedStatsSampler {
    docker: Docker,
    engine: DaemonEngine,
    container_id: String,
    cgroup: Option<std::sync::Arc<cgroup_stats::CgroupStatsReader>>,
    retry_cgroup_at: tokio::time::Instant,
}

/// Both variants carry the counters the engine's compat stats endpoint would report.
#[derive(Debug, Clone)]
pub(crate) enum ContainerStatsSample {
    Cgroup(CgroupCounters),
    Engine(Box<bollard::models::ContainerStatsResponse>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerContainerStatus {
    Running,
    Created,
    Starting,
    Stopped,
    Failed,
}

#[derive(Debug, Clone)]
pub struct DockerRuntime {
    docker: Docker,
    engine: DaemonEngine,
    socket_path: String,
    enforce_disk_limits: bool,
    security: DockerSecurityPolicy,
    rootless_podman: bool,
    rootless_podman_owner: Option<HostOwner>,
    engine_version: Option<String>,
    engine_api_version: Option<String>,
    cgroup_version: Option<String>,
    node_id: Option<String>,
    startup_history: Option<sqlx::SqlitePool>,
}

#[derive(Debug, Clone)]
pub struct DockerImagePullProgress {
    pub image: String,
    pub layer: Option<String>,
    pub status: String,
    pub current: Option<u64>,
    pub total: Option<u64>,
}

impl DockerRuntime {
    pub fn new(config: &DaemonConfig, enforce_disk_limits: bool) -> Result<Self, DockerError> {
        let connection = DaemonEngineConnection::from_config(config);
        if let Some(error) = connection
            .socket_path
            .as_deref()
            .and_then(|path| missing_podman_socket(connection.engine, path))
        {
            return Err(error);
        }
        Ok(Self::from_client(
            connection.connect()?,
            connection.engine,
            connection.socket_path_for_logs(),
            enforce_disk_limits,
            DockerSecurityPolicy::from_config_for_engine(config, connection.engine),
        ))
    }

    #[cfg(test)]
    pub(crate) fn offline_for_tests(config: &DaemonConfig, enforce_disk_limits: bool) -> Self {
        let connection = DaemonEngineConnection::from_config(config);
        let socket_dir = tempfile::tempdir().expect("create offline Docker test socket directory");
        let socket_path = socket_dir.path().join("docker.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path)
            .expect("bind offline Docker test socket");
        let docker = Docker::connect_with_socket(
            socket_path
                .to_str()
                .expect("offline Docker test socket path must be UTF-8"),
            1,
            bollard::API_DEFAULT_VERSION,
        )
        .expect("create offline Docker test client");
        drop(listener);
        drop(socket_dir);
        Self::from_client(
            docker,
            connection.engine,
            connection.socket_path_for_logs(),
            enforce_disk_limits,
            DockerSecurityPolicy::from_config_for_engine(config, connection.engine),
        )
    }

    fn from_client(
        docker: Docker,
        engine: DaemonEngine,
        socket_path: impl Into<String>,
        enforce_disk_limits: bool,
        security: DockerSecurityPolicy,
    ) -> Self {
        let socket_path = socket_path.into();
        let rootless_podman =
            engine == DaemonEngine::Podman && socket_path.starts_with("/run/user/");
        let rootless_podman_owner =
            rootless_uid_from_socket(&socket_path).map(|uid| HostOwner { uid, gid: uid });
        Self {
            docker,
            engine,
            socket_path,
            enforce_disk_limits,
            security,
            rootless_podman,
            rootless_podman_owner,
            engine_version: None,
            engine_api_version: None,
            cgroup_version: None,
            node_id: None,
            startup_history: None,
        }
    }

    pub fn with_node_id(mut self, node_id: impl Into<String>) -> Self {
        let node_id = node_id.into();
        self.node_id = (!node_id.trim().is_empty()).then_some(node_id);
        self
    }

    pub fn engine(&self) -> DaemonEngine {
        self.engine
    }

    pub fn engine_name(&self) -> &'static str {
        self.engine.as_str()
    }

    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    pub fn uses_rootless_podman(&self) -> bool {
        self.engine == DaemonEngine::Podman && self.rootless_podman
    }

    pub fn rootless_podman_host_owner(&self) -> Option<(u32, u32)> {
        self.uses_rootless_podman()
            .then_some(self.rootless_podman_owner)
            .flatten()
            .map(|owner| (owner.uid, owner.gid))
    }

    pub fn engine_version(&self) -> Option<&str> {
        self.engine_version.as_deref()
    }

    pub fn engine_api_version(&self) -> Option<&str> {
        self.engine_api_version.as_deref()
    }

    pub fn cgroup_version(&self) -> Option<&str> {
        self.cgroup_version.as_deref()
    }

    pub async fn refresh_engine_info(&mut self) -> Result<(), DockerError> {
        if let Some(error) = missing_podman_socket(self.engine, &self.socket_path) {
            return Err(error);
        }
        let negotiated = self.docker.clone().negotiate_version().await?;
        let (version, info) = tokio::try_join!(negotiated.version(), negotiated.info())?;
        let reports_podman = engine::reports_podman(&version);
        match (self.engine, reports_podman) {
            (DaemonEngine::Docker, true) => {
                return Err(DockerError::EngineMismatch {
                    configured: "docker",
                    reported: "podman",
                });
            }
            (DaemonEngine::Podman, false) => {
                return Err(DockerError::EngineMismatch {
                    configured: "podman",
                    reported: "non-podman Docker-compatible runtime",
                });
            }
            _ => {}
        }
        if self.engine == DaemonEngine::Podman {
            let detected = version.version.as_deref().unwrap_or("unknown");
            if !engine::is_supported_podman_version(detected) {
                return Err(DockerError::UnsupportedPodmanVersion {
                    detected: detected.to_string(),
                    minimum: engine::MINIMUM_PODMAN_VERSION,
                });
            }
            if !engine::is_recommended_podman_version(detected) {
                tracing::warn!(
                    version = detected,
                    recommended = engine::RECOMMENDED_PODMAN_VERSION,
                    "older Podman may not persist live CPU and memory updates across container restarts and may lack the legacy restart-policy repair route"
                );
            }
        }
        self.docker = negotiated;
        self.engine_version = version.version;
        self.engine_api_version = version.api_version;
        self.cgroup_version = info.cgroup_version.map(|version| version.to_string());

        if self.engine != DaemonEngine::Podman {
            self.rootless_podman = false;
            self.rootless_podman_owner = None;
            return Ok(());
        }

        let socket_owner = engine::podman_socket_owner(&self.socket_path).map_err(|source| {
            DockerError::InvalidEngineSocket {
                path: self.socket_path.clone(),
                source,
            }
        })?;
        let security_rootless = info.security_options.as_ref().is_some_and(|options| {
            options
                .iter()
                .any(|option| is_rootless_security_option(option))
        });
        self.rootless_podman = security_rootless
            || socket_owner.uid != 0
            || rootless_uid_from_socket(&self.socket_path).is_some();
        self.rootless_podman_owner = self.rootless_podman.then_some(socket_owner);
        if self.rootless_podman && socket_owner.uid == 0 {
            return Err(DockerError::RootlessPodmanOwnerUnavailable {
                path: self.socket_path.clone(),
            });
        }
        if self.rootless_podman && info.cgroup_version != Some(SystemInfoCgroupVersionEnum::_2) {
            return Err(DockerError::RootlessPodmanRequiresCgroupV2);
        }
        if self.rootless_podman {
            rootless_preflight::log_startup_advisories(socket_owner.uid);
        }
        Ok(())
    }

    pub fn rootless_podman_container_user(&self, protocol: Protocol) -> Option<&'static str> {
        if !self.uses_rootless_podman() {
            return None;
        }
        Some(protocol.engine().rootless_podman_identity().0)
    }

    pub fn container_name(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<String, DockerError> {
        let suffix = sanitize_docker_suffix(instance_id)?;
        Ok(format!("dbe-{}-{suffix}", protocol.as_str()))
    }

    pub async fn ping(&self) -> Result<String, DockerError> {
        self.docker.ping().await.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod podman_live_tests;

/// A Podman socket that is confirmed absent, with the unit that provides it.
/// An inspection error is left for the connection attempt to report.
fn missing_podman_socket(engine: DaemonEngine, socket_path: &str) -> Option<DockerError> {
    if engine != DaemonEngine::Podman
        || !matches!(std::fs::symlink_metadata(socket_path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        return None;
    }
    let unit = if let Some(uid) = rootless_uid_from_socket(socket_path) {
        format!(
            "podman.socket in the user manager for uid {uid} (systemctl --user enable --now podman.socket as that account)"
        )
    } else if matches!(
        socket_path,
        "/run/podman/podman.sock" | "/var/run/podman/podman.sock"
    ) {
        "the system podman.socket (systemctl enable --now podman.socket)".to_string()
    } else {
        "the service that provides this externally managed socket".to_string()
    };
    Some(DockerError::PodmanSocketMissing {
        path: socket_path.to_string(),
        unit,
    })
}
