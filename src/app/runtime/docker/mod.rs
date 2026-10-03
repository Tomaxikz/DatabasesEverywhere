mod command;
mod container_config;
mod cpu_burst;
mod create;
mod engine;
mod error;
mod events;
mod helpers;
mod image_probe;
mod inspection;
mod lifecycle;
mod mounts;
mod podman_api;
mod remote_import;
mod security;
mod spec;
mod startup;
mod stream_exec;
mod transfer;

pub use error::DockerError;
use helpers::*;
use transfer::{CappedExecOutput, container_mounts, ensure_bind_mount_sources};

pub use command::{CommandOutput, ExecRecovery};
pub(crate) use cpu_burst::CpuBurstPolicyStatus;
pub use engine::{DaemonEngineConnection, rootless_uid_from_socket};
pub use events::{ManagedContainerAction, ManagedContainerEvent};
pub use remote_import::{
    IMPORT_HELPER_INPUT_PATH, ImportHelperInput, ImportHelperNetwork, RemoteImportHelperSpec,
};
pub use security::DockerSecurityPolicy;
pub use spec::{DockerEnv, DockerInstanceSpec, DockerMount};
pub use stream_exec::ExecStreamResult;

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use bollard::{
    Docker,
    errors::Error as BollardError,
    models::{
        ContainerCreateBody, ContainerSummary, ContainerUpdateBody, HostConfig,
        SystemInfoCgroupVersionEnum,
    },
    query_parameters::{
        CreateContainerOptionsBuilder, CreateImageOptionsBuilder, KillContainerOptions,
        ListContainersOptionsBuilder, RemoveContainerOptions, StartContainerOptions,
        StopContainerOptions,
    },
};
use futures::TryStreamExt;
use secrecy::ExposeSecret;

use crate::{
    config::{DaemonConfig, DaemonEngine},
    databases::protocol::Protocol,
    io::ownership::HostOwner,
    runtime::docker::container_config::{cpu_to_nano, disabled_healthcheck, mib_to_bytes},
    runtime::socket_bridge::supervisor_arguments,
    utils::constants::docker::{
        INSTANCE_LABEL, MANAGED_LABEL, NODE_LABEL, PROJECT_LABEL, PROTOCOL_LABEL,
    },
    utils::{
        backend::SOCKET_BRIDGE_CONTAINER_PATH,
        ids::sanitize_docker_suffix,
        limits::{ResourceLimitError, validate_runtime_limits},
    },
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
    /// Docker's immutable start generation for this container. A stop/start
    /// keeps the container ID but changes this value.
    pub started_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagedContainerCompatibilityIdentity {
    pub id: String,
    pub image_id: String,
}

/// A stats reader bound to one verified managed-container generation. It is
/// recreated after an engine error so a container restart cannot leave the
/// sampler polling a stale container ID.
#[derive(Debug, Clone)]
pub(crate) struct ManagedStatsSampler {
    docker: Docker,
    container_id: String,
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
