mod command;
mod container_config;
mod disk_probe;
mod engine;
mod events;
mod inspection;
mod podman_api;
mod remote_import;
mod security;
mod spec;
mod stream_exec;
mod transfer;

use transfer::*;

pub use command::CommandOutput;
pub use engine::{DaemonEngineConnection, rootless_podman_uid_from_socket_path};
pub use events::{ManagedContainerAction, ManagedContainerEvent};
pub use remote_import::RemoteImportHelperSpec;
pub use security::DockerSecurityPolicy;
pub use spec::{DockerEnv, DockerInstanceSpec, DockerMount};
pub use stream_exec::ExecStreamResult;

use std::{
    collections::{HashMap, HashSet},
    io::{Error as IoError, ErrorKind, Read, Write},
    path::{Component, Path},
    time::{Duration, Instant},
};

use bollard::{
    Docker, body_try_stream,
    errors::Error as BollardError,
    models::{ContainerCreateBody, ContainerUpdateBody, HostConfig, SystemInfoCgroupVersionEnum},
    query_parameters::{
        CreateContainerOptionsBuilder, CreateImageOptionsBuilder,
        DownloadFromContainerOptionsBuilder, KillContainerOptions, ListContainersOptionsBuilder,
        RemoveContainerOptions, StartContainerOptions, StopContainerOptions,
        UploadToContainerOptionsBuilder,
    },
};
use bytes::Bytes;
use futures::{Stream, StreamExt, TryStreamExt, stream};
use secrecy::ExposeSecret;
use tokio_util::io::{ReaderStream, StreamReader, SyncIoBridge};

use crate::{
    config::{DaemonConfig, DaemonEngine},
    constants::docker::{INSTANCE_LABEL, MANAGED_LABEL, NODE_LABEL, PROJECT_LABEL, PROTOCOL_LABEL},
    runtime::docker::container_config::{
        bind_mount, cpu_to_nano, disabled_healthcheck, mib_to_bytes,
    },
    runtime::socket_bridge::supervisor_arguments,
    shared::{
        backend::SOCKET_BRIDGE_CONTAINER_PATH,
        ids::sanitize_docker_suffix,
        limits::{ResourceLimitError, validate_runtime_limits},
        ownership::HostOwner,
        protocol::Protocol,
    },
};

const MAX_CONTAINER_TRANSFER_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_EXEC_OUTPUT_BYTES_PER_CHANNEL: usize = 1024 * 1024;
const FILE_TRANSFER_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const EXEC_OUTPUT_TRUNCATION_MARKER: &str = "[... earlier output truncated ...]\n";

#[derive(Debug, Clone)]
pub struct DockerInstanceInspection {
    pub status: DockerContainerStatus,
    pub network_mode: Option<String>,
    pub health: Option<String>,
    pub image: Option<String>,
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
    legacy_network: String,
    enforce_disk_limits: bool,
    security: DockerSecurityPolicy,
    rootless_podman: bool,
    rootless_podman_owner: Option<HostOwner>,
    engine_version: Option<String>,
    engine_api_version: Option<String>,
    cgroup_version: Option<String>,
    node_id: Option<String>,
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
        let rootless_podman = connection.engine == DaemonEngine::Podman
            && connection.socket_path_for_logs().starts_with("/run/user/");
        let rootless_podman_owner =
            rootless_podman_uid_from_socket_path(connection.socket_path_for_logs())
                .map(|uid| HostOwner { uid, gid: uid });
        Ok(Self {
            docker: connection.connect()?,
            engine: connection.engine,
            socket_path: connection.socket_path_for_logs().to_string(),
            legacy_network: crate::constants::docker::DEFAULT_NETWORK.to_string(),
            enforce_disk_limits,
            security: DockerSecurityPolicy::from_config_for_engine(config, connection.engine),
            rootless_podman,
            rootless_podman_owner,
            engine_version: None,
            engine_api_version: None,
            cgroup_version: None,
            node_id: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn offline_for_tests(config: &DaemonConfig, enforce_disk_limits: bool) -> Self {
        let connection = DaemonEngineConnection::from_config(config);
        let docker =
            Docker::connect_with_http("http://127.0.0.1:9", 1, bollard::API_DEFAULT_VERSION)
                .expect("the fixed offline Docker test endpoint must be a valid HTTP URL");
        Self::with_client(
            docker,
            connection.engine,
            connection.socket_path_for_logs(),
            enforce_disk_limits,
            DockerSecurityPolicy::from_config_for_engine(config, connection.engine),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn with_client(
        docker: Docker,
        engine: DaemonEngine,
        socket_path: impl Into<String>,
        enforce_disk_limits: bool,
        security: DockerSecurityPolicy,
    ) -> Self {
        let socket_path = socket_path.into();
        let rootless_podman =
            engine == DaemonEngine::Podman && socket_path.starts_with("/run/user/");
        let rootless_podman_owner = rootless_podman_uid_from_socket_path(&socket_path)
            .map(|uid| HostOwner { uid, gid: uid });
        Self {
            docker,
            engine,
            socket_path,
            legacy_network: crate::constants::docker::DEFAULT_NETWORK.to_string(),
            enforce_disk_limits,
            security,
            rootless_podman,
            rootless_podman_owner,
            engine_version: None,
            engine_api_version: None,
            cgroup_version: None,
            node_id: None,
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
            options.iter().any(|option| {
                let option = option.to_ascii_lowercase();
                option == "rootless"
                    || option == "name=rootless"
                    || option.split(',').any(|part| part.trim() == "rootless")
            })
        });
        self.rootless_podman = security_rootless
            || socket_owner.uid != 0
            || rootless_podman_uid_from_socket_path(&self.socket_path).is_some();
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

        Some(match protocol {
            Protocol::Postgres | Protocol::Mariadb | Protocol::Mysql | Protocol::Mongodb => {
                "999:999"
            }
            Protocol::Redis | Protocol::Valkey | Protocol::Clickhouse | Protocol::Qdrant => "0:0",
        })
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

    pub fn create_body(
        &self,
        spec: &DockerInstanceSpec,
    ) -> Result<ContainerCreateBody, DockerError> {
        self.security.validate_spec(spec)?;
        validate_runtime_limits(spec.cpu_cores, spec.memory_mib)?;
        let nano_cpus = cpu_to_nano(spec.cpu_cores).ok_or(DockerError::CpuLimitConversion {
            cpu_cores: spec.cpu_cores,
        })?;
        let memory_bytes =
            mib_to_bytes(spec.memory_mib).ok_or(DockerError::MemoryLimitConversion {
                memory_mib: spec.memory_mib,
            })?;
        let mut labels = HashMap::from([
            (MANAGED_LABEL.to_string(), "true".to_string()),
            (INSTANCE_LABEL.to_string(), spec.instance_id.clone()),
            (PROTOCOL_LABEL.to_string(), spec.protocol.to_string()),
        ]);
        if let Some(node_id) = &self.node_id {
            labels.insert(NODE_LABEL.to_string(), node_id.clone());
        }
        if let Some(project_id) = &spec.project_id {
            labels.insert(PROJECT_LABEL.to_string(), project_id.clone());
        }

        let mut host_config = HostConfig {
            network_mode: Some("none".to_string()),
            nano_cpus: Some(nano_cpus),
            memory: Some(memory_bytes),
            memory_swap: Some(memory_bytes),
            mounts: Some(container_mounts(spec)),
            storage_opt: storage_opt(self.enforce_disk_limits, spec.disk_mib),
            port_bindings: None,
            ..Default::default()
        };
        self.security.apply(&mut host_config);
        if let Some(userns_mode) = self.rootless_podman_userns_mode(spec.protocol) {
            host_config.userns_mode = Some(userns_mode.to_string());
        }
        if let Some(pids_limit) = spec.pids_limit {
            host_config.pids_limit = Some(pids_limit);
        }

        Ok(ContainerCreateBody {
            image: Some(spec.image.clone()),
            hostname: (spec.protocol == Protocol::Clickhouse).then(|| "localhost".to_string()),
            user: spec.user.clone(),
            working_dir: spec.working_dir.clone(),
            entrypoint: spec.entrypoint.clone(),
            env: Some(
                spec.env
                    .iter()
                    .map(|env| format!("{}={}", env.key, env.value.expose_secret()))
                    .collect(),
            ),
            cmd: if spec.command.is_empty() {
                None
            } else {
                Some(spec.command.clone())
            },
            labels: Some(labels),
            stop_timeout: Some(30),
            host_config: Some(host_config),
            exposed_ports: None,
            // Do not inherit image healthchecks. DBE runs a bounded readiness
            // query during startup and then follows container lifecycle events.
            healthcheck: Some(disabled_healthcheck()),
            ..Default::default()
        })
    }

    fn rootless_podman_userns_mode(&self, protocol: Protocol) -> Option<&'static str> {
        if !self.uses_rootless_podman() {
            return None;
        }

        match protocol {
            Protocol::Postgres | Protocol::Mariadb | Protocol::Mysql | Protocol::Mongodb => {
                Some("keep-id:uid=999,gid=999")
            }
            Protocol::Redis | Protocol::Valkey | Protocol::Clickhouse | Protocol::Qdrant => {
                Some("host")
            }
        }
    }

    pub fn update_limits_body(
        cpu_cores: f64,
        memory_mib: u64,
    ) -> Result<ContainerUpdateBody, DockerError> {
        validate_runtime_limits(cpu_cores, memory_mib)?;
        let nano_cpus =
            cpu_to_nano(cpu_cores).ok_or(DockerError::CpuLimitConversion { cpu_cores })?;
        let memory_bytes =
            mib_to_bytes(memory_mib).ok_or(DockerError::MemoryLimitConversion { memory_mib })?;
        Ok(ContainerUpdateBody {
            nano_cpus: Some(nano_cpus),
            memory: Some(memory_bytes),
            memory_swap: Some(memory_bytes),
            ..Default::default()
        })
    }

    pub async fn create(&self, spec: &DockerInstanceSpec) -> Result<CommandOutput, DockerError> {
        self.create_inner(spec, None).await
    }

    pub async fn create_with_progress(
        &self,
        spec: &DockerInstanceSpec,
        progress: &(dyn Fn(DockerImagePullProgress) + Send + Sync),
    ) -> Result<CommandOutput, DockerError> {
        self.create_inner(spec, Some(progress)).await
    }

    async fn create_inner(
        &self,
        spec: &DockerInstanceSpec,
        progress: Option<&(dyn Fn(DockerImagePullProgress) + Send + Sync)>,
    ) -> Result<CommandOutput, DockerError> {
        let name = self.container_name(spec.protocol, &spec.instance_id)?;
        self.ensure_image_with_progress(&spec.image, progress)
            .await?;
        ensure_bind_mount_sources(spec).await?;
        let mut body = self.create_body(spec)?;
        if !spec.socket_bridges.is_empty() {
            self.apply_socket_bridge_wrapper(spec, &mut body).await?;
        }
        let response = self
            .docker
            .create_container(
                Some(CreateContainerOptionsBuilder::default().name(&name).build()),
                body,
            )
            .await?;
        Ok(CommandOutput {
            stdout: response.id,
            stderr: response.warnings.join("\n"),
        })
    }

    async fn apply_socket_bridge_wrapper(
        &self,
        spec: &DockerInstanceSpec,
        body: &mut ContainerCreateBody,
    ) -> Result<(), DockerError> {
        let image = self.docker.inspect_image(&spec.image).await?;
        let image_config = image.config.unwrap_or_default();
        let entrypoint = spec
            .entrypoint
            .clone()
            .or(image_config.entrypoint)
            .unwrap_or_default();
        let command = if spec.command.is_empty() {
            image_config.cmd.unwrap_or_default()
        } else {
            spec.command.clone()
        };
        let effective_command = entrypoint.into_iter().chain(command).collect::<Vec<_>>();
        if effective_command.is_empty() {
            return Err(DockerError::MissingImageCommand {
                image: spec.image.clone(),
            });
        }

        body.entrypoint = Some(vec![SOCKET_BRIDGE_CONTAINER_PATH.to_string()]);
        body.cmd = Some(supervisor_arguments(
            &spec.socket_bridges,
            &effective_command,
        ));
        Ok(())
    }

    pub async fn pull_image(&self, image: &str) -> Result<CommandOutput, DockerError> {
        self.ensure_image_with_progress(image, None).await?;
        Ok(CommandOutput {
            stdout: image.to_string(),
            stderr: String::new(),
        })
    }

    pub async fn pull_image_with_progress(
        &self,
        image: &str,
        progress: &(dyn Fn(DockerImagePullProgress) + Send + Sync),
    ) -> Result<CommandOutput, DockerError> {
        self.ensure_image_with_progress(image, Some(progress))
            .await?;
        Ok(CommandOutput {
            stdout: image.to_string(),
            stderr: String::new(),
        })
    }

    async fn ensure_image_with_progress(
        &self,
        image: &str,
        progress: Option<&(dyn Fn(DockerImagePullProgress) + Send + Sync)>,
    ) -> Result<(), DockerError> {
        match self.docker.inspect_image(image).await {
            Ok(_) => {
                tracing::debug!(image, "docker image already present");
                if let Some(progress) = progress {
                    progress(DockerImagePullProgress {
                        image: image.to_string(),
                        layer: None,
                        status: "image already present".to_string(),
                        current: None,
                        total: None,
                    });
                }
                return Ok(());
            }
            Err(BollardError::DockerResponseServerError {
                status_code: 404, ..
            }) => {}
            Err(error) => return Err(error.into()),
        }

        tracing::info!(image, "pulling missing docker image");
        let mut logged = HashSet::new();
        let mut stream = self.docker.create_image(
            Some(
                CreateImageOptionsBuilder::default()
                    .from_image(image)
                    .build(),
            ),
            None,
            None,
        );

        while let Some(info) = stream.try_next().await? {
            if let Some(error) = info.error_detail {
                return Err(DockerError::ImagePullFailed {
                    image: image.to_string(),
                    message: error.message.unwrap_or_else(|| "unknown error".to_string()),
                });
            }
            if let Some(status) = info.status {
                let current = info
                    .progress_detail
                    .as_ref()
                    .and_then(|progress| progress.current)
                    .and_then(|value| u64::try_from(value).ok());
                let total = info
                    .progress_detail
                    .as_ref()
                    .and_then(|progress| progress.total)
                    .and_then(|value| u64::try_from(value).ok());
                if let Some(progress) = progress {
                    progress(DockerImagePullProgress {
                        image: image.to_string(),
                        layer: info.id.clone(),
                        status: status.clone(),
                        current,
                        total,
                    });
                }
                let key = format!(
                    "{}:{}:{}",
                    info.id.as_deref().unwrap_or_default(),
                    status,
                    current.unwrap_or_default()
                );
                if logged.insert(key) {
                    tracing::info!(
                        image,
                        layer = info.id.as_deref().unwrap_or(""),
                        status,
                        current = current.unwrap_or_default(),
                        total = total.unwrap_or_default(),
                        "docker image pull progress"
                    );
                }
            }
        }

        self.docker.inspect_image(image).await?;
        tracing::info!(image, "docker image pull complete");
        if let Some(progress) = progress {
            progress(DockerImagePullProgress {
                image: image.to_string(),
                layer: None,
                status: "image pull complete".to_string(),
                current: None,
                total: None,
            });
        }
        Ok(())
    }

    pub async fn start(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<CommandOutput, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        self.docker
            .start_container(&name, None::<StartContainerOptions>)
            .await?;
        Ok(CommandOutput::empty())
    }

    pub async fn stop(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<CommandOutput, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        self.docker
            .stop_container(&name, None::<StopContainerOptions>)
            .await?;
        Ok(CommandOutput::empty())
    }

    pub async fn stop_with_timeout(
        &self,
        protocol: Protocol,
        instance_id: &str,
        timeout: Duration,
    ) -> Result<CommandOutput, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let seconds = i32::try_from(timeout.as_secs()).unwrap_or(i32::MAX).max(1);
        self.docker
            .stop_container(
                &name,
                Some(StopContainerOptions {
                    signal: None,
                    t: Some(seconds),
                }),
            )
            .await?;
        Ok(CommandOutput::empty())
    }

    pub async fn restart(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<CommandOutput, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        self.docker.restart_container(&name, None).await?;
        Ok(CommandOutput::empty())
    }

    pub async fn kill(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<CommandOutput, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        self.docker
            .kill_container(
                &name,
                Some(KillContainerOptions {
                    signal: "SIGKILL".to_string(),
                }),
            )
            .await?;
        Ok(CommandOutput::empty())
    }

    pub async fn delete(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<CommandOutput, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        self.docker
            .remove_container(
                &name,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await?;
        Ok(CommandOutput::empty())
    }

    pub async fn inspect(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<CommandOutput, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let response = self.docker.inspect_container(&name, None).await?;
        Ok(CommandOutput {
            stdout: serde_json::to_string(&response)?,
            stderr: String::new(),
        })
    }

    pub async fn update_limits(
        &self,
        protocol: Protocol,
        instance_id: &str,
        cpu_cores: f64,
        memory_mib: u64,
    ) -> Result<CommandOutput, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        match self.engine {
            DaemonEngine::Docker => {
                let body = Self::update_limits_body(cpu_cores, memory_mib)?;
                self.docker.update_container(&name, body).await?;
            }
            DaemonEngine::Podman => {
                podman_api::update_limits(&self.socket_path, &name, cpu_cores, memory_mib).await?;
            }
        }
        Ok(CommandOutput::empty())
    }

    pub async fn upload_file(
        &self,
        protocol: Protocol,
        instance_id: &str,
        host_path: &Path,
        container_path: &str,
    ) -> Result<(), DockerError> {
        let container = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let (container_parent, container_file_name) = container_file_parts(container_path)?;
        let metadata = tokio::fs::symlink_metadata(host_path)
            .await
            .map_err(|source| DockerError::FileTransferIo {
                path: host_path.display().to_string(),
                source,
            })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(DockerError::InvalidTransferSource {
                path: host_path.display().to_string(),
            });
        }
        if metadata.len() > MAX_CONTAINER_TRANSFER_BYTES {
            return Err(DockerError::FileTransferTooLarge {
                path: host_path.display().to_string(),
                size: metadata.len(),
                max_bytes: MAX_CONTAINER_TRANSFER_BYTES,
            });
        }

        let (uid, gid) = self
            .configured_container_user(protocol, instance_id)
            .await?
            .as_deref()
            .and_then(numeric_container_user)
            .unwrap_or((0, 0));

        let file = tokio::fs::File::open(host_path).await.map_err(|source| {
            DockerError::FileTransferIo {
                path: host_path.display().to_string(),
                source,
            }
        })?;
        let header = transfer_tar_header(&container_file_name, metadata.len(), uid, gid)?;
        let trailer_len = tar_padding(metadata.len()) + 1024;
        let stream = stream::once(async move { Ok::<Bytes, IoError>(header) })
            .chain(ReaderStream::new(tokio::io::AsyncReadExt::take(
                file,
                metadata.len(),
            )))
            .chain(stream::once(async move {
                Ok::<Bytes, IoError>(Bytes::from(vec![0_u8; trailer_len]))
            }));

        match tokio::time::timeout(
            FILE_TRANSFER_TIMEOUT,
            self.docker.upload_to_container(
                &container,
                Some(
                    UploadToContainerOptionsBuilder::default()
                        .path(&container_parent)
                        .no_overwrite_dir_non_dir("true")
                        .copy_uidgid("true")
                        .build(),
                ),
                body_try_stream(stream),
            ),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => {
                return Err(DockerError::FileTransferTimedOut {
                    direction: "upload",
                    path: host_path.display().to_string(),
                    timeout_seconds: FILE_TRANSFER_TIMEOUT.as_secs(),
                });
            }
        }
        Ok(())
    }

    pub async fn download_file(
        &self,
        protocol: Protocol,
        instance_id: &str,
        container_path: &str,
        host_path: &Path,
    ) -> Result<(), DockerError> {
        self.download_file_bounded(
            protocol,
            instance_id,
            container_path,
            host_path,
            MAX_CONTAINER_TRANSFER_BYTES,
        )
        .await
    }

    pub async fn download_file_bounded(
        &self,
        protocol: Protocol,
        instance_id: &str,
        container_path: &str,
        host_path: &Path,
        max_bytes: u64,
    ) -> Result<(), DockerError> {
        let max_bytes = max_bytes.min(MAX_CONTAINER_TRANSFER_BYTES);
        let container = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let (_, expected_file_name) = container_file_parts(container_path)?;
        let async_deadline = tokio::time::Instant::now() + FILE_TRANSFER_TIMEOUT;
        let blocking_deadline = Instant::now() + FILE_TRANSFER_TIMEOUT;
        let stream = self
            .docker
            .download_from_container(
                &container,
                Some(
                    DownloadFromContainerOptionsBuilder::default()
                        .path(container_path)
                        .build(),
                ),
            )
            .map_err(IoError::other);
        let stream = stream_with_deadline(stream, async_deadline).boxed();
        let reader = StreamReader::new(stream);
        let bridge = SyncIoBridge::new(reader);
        let host_path = host_path.to_path_buf();
        let error_path = host_path.display().to_string();

        let result = tokio::task::spawn_blocking(move || {
            extract_single_regular_file_with_constraints(
                bridge,
                &expected_file_name,
                &host_path,
                max_bytes,
                blocking_deadline,
            )
        })
        .await
        .map_err(|error| DockerError::FileTransferTask(error.to_string()))?;
        match result {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == ErrorKind::TimedOut => {
                Err(DockerError::FileTransferTimedOut {
                    direction: "download",
                    path: error_path,
                    timeout_seconds: FILE_TRANSFER_TIMEOUT.as_secs(),
                })
            }
            Err(source) => Err(DockerError::FileTransferIo {
                path: error_path,
                source,
            }),
        }
    }

    pub async fn remove_managed_containers(&self) -> Result<usize, DockerError> {
        let node_id = self
            .node_id
            .as_deref()
            .ok_or(DockerError::RuntimeNodeIdUnavailable)?;
        let filters = managed_container_filters(node_id);
        let containers = self
            .docker
            .list_containers(Some(
                ListContainersOptionsBuilder::default()
                    .all(true)
                    .filters(&filters)
                    .build(),
            ))
            .await?;

        let mut removed = 0;
        for container in containers {
            if !is_owned_managed_container(container.labels.as_ref(), node_id) {
                continue;
            }
            let Some(id) = container.id else {
                continue;
            };
            self.docker
                .remove_container(
                    &id,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await?;
            removed += 1;
        }
        Ok(removed)
    }

    pub async fn active_managed_container_count(&self) -> Result<usize, DockerError> {
        let node_id = self
            .node_id
            .as_deref()
            .ok_or(DockerError::RuntimeNodeIdUnavailable)?;
        let filters = managed_container_filters(node_id);
        let containers = self
            .docker
            .list_containers(Some(
                ListContainersOptionsBuilder::default()
                    .all(false)
                    .filters(&filters)
                    .build(),
            ))
            .await?;
        Ok(containers
            .iter()
            .filter(|container| is_owned_managed_container(container.labels.as_ref(), node_id))
            .count())
    }

    pub async fn remove_network(&self) -> Result<(), DockerError> {
        match self.docker.remove_network(&self.legacy_network).await {
            Ok(()) => Ok(()),
            Err(BollardError::DockerResponseServerError {
                status_code: 404, ..
            }) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

fn managed_container_filters(node_id: &str) -> HashMap<String, Vec<String>> {
    HashMap::from([(
        "label".to_string(),
        vec![
            format!("{MANAGED_LABEL}=true"),
            format!("{NODE_LABEL}={node_id}"),
        ],
    )])
}

fn is_owned_managed_container(labels: Option<&HashMap<String, String>>, node_id: &str) -> bool {
    labels.and_then(|labels| labels.get(MANAGED_LABEL).map(String::as_str)) == Some("true")
        && labels.and_then(|labels| labels.get(NODE_LABEL).map(String::as_str)) == Some(node_id)
}

fn storage_opt(enforce_disk_limits: bool, disk_mib: u64) -> Option<HashMap<String, String>> {
    if !enforce_disk_limits || disk_mib == 0 {
        None
    } else {
        Some(HashMap::from([(
            "size".to_string(),
            format!("{}m", disk_mib),
        )]))
    }
}

fn verify_managed_instance_labels(
    labels: &HashMap<String, String>,
    container: &str,
    protocol: Protocol,
    instance_id: &str,
    expected_node_id: Option<&str>,
) -> Result<(), DockerError> {
    let node_matches = expected_node_id.is_none_or(|expected| {
        labels
            .get(NODE_LABEL)
            .is_none_or(|actual| actual == expected)
    });
    let is_expected = labels.get(MANAGED_LABEL).map(String::as_str) == Some("true")
        && labels.get(INSTANCE_LABEL).map(String::as_str) == Some(instance_id)
        && labels.get(PROTOCOL_LABEL).map(String::as_str) == Some(protocol.as_str())
        && node_matches;
    if is_expected {
        Ok(())
    } else {
        Err(DockerError::UntrustedContainerNameCollision {
            container: container.to_string(),
            instance_id: instance_id.to_string(),
            protocol: protocol.as_str().to_string(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DockerError {
    #[error(transparent)]
    InvalidId(#[from] crate::shared::ids::IdError),
    #[error("docker api error: {0}")]
    Api(#[from] BollardError),
    #[error("podman api {operation} request failed: {reason}")]
    PodmanApiRequest {
        operation: &'static str,
        reason: String,
    },
    #[error("podman api {operation} failed with HTTP {status}: {message}")]
    PodmanApiResponse {
        operation: &'static str,
        status: u16,
        message: String,
    },
    #[error(
        "container engine mismatch: daemon.engine is {configured}, but the configured socket reports {reported}"
    )]
    EngineMismatch {
        configured: &'static str,
        reported: &'static str,
    },
    #[error("invalid container engine socket {path}: {source}")]
    InvalidEngineSocket {
        path: String,
        source: std::io::Error,
    },
    #[error(
        "rootless Podman was detected through {path}, but its non-root host uid/gid could not be determined; configure the direct user-owned Podman socket"
    )]
    RootlessPodmanOwnerUnavailable { path: String },
    #[error(
        "rootless Podman requires cgroup v2 so DBE CPU, memory, and PID limits remain enforceable"
    )]
    RootlessPodmanRequiresCgroupV2,
    #[error("unsupported Podman version {detected}; DBE requires Podman {minimum} or newer")]
    UnsupportedPodmanVersion {
        detected: String,
        minimum: &'static str,
    },
    #[error("docker security policy rejected spec: {0}")]
    Security(#[from] security::DockerSecurityError),
    #[error("invalid container resource limits: {0}")]
    ResourceLimit(#[from] ResourceLimitError),
    #[error("cpu limit {cpu_cores} cannot be represented in Docker nano-CPU units")]
    CpuLimitConversion { cpu_cores: f64 },
    #[error("memory limit {memory_mib} MiB cannot be represented in Docker bytes")]
    MemoryLimitConversion { memory_mib: u64 },
    #[error("failed to prepare bind mount source {path}: {source}")]
    MountSourceIo {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid bind mount source {path}: {reason}")]
    InvalidMountSource { path: String, reason: String },
    #[error("invalid file-transfer source {path}: expected a real regular file")]
    InvalidTransferSource { path: String },
    #[error("invalid container file-transfer path {path}")]
    InvalidContainerTransferPath { path: String },
    #[error(
        "refusing to modify same-name container {container}: it does not have the complete DBE ownership labels for instance {instance_id} and protocol {protocol}"
    )]
    UntrustedContainerNameCollision {
        container: String,
        instance_id: String,
        protocol: String,
    },
    #[error("managed container for instance {instance_id} and protocol {protocol} was not found")]
    ManagedContainerNotFound {
        instance_id: String,
        protocol: String,
    },
    #[error(
        "managed {protocol} container for instance {instance_id} has an invalid legacy credential environment: {reason}"
    )]
    InvalidLegacyCredentialEnvironment {
        instance_id: String,
        protocol: String,
        reason: String,
    },
    #[error(
        "managed container {instance_id} data bind mismatch at {destination}: expected {expected_source}, actual {actual_source}; recreate or migrate the container before using the selected disk-limit mode"
    )]
    DiskBindSourceMismatch {
        instance_id: String,
        destination: String,
        expected_source: String,
        actual_source: String,
    },
    #[error("managed container {container} did not report an immutable container id")]
    ManagedContainerIdUnavailable { container: String },
    #[error("DBE node ownership identity is unavailable for this container operation")]
    RuntimeNodeIdUnavailable,
    #[error("file transfer failed for {path}: {source}")]
    FileTransferIo {
        path: String,
        source: std::io::Error,
    },
    #[error("file transfer {direction} for {path} exceeded the {timeout_seconds}-second deadline")]
    FileTransferTimedOut {
        direction: &'static str,
        path: String,
        timeout_seconds: u64,
    },
    #[error("file transfer source {path} is {size} bytes; maximum is {max_bytes} bytes")]
    FileTransferTooLarge {
        path: String,
        size: u64,
        max_bytes: u64,
    },
    #[error("file transfer task failed: {0}")]
    FileTransferTask(String),
    #[error("invalid remote import helper specification: {reason}")]
    InvalidRemoteImportHelperSpec { reason: String },
    #[error("remote import helper work directory operation failed for {path}: {source}")]
    RemoteImportHelperIo {
        path: String,
        source: std::io::Error,
    },
    #[error("remote import helper filesystem task failed: {0}")]
    RemoteImportHelperTask(String),
    #[error("remote import helper output is {size} bytes; maximum is {max_bytes} bytes")]
    RemoteImportHelperOutputTooLarge { size: u64, max_bytes: u64 },
    #[error("remote import helper exceeded its {timeout_seconds}-second deadline")]
    RemoteImportHelperTimedOut { timeout_seconds: u64 },
    #[error("remote import helper was cancelled")]
    RemoteImportHelperCancelled,
    #[error("remote import helper wait stream ended without an exit status")]
    RemoteImportHelperWaitEnded,
    #[error("remote import helper exited with code {exit_code}: {failure_output}")]
    RemoteImportHelperFailed {
        exit_code: i64,
        failure_output: String,
    },
    #[error("failed to force-remove remote import helper {container}: {source}")]
    RemoteImportHelperCleanupFailed {
        container: String,
        source: BollardError,
    },
    #[error(
        "timed out after {timeout_seconds} seconds while force-removing remote import helper {container}"
    )]
    RemoteImportHelperCleanupTimedOut {
        container: String,
        timeout_seconds: u64,
    },
    #[error("docker stats stream ended without data")]
    EmptyStatsStream,
    #[error("docker disk limit probe failed for image {image}: {source}")]
    DiskLimitUnsupported {
        image: String,
        source: Box<BollardError>,
    },
    #[error(
        "docker disk limit probe wrote past the configured limit; bind-mounted database data is not quota-enforced"
    )]
    DiskLimitNotEnforced,
    #[error("docker disk limit probe failed: {0}")]
    DiskLimitProbeFailed(String),
    #[error("docker image pull failed for {image}: {message}")]
    ImagePullFailed { image: String, message: String },
    #[error("container image {image} has no command for the socket bridge to supervise")]
    MissingImageCommand { image: String },
    #[error("docker disk limit probe io failed: {0}")]
    DiskLimitProbeIo(std::io::Error),
    #[error(
        "container {instance_id} was not ready before timeout (status={status}, runtime_health={health:?}, startup_readiness={readiness_error:?})"
    )]
    ContainerNotReady {
        instance_id: String,
        status: String,
        health: Option<String>,
        readiness_error: Option<String>,
    },
    #[error(
        "docker exec failed in {container} with exit code {exit_code}: {operation}; output: {failure_output}"
    )]
    ExecFailed {
        container: String,
        operation: String,
        exit_code: i64,
        failure_output: String,
    },
    #[error("invalid streaming exec command")]
    InvalidExecCommand,
    #[error("invalid streaming exec environment")]
    InvalidExecEnvironment,
    #[error("invalid streaming exec {direction} file {path}")]
    InvalidExecStreamFile {
        direction: &'static str,
        path: String,
    },
    #[error("streaming exec {direction} failed for {path}: {source}")]
    ExecStreamIo {
        direction: &'static str,
        path: String,
        source: std::io::Error,
    },
    #[error("streaming exec input {path} is {size} bytes; maximum is {max_bytes} bytes")]
    ExecStreamInputTooLarge {
        path: String,
        size: u64,
        max_bytes: u64,
    },
    #[error("streaming exec output {path} exceeded the {max_bytes}-byte limit")]
    ExecStreamOutputTooLarge { path: String, max_bytes: u64 },
    #[error(
        "streaming exec failed in {container} with exit code {exit_code}; stderr: {failure_output}"
    )]
    ExecStreamFailed {
        container: String,
        exit_code: i64,
        failure_output: String,
    },
    #[error("streaming exec unexpectedly started detached in {container}")]
    ExecStreamDetached { container: String },
    #[error("streaming exec ended without an exit status")]
    ExecExitStatusUnavailable,
    #[error("streaming exec was cancelled in {container}; the container was restarted")]
    ExecStreamCancelled { container: String },
    #[error("streaming exec task failed: {0}")]
    ExecStreamTask(String),
    #[error("docker exec timeout must be greater than zero")]
    InvalidExecTimeout,
    #[error(
        "PostgreSQL tenant role {username} in instance {instance_id} is the immutable bootstrap superuser; export the database and recreate the instance with purge before opening its gateway"
    )]
    LegacyPostgresBootstrapSuperuser {
        instance_id: String,
        username: String,
    },
    #[error("PostgreSQL tenant role {username} is missing from managed instance {instance_id}")]
    MissingPostgresTenantRole {
        instance_id: String,
        username: String,
    },
    #[error("PostgreSQL provisioning returned no recognized result for instance {instance_id}")]
    UnexpectedPostgresProvisioningOutput { instance_id: String },
    #[error("PostgreSQL authentication hardening failed for instance {instance_id}: {reason}")]
    PostgresAuthHardeningFailed { instance_id: String, reason: String },
    #[error(
        "docker exec timed out after {timeout_seconds} seconds in {container}: {operation}; the container was restarted to cancel the command"
    )]
    ExecTimedOut {
        container: String,
        operation: String,
        timeout_seconds: u64,
    },
    #[error("failed to recover from timed-out docker exec in {container} ({operation}): {reason}")]
    ExecRecoveryFailed {
        container: String,
        operation: String,
        reason: String,
    },
    #[error("docker json serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

impl DockerError {
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::Api(BollardError::DockerResponseServerError {
                status_code: 404,
                ..
            }) | Self::PodmanApiResponse { status: 404, .. }
                | Self::ManagedContainerNotFound { .. }
        )
    }

    pub fn is_not_running(&self) -> bool {
        matches!(
            self,
            Self::Api(BollardError::DockerResponseServerError {
                status_code: 304,
                ..
            })
        )
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod podman_live_tests;
