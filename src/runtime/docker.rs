mod command;
mod container_config;
mod disk_probe;
mod engine;
mod inspection;
mod security;
mod spec;

pub use command::CommandOutput;
pub use engine::DaemonEngineConnection;
pub use security::DockerSecurityPolicy;
pub use spec::{DockerEnv, DockerInstanceSpec, DockerMount};

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::{Error as IoError, ErrorKind, Read, Write},
    path::{Component, Path},
    time::{Duration, Instant},
};

use bollard::{
    Docker, body_try_stream,
    container::LogOutput,
    errors::Error as BollardError,
    exec::{CreateExecOptions, StartExecOptions, StartExecResults},
    models::{ContainerCreateBody, ContainerUpdateBody, HostConfig},
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
    constants::docker::{INSTANCE_LABEL, MANAGED_LABEL, PROJECT_LABEL, PROTOCOL_LABEL},
    runtime::docker::container_config::{bind_mount, cpu_to_nano, healthcheck, mib_to_bytes},
    runtime::socket_bridge::supervisor_arguments,
    shared::{
        backend::SOCKET_BRIDGE_CONTAINER_PATH,
        ids::sanitize_docker_suffix,
        limits::{ResourceLimitError, validate_runtime_limits},
        logs::truncate_log_tail,
        protocol::Protocol,
        redaction,
    },
};

const MAX_CONTAINER_TRANSFER_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_EXEC_OUTPUT_BYTES_PER_CHANNEL: usize = 1024 * 1024;
const DOCKER_EXEC_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const DOCKER_EXEC_RECOVERY_STEP_TIMEOUT: Duration = Duration::from_secs(30);
const DOCKER_EXEC_RECOVERY_READINESS_TIMEOUT: Duration = Duration::from_secs(120);
const FILE_TRANSFER_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const EXEC_OUTPUT_TRUNCATION_MARKER: &str = "[... earlier output truncated ...]\n";

#[derive(Debug, Clone)]
pub struct DockerInstanceInspection {
    pub status: DockerContainerStatus,
    pub network_mode: Option<String>,
    pub health: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerContainerStatus {
    Running,
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
        Ok(Self {
            docker: connection.connect()?,
            engine: connection.engine,
            socket_path: connection.socket_path_for_logs().to_string(),
            legacy_network: crate::constants::docker::DEFAULT_NETWORK.to_string(),
            enforce_disk_limits,
            security: DockerSecurityPolicy::from_config(config),
            rootless_podman,
        })
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
        Self {
            docker,
            engine,
            socket_path,
            legacy_network: crate::constants::docker::DEFAULT_NETWORK.to_string(),
            enforce_disk_limits,
            security,
            rootless_podman,
        }
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

    pub async fn refresh_engine_info(&mut self) -> Result<(), DockerError> {
        let info = self.docker.info().await?;
        if self.engine == DaemonEngine::Podman
            && let Some(security_options) = info.security_options
        {
            self.rootless_podman = security_options.iter().any(|option| {
                let option = option.to_ascii_lowercase();
                option == "rootless"
                    || option == "name=rootless"
                    || option.split(',').any(|part| part.trim() == "rootless")
            });
        }
        Ok(())
    }

    pub fn rootless_podman_container_user(&self, protocol: Protocol) -> Option<&'static str> {
        if !self.uses_rootless_podman() {
            return None;
        }

        Some(match protocol {
            Protocol::Postgres | Protocol::Mariadb | Protocol::Mongodb => "999:999",
            Protocol::Redis | Protocol::Clickhouse | Protocol::Qdrant => "0:0",
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
            healthcheck: self.container_healthcheck(spec.protocol),
            ..Default::default()
        })
    }

    fn container_healthcheck(&self, protocol: Protocol) -> Option<bollard::models::HealthConfig> {
        if self.engine == DaemonEngine::Podman {
            return None;
        }

        Some(healthcheck(protocol))
    }

    fn rootless_podman_userns_mode(&self, protocol: Protocol) -> Option<&'static str> {
        if !self.uses_rootless_podman() {
            return None;
        }

        match protocol {
            Protocol::Postgres | Protocol::Mariadb | Protocol::Mongodb => {
                Some("keep-id:uid=999,gid=999")
            }
            Protocol::Redis | Protocol::Clickhouse | Protocol::Qdrant => None,
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
        let name = self.container_name(protocol, instance_id)?;
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
        let name = self.container_name(protocol, instance_id)?;
        self.docker
            .stop_container(&name, None::<StopContainerOptions>)
            .await?;
        Ok(CommandOutput::empty())
    }

    pub async fn restart(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<CommandOutput, DockerError> {
        let name = self.container_name(protocol, instance_id)?;
        self.docker.restart_container(&name, None).await?;
        Ok(CommandOutput::empty())
    }

    pub async fn kill(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<CommandOutput, DockerError> {
        let name = self.container_name(protocol, instance_id)?;
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
        let name = self.container_name(protocol, instance_id)?;
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
        let name = self.container_name(protocol, instance_id)?;
        let response = self.docker.inspect_container(&name, None).await?;
        Ok(CommandOutput {
            stdout: serde_json::to_string(&response)?,
            stderr: String::new(),
        })
    }

    /// Returns the exact protocol-qualified container name when it belongs to
    /// the requested DBE instance. A same-name container without the complete
    /// ownership label tuple is treated as an untrusted collision.
    pub async fn verified_managed_container_name(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<Option<String>, DockerError> {
        let container = self.container_name(protocol, instance_id)?;
        let response = match self.docker.inspect_container(&container, None).await {
            Ok(response) => response,
            Err(BollardError::DockerResponseServerError {
                status_code: 404, ..
            }) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let labels = response
            .config
            .and_then(|config| config.labels)
            .unwrap_or_default();
        verify_managed_instance_labels(&labels, &container, protocol, instance_id)?;
        Ok(Some(container))
    }

    pub async fn update_limits(
        &self,
        protocol: Protocol,
        instance_id: &str,
        cpu_cores: f64,
        memory_mib: u64,
    ) -> Result<CommandOutput, DockerError> {
        let name = self.container_name(protocol, instance_id)?;
        let body = Self::update_limits_body(cpu_cores, memory_mib)?;
        self.docker.update_container(&name, body).await?;
        Ok(CommandOutput::empty())
    }

    pub async fn exec(
        &self,
        protocol: Protocol,
        instance_id: &str,
        command: Vec<String>,
    ) -> Result<CommandOutput, DockerError> {
        let name = self.container_name(protocol, instance_id)?;
        let operation = command
            .first()
            .map(|program| format!("{program} [arguments redacted]"))
            .unwrap_or_else(|| "[empty command]".to_string());
        let exec = self
            .docker
            .create_exec(
                &name,
                CreateExecOptions {
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(command),
                    ..Default::default()
                },
            )
            .await?;

        let deadline = tokio::time::Instant::now() + DOCKER_EXEC_TIMEOUT;
        let started = match tokio::time::timeout_at(
            deadline,
            self.docker.start_exec(&exec.id, None::<StartExecOptions>),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                self.recover_timed_out_exec(protocol, instance_id, &name, &operation)
                    .await?;
                return Err(DockerError::ExecTimedOut {
                    container: name,
                    operation,
                    timeout_seconds: DOCKER_EXEC_TIMEOUT.as_secs(),
                });
            }
        };

        let mut stdout = CappedExecOutput::default();
        let mut stderr = CappedExecOutput::default();
        match started {
            StartExecResults::Attached { mut output, .. } => {
                let drain = async {
                    while let Some(chunk) = output.next().await {
                        match chunk? {
                            LogOutput::StdOut { message } => stdout.append(&message),
                            LogOutput::StdErr { message } => stderr.append(&message),
                            LogOutput::Console { message } => stdout.append(&message),
                            LogOutput::StdIn { .. } => {}
                        }
                    }
                    Ok::<(), BollardError>(())
                };
                match tokio::time::timeout_at(deadline, drain).await {
                    Ok(result) => result?,
                    Err(_) => {
                        self.recover_timed_out_exec(protocol, instance_id, &name, &operation)
                            .await?;
                        return Err(DockerError::ExecTimedOut {
                            container: name,
                            operation,
                            timeout_seconds: DOCKER_EXEC_TIMEOUT.as_secs(),
                        });
                    }
                }
            }
            StartExecResults::Detached => {}
        }

        let inspect = self.docker.inspect_exec(&exec.id).await?;
        let exit_code = inspect.exit_code.unwrap_or_default();
        let output = CommandOutput {
            stdout: stdout.into_string(),
            stderr: stderr.into_string(),
        };
        if exit_code == 0 {
            Ok(output)
        } else {
            let failure_output = if output.stderr.trim().is_empty() {
                output.stdout.trim()
            } else {
                output.stderr.trim()
            };
            let failure_output =
                truncate_log_tail(&redaction::redact_connection_url(failure_output), 4_000);
            tracing::warn!(
                container = %name,
                %operation,
                exit_code,
                %failure_output,
                "docker exec failed"
            );
            Err(DockerError::ExecFailed {
                container: name,
                operation,
                exit_code,
                failure_output,
            })
        }
    }

    async fn recover_timed_out_exec(
        &self,
        protocol: Protocol,
        instance_id: &str,
        container: &str,
        operation: &str,
    ) -> Result<(), DockerError> {
        tracing::warn!(
            %container,
            %operation,
            timeout_seconds = DOCKER_EXEC_TIMEOUT.as_secs(),
            "docker exec timed out; restarting the managed container to stop the command and preserve runtime availability"
        );
        match tokio::time::timeout(
            DOCKER_EXEC_RECOVERY_STEP_TIMEOUT,
            self.docker.kill_container(
                container,
                Some(KillContainerOptions {
                    signal: "SIGKILL".to_string(),
                }),
            ),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(source)) => {
                return Err(exec_recovery_error(container, operation, source));
            }
            Err(_) => {
                return Err(exec_recovery_error(
                    container,
                    operation,
                    format!(
                        "container kill exceeded {} seconds",
                        DOCKER_EXEC_RECOVERY_STEP_TIMEOUT.as_secs()
                    ),
                ));
            }
        }

        match tokio::time::timeout(
            DOCKER_EXEC_RECOVERY_STEP_TIMEOUT,
            self.docker
                .start_container(container, None::<StartContainerOptions>),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(source)) => {
                return Err(exec_recovery_error(container, operation, source));
            }
            Err(_) => {
                return Err(exec_recovery_error(
                    container,
                    operation,
                    format!(
                        "container restart exceeded {} seconds",
                        DOCKER_EXEC_RECOVERY_STEP_TIMEOUT.as_secs()
                    ),
                ));
            }
        }

        self.wait_until_ready(
            protocol,
            instance_id,
            DOCKER_EXEC_RECOVERY_READINESS_TIMEOUT,
        )
        .await
        .map_err(|error| exec_recovery_error(container, operation, error))?;
        tracing::info!(
            %container,
            %operation,
            "managed container recovered after docker exec timeout"
        );
        Ok(())
    }

    pub async fn exec_shell(
        &self,
        protocol: Protocol,
        instance_id: &str,
        script: &str,
    ) -> Result<CommandOutput, DockerError> {
        self.exec(
            protocol,
            instance_id,
            vec!["sh".to_string(), "-c".to_string(), script.to_string()],
        )
        .await
    }

    pub async fn upload_file(
        &self,
        protocol: Protocol,
        instance_id: &str,
        host_path: &Path,
        container_path: &str,
    ) -> Result<(), DockerError> {
        let container = self.container_name(protocol, instance_id)?;
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
        let container = self.container_name(protocol, instance_id)?;
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
                MAX_CONTAINER_TRANSFER_BYTES,
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
        let filters = HashMap::from([("label".to_string(), vec![format!("{MANAGED_LABEL}=true")])]);
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
        let filters = HashMap::from([("label".to_string(), vec![format!("{MANAGED_LABEL}=true")])]);
        let containers = self
            .docker
            .list_containers(Some(
                ListContainersOptionsBuilder::default()
                    .all(false)
                    .filters(&filters)
                    .build(),
            ))
            .await?;
        Ok(containers.len())
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

fn container_mounts(spec: &DockerInstanceSpec) -> Vec<bollard::models::Mount> {
    let mut mounts = vec![
        bind_mount(&spec.data_path, &spec.data_target, false),
        bind_mount(&spec.logs_path, &spec.logs_target, false),
    ];
    mounts.extend(
        spec.extra_mounts
            .iter()
            .map(|mount| bind_mount(&mount.source, &mount.target, mount.read_only)),
    );
    mounts
}

async fn ensure_bind_mount_sources(spec: &DockerInstanceSpec) -> Result<(), DockerError> {
    ensure_bind_mount_dir(&spec.data_path).await?;
    ensure_bind_mount_dir(&spec.logs_path).await?;
    for mount in &spec.extra_mounts {
        if mount.read_only {
            ensure_bind_mount_file(&mount.source).await?;
        } else {
            ensure_bind_mount_dir(&mount.source).await?;
        }
    }
    Ok(())
}

async fn ensure_bind_mount_dir(path: &std::path::Path) -> Result<(), DockerError> {
    tokio::fs::create_dir_all(path)
        .await
        .map_err(|source| DockerError::MountSourceIo {
            path: path.display().to_string(),
            source,
        })?;
    let metadata =
        tokio::fs::symlink_metadata(path)
            .await
            .map_err(|source| DockerError::MountSourceIo {
                path: path.display().to_string(),
                source,
            })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DockerError::InvalidMountSource {
            path: path.display().to_string(),
            reason: "expected a real directory".to_string(),
        });
    }
    Ok(())
}

async fn ensure_bind_mount_file(path: &std::path::Path) -> Result<(), DockerError> {
    let metadata =
        tokio::fs::symlink_metadata(path)
            .await
            .map_err(|source| DockerError::MountSourceIo {
                path: path.display().to_string(),
                source,
            })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DockerError::InvalidMountSource {
            path: path.display().to_string(),
            reason: "expected a real file".to_string(),
        });
    }
    Ok(())
}

fn container_file_parts(container_path: &str) -> Result<(String, String), DockerError> {
    let path = Path::new(container_path);
    let valid = path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
    let parent = path.parent().and_then(Path::to_str);
    let file_name = path.file_name().and_then(|value| value.to_str());
    match (valid, parent, file_name) {
        (true, Some(parent), Some(file_name)) if !file_name.is_empty() => {
            Ok((parent.to_string(), file_name.to_string()))
        }
        _ => Err(DockerError::InvalidContainerTransferPath {
            path: container_path.to_string(),
        }),
    }
}

fn numeric_container_user(user: &str) -> Option<(u64, u64)> {
    let (uid, gid) = user.trim().split_once(':').unwrap_or((user.trim(), ""));
    let uid = uid.parse::<u64>().ok()?;
    let gid = if gid.is_empty() {
        uid
    } else {
        gid.parse::<u64>().ok()?
    };
    Some((uid, gid))
}

fn transfer_tar_header(
    file_name: &str,
    size: u64,
    uid: u64,
    gid: u64,
) -> Result<Bytes, DockerError> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o600);
    header.set_uid(uid);
    header.set_gid(gid);
    header.set_mtime(0);
    header.set_size(size);
    header
        .set_path(file_name)
        .map_err(|source| DockerError::FileTransferIo {
            path: file_name.to_string(),
            source,
        })?;
    header.set_cksum();
    Ok(Bytes::copy_from_slice(header.as_bytes()))
}

fn tar_padding(size: u64) -> usize {
    ((512 - (size % 512)) % 512) as usize
}

fn stream_with_deadline<S>(
    source: S,
    deadline: tokio::time::Instant,
) -> impl Stream<Item = Result<Bytes, IoError>>
where
    S: Stream<Item = Result<Bytes, IoError>> + Unpin,
{
    stream::unfold((source, false), move |(mut source, finished)| async move {
        if finished {
            return None;
        }
        match tokio::time::timeout_at(deadline, source.next()).await {
            Ok(Some(Ok(bytes))) => Some((Ok(bytes), (source, false))),
            Ok(Some(Err(error))) => Some((Err(error), (source, true))),
            Ok(None) => None,
            Err(_) => Some((
                Err(IoError::new(
                    ErrorKind::TimedOut,
                    "container file transfer exceeded time limit",
                )),
                (source, true),
            )),
        }
    })
}

#[cfg(test)]
fn extract_single_regular_file<R: Read>(
    reader: R,
    expected_file_name: &str,
    host_path: &Path,
) -> Result<(), IoError> {
    extract_single_regular_file_with_limit(
        reader,
        expected_file_name,
        host_path,
        MAX_CONTAINER_TRANSFER_BYTES,
    )
}

#[cfg(test)]
fn extract_single_regular_file_with_limit<R: Read>(
    reader: R,
    expected_file_name: &str,
    host_path: &Path,
    max_bytes: u64,
) -> Result<(), IoError> {
    extract_single_regular_file_with_constraints(
        reader,
        expected_file_name,
        host_path,
        max_bytes,
        Instant::now() + FILE_TRANSFER_TIMEOUT,
    )
}

fn extract_single_regular_file_with_constraints<R: Read>(
    reader: R,
    expected_file_name: &str,
    host_path: &Path,
    max_bytes: u64,
    deadline: Instant,
) -> Result<(), IoError> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let parent = host_path
        .parent()
        .ok_or_else(|| IoError::new(ErrorKind::InvalidInput, "download target has no parent"))?;
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(IoError::new(
            ErrorKind::InvalidInput,
            "download target parent must be a real directory",
        ));
    }

    let mut created_path = false;
    let result = (|| {
        let mut archive = tar::Archive::new(reader);
        let mut extracted = false;
        for entry in archive.entries()? {
            let mut entry = entry?;
            if !entry.header().entry_type().is_file() {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "container download contained a non-file entry",
                ));
            }
            let entry_path = entry.path()?;
            let safe_path = entry_path
                .components()
                .all(|component| matches!(component, Component::CurDir | Component::Normal(_)));
            if !safe_path
                || entry_path.file_name().and_then(|value| value.to_str())
                    != Some(expected_file_name)
                || extracted
            {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    "container download contained an unexpected archive path",
                ));
            }

            let expected_size = entry.header().size()?;
            if expected_size > max_bytes {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    format!("container download exceeds the configured {max_bytes}-byte limit"),
                ));
            }
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut output = options.open(host_path)?;
            created_path = true;
            let copied = copy_download_entry(&mut entry, &mut output, max_bytes, deadline)?;
            if copied != expected_size {
                return Err(IoError::new(
                    ErrorKind::UnexpectedEof,
                    "container download ended before the declared file size",
                ));
            }
            ensure_file_transfer_deadline(deadline)?;
            output.flush()?;
            output.sync_all()?;
            ensure_file_transfer_deadline(deadline)?;
            extracted = true;
        }
        if !extracted {
            return Err(IoError::new(
                ErrorKind::NotFound,
                "container download did not contain the requested file",
            ));
        }
        Ok(())
    })();

    if result.is_err() && created_path {
        let _ = std::fs::remove_file(host_path);
    }
    result
}

fn copy_download_entry<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    max_bytes: u64,
    deadline: Instant,
) -> Result<u64, IoError> {
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        ensure_file_transfer_deadline(deadline)?;
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(copied);
        }
        copied = copied.checked_add(read as u64).ok_or_else(|| {
            IoError::new(ErrorKind::InvalidData, "container download size overflow")
        })?;
        if copied > max_bytes {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!("container download exceeds the configured {max_bytes}-byte limit"),
            ));
        }
        writer.write_all(&buffer[..read])?;
    }
}

fn ensure_file_transfer_deadline(deadline: Instant) -> Result<(), IoError> {
    if Instant::now() >= deadline {
        return Err(IoError::new(
            ErrorKind::TimedOut,
            "container file transfer exceeded time limit",
        ));
    }
    Ok(())
}

#[derive(Default)]
struct CappedExecOutput {
    bytes: VecDeque<u8>,
    truncated: bool,
}

impl CappedExecOutput {
    fn append(&mut self, chunk: &[u8]) {
        if chunk.len() >= MAX_EXEC_OUTPUT_BYTES_PER_CHANNEL {
            let discarded_output = self.truncated
                || !self.bytes.is_empty()
                || chunk.len() > MAX_EXEC_OUTPUT_BYTES_PER_CHANNEL;
            self.bytes.clear();
            self.bytes.extend(
                chunk[chunk.len() - MAX_EXEC_OUTPUT_BYTES_PER_CHANNEL..]
                    .iter()
                    .copied(),
            );
            self.truncated = discarded_output;
            return;
        }

        let overflow = self
            .bytes
            .len()
            .saturating_add(chunk.len())
            .saturating_sub(MAX_EXEC_OUTPUT_BYTES_PER_CHANNEL);
        if overflow > 0 {
            self.bytes.drain(..overflow);
            self.truncated = true;
        }
        self.bytes.extend(chunk.iter().copied());
    }

    fn into_string(self) -> String {
        let bytes: Vec<u8> = self.bytes.into_iter().collect();
        let retained = String::from_utf8_lossy(&bytes);
        if self.truncated {
            format!("{EXEC_OUTPUT_TRUNCATION_MARKER}{retained}")
        } else {
            retained.into_owned()
        }
    }
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

fn exec_recovery_error(
    container: &str,
    operation: &str,
    reason: impl std::fmt::Display,
) -> DockerError {
    DockerError::ExecRecoveryFailed {
        container: container.to_string(),
        operation: operation.to_string(),
        reason: reason.to_string(),
    }
}

fn verify_managed_instance_labels(
    labels: &HashMap<String, String>,
    container: &str,
    protocol: Protocol,
    instance_id: &str,
) -> Result<(), DockerError> {
    let is_expected = labels.get(MANAGED_LABEL).map(String::as_str) == Some("true")
        && labels.get(INSTANCE_LABEL).map(String::as_str) == Some(instance_id)
        && labels.get(PROTOCOL_LABEL).map(String::as_str) == Some(protocol.as_str());
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
        "container {instance_id} was not ready before timeout (status={status}, health={health:?})"
    )]
    ContainerNotReady {
        instance_id: String,
        status: String,
        health: Option<String>,
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
            })
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
