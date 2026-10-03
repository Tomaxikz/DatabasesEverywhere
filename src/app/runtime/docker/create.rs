use super::*;

impl DockerRuntime {
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
            (
                container_config::LOG_POLICY_LABEL.to_string(),
                container_config::LOG_POLICY_VERSION.to_string(),
            ),
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
            restart_policy: Some(startup::no_restarts()),
            log_config: Some(container_config::log_config(self.engine)),
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
            cmd: (!spec.command.is_empty()).then(|| spec.command.clone()),
            labels: Some(labels),
            stop_timeout: Some(CONTAINER_STOP_TIMEOUT_SECONDS),
            host_config: Some(host_config),
            exposed_ports: None,
            // Do not inherit image healthchecks. DBE runs a bounded readiness
            // query during startup and then follows container lifecycle events.
            healthcheck: Some(disabled_healthcheck()),
            ..Default::default()
        })
    }

    pub(super) fn rootless_podman_userns_mode(&self, protocol: Protocol) -> Option<&'static str> {
        if !self.uses_rootless_podman() {
            return None;
        }

        Some(protocol.engine().rootless_podman_identity().1)
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

    pub(super) async fn create_inner(
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

    pub(super) async fn apply_socket_bridge_wrapper(
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
        self.pull_image_inner(image, None).await
    }

    pub async fn pull_image_with_progress(
        &self,
        image: &str,
        progress: &(dyn Fn(DockerImagePullProgress) + Send + Sync),
    ) -> Result<CommandOutput, DockerError> {
        self.pull_image_inner(image, Some(progress)).await
    }

    pub(super) async fn pull_image_inner(
        &self,
        image: &str,
        progress: Option<&(dyn Fn(DockerImagePullProgress) + Send + Sync)>,
    ) -> Result<CommandOutput, DockerError> {
        self.ensure_image_with_progress(image, progress).await?;
        Ok(CommandOutput {
            stdout: image.to_string(),
            stderr: String::new(),
        })
    }

    pub(super) async fn ensure_image_with_progress(
        &self,
        image: &str,
        progress: Option<&(dyn Fn(DockerImagePullProgress) + Send + Sync)>,
    ) -> Result<(), DockerError> {
        match self.docker.inspect_image(image).await {
            Ok(_) => {
                tracing::debug!(image, "docker image already present");
                report_pull_progress(progress, image, "image already present");
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
            let Some(status) = info.status else {
                continue;
            };
            let detail = info.progress_detail.as_ref();
            let current = detail
                .and_then(|detail| detail.current)
                .and_then(|value| u64::try_from(value).ok());
            let total = detail
                .and_then(|detail| detail.total)
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
            let layer = info.id.as_deref().unwrap_or_default();
            let key = format!("{layer}:{status}:{}", current.unwrap_or_default());
            if logged.insert(key) {
                tracing::info!(
                    image,
                    layer,
                    status,
                    current = current.unwrap_or_default(),
                    total = total.unwrap_or_default(),
                    "docker image pull progress"
                );
            }
        }

        self.docker.inspect_image(image).await?;
        tracing::info!(image, "docker image pull complete");
        report_pull_progress(progress, image, "image pull complete");
        Ok(())
    }
}
