use super::*;

impl DockerRuntime {
    pub async fn start(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<CommandOutput, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        self.disable_restarts(protocol, instance_id).await?;
        let already_running = self
            .docker
            .inspect_container(&name, None)
            .await?
            .state
            .is_some_and(|state| state.running == Some(true));
        if already_running {
            return Ok(CommandOutput::empty());
        }
        self.note_start(instance_id, false).await?;
        self.docker
            .start_container(&name, None::<StartContainerOptions>)
            .await?;
        self.enforce_cpu_burst_policy(protocol, instance_id).await;
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
        self.disable_restarts(protocol, instance_id).await?;
        self.note_start(instance_id, false).await?;
        self.docker.restart_container(&name, None).await?;
        self.enforce_cpu_burst_policy(protocol, instance_id).await;
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
            .remove_container(&name, Some(force_remove_options()))
            .await?;
        Ok(CommandOutput::empty())
    }

    pub async fn update_limits(
        &self,
        protocol: Protocol,
        instance_id: &str,
        cpu_cores: f64,
        memory_mib: u64,
    ) -> Result<CommandOutput, DockerError> {
        validate_runtime_limits(cpu_cores, memory_mib)?;
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let docker_body = match self.engine {
            DaemonEngine::Docker => Some(Self::update_limits_body(cpu_cores, memory_mib)?),
            DaemonEngine::Podman => None,
        };
        self.clear_cpu_burst(protocol, instance_id).await;
        let update_result: Result<(), DockerError> = match docker_body {
            Some(body) => self
                .docker
                .update_container(&name, body)
                .await
                .map(|_| ())
                .map_err(Into::into),
            None => {
                podman_api::update_limits(&self.socket_path, &name, cpu_cores, memory_mib).await
            }
        };
        self.enforce_cpu_burst_policy(protocol, instance_id).await;
        update_result?;
        Ok(CommandOutput::empty())
    }

    pub async fn remove_managed_containers(&self) -> Result<usize, DockerError> {
        let mut removed = 0;
        for container in self.owned_managed_containers(true).await? {
            let Some(id) = container.id else {
                continue;
            };
            self.docker
                .remove_container(&id, Some(force_remove_options()))
                .await?;
            removed += 1;
        }
        Ok(removed)
    }

    pub async fn active_managed_container_count(&self) -> Result<usize, DockerError> {
        Ok(self.owned_managed_containers(false).await?.len())
    }

    pub(super) async fn owned_managed_containers(
        &self,
        all: bool,
    ) -> Result<Vec<ContainerSummary>, DockerError> {
        let node_id = self
            .node_id
            .as_deref()
            .ok_or(DockerError::RuntimeNodeIdUnavailable)?;
        let filters = managed_container_filters(node_id);
        let containers = self
            .docker
            .list_containers(Some(
                ListContainersOptionsBuilder::default()
                    .all(all)
                    .filters(&filters)
                    .build(),
            ))
            .await?;
        Ok(containers
            .into_iter()
            .filter(|container| is_owned_managed_container(container.labels.as_ref(), node_id))
            .collect())
    }
}
