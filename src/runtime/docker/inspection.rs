use std::time::Duration;

use bollard::{
    container::LogOutput,
    query_parameters::{LogsOptionsBuilder, StatsOptionsBuilder},
};
use futures::{StreamExt, TryStreamExt};
use tokio::{
    sync::mpsc,
    time::{Instant, sleep},
};

use crate::{
    runtime::docker::{
        CommandOutput, DockerContainerStatus, DockerError, DockerInstanceInspection, DockerRuntime,
        container_config::serialize_stats,
    },
    shared::protocol::Protocol,
};

impl DockerRuntime {
    pub async fn inspect_instance(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<DockerInstanceInspection, DockerError> {
        let name = self.container_name(protocol, instance_id)?;
        let response = self.docker.inspect_container(&name, None).await?;
        let state = response.state;
        let health = state
            .as_ref()
            .and_then(|state| state.health.as_ref())
            .and_then(|health| health.status.as_ref())
            .map(|status| status.as_ref().to_string());
        let status = state
            .and_then(|state| state.status)
            .map(|status| match (status.as_ref(), health.as_deref()) {
                ("running", Some("healthy" | "none")) | ("running", None) => {
                    DockerContainerStatus::Running
                }
                ("running", Some("starting")) => DockerContainerStatus::Starting,
                ("running", Some("unhealthy")) => DockerContainerStatus::Failed,
                ("created" | "restarting", _) => DockerContainerStatus::Starting,
                ("paused" | "exited" | "stopping", _) => DockerContainerStatus::Stopped,
                _ => DockerContainerStatus::Failed,
            })
            .unwrap_or(DockerContainerStatus::Failed);
        let network_ip = response
            .network_settings
            .and_then(|settings| settings.networks)
            .and_then(|networks| {
                networks
                    .get(&self.network)
                    .and_then(|settings| settings.ip_address.clone())
                    .filter(|address| !address.is_empty())
            });

        Ok(DockerInstanceInspection {
            status,
            network_ip,
            health,
        })
    }

    pub async fn wait_until_ready(
        &self,
        protocol: Protocol,
        instance_id: &str,
        timeout: Duration,
    ) -> Result<DockerInstanceInspection, DockerError> {
        let deadline = Instant::now() + timeout;
        let mut last = self.inspect_instance(protocol, instance_id).await?;
        loop {
            match last.status {
                DockerContainerStatus::Running => return Ok(last),
                DockerContainerStatus::Failed | DockerContainerStatus::Stopped => {
                    return Err(DockerError::ContainerNotReady {
                        instance_id: instance_id.to_string(),
                        status: format!("{:?}", last.status),
                        health: last.health,
                    });
                }
                DockerContainerStatus::Starting => {}
            }

            if Instant::now() >= deadline {
                return Err(DockerError::ContainerNotReady {
                    instance_id: instance_id.to_string(),
                    status: format!("{:?}", last.status),
                    health: last.health,
                });
            }

            sleep(Duration::from_secs(1)).await;
            last = self.inspect_instance(protocol, instance_id).await?;
        }
    }

    pub async fn container_ip(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<String, DockerError> {
        let name = self.container_name(protocol, instance_id)?;
        let response = self.docker.inspect_container(&name, None).await?;
        let networks = response
            .network_settings
            .and_then(|settings| settings.networks)
            .ok_or_else(|| DockerError::MissingNetworkAddress {
                container: name.clone(),
                network: self.network.clone(),
            })?;
        let address = networks
            .get(&self.network)
            .and_then(|settings| settings.ip_address.as_ref())
            .filter(|address| !address.is_empty())
            .ok_or_else(|| DockerError::MissingNetworkAddress {
                container: name,
                network: self.network.clone(),
            })?;

        Ok(address.clone())
    }

    pub async fn configured_container_user(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<Option<String>, DockerError> {
        let name = self.container_name(protocol, instance_id)?;
        let response = self.docker.inspect_container(&name, None).await?;
        Ok(response
            .config
            .and_then(|config| config.user)
            .map(|user| user.trim().to_string())
            .filter(|user| !user.is_empty()))
    }

    pub async fn container_image(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<Option<String>, DockerError> {
        let name = self.container_name(protocol, instance_id)?;
        let response = self.docker.inspect_container(&name, None).await?;
        Ok(response
            .config
            .and_then(|config| config.image)
            .map(|image| image.trim().to_string())
            .filter(|image| !image.is_empty()))
    }

    pub async fn logs(
        &self,
        protocol: Protocol,
        instance_id: &str,
        tail: Option<usize>,
    ) -> Result<CommandOutput, DockerError> {
        let name = self.container_name(protocol, instance_id)?;
        let tail = tail.unwrap_or(200).clamp(1, 2_000).to_string();
        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut stream = self.docker.logs(
            &name,
            Some(
                LogsOptionsBuilder::default()
                    .stdout(true)
                    .stderr(true)
                    .tail(&tail)
                    .build(),
            ),
        );

        while let Some(chunk) = stream.try_next().await? {
            match chunk {
                LogOutput::StdErr { message } => {
                    stderr.push_str(&String::from_utf8_lossy(&message));
                }
                LogOutput::StdOut { message } | LogOutput::Console { message } => {
                    stdout.push_str(&String::from_utf8_lossy(&message));
                }
                LogOutput::StdIn { .. } => {}
            }
        }

        Ok(CommandOutput { stdout, stderr })
    }

    pub fn follow_logs(
        &self,
        protocol: Protocol,
        instance_id: &str,
        tail: Option<usize>,
    ) -> Result<mpsc::Receiver<Result<CommandOutput, DockerError>>, DockerError> {
        let name = self.container_name(protocol, instance_id)?;
        let docker = self.docker.clone();
        let tail = tail.unwrap_or(100).clamp(1, 2_000).to_string();
        let (tx, rx) = mpsc::channel(128);

        tokio::spawn(async move {
            let mut stream = docker.logs(
                &name,
                Some(
                    LogsOptionsBuilder::default()
                        .stdout(true)
                        .stderr(true)
                        .tail(&tail)
                        .follow(true)
                        .build(),
                ),
            );

            while let Some(chunk) = stream.next().await {
                let output = match chunk {
                    Ok(LogOutput::StdErr { message }) => Ok(CommandOutput {
                        stdout: String::new(),
                        stderr: String::from_utf8_lossy(&message).to_string(),
                    }),
                    Ok(LogOutput::StdOut { message } | LogOutput::Console { message }) => {
                        Ok(CommandOutput {
                            stdout: String::from_utf8_lossy(&message).to_string(),
                            stderr: String::new(),
                        })
                    }
                    Ok(LogOutput::StdIn { .. }) => continue,
                    Err(error) => Err(DockerError::from(error)),
                };

                if tx.send(output).await.is_err() {
                    break;
                }
            }
        });

        Ok(rx)
    }

    pub async fn stats(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<CommandOutput, DockerError> {
        let name = self.container_name(protocol, instance_id)?;
        let mut stream = self.docker.stats(
            &name,
            Some(
                StatsOptionsBuilder::default()
                    .stream(false)
                    .one_shot(true)
                    .build(),
            ),
        );
        let stats = stream.next().await.ok_or(DockerError::EmptyStatsStream)??;
        Ok(CommandOutput {
            stdout: serialize_stats(&stats)?,
            stderr: String::new(),
        })
    }
}
