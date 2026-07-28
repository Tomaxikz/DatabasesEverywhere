use std::time::Duration;

use bollard::{
    container::LogOutput,
    models::ContainerStatsResponse,
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
        container_config::startup_readiness_script,
    },
    shared::protocol::Protocol,
};

const STARTUP_READINESS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

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
            .map(|status| match status.as_ref() {
                "running" => DockerContainerStatus::Running,
                "created" | "restarting" => DockerContainerStatus::Starting,
                "paused" | "exited" | "stopping" => DockerContainerStatus::Stopped,
                _ => DockerContainerStatus::Failed,
            })
            .unwrap_or(DockerContainerStatus::Failed);
        let network_mode = response
            .host_config
            .and_then(|host_config| host_config.network_mode)
            .map(|mode| mode.trim().to_ascii_lowercase())
            .filter(|mode| !mode.is_empty());
        let image = response
            .config
            .and_then(|config| config.image)
            .map(|image| image.trim().to_string())
            .filter(|image| !image.is_empty());

        Ok(DockerInstanceInspection {
            status,
            network_mode,
            health,
            image,
        })
    }

    pub async fn wait_until_ready(
        &self,
        protocol: Protocol,
        instance_id: &str,
        readiness_timeout: Duration,
    ) -> Result<DockerInstanceInspection, DockerError> {
        let deadline = Instant::now() + readiness_timeout;
        let mut last = self.inspect_instance(protocol, instance_id).await?;
        let mut last_readiness_error = None;
        loop {
            match last.status {
                DockerContainerStatus::Running => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(DockerError::ContainerNotReady {
                            instance_id: instance_id.to_string(),
                            status: format!("{:?}", last.status),
                            health: last.health,
                            readiness_error: last_readiness_error,
                        });
                    }
                    let attempt_timeout = STARTUP_READINESS_ATTEMPT_TIMEOUT.min(remaining);
                    match tokio::time::timeout(
                        attempt_timeout,
                        self.exec_readiness_probe(
                            protocol,
                            instance_id,
                            startup_readiness_script(protocol),
                        ),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {
                            tracing::debug!(
                                instance_id,
                                %protocol,
                                "database startup readiness confirmed"
                            );
                            return Ok(last);
                        }
                        Ok(Err(error)) => {
                            last_readiness_error = Some(error.to_string());
                        }
                        Err(_) => {
                            last_readiness_error = Some(format!(
                                "readiness attempt exceeded {} seconds",
                                attempt_timeout.as_secs()
                            ));
                        }
                    }
                }
                DockerContainerStatus::Failed | DockerContainerStatus::Stopped => {
                    return Err(DockerError::ContainerNotReady {
                        instance_id: instance_id.to_string(),
                        status: format!("{:?}", last.status),
                        health: last.health,
                        readiness_error: last_readiness_error,
                    });
                }
                DockerContainerStatus::Starting => {}
            }

            if Instant::now() >= deadline {
                return Err(DockerError::ContainerNotReady {
                    instance_id: instance_id.to_string(),
                    status: format!("{:?}", last.status),
                    health: last.health,
                    readiness_error: last_readiness_error,
                });
            }

            sleep(Duration::from_secs(1)).await;
            last = self.inspect_instance(protocol, instance_id).await?;
        }
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
    ) -> Result<ContainerStatsResponse, DockerError> {
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
        Ok(stream.next().await.ok_or(DockerError::EmptyStatsStream)??)
    }
}
