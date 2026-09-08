use std::time::Duration;

use bollard::{
    container::LogOutput,
    errors::Error as BollardError,
    models::{ContainerInspectResponse, ContainerStatsResponse},
    query_parameters::{LogsOptionsBuilder, StatsOptionsBuilder},
};
use futures::{StreamExt, TryStreamExt};
use secrecy::SecretString;
use tokio::time::{Instant, sleep};

use crate::{
    constants::docker::PROJECT_LABEL,
    runtime::docker::{
        CommandOutput, DockerContainerStatus, DockerError, DockerInstanceInspection, DockerRuntime,
        ManagedContainerCompatibilityIdentity, ManagedContainerIdentity, ManagedStatsSampler,
        startup_readiness_script,
    },
    shared::protocol::Protocol,
};

const STARTUP_READINESS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

impl DockerRuntime {
    pub(crate) async fn log_policy_is_current(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<bool, DockerError> {
        let id = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let inspection = self.docker.inspect_container(&id, None).await?;
        Ok(log_policy_matches(&inspection, self.engine()))
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
        if self
            .verified_managed_container_id(protocol, instance_id)
            .await?
            .is_none()
        {
            return Ok(None);
        }
        Ok(Some(container))
    }

    pub(crate) async fn verified_managed_container_id(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<Option<String>, DockerError> {
        let Some(response) = self
            .inspect_verified_container(protocol, instance_id)
            .await?
        else {
            return Ok(None);
        };
        let container = self.container_name(protocol, instance_id)?;
        let id = container_id(&response, &container)?;
        Ok(Some(id))
    }

    pub(super) async fn inspect_verified_container(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<Option<ContainerInspectResponse>, DockerError> {
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
            .as_ref()
            .and_then(|config| config.labels.as_ref())
            .cloned()
            .unwrap_or_default();
        super::verify_managed_instance_labels(
            &labels,
            &container,
            protocol,
            instance_id,
            self.node_id.as_deref(),
        )?;
        Ok(Some(response))
    }

    /// Returns a hardening-safe runtime identity. Container IDs survive a
    /// stop/start, so the start timestamp is included to distinguish a fresh
    /// database process from a daemon-only restart.
    pub(crate) async fn verified_container_identity(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<Option<ManagedContainerIdentity>, DockerError> {
        let Some(response) = self
            .inspect_verified_container(protocol, instance_id)
            .await?
        else {
            return Ok(None);
        };
        let container = self.container_name(protocol, instance_id)?;
        let id = container_id(&response, &container)?;
        let started_at = response
            .state
            .and_then(|state| state.started_at)
            .filter(|started_at| !started_at.trim().is_empty())
            .ok_or_else(|| DockerError::ManagedContainerStartedAtUnavailable {
                container: container.clone(),
            })?;
        Ok(Some(ManagedContainerIdentity { id, started_at }))
    }

    /// Reads both immutable IDs from one verified inspection. Callers re-read
    /// this after probing to reject an external replacement during the exec.
    pub(crate) async fn verified_compatibility_identity(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<Option<ManagedContainerCompatibilityIdentity>, DockerError> {
        let Some(response) = self
            .inspect_verified_container(protocol, instance_id)
            .await?
        else {
            return Ok(None);
        };
        let container = self.container_name(protocol, instance_id)?;
        let id = container_id(&response, &container)?;
        let image_id = response
            .image
            .filter(|image| !image.trim().is_empty())
            .ok_or(DockerError::ManagedContainerImageIdUnavailable { container })?;
        Ok(Some(ManagedContainerCompatibilityIdentity { id, image_id }))
    }

    pub(super) async fn required_managed_container_id(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<String, DockerError> {
        self.verified_managed_container_id(protocol, instance_id)
            .await?
            .ok_or_else(|| DockerError::ManagedContainerNotFound {
                instance_id: instance_id.to_string(),
                protocol: protocol.as_str().to_string(),
            })
    }

    pub async fn inspect_instance(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<DockerInstanceInspection, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
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
                "created" => DockerContainerStatus::Created,
                "restarting" => DockerContainerStatus::Starting,
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
                        return Err(not_ready_error(instance_id, last, last_readiness_error));
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
                    return Err(not_ready_error(instance_id, last, last_readiness_error));
                }
                DockerContainerStatus::Created | DockerContainerStatus::Starting => {}
            }

            if Instant::now() >= deadline {
                return Err(not_ready_error(instance_id, last, last_readiness_error));
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
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let response = self.docker.inspect_container(&name, None).await?;
        Ok(response
            .config
            .and_then(|config| config.user)
            .map(|user| user.trim().to_string())
            .filter(|user| !user.is_empty()))
    }

    pub(crate) async fn postgres_bootstrap_credentials(
        &self,
        instance_id: &str,
    ) -> Result<(String, SecretString), DockerError> {
        let name = self
            .required_managed_container_id(Protocol::Postgres, instance_id)
            .await?;
        let response = self.docker.inspect_container(&name, None).await?;
        let environment = response
            .config
            .and_then(|config| config.env)
            .unwrap_or_default();
        let username = unique_environment_value(&environment, "POSTGRES_USER", instance_id)?;
        let password = unique_environment_value(&environment, "POSTGRES_PASSWORD", instance_id)?;
        if username.trim().is_empty() || password.is_empty() {
            return Err(DockerError::PostgresAuthHardeningFailed {
                instance_id: instance_id.to_string(),
                reason: "the managed container has an empty PostgreSQL bootstrap credential"
                    .to_string(),
            });
        }
        Ok((username, SecretString::from(password)))
    }

    pub(crate) async fn postgres_legacy_credentials(
        &self,
        instance_id: &str,
    ) -> Result<Option<(String, SecretString)>, DockerError> {
        self.legacy_tenant_credentials(
            Protocol::Postgres,
            instance_id,
            &[("DBE_POSTGRES_USER", "DBE_POSTGRES_PASSWORD")],
        )
        .await
    }

    pub(crate) async fn mysql_legacy_tenant_credentials(
        &self,
        instance_id: &str,
    ) -> Result<Option<(String, SecretString)>, DockerError> {
        self.legacy_tenant_credentials(
            Protocol::Mysql,
            instance_id,
            &[
                ("DBE_MYSQL_USER", "DBE_MYSQL_PASSWORD"),
                ("MYSQL_USER", "MYSQL_PASSWORD"),
            ],
        )
        .await
    }

    async fn legacy_tenant_credentials(
        &self,
        protocol: Protocol,
        instance_id: &str,
        key_pairs: &[(&str, &str)],
    ) -> Result<Option<(String, SecretString)>, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let response = self.docker.inspect_container(&name, None).await?;
        let environment = response
            .config
            .and_then(|config| config.env)
            .unwrap_or_default();
        let mut credential = None;
        for (username_key, password_key) in key_pairs {
            let username = unique_optional_env(&environment, username_key).map_err(|reason| {
                DockerError::InvalidLegacyCredentialEnvironment {
                    instance_id: instance_id.to_string(),
                    protocol: protocol.as_str().to_string(),
                    reason,
                }
            })?;
            let password = unique_optional_env(&environment, password_key).map_err(|reason| {
                DockerError::InvalidLegacyCredentialEnvironment {
                    instance_id: instance_id.to_string(),
                    protocol: protocol.as_str().to_string(),
                    reason,
                }
            })?;
            match (username, password) {
                (None, None) => {}
                (Some(username), Some(password))
                    if !username.trim().is_empty() && !password.is_empty() =>
                {
                    if credential.is_some() {
                        return Err(DockerError::InvalidLegacyCredentialEnvironment {
                            instance_id: instance_id.to_string(),
                            protocol: protocol.as_str().to_string(),
                            reason: "multiple tenant credential pairs are present".to_string(),
                        });
                    }
                    credential = Some((username, SecretString::from(password)));
                }
                _ => {
                    return Err(DockerError::InvalidLegacyCredentialEnvironment {
                        instance_id: instance_id.to_string(),
                        protocol: protocol.as_str().to_string(),
                        reason: format!(
                            "{username_key} and {password_key} must both be present and non-empty"
                        ),
                    });
                }
            }
        }
        Ok(credential)
    }

    pub async fn container_image(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<Option<String>, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let response = self.docker.inspect_container(&name, None).await?;
        Ok(response
            .config
            .and_then(|config| config.image)
            .map(|image| image.trim().to_string())
            .filter(|image| !image.is_empty()))
    }

    /// Return the immutable image ID backing a managed container. Internal
    /// safety migrations use this rather than a mutable tag so recreation
    /// cannot silently switch database versions between stop and create.
    pub async fn container_immutable_image_id(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<Option<String>, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let response = self.docker.inspect_container(&name, None).await?;
        Ok(response
            .image
            .map(|image| image.trim().to_string())
            .filter(|image| !image.is_empty()))
    }

    pub async fn container_bind_source(
        &self,
        protocol: Protocol,
        instance_id: &str,
        destination: &str,
    ) -> Result<Option<std::path::PathBuf>, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let response = self.docker.inspect_container(&name, None).await?;
        Ok(response
            .mounts
            .unwrap_or_default()
            .into_iter()
            .find(|mount| mount.destination.as_deref() == Some(destination))
            .and_then(|mount| mount.source.map(std::path::PathBuf::from)))
    }

    /// Fail closed when an existing managed container is not actually bound
    /// to the data source selected by the effective disk-limit mode. Merely
    /// preparing a quota mount cannot protect a container that still uses the
    /// old raw path (or vice versa).
    pub async fn verify_data_bind(
        &self,
        protocol: Protocol,
        instance_id: &str,
        expected_source: &std::path::Path,
    ) -> Result<(), DockerError> {
        let actual_source = self
            .container_bind_source(protocol, instance_id, protocol.container_data_target())
            .await?;
        if actual_source.as_deref() == Some(expected_source) {
            return Ok(());
        }
        Err(DockerError::DiskBindSourceMismatch {
            instance_id: instance_id.to_string(),
            destination: protocol.container_data_target().to_string(),
            expected_source: expected_source.display().to_string(),
            actual_source: actual_source
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<missing>".to_string()),
        })
    }

    /// Returns the original image reference only when it still resolves to the
    /// exact image backing the managed container. This prevents a non-upgrade
    /// recreation from silently pulling or switching to a retagged image.
    pub async fn container_recreation_image(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<Option<String>, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let response = self.docker.inspect_container(&name, None).await?;
        let Some(reference) = response
            .config
            .and_then(|config| config.image)
            .map(|image| image.trim().to_string())
            .filter(|image| !image.is_empty())
        else {
            return Ok(None);
        };
        let Some(container_image_id) = response
            .image
            .map(|image| image.trim().to_string())
            .filter(|image| !image.is_empty())
        else {
            return Ok(None);
        };
        let resolved = match self.docker.inspect_image(&reference).await {
            Ok(image) => image,
            Err(BollardError::DockerResponseServerError {
                status_code: 404, ..
            }) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let resolves_to_current_image = resolved
            .id
            .as_deref()
            .is_some_and(|resolved_id| resolved_id == container_image_id);
        Ok(resolves_to_current_image.then_some(reference))
    }

    /// Reads one configured environment value without serializing or logging
    /// the rest of the container configuration.
    pub async fn container_environment_value(
        &self,
        protocol: Protocol,
        instance_id: &str,
        key: &str,
    ) -> Result<Option<SecretString>, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let response = self.docker.inspect_container(&name, None).await?;
        Ok(response
            .config
            .and_then(|config| config.env)
            .as_deref()
            .and_then(|environment| environment_value(environment, key))
            .map(SecretString::from))
    }

    /// Preserves the optional project ownership label across a same-image
    /// container recreation.
    pub async fn container_project_id(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<Option<String>, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let response = self.docker.inspect_container(&name, None).await?;
        Ok(response
            .config
            .and_then(|config| config.labels)
            .and_then(|labels| labels.get(PROJECT_LABEL).cloned())
            .map(|project_id| project_id.trim().to_string())
            .filter(|project_id| !project_id.is_empty()))
    }

    pub async fn logs(
        &self,
        protocol: Protocol,
        instance_id: &str,
        tail: Option<usize>,
    ) -> Result<CommandOutput, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let tail = tail.unwrap_or(200).clamp(1, 2_000).to_string();
        let mut stdout = super::CappedExecOutput::default();
        let mut stderr = super::CappedExecOutput::default();
        let mut stdout_redactor = crate::shared::logs::LogRedactor::default();
        let mut stderr_redactor = crate::shared::logs::LogRedactor::default();
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

        tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(chunk) = stream.try_next().await? {
                match chunk {
                    LogOutput::StdErr { message } => {
                        stderr.append(
                            stderr_redactor
                                .push(&String::from_utf8_lossy(&message))
                                .as_bytes(),
                        );
                    }
                    LogOutput::StdOut { message } | LogOutput::Console { message } => {
                        stdout.append(
                            stdout_redactor
                                .push(&String::from_utf8_lossy(&message))
                                .as_bytes(),
                        );
                    }
                    LogOutput::StdIn { .. } => {}
                }
                if stdout_redactor.failed || stderr_redactor.failed {
                    break;
                }
            }
            Ok::<_, DockerError>(())
        })
        .await
        .map_err(|_| DockerError::LogsTimedOut)??;
        stdout.append(stdout_redactor.finish().as_bytes());
        stderr.append(stderr_redactor.finish().as_bytes());
        Ok(CommandOutput {
            stdout: stdout.into_string(),
            stderr: stderr.into_string(),
        })
    }

    pub async fn follow_logs(
        &self,
        protocol: Protocol,
        instance_id: &str,
        tail: Option<usize>,
    ) -> Result<
        impl futures::Stream<Item = Result<CommandOutput, DockerError>> + Send + Unpin + 'static,
        DockerError,
    > {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        let tail = tail.unwrap_or(100).clamp(1, 2_000).to_string();
        // Poll Docker directly: dropping the WebSocket drops this stream too.
        // No detached producer or per-viewer queue retains console output.
        Ok(self
            .docker
            .logs(
                &name,
                Some(
                    LogsOptionsBuilder::default()
                        .stdout(true)
                        .stderr(true)
                        .tail(&tail)
                        .follow(true)
                        .build(),
                ),
            )
            .filter_map(|chunk| {
                futures::future::ready(match chunk {
                    Ok(LogOutput::StdErr { message }) => Some(Ok(CommandOutput {
                        stdout: String::new(),
                        stderr: String::from_utf8_lossy(&message).to_string(),
                    })),
                    Ok(LogOutput::StdOut { message } | LogOutput::Console { message }) => {
                        Some(Ok(CommandOutput {
                            stdout: String::from_utf8_lossy(&message).to_string(),
                            stderr: String::new(),
                        }))
                    }
                    Ok(LogOutput::StdIn { .. }) => None,
                    Err(error) => Some(Err(DockerError::from(error))),
                })
            }))
    }

    pub async fn stats(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<ContainerStatsResponse, DockerError> {
        self.stats_sampler(protocol, instance_id)
            .await?
            .sample()
            .await
    }

    pub(crate) async fn stats_sampler(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<ManagedStatsSampler, DockerError> {
        let container_id = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        Ok(ManagedStatsSampler {
            docker: self.docker.clone(),
            container_id,
        })
    }
}

fn log_policy_matches(
    inspection: &ContainerInspectResponse,
    engine: crate::config::DaemonEngine,
) -> bool {
    let expected = super::container_config::log_config(engine);
    let marked = inspection
        .config
        .as_ref()
        .and_then(|config| config.labels.as_ref())
        .and_then(|labels| labels.get(super::container_config::LOG_POLICY_LABEL))
        .is_some_and(|value| value == super::container_config::LOG_POLICY_VERSION);
    let configured = inspection
        .host_config
        .as_ref()
        .and_then(|host| host.log_config.as_ref());
    // Podman's Docker-compatible inspect omits native LogConfig.Size and
    // reports k8s-file as json-file. Its policy marker is written only by our
    // bounded create path; do not repeatedly recreate a compliant container.
    let matches = match engine {
        crate::config::DaemonEngine::Docker => configured == Some(&expected),
        crate::config::DaemonEngine::Podman => configured.is_some_and(|value| {
            matches!(value.typ.as_deref(), Some("json-file" | "k8s-file"))
                && (value.config.is_none()
                    || value
                        .config
                        .as_ref()
                        .is_some_and(|values| values.is_empty())
                    || value.config == expected.config)
        }),
    };
    marked
        && matches
        && !inspection.mounts.as_ref().is_some_and(|mounts| {
            mounts.iter().any(|mount| {
                matches!(
                    mount.destination.as_deref(),
                    Some("/logs" | "/var/log/clickhouse-server")
                ) && mount.typ.as_deref() == Some("bind")
            })
        })
}

impl ManagedStatsSampler {
    pub(crate) async fn sample(&self) -> Result<ContainerStatsResponse, DockerError> {
        let mut stream = self.docker.stats(
            &self.container_id,
            Some(
                StatsOptionsBuilder::default()
                    .stream(false)
                    // Match wings-rs: take a non-streaming counter snapshot.
                    // Callers calculate CPU from consecutive samples and real
                    // wall-clock time rather than Docker's system CPU counter.
                    .one_shot(true)
                    .build(),
            ),
        );
        Ok(stream.next().await.ok_or(DockerError::EmptyStatsStream)??)
    }
}

fn container_id(
    response: &ContainerInspectResponse,
    container: &str,
) -> Result<String, DockerError> {
    response
        .id
        .as_ref()
        .filter(|id| !id.trim().is_empty())
        .cloned()
        .ok_or_else(|| DockerError::ManagedContainerIdUnavailable {
            container: container.to_string(),
        })
}

fn not_ready_error(
    instance_id: &str,
    inspection: DockerInstanceInspection,
    readiness_error: Option<String>,
) -> DockerError {
    DockerError::ContainerNotReady {
        instance_id: instance_id.to_string(),
        status: format!("{:?}", inspection.status),
        health: inspection.health,
        readiness_error,
    }
}

fn unique_environment_value(
    environment: &[String],
    key: &str,
    instance_id: &str,
) -> Result<String, DockerError> {
    let prefix = format!("{key}=");
    let mut values = environment
        .iter()
        .filter_map(|entry| entry.strip_prefix(&prefix));
    let value = values
        .next()
        .ok_or_else(|| DockerError::PostgresAuthHardeningFailed {
            instance_id: instance_id.to_string(),
            reason: format!("the managed container is missing {key}"),
        })?;
    if values.next().is_some() {
        return Err(DockerError::PostgresAuthHardeningFailed {
            instance_id: instance_id.to_string(),
            reason: format!("the managed container contains duplicate {key} entries"),
        });
    }
    Ok(value.to_string())
}

fn environment_value(environment: &[String], key: &str) -> Option<String> {
    environment.iter().find_map(|entry| {
        let (entry_key, value) = entry.split_once('=')?;
        (entry_key == key).then(|| value.to_string())
    })
}

fn unique_optional_env(environment: &[String], key: &str) -> Result<Option<String>, String> {
    let prefix = format!("{key}=");
    let mut values = environment
        .iter()
        .filter_map(|entry| entry.strip_prefix(&prefix));
    let value = values.next().map(str::to_string);
    if values.next().is_some() {
        return Err(format!("duplicate {key} entries are present"));
    }
    Ok(value)
}

#[cfg(test)]
mod logging_tests {
    use super::*;
    use crate::{
        config::{DaemonConfig, DaemonEngine},
        constants::docker::{INSTANCE_LABEL, MANAGED_LABEL, NODE_LABEL, PROTOCOL_LABEL},
    };

    #[test]
    fn log_policy_upgrade_is_idempotent_and_rejects_unbounded_or_legacy_layouts() {
        for engine in [DaemonEngine::Docker, DaemonEngine::Podman] {
            let mut value = serde_json::json!({
                "Config":{"Labels":{"dbev.console-policy":"1"}},
                "HostConfig":{"LogConfig":super::super::container_config::log_config(engine)},
                "Mounts":[]
            });
            let matches = |value: &serde_json::Value| {
                log_policy_matches(&serde_json::from_value(value.clone()).unwrap(), engine)
            };
            assert!(matches(&value));
            if engine == DaemonEngine::Podman {
                value["HostConfig"]["LogConfig"] =
                    serde_json::json!({"Type":"json-file","Config":null});
                assert!(
                    matches(&value),
                    "native Podman size is omitted from Docker-compatible inspect"
                );
            }
            let valid = value.clone();
            value["Config"]["Labels"] = serde_json::json!({});
            assert!(!matches(&value));
            value = valid.clone();
            value["HostConfig"]["LogConfig"] = serde_json::json!({"Type":"json-file","Config":{}});
            if engine == DaemonEngine::Docker {
                assert!(!matches(&value));
            }
            value = valid.clone();
            value["HostConfig"]["LogConfig"]["Config"] = serde_json::json!({"max-size":"-1"});
            assert!(!matches(&value));
            value = valid;
            value["Mounts"] = serde_json::json!([{"Type":"bind","Destination":"/var/log/clickhouse-server","Source":"/logs/legacy"}]);
            assert!(!matches(&value));
        }
    }

    #[tokio::test]
    async fn history_is_bounded_and_dropping_a_live_reader_closes_the_stream() {
        use axum::body::Body;
        use bytes::Bytes;
        use hyper::{Response, server::conn::http1, service::service_fn};
        use hyper_util::rt::TokioIo;
        use std::{
            convert::Infallible,
            sync::{Arc, Mutex},
        };
        use tokio::{net::UnixListener, sync::oneshot};

        struct StreamDropped(Option<oneshot::Sender<()>>);
        impl Drop for StreamDropped {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _ = sender.send(());
                }
            }
        }
        fn frame(channel: u8, contents: &[u8]) -> Bytes {
            let mut bytes = vec![channel, 0, 0, 0];
            bytes.extend_from_slice(&(contents.len() as u32).to_be_bytes());
            bytes.extend_from_slice(contents);
            Bytes::from(bytes)
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("docker.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let config = DaemonConfig {
            socket_path: path.display().to_string(),
            ..Default::default()
        };
        let runtime = DockerRuntime::new(&config, false)
            .unwrap()
            .with_node_id("test-node");
        let labels = std::collections::HashMap::from([
            (MANAGED_LABEL, "true"),
            (INSTANCE_LABEL, "inst_abc"),
            (PROTOCOL_LABEL, "postgres"),
            (NODE_LABEL, "test-node"),
        ]);
        let inspection =
            serde_json::json!({"Id":"a".repeat(64),"Config":{"Labels":labels}}).to_string();
        let (dropped, finished) = oneshot::channel();
        let dropped = Arc::new(Mutex::new(Some(dropped)));
        let server = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let inspection = inspection.clone();
                let dropped = dropped.clone();
                tokio::spawn(async move {
                    let service =
                        service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                            let inspection = inspection.clone();
                            let dropped = dropped.clone();
                            async move {
                                let body = if request.uri().path().ends_with("/json") {
                                    Body::from(inspection)
                                } else {
                                    assert!(request.uri().path().ends_with("/logs"));
                                    let query = request.uri().query().unwrap();
                                    assert!(query.contains("tail="));
                                    if query.contains("follow=true") {
                                        let guard = StreamDropped(dropped.lock().unwrap().take());
                                        Body::from_stream(futures::stream::unfold(
                                            (guard, 0),
                                            |(guard, index)| async move {
                                                let bytes = match index {
                                                    0 => frame(1, b"recent tail\n"),
                                                    1 => frame(2, b"live output\n"),
                                                    _ => futures::future::pending().await,
                                                };
                                                Some((
                                                    Ok::<_, Infallible>(bytes),
                                                    (guard, index + 1),
                                                ))
                                            },
                                        ))
                                    } else {
                                        let mut history = "old line\n".repeat(160_000);
                                        history.push_str(
                                            "PASSWORD=\"hidden-secret\"\nimportant tail\n",
                                        );
                                        Body::from(frame(1, history.as_bytes()))
                                    }
                                };
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .header("Content-Type", "application/vnd.docker.raw-stream")
                                        .body(body)
                                        .unwrap(),
                                )
                            }
                        });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(socket), service)
                        .await;
                });
            }
        });
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let history = runtime
                .logs(Protocol::Postgres, "inst_abc", Some(2000))
                .await
                .unwrap();
            assert!(
                history
                    .stdout
                    .starts_with(super::super::EXEC_OUTPUT_TRUNCATION_MARKER)
            );
            assert!(history.stdout.ends_with("important tail\n"));
            assert!(!history.stdout.contains("hidden-secret"));
            assert!(
                history.stdout.len()
                    <= super::super::MAX_EXEC_OUTPUT_BYTES_PER_CHANNEL
                        + super::super::EXEC_OUTPUT_TRUNCATION_MARKER.len()
            );
            let mut live = runtime
                .follow_logs(Protocol::Postgres, "inst_abc", None)
                .await
                .unwrap();
            assert_eq!(live.next().await.unwrap().unwrap().stdout, "recent tail\n");
            assert_eq!(live.next().await.unwrap().unwrap().stderr, "live output\n");
            drop(live);
            finished.await.unwrap();
            assert!(
                runtime
                    .logs(Protocol::Postgres, "another_instance", None)
                    .await
                    .is_err()
            );
        })
        .await;
        server.abort();
        result.unwrap();
    }
}

#[cfg(test)]
mod environment_tests {
    use super::{environment_value, unique_environment_value};

    #[test]
    fn reads_an_exact_environment_key_and_preserves_equals_in_the_value() {
        let environment = vec![
            "PASSWORD_EXTRA=wrong".to_string(),
            "PASSWORD=correct=with=equals".to_string(),
        ];

        assert_eq!(
            environment_value(&environment, "PASSWORD").as_deref(),
            Some("correct=with=equals")
        );
        assert_eq!(environment_value(&environment, "MISSING"), None);
    }

    #[test]
    fn protected_environment_lookup_rejects_missing_and_duplicate_values_without_leaking_them() {
        let missing = unique_environment_value(&[], "POSTGRES_PASSWORD", "inst_pg")
            .unwrap_err()
            .to_string();
        assert!(missing.contains("POSTGRES_PASSWORD"));
        assert!(!missing.contains("secret"));

        let duplicate = unique_environment_value(
            &[
                "POSTGRES_PASSWORD=first-secret".to_string(),
                "POSTGRES_PASSWORD=second-secret".to_string(),
            ],
            "POSTGRES_PASSWORD",
            "inst_pg",
        )
        .unwrap_err()
        .to_string();
        assert!(duplicate.contains("duplicate POSTGRES_PASSWORD"));
        assert!(!duplicate.contains("first-secret"));
        assert!(!duplicate.contains("second-secret"));

        assert_eq!(
            unique_environment_value(
                &["POSTGRES_PASSWORD=value=with=equals".to_string()],
                "POSTGRES_PASSWORD",
                "inst_pg",
            )
            .unwrap(),
            "value=with=equals"
        );
    }
}
