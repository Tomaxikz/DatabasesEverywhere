use std::time::Duration;

use bollard::{
    container::LogOutput,
    errors::Error as BollardError,
    models::{ContainerInspectResponse, ContainerStatsResponse, HostConfigLogConfig},
    query_parameters::{LogsOptionsBuilder, StatsOptionsBuilder},
};
use futures::{StreamExt, TryStreamExt};
use secrecy::SecretString;
use tokio::time::{Instant, sleep};

use crate::{
    databases::protocol::Protocol,
    runtime::docker::helpers::verify_managed_instance_labels,
    runtime::docker::{
        CommandOutput, DockerContainerStatus, DockerError, DockerInstanceInspection, DockerRuntime,
        ManagedContainerCompatibilityIdentity, ManagedContainerIdentity, ManagedStatsSampler,
    },
    utils::constants::docker::PROJECT_LABEL,
};

const STARTUP_READINESS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const READINESS_POLL_INTERVAL: Duration = Duration::from_secs(1);
const LOG_HISTORY_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_LOG_HISTORY_TAIL_LINES: usize = 200;
const DEFAULT_FOLLOW_TAIL_LINES: usize = 100;
const MAX_LOG_TAIL_LINES: usize = 2_000;

impl DockerRuntime {
    pub(crate) async fn log_policy_is_current(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<bool, DockerError> {
        let inspection = self
            .inspect_managed_container(protocol, instance_id)
            .await?;
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
        verify_managed_instance_labels(
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

    async fn inspect_managed_container(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<ContainerInspectResponse, DockerError> {
        let id = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
        Ok(self.docker.inspect_container(&id, None).await?)
    }

    pub async fn inspect_instance(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<DockerInstanceInspection, DockerError> {
        let response = self
            .inspect_managed_container(protocol, instance_id)
            .await?;
        let state = response.state;
        let oom_killed = state
            .as_ref()
            .and_then(|state| state.oom_killed)
            .unwrap_or(false);
        let memory_limit_bytes = response
            .host_config
            .as_ref()
            .and_then(|config| config.memory)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .filter(|bytes| *bytes > 0);
        let health = state
            .as_ref()
            .and_then(|state| state.health.as_ref())
            .and_then(|health| health.status.as_ref())
            .map(|status| status.as_ref().to_string());
        let status = state
            .and_then(|state| state.status)
            .map(|status| container_status(status.as_ref()))
            .unwrap_or(DockerContainerStatus::Failed);
        let network_mode = response
            .host_config
            .and_then(|host_config| host_config.network_mode)
            .map(|mode| mode.trim().to_ascii_lowercase())
            .filter(|mode| !mode.is_empty());
        let image = trimmed_non_empty(response.config.and_then(|config| config.image));

        Ok(DockerInstanceInspection {
            status,
            oom_killed,
            memory_limit_bytes,
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
                            protocol.engine().startup_readiness_script(),
                        ),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {
                            self.startup_ready(instance_id).await?;
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
                            // Cancelling an exec HTTP request does not prove its
                            // process exited. Do not pile up hung probes: let the
                            // startup owner stop the container and report failure.
                            return Err(not_ready_error(
                                instance_id,
                                last,
                                Some(format!(
                                    "readiness attempt exceeded {} seconds",
                                    attempt_timeout.as_secs()
                                )),
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

            sleep(READINESS_POLL_INTERVAL).await;
            last = self.inspect_instance(protocol, instance_id).await?;
        }
    }

    pub async fn configured_container_user(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<Option<String>, DockerError> {
        let response = self
            .inspect_managed_container(protocol, instance_id)
            .await?;
        Ok(trimmed_non_empty(
            response.config.and_then(|config| config.user),
        ))
    }

    pub(crate) async fn postgres_bootstrap_credentials(
        &self,
        instance_id: &str,
    ) -> Result<(String, SecretString), DockerError> {
        let response = self
            .inspect_managed_container(Protocol::Postgres, instance_id)
            .await?;
        let environment = container_environment(response);
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
        let response = self
            .inspect_managed_container(protocol, instance_id)
            .await?;
        let environment = container_environment(response);
        let invalid_environment =
            |reason: String| DockerError::InvalidLegacyCredentialEnvironment {
                instance_id: instance_id.to_string(),
                protocol: protocol.as_str().to_string(),
                reason,
            };
        let mut credential = None;
        for (username_key, password_key) in key_pairs {
            let username =
                unique_optional_env(&environment, username_key).map_err(invalid_environment)?;
            let password =
                unique_optional_env(&environment, password_key).map_err(invalid_environment)?;
            match (username, password) {
                (None, None) => {}
                (Some(username), Some(password))
                    if !username.trim().is_empty() && !password.is_empty() =>
                {
                    if credential.is_some() {
                        return Err(invalid_environment(
                            "multiple tenant credential pairs are present".to_string(),
                        ));
                    }
                    credential = Some((username, SecretString::from(password)));
                }
                _ => {
                    return Err(invalid_environment(format!(
                        "{username_key} and {password_key} must both be present and non-empty"
                    )));
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
        let response = self
            .inspect_managed_container(protocol, instance_id)
            .await?;
        Ok(trimmed_non_empty(
            response.config.and_then(|config| config.image),
        ))
    }

    /// Return the immutable image ID backing a managed container. Internal
    /// safety migrations use this rather than a mutable tag so recreation
    /// cannot silently switch database versions between stop and create.
    pub async fn container_immutable_image_id(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<Option<String>, DockerError> {
        let response = self
            .inspect_managed_container(protocol, instance_id)
            .await?;
        Ok(trimmed_non_empty(response.image))
    }

    pub async fn container_bind_source(
        &self,
        protocol: Protocol,
        instance_id: &str,
        destination: &str,
    ) -> Result<Option<std::path::PathBuf>, DockerError> {
        let response = self
            .inspect_managed_container(protocol, instance_id)
            .await?;
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
            .container_bind_source(
                protocol,
                instance_id,
                protocol.engine().container_data_target(),
            )
            .await?;
        if actual_source.as_deref() == Some(expected_source) {
            return Ok(());
        }
        Err(DockerError::DiskBindSourceMismatch {
            instance_id: instance_id.to_string(),
            destination: protocol.engine().container_data_target().to_string(),
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
        let response = self
            .inspect_managed_container(protocol, instance_id)
            .await?;
        let Some(reference) = trimmed_non_empty(response.config.and_then(|config| config.image))
        else {
            return Ok(None);
        };
        let Some(container_image_id) = trimmed_non_empty(response.image) else {
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
        let response = self
            .inspect_managed_container(protocol, instance_id)
            .await?;
        Ok(response
            .config
            .and_then(|config| config.env)
            .as_deref()
            .and_then(|environment| environment_value(environment, key))
            .map(SecretString::from))
    }

    /// Legacy recovery rejects duplicate keys, even if their first value looks valid.
    pub(crate) async fn legacy_environment_secret(
        &self,
        protocol: Protocol,
        instance_id: &str,
        key: &str,
    ) -> Result<Option<SecretString>, DockerError> {
        let response = self
            .inspect_managed_container(protocol, instance_id)
            .await?;
        let environment = container_environment(response);
        unique_optional_env(&environment, key)
            .map(|value| value.map(SecretString::from))
            .map_err(|reason| DockerError::InvalidLegacyCredentialEnvironment {
                instance_id: instance_id.to_string(),
                protocol: protocol.as_str().to_string(),
                reason,
            })
    }

    /// Preserves the optional project ownership label across a same-image
    /// container recreation.
    pub async fn container_project_id(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<Option<String>, DockerError> {
        let response = self
            .inspect_managed_container(protocol, instance_id)
            .await?;
        Ok(trimmed_non_empty(
            response
                .config
                .and_then(|config| config.labels)
                .and_then(|labels| labels.get(PROJECT_LABEL).cloned()),
        ))
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
        let tail = tail
            .unwrap_or(DEFAULT_LOG_HISTORY_TAIL_LINES)
            .clamp(1, MAX_LOG_TAIL_LINES)
            .to_string();
        let mut stdout = super::CappedExecOutput::default();
        let mut stderr = super::CappedExecOutput::default();
        let mut stdout_redactor = crate::utils::logs::LogRedactor::default();
        let mut stderr_redactor = crate::utils::logs::LogRedactor::default();
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

        tokio::time::timeout(LOG_HISTORY_TIMEOUT, async {
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
        let tail = tail
            .unwrap_or(DEFAULT_FOLLOW_TAIL_LINES)
            .clamp(1, MAX_LOG_TAIL_LINES)
            .to_string();
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
        crate::config::DaemonEngine::Podman => {
            configured.is_some_and(|configured| podman_log_config_matches(configured, &expected))
        }
    };
    marked && matches && !has_legacy_log_bind_mount(inspection)
}

fn podman_log_config_matches(
    configured: &HostConfigLogConfig,
    expected: &HostConfigLogConfig,
) -> bool {
    let reports_file_driver = matches!(configured.typ.as_deref(), Some("json-file" | "k8s-file"));
    let options_match = configured
        .config
        .as_ref()
        .is_none_or(|options| options.is_empty())
        || configured.config == expected.config;
    reports_file_driver && options_match
}

fn has_legacy_log_bind_mount(inspection: &ContainerInspectResponse) -> bool {
    inspection.mounts.as_ref().is_some_and(|mounts| {
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

fn container_status(status: &str) -> DockerContainerStatus {
    match status {
        "running" => DockerContainerStatus::Running,
        "created" => DockerContainerStatus::Created,
        "restarting" => DockerContainerStatus::Starting,
        "paused" | "exited" | "stopping" => DockerContainerStatus::Stopped,
        _ => DockerContainerStatus::Failed,
    }
}

fn trimmed_non_empty(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn container_environment(response: ContainerInspectResponse) -> Vec<String> {
    response
        .config
        .and_then(|config| config.env)
        .unwrap_or_default()
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
mod logging_tests;

#[cfg(test)]
mod environment_tests;
