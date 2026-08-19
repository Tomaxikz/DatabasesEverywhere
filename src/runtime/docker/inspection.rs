use std::time::Duration;

use bollard::{
    container::LogOutput,
    errors::Error as BollardError,
    models::{ContainerInspectResponse, ContainerStatsResponse},
    query_parameters::{LogsOptionsBuilder, StatsOptionsBuilder},
};
use futures::{StreamExt, TryStreamExt};
use secrecy::SecretString;
use tokio::{
    sync::mpsc,
    time::{Instant, sleep},
};

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
            .verified_managed_container_inspection(protocol, instance_id)
            .await?
        else {
            return Ok(None);
        };
        let container = self.container_name(protocol, instance_id)?;
        let id = response
            .id
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| DockerError::ManagedContainerIdUnavailable { container })?;
        Ok(Some(id))
    }

    pub(super) async fn verified_managed_container_inspection(
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
    pub(crate) async fn verified_managed_container_identity(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<Option<ManagedContainerIdentity>, DockerError> {
        let Some(response) = self
            .verified_managed_container_inspection(protocol, instance_id)
            .await?
        else {
            return Ok(None);
        };
        let container = self.container_name(protocol, instance_id)?;
        let id = response
            .id
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| DockerError::ManagedContainerIdUnavailable {
                container: container.clone(),
            })?;
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
    pub(crate) async fn verified_managed_compatibility_identity(
        &self,
        protocol: Protocol,
        instance_id: &str,
    ) -> Result<Option<ManagedContainerCompatibilityIdentity>, DockerError> {
        let Some(response) = self
            .verified_managed_container_inspection(protocol, instance_id)
            .await?
        else {
            return Ok(None);
        };
        let container = self.container_name(protocol, instance_id)?;
        let id = response
            .id
            .filter(|id| !id.trim().is_empty())
            .ok_or_else(|| DockerError::ManagedContainerIdUnavailable {
                container: container.clone(),
            })?;
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
                DockerContainerStatus::Created | DockerContainerStatus::Starting => {}
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

    pub(crate) async fn postgres_legacy_tenant_credentials(
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
            let username = optional_unique_environment_value(&environment, username_key).map_err(
                |reason| DockerError::InvalidLegacyCredentialEnvironment {
                    instance_id: instance_id.to_string(),
                    protocol: protocol.as_str().to_string(),
                    reason,
                },
            )?;
            let password = optional_unique_environment_value(&environment, password_key).map_err(
                |reason| DockerError::InvalidLegacyCredentialEnvironment {
                    instance_id: instance_id.to_string(),
                    protocol: protocol.as_str().to_string(),
                    reason,
                },
            )?;
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
    pub async fn verify_container_data_bind(
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

    pub async fn follow_logs(
        &self,
        protocol: Protocol,
        instance_id: &str,
        tail: Option<usize>,
    ) -> Result<mpsc::Receiver<Result<CommandOutput, DockerError>>, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
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

fn optional_unique_environment_value(
    environment: &[String],
    key: &str,
) -> Result<Option<String>, String> {
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
