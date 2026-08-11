use std::time::Duration;

use bollard::{
    container::LogOutput,
    errors::Error as BollardError,
    exec::{CreateExecOptions, StartExecOptions, StartExecResults},
    query_parameters::{KillContainerOptions, StartContainerOptions},
};
use futures::StreamExt;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;

use super::{CappedExecOutput, DockerError, DockerRuntime};
use crate::shared::{logs::truncate_log_tail, protocol::Protocol, redaction};

const DOCKER_EXEC_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const DOCKER_EXEC_RECOVERY_STEP_TIMEOUT: Duration = Duration::from_secs(30);
const DOCKER_EXEC_RECOVERY_READINESS_TIMEOUT: Duration = Duration::from_secs(120);
const DOCKER_EXEC_SHORT_RECOVERY_READINESS_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy)]
struct ExecPolicy {
    log_failure: bool,
    timeout: Duration,
    recovery_readiness_timeout: Duration,
}

#[derive(Debug, Clone, Serialize)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn empty() -> Self {
        Self {
            stdout: String::new(),
            stderr: String::new(),
        }
    }
}

impl DockerRuntime {
    pub async fn exec(
        &self,
        protocol: Protocol,
        instance_id: &str,
        command: Vec<String>,
    ) -> Result<CommandOutput, DockerError> {
        self.exec_with_failure_logging(
            protocol,
            instance_id,
            command,
            None,
            ExecPolicy {
                log_failure: true,
                timeout: DOCKER_EXEC_TIMEOUT,
                recovery_readiness_timeout: DOCKER_EXEC_RECOVERY_READINESS_TIMEOUT,
            },
        )
        .await
    }

    pub async fn exec_with_timeout(
        &self,
        protocol: Protocol,
        instance_id: &str,
        command: Vec<String>,
        timeout: Duration,
    ) -> Result<CommandOutput, DockerError> {
        if timeout.is_zero() {
            return Err(DockerError::InvalidExecTimeout);
        }
        self.exec_with_failure_logging(
            protocol,
            instance_id,
            command,
            None,
            ExecPolicy {
                log_failure: true,
                timeout,
                recovery_readiness_timeout: DOCKER_EXEC_RECOVERY_READINESS_TIMEOUT,
            },
        )
        .await
    }

    pub(crate) async fn exec_readiness_probe(
        &self,
        protocol: Protocol,
        instance_id: &str,
        script: &str,
    ) -> Result<CommandOutput, DockerError> {
        self.exec_with_failure_logging(
            protocol,
            instance_id,
            vec!["sh".to_string(), "-c".to_string(), script.to_string()],
            None,
            ExecPolicy {
                log_failure: false,
                timeout: DOCKER_EXEC_TIMEOUT,
                recovery_readiness_timeout: DOCKER_EXEC_RECOVERY_READINESS_TIMEOUT,
            },
        )
        .await
    }

    pub(crate) async fn exec_readiness_probe_with_secret_env_timeout(
        &self,
        protocol: Protocol,
        instance_id: &str,
        script: &str,
        environment: &[(&str, &SecretString)],
        timeout: Duration,
    ) -> Result<CommandOutput, DockerError> {
        if timeout.is_zero() {
            return Err(DockerError::InvalidExecTimeout);
        }
        let environment = environment
            .iter()
            .map(|(key, value)| format!("{key}={}", value.expose_secret()))
            .collect();
        self.exec_with_failure_logging(
            protocol,
            instance_id,
            vec!["sh".to_string(), "-c".to_string(), script.to_string()],
            Some(environment),
            ExecPolicy {
                log_failure: false,
                timeout,
                recovery_readiness_timeout: DOCKER_EXEC_SHORT_RECOVERY_READINESS_TIMEOUT,
            },
        )
        .await
    }

    /// Runs a shell command with short-lived, explicitly supplied secret
    /// environment values. Secrets stay out of the command line and DBE's
    /// diagnostics; Docker/Podman retains them only for the lifetime of the
    /// exec operation.
    pub async fn exec_shell_with_secret_env(
        &self,
        protocol: Protocol,
        instance_id: &str,
        script: &str,
        environment: &[(&str, &SecretString)],
    ) -> Result<CommandOutput, DockerError> {
        let environment = environment
            .iter()
            .map(|(key, value)| format!("{key}={}", value.expose_secret()))
            .collect();
        self.exec_with_failure_logging(
            protocol,
            instance_id,
            vec!["sh".to_string(), "-c".to_string(), script.to_string()],
            Some(environment),
            ExecPolicy {
                log_failure: true,
                timeout: DOCKER_EXEC_TIMEOUT,
                recovery_readiness_timeout: DOCKER_EXEC_RECOVERY_READINESS_TIMEOUT,
            },
        )
        .await
    }

    pub async fn exec_shell_with_secret_env_timeout(
        &self,
        protocol: Protocol,
        instance_id: &str,
        script: &str,
        environment: &[(&str, &SecretString)],
        timeout: Duration,
    ) -> Result<CommandOutput, DockerError> {
        if timeout.is_zero() {
            return Err(DockerError::InvalidExecTimeout);
        }
        let environment = environment
            .iter()
            .map(|(key, value)| format!("{key}={}", value.expose_secret()))
            .collect();
        self.exec_with_failure_logging(
            protocol,
            instance_id,
            vec!["sh".to_string(), "-c".to_string(), script.to_string()],
            Some(environment),
            ExecPolicy {
                log_failure: true,
                timeout,
                recovery_readiness_timeout: DOCKER_EXEC_SHORT_RECOVERY_READINESS_TIMEOUT,
            },
        )
        .await
    }

    async fn exec_with_failure_logging(
        &self,
        protocol: Protocol,
        instance_id: &str,
        command: Vec<String>,
        environment: Option<Vec<String>>,
        policy: ExecPolicy,
    ) -> Result<CommandOutput, DockerError> {
        let name = self
            .required_managed_container_id(protocol, instance_id)
            .await?;
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
                    env: environment,
                    ..Default::default()
                },
            )
            .await?;

        let deadline = tokio::time::Instant::now() + policy.timeout;
        let started = match tokio::time::timeout_at(
            deadline,
            self.docker.start_exec(&exec.id, None::<StartExecOptions>),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                self.recover_timed_out_exec(
                    protocol,
                    instance_id,
                    &name,
                    &operation,
                    policy.timeout,
                    policy.recovery_readiness_timeout,
                )
                .await?;
                return Err(DockerError::ExecTimedOut {
                    container: name,
                    operation,
                    timeout_seconds: policy.timeout.as_secs(),
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
                        self.recover_timed_out_exec(
                            protocol,
                            instance_id,
                            &name,
                            &operation,
                            policy.timeout,
                            policy.recovery_readiness_timeout,
                        )
                        .await?;
                        return Err(DockerError::ExecTimedOut {
                            container: name,
                            operation,
                            timeout_seconds: policy.timeout.as_secs(),
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
            if policy.log_failure {
                tracing::warn!(
                    container = %name,
                    %operation,
                    exit_code,
                    %failure_output,
                    "docker exec failed"
                );
            }
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
        timeout: Duration,
        readiness_timeout: Duration,
    ) -> Result<(), DockerError> {
        tracing::warn!(
            %container,
            %operation,
            timeout_seconds = timeout.as_secs(),
            "docker exec timed out; restarting the managed container to stop the command and preserve runtime availability"
        );
        self.restart_after_exec_interruption(
            protocol,
            instance_id,
            container,
            operation,
            readiness_timeout,
        )
        .await
    }

    pub(super) async fn recover_interrupted_exec(
        &self,
        protocol: Protocol,
        instance_id: &str,
        container: &str,
        operation: &str,
        readiness_timeout: Duration,
    ) -> Result<(), DockerError> {
        tracing::warn!(
            %container,
            %operation,
            "docker exec was interrupted before exit could be confirmed; restarting the managed container"
        );
        self.restart_after_exec_interruption(
            protocol,
            instance_id,
            container,
            operation,
            readiness_timeout,
        )
        .await
    }

    async fn restart_after_exec_interruption(
        &self,
        protocol: Protocol,
        instance_id: &str,
        container: &str,
        operation: &str,
        readiness_timeout: Duration,
    ) -> Result<(), DockerError> {
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

        Box::pin(self.wait_until_ready(protocol, instance_id, readiness_timeout))
            .await
            .map_err(|error| exec_recovery_error(container, operation, error))?;
        tracing::info!(
            %container,
            %operation,
            "managed container recovered after interrupted docker exec"
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

    pub async fn exec_shell_with_timeout(
        &self,
        protocol: Protocol,
        instance_id: &str,
        script: &str,
        timeout: Duration,
    ) -> Result<CommandOutput, DockerError> {
        self.exec_with_timeout(
            protocol,
            instance_id,
            vec!["sh".to_string(), "-c".to_string(), script.to_string()],
            timeout,
        )
        .await
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
