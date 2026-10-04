use std::{collections::HashMap, path::Path, sync::Arc};

use bollard::{
    container::{AttachContainerResults, LogOutput},
    errors::Error as BollardError,
    query_parameters::{
        AttachContainerOptionsBuilder, CreateContainerOptionsBuilder, ListContainersOptionsBuilder,
        StartContainerOptions, WaitContainerOptions,
    },
};
use futures::StreamExt;
use tokio::time::{Instant, MissedTickBehavior};

use crate::{
    runtime::docker::{
        DockerRuntime,
        command::CommandOutput,
        error::DockerError,
        remote_import::{
            HELPER_FAILURE_TAIL_CHARS, HELPER_LABEL, HELPER_NAME_PREFIX, ImportHelperNetwork,
            OUTPUT_SIZE_POLL_INTERVAL, RemoteImportHelperSpec, ResolvedHelperNetwork,
            cancellation::{
                CancelHelperOnDrop, HelperCancellation, RemoteImportHelperCleanupGuard,
            },
            container::{
                ImportHelperCreateOptions, chown_work_directory, ensure_output_within_limit,
                import_helper_body, is_owned_import_helper, remove_import_helper,
                run_unless_cancelled,
            },
            output::{
                helper_timeout, invalid_helper_spec, measure_work_directory, redact_helper_output,
                sanitized_helper_output,
            },
            validation::{
                validate_helper_environment, validate_helper_input, validate_helper_spec,
            },
        },
        transfer::CappedExecOutput,
    },
    utils::logs::truncate_log_tail,
};

impl DockerRuntime {
    pub async fn prepare_import_image(&self, image: &str) -> Result<(), DockerError> {
        if image.trim().is_empty() {
            return Err(invalid_helper_spec("image must not be empty"));
        }
        self.ensure_image_with_progress(image, None).await
    }

    pub async fn run_import_helper(
        &self,
        spec: &RemoteImportHelperSpec,
    ) -> Result<CommandOutput, DockerError> {
        // The supervisor owns the helper lifecycle. Dropping the caller's
        // future signals cancellation instead of detaching an unmonitored
        // container, and the supervisor remains alive long enough to remove
        // any container it may already have created.
        let cancellation = Arc::new(HelperCancellation::default());
        let mut cancel_on_drop = CancelHelperOnDrop::new(cancellation.clone());
        let runtime = self.clone();
        let spec = spec.clone();
        let supervisor =
            tokio::spawn(async move { runtime.run_import_worker(spec, cancellation).await });
        let joined = supervisor.await;
        cancel_on_drop.disarm();
        joined.map_err(|error| DockerError::RemoteImportHelperStateUncertain {
            reason: format!(
                "lifecycle supervisor terminated before cleanup was confirmed: {error}"
            ),
        })?
    }

    pub(super) async fn run_import_worker(
        &self,
        spec: RemoteImportHelperSpec,
        cancellation: Arc<HelperCancellation>,
    ) -> Result<CommandOutput, DockerError> {
        let node_id = self
            .node_id
            .as_deref()
            .ok_or(DockerError::RuntimeNodeIdUnavailable)?;
        let work_dir = run_unless_cancelled(&cancellation, validate_helper_spec(&spec)).await?;
        let (environment, secret_values) = validate_helper_environment(&spec)?;
        let input_path =
            run_unless_cancelled(&cancellation, validate_helper_input(spec.input.as_ref())).await?;
        let network =
            run_unless_cancelled(&cancellation, self.resolve_helper_network(&spec)).await?;
        if let Some((uid, gid)) = self.rootless_podman_host_owner() {
            run_unless_cancelled(
                &cancellation,
                chown_work_directory(work_dir.clone(), uid, gid),
            )
            .await?;
        }
        let initial_size = run_unless_cancelled(
            &cancellation,
            measure_work_directory(&work_dir, spec.max_output_bytes),
        )
        .await?;
        ensure_output_within_limit(initial_size, spec.max_output_bytes)?;

        // Resolve/pull the trusted caller-selected image before creating any
        // helper container. Remote-import API code writes secrets only after
        // it has selected this configured image.
        run_unless_cancelled(&cancellation, self.prepare_import_image(&spec.image)).await?;
        if cancellation.is_cancelled() {
            return Err(DockerError::RemoteImportHelperCancelled);
        }

        let name = format!("{HELPER_NAME_PREFIX}{}", uuid::Uuid::new_v4().simple());
        let mut cleanup = RemoteImportHelperCleanupGuard::new(self.docker.clone(), name.clone());
        let body = import_helper_body(ImportHelperCreateOptions {
            spec: &spec,
            work_dir: &work_dir,
            input_path: input_path.as_deref(),
            network: &network,
            environment,
            security: &self.security,
            rootless_podman: self.uses_rootless_podman(),
            node_id,
        });
        // Once submitted, let the short Docker create call finish. Dropping an
        // in-flight request could race a 404 cleanup with a late server-side
        // creation and leave an unstarted orphan. Cancellation is observed
        // immediately after creation and then takes the guarded cleanup path.
        let response = match self
            .docker
            .create_container(
                Some(CreateContainerOptionsBuilder::default().name(&name).build()),
                body,
            )
            .await
        {
            Ok(response) => response,
            Err(source) => {
                if let Err(cleanup_error) = cleanup.cleanup().await {
                    tracing::error!(
                        helper = %name,
                        error = %cleanup_error,
                        "failed to force-remove a possibly-created remote import helper"
                    );
                    return Err(DockerError::RemoteImportHelperStateUncertain {
                        reason: format!(
                            "container creation failed ({source}) and cleanup could not be confirmed ({cleanup_error})"
                        ),
                    });
                }
                return Err(source.into());
            }
        };
        if !response.warnings.is_empty() {
            tracing::warn!(
                helper = %name,
                warnings = %truncate_log_tail(
                    &redact_helper_output(&response.warnings.join("\n"), &secret_values),
                    HELPER_FAILURE_TAIL_CHARS,
                ),
                "remote import helper container was created with warnings"
            );
        }

        let result = tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(DockerError::RemoteImportHelperCancelled),
            result = self.start_import_helper(&name, &spec, &work_dir, &secret_values) => result,
        };
        let cleanup_result = cleanup.cleanup().await;
        match (result, cleanup_result) {
            (Ok(output), Ok(())) => Ok(output),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
            (Err(error), Err(cleanup_error)) => {
                tracing::error!(
                    helper = %name,
                    error = %cleanup_error,
                    "failed to force-remove remote import helper after an operation error"
                );
                Err(DockerError::RemoteImportHelperStateUncertain {
                    reason: format!(
                        "operation failed ({error}) and cleanup could not be confirmed ({cleanup_error})"
                    ),
                })
            }
        }
    }

    pub(super) async fn resolve_helper_network(
        &self,
        spec: &RemoteImportHelperSpec,
    ) -> Result<ResolvedHelperNetwork, DockerError> {
        let mode = match &spec.network {
            ImportHelperNetwork::Outbound => "bridge".to_string(),
            ImportHelperNetwork::ManagedRuntime {
                protocol,
                runtime_id,
            } => {
                let container = self
                    .required_managed_container_id(*protocol, runtime_id)
                    .await?;
                format!("container:{container}")
            }
        };
        Ok(ResolvedHelperNetwork { mode })
    }

    /// Removes helper containers left behind by an interrupted daemon process.
    ///
    /// Both the exact helper label and the generated name format must match.
    /// This prevents reconciliation from touching managed database containers
    /// or unrelated containers that happen to use a similar label or name.
    pub async fn reconcile_import_helpers(&self) -> Result<usize, DockerError> {
        let node_id = self
            .node_id
            .as_deref()
            .ok_or(DockerError::RuntimeNodeIdUnavailable)?;
        let filters = HashMap::from([("label".to_string(), vec![format!("{HELPER_LABEL}=true")])]);
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
        let mut first_error = None;
        for container in containers {
            if !is_owned_import_helper(
                container.labels.as_ref(),
                container.names.as_deref(),
                node_id,
            ) {
                continue;
            }
            let Some(id) = container.id else {
                continue;
            };
            match remove_import_helper(&self.docker, &id).await {
                Ok(()) => removed += 1,
                Err(error) => {
                    tracing::error!(
                        helper = %id,
                        error = %error,
                        "failed to reconcile stale remote import helper"
                    );
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }

        if let Some(error) = first_error {
            Err(error)
        } else {
            Ok(removed)
        }
    }

    pub(super) async fn start_import_helper(
        &self,
        name: &str,
        spec: &RemoteImportHelperSpec,
        work_dir: &Path,
        secret_values: &[String],
    ) -> Result<CommandOutput, DockerError> {
        let deadline = Instant::now()
            .checked_add(spec.timeout)
            .ok_or_else(|| invalid_helper_spec("timeout is too large"))?;
        let AttachContainerResults {
            mut output,
            input: _,
        } = tokio::time::timeout_at(
            deadline,
            self.docker.attach_container(
                name,
                Some(
                    AttachContainerOptionsBuilder::default()
                        .stream(true)
                        .stdin(false)
                        .stdout(true)
                        .stderr(true)
                        .build(),
                ),
            ),
        )
        .await
        .map_err(|_| helper_timeout(spec.timeout))??;

        tokio::time::timeout_at(
            deadline,
            self.docker
                .start_container(name, None::<StartContainerOptions>),
        )
        .await
        .map_err(|_| helper_timeout(spec.timeout))??;

        let mut wait = Box::pin(
            self.docker
                .wait_container(name, None::<WaitContainerOptions>),
        );
        let mut size_interval = tokio::time::interval(OUTPUT_SIZE_POLL_INTERVAL);
        size_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let timeout = tokio::time::sleep_until(deadline);
        tokio::pin!(timeout);

        let mut stdout = CappedExecOutput::default();
        let mut stderr = CappedExecOutput::default();
        let mut exit_code = None;
        let mut output_closed = false;

        loop {
            tokio::select! {
                chunk = output.next(), if !output_closed => {
                    match chunk {
                        Some(Ok(LogOutput::StdOut { message } | LogOutput::Console { message })) => {
                            stdout.append(&message);
                        }
                        Some(Ok(LogOutput::StdErr { message })) => {
                            stderr.append(&message);
                        }
                        Some(Ok(LogOutput::StdIn { .. })) => {}
                        Some(Err(error)) => return Err(error.into()),
                        None => output_closed = true,
                    }
                }
                wait_result = wait.next(), if exit_code.is_none() => {
                    match wait_result {
                        Some(Ok(response)) => exit_code = Some(response.status_code),
                        Some(Err(BollardError::DockerContainerWaitError { code, error })) => {
                            stderr.append(error.as_bytes());
                            exit_code = Some(code);
                        }
                        Some(Err(error)) => return Err(error.into()),
                        None => return Err(DockerError::RemoteImportHelperWaitEnded),
                    }
                }
                _ = size_interval.tick() => {
                    let size =
                        measure_work_directory(work_dir, spec.max_output_bytes).await?;
                    ensure_output_within_limit(size, spec.max_output_bytes)?;
                }
                _ = &mut timeout => return Err(helper_timeout(spec.timeout)),
            }

            if output_closed && exit_code.is_some() {
                break;
            }
        }

        let final_size = measure_work_directory(work_dir, spec.max_output_bytes).await?;
        ensure_output_within_limit(final_size, spec.max_output_bytes)?;

        let output = sanitized_helper_output(stdout, stderr, secret_values);
        let exit_code = exit_code.unwrap_or_default();
        if exit_code == 0 {
            return Ok(output);
        }
        Err(DockerError::RemoteImportHelperFailed {
            exit_code,
            failure_output: truncate_log_tail(output.failure_output(), HELPER_FAILURE_TAIL_CHARS),
        })
    }
}
