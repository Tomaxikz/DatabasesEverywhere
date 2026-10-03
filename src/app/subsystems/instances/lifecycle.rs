use super::*;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAction {
    Start,
    Stop,
    Restart,
    Kill,
}

pub(crate) async fn change_instance_state(
    state: &AppState,
    instance_id: &str,
    action: LifecycleAction,
) -> ApiResult<InstanceMetadata> {
    let operation = state.instance_locks.lock(instance_id).await;
    let mut metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    deployment::ensure_no_active_migration(state, instance_id).await?;
    if metadata.deployment_mode == crate::server::placement::DeploymentMode::Shared {
        let worker_state = state.clone();
        let worker_instance_id = instance_id.to_string();
        let worker = spawn_owned_mutation_task(async move {
            let _operation = operation;
            match std::panic::AssertUnwindSafe(shared::change_state(
                &worker_state,
                metadata,
                action,
            ))
            .catch_unwind()
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    let recovery =
                        shared::recover_lifecycle_panic(&worker_state, &worker_instance_id).await;
                    Err(ApiError::Runtime(format!(
                        "shared tenant lifecycle worker panicked; {recovery}"
                    )))
                }
            }
        });
        return worker.await.map_err(|error| {
            ApiError::Runtime(format!(
                "shared tenant lifecycle supervisor stopped unexpectedly: {error}; the tenant remains fenced until it is reconciled"
            ))
        })?;
    }
    reject_quarantined_start(&metadata, action)?;
    let mut metadata_changed = false;
    if starts_runtime(action) {
        metadata_changed = precheck_dedicated_start(state, &mut metadata).await?;
    }
    let desired_state = match action {
        LifecycleAction::Start | LifecycleAction::Restart => DesiredInstanceState::Running,
        LifecycleAction::Stop | LifecycleAction::Kill => DesiredInstanceState::Stopped,
    };
    if metadata.desired_state != desired_state {
        metadata.desired_state = desired_state;
        metadata.updated_at = now_rfc3339();
        metadata_changed = true;
    }
    let mutation = state
        .daemon_shutdown
        .try_admit_background_mutation()
        .ok_or_else(|| {
            ApiError::ServiceUnavailable(
                "daemon shutdown has started; lifecycle operations are not accepted".to_string(),
            )
        })?;
    let worker_state = state.clone();
    let worker_instance_id = instance_id.to_string();
    let recovery = metadata.clone();
    let worker = spawn_owned_mutation_task(async move {
        let _mutation = mutation;
        let _operation = operation;
        let lifecycle = async {
            if metadata_changed {
                worker_state
                    .manager
                    .upsert(metadata)
                    .await
                    .map_err(|error| {
                        ApiError::Runtime(format!(
                            "failed to persist requested lifecycle state before applying it: {error}"
                        ))
                    })?;
            }
            change_instance_state_locked(&worker_state, &worker_instance_id, action).await
        };
        match std::panic::AssertUnwindSafe(lifecycle).catch_unwind().await {
            Ok(result) => result,
            Err(_) => {
                let durable = worker_state
                    .manager
                    .get_persisted(&worker_instance_id)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or(recovery);
                let quarantine = quarantine_image_update(
                    &worker_state,
                    &durable,
                    "lifecycle worker panicked after runtime mutation may have begun",
                )
                .await;
                Err(ApiError::Runtime(format!(
                    "lifecycle worker stopped unexpectedly; {}",
                    image_quarantine_summary(&quarantine)
                )))
            }
        }
    });
    worker.await.map_err(|error| {
        ApiError::Runtime(format!(
            "lifecycle supervisor stopped unexpectedly: {error}; inspect and reconcile the instance before retrying"
        ))
    })?
}

pub(crate) async fn change_instance_state_locked(
    state: &AppState,
    instance_id: &str,
    action: LifecycleAction,
) -> ApiResult<InstanceMetadata> {
    let mut metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    deployment::ensure_no_active_migration(state, instance_id).await?;

    if metadata.deployment_mode == crate::server::placement::DeploymentMode::Shared {
        return shared::change_state(state, metadata, action).await;
    }

    reject_quarantined_start(&metadata, action)?;

    let inspection = state
        .docker
        .inspect_instance(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(docker_error)?;
    let should_call_docker = match action {
        LifecycleAction::Start => inspection.status != DockerContainerStatus::Running,
        LifecycleAction::Stop => inspection.status == DockerContainerStatus::Running,
        LifecycleAction::Restart => true,
        LifecycleAction::Kill => inspection.status == DockerContainerStatus::Running,
    };

    let starting = starts_runtime(action);
    let mut startup_readiness_failed = false;
    if starting {
        route_fence::fence(state, &metadata.instance_id).await;
    }
    let operation_result: Result<(), ApiError> = async {
        if should_call_docker {
            if starting {
                prepare_dedicated_start(state, &mut metadata).await?;
            }
            let refresh_console = starting
                && !state
                    .docker
                    .log_policy_is_current(metadata.protocol, &metadata.instance_id)
                    .await
                    .map_err(docker_error)?;
            if refresh_console {
                metadata = recreate_with_current_console_policy(state, &metadata).await?;
            } else {
                run_lifecycle_command(state, &metadata, action).await?;
            }
        }

        if starting && let Err(error) = verify_startup_readiness(state, &metadata).await {
            startup_readiness_failed = true;
            return Err(error);
        }
        Ok(())
    }
    .await;

    if startup_readiness_failed
        && let Err(error) = state
            .docker
            .stop(metadata.protocol, &metadata.instance_id)
            .await
        && !error.is_not_running()
        && !error.is_not_found()
    {
        tracing::error!(
            event = "audit startup_readiness_cleanup_failed",
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            %error,
            "database startup readiness failed and the container could not be stopped"
        );
    }

    let previous = metadata.status;
    let mut metadata = reconcile::reconcile_one(metadata, &state.docker).await;
    if startup_readiness_failed {
        metadata.status = InstanceStatus::Failed;
        metadata.updated_at = now_rfc3339();
    }
    let persistence_result =
        reconcile::persist_reconciled(&state.manager, previous, metadata.clone()).await;
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;

    match (operation_result, persistence_result) {
        (Ok(()), Ok(())) => {}
        (Err(operation_error), Ok(())) => return Err(operation_error),
        (operation_result, Err(persistence_error)) => {
            let rollback = rollback_runtime_state(
                state,
                &metadata,
                matches!(
                    inspection.status,
                    DockerContainerStatus::Running | DockerContainerStatus::Starting
                ),
            )
            .await;
            return Err(ApiError::Runtime(format!(
                "failed to persist lifecycle reconciliation: {persistence_error}; operation: {}; rollback: {rollback}",
                operation_result
                    .err()
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| "completed".to_string())
            )));
        }
    }

    Ok(ApiResponse::ok(metadata))
}
