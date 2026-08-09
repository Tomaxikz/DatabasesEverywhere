use super::*;

pub(super) async fn rollback_normal_image_update_or_quarantine(
    state: &AppState,
    rollback_metadata: &InstanceMetadata,
    rollback_spec: &DockerInstanceSpec,
    original_error: ApiError,
) -> ApiError {
    let original_message = original_error.to_string();
    state.install_progress.stage(
        &rollback_metadata.instance_id,
        "rollback",
        "image replacement failed; restoring the previous container",
    );
    let rollback = tokio::time::timeout(
        IMAGE_UPDATE_ROLLBACK_TIMEOUT,
        restore_normal_image_update(state, rollback_metadata, rollback_spec),
    )
    .await;
    let rollback_error = match rollback {
        Ok(Ok(())) => {
            tracing::warn!(
                event = "audit instance_image_update_rolled_back",
                instance_id = %rollback_metadata.instance_id,
                protocol = %rollback_metadata.protocol,
                error = %original_message,
                "image replacement failed and the previous immutable image was restored"
            );
            return original_error;
        }
        Ok(Err(error)) => error.to_string(),
        Err(_) => format!(
            "rollback exceeded its {} second deadline",
            IMAGE_UPDATE_ROLLBACK_TIMEOUT.as_secs()
        ),
    };

    let quarantine = quarantine_after_image_update_uncertainty(
        state,
        rollback_metadata,
        "normal image update rollback failed",
    )
    .await;
    tracing::error!(
        event = "audit instance_image_update_rollback_failed",
        instance_id = %rollback_metadata.instance_id,
        protocol = %rollback_metadata.protocol,
        error = %original_message,
        rollback_error = %rollback_error,
        quarantine_complete = quarantine.is_ok(),
        "image replacement and rollback both failed; instance was quarantined fail-closed"
    );
    ApiError::Runtime(format!(
        "image update failed ({original_message}) and rollback failed ({rollback_error}); {}",
        image_update_quarantine_summary(&quarantine)
    ))
}

async fn restore_normal_image_update(
    state: &AppState,
    rollback_metadata: &InstanceMetadata,
    rollback_spec: &DockerInstanceSpec,
) -> Result<(), ApiError> {
    delete_image_update_container(
        state,
        rollback_metadata.protocol,
        &rollback_metadata.instance_id,
    )
    .await?;
    let no_progress = |_event| {};
    launch_container_from_spec(
        state,
        rollback_spec,
        rollback_metadata.protocol,
        &rollback_metadata.instance_id,
        &no_progress,
        false,
        || async { Ok(()) },
    )
    .await
    .map_err(|error| error.into_api_error())?;
    state
        .manager
        .upsert(rollback_metadata.clone())
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "previous container was restored but its metadata could not be persisted: {error}"
            ))
        })?;
    invalidate_image_update_caches(state, &rollback_metadata.instance_id).await;
    Ok(())
}

async fn delete_image_update_container(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
) -> Result<(), ApiError> {
    match state.docker.delete(protocol, instance_id).await {
        Ok(_) => Ok(()),
        Err(error) if error.is_not_found() => Ok(()),
        Err(error) => Err(docker_error(error)),
    }
}

pub(super) async fn quarantine_after_image_update_uncertainty(
    state: &AppState,
    metadata: &InstanceMetadata,
    reason: &str,
) -> Result<(), ApiError> {
    let quarantined = quarantined_image_update_metadata(metadata);

    // Remove gateway routes before waiting for Docker or SQLite. A failed
    // durable quarantine must not leave the process routing to an uncertain
    // replacement during this daemon lifetime.
    state.instances.upsert(quarantined.clone()).await;
    invalidate_image_update_caches(state, &quarantined.instance_id).await;

    let (runtime_result, persistence_result) = tokio::join!(
        stop_image_update_target_fail_closed(state, &quarantined),
        state.manager.upsert(quarantined.clone()),
    );
    let persistence_result = persistence_result
        .map_err(|error| format!("failed to persist image-update quarantine: {error}"));
    tracing::error!(
        event = "audit uncertain_image_update_quarantined",
        instance_id = %quarantined.instance_id,
        protocol = %quarantined.protocol,
        %reason,
        runtime_stopped = runtime_result.is_ok(),
        quarantine_persisted = persistence_result.is_ok(),
        "image-update runtime or commit state became uncertain; gateway routes were removed and the instance was quarantined"
    );

    match (runtime_result, persistence_result) {
        (Ok(()), Ok(())) => Ok(()),
        (runtime, persistence) => {
            let mut failures = Vec::new();
            if let Err(error) = runtime {
                failures.push(error);
            }
            if let Err(error) = persistence {
                failures.push(error);
            }
            Err(ApiError::Runtime(failures.join("; ")))
        }
    }
}

async fn stop_image_update_target_fail_closed(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<(), String> {
    match tokio::time::timeout(
        IMAGE_UPDATE_FAIL_CLOSED_STOP_TIMEOUT,
        state.docker.stop(metadata.protocol, &metadata.instance_id),
    )
    .await
    {
        Ok(Ok(_)) => return Ok(()),
        Ok(Err(error)) if error.is_not_running() || error.is_not_found() => return Ok(()),
        Ok(Err(error)) => {
            tracing::warn!(
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                %error,
                "graceful stop failed while quarantining an uncertain image update; forcing shutdown"
            );
        }
        Err(_) => {
            tracing::warn!(
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                "graceful stop timed out while quarantining an uncertain image update; forcing shutdown"
            );
        }
    }

    match tokio::time::timeout(
        IMAGE_UPDATE_FAIL_CLOSED_STOP_TIMEOUT,
        state.docker.kill(metadata.protocol, &metadata.instance_id),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) if error.is_not_running() || error.is_not_found() => Ok(()),
        Ok(Err(error)) => Err(format!(
            "failed to stop or kill uncertain image-update target: {error}"
        )),
        Err(_) => Err("timed out stopping and killing uncertain image-update target".to_string()),
    }
}

async fn invalidate_image_update_caches(state: &AppState, instance_id: &str) {
    state.instance_runtime_cache.remove(instance_id).await;
    state.resource_cache.remove(instance_id).await;
    state.monitoring_cache.invalidate().await;
}

pub(super) fn quarantined_image_update_metadata(metadata: &InstanceMetadata) -> InstanceMetadata {
    let mut quarantined = metadata.clone();
    quarantined.status = InstanceStatus::Quarantined;
    quarantined.desired_state = DesiredInstanceState::Stopped;
    quarantined.updated_at = now_rfc3339();
    quarantined
}

pub(super) fn image_update_quarantine_summary(result: &Result<(), ApiError>) -> String {
    match result {
        Ok(()) => "the instance was stopped and quarantined".to_string(),
        Err(error) => format!(
            "the instance was quarantined in memory, but complete shutdown or persistence failed: {error}"
        ),
    }
}
