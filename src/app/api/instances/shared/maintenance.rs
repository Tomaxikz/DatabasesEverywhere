use super::{
    ApiError, AppState, EngineRuntime, EngineRuntimeStatus, InstanceMetadata,
    SESSION_DRAIN_TIMEOUT, docker_error, placement_error, purge_runtime_paths, shared_runtime,
};

pub(super) async fn clear_caches(state: &AppState, metadata: &InstanceMetadata) {
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state
        .instance_runtime_cache
        .remove(metadata.runtime_id())
        .await;
    state
        .resource_cache
        .invalidate_disk(&metadata.instance_id)
        .await;
    state
        .resource_cache
        .invalidate_disk(metadata.runtime_id())
        .await;
}

pub(super) async fn drain_tenant_sessions(
    state: &AppState,
    instance_id: &str,
) -> Result<(), ApiError> {
    if crate::instances::sessions::fence_and_wait(
        &state.instances,
        &state.gateway_supervisor.tenant_sessions(),
        instance_id,
        SESSION_DRAIN_TIMEOUT,
    )
    .await
    {
        return Ok(());
    }
    Err(ApiError::Conflict(
        "shared tenant gateway sessions did not drain before the lifecycle deadline; the tenant remains fenced"
            .to_string(),
    ))
}

pub(super) async fn maintain_pool_after_delete(state: &AppState, deleted_from: EngineRuntime) {
    let runtime = match state.placements.get(&deleted_from.runtime_id).await {
        Ok(Some(runtime)) => runtime,
        Ok(None) => {
            let containment = super::super::containment::contain_locked(
                state,
                &deleted_from,
                "tenant deletion released capacity but its shared runtime disappeared",
            )
            .await;
            tracing::error!(
                event = "audit shared_runtime_cleanup_failed",
                runtime_id = %deleted_from.runtime_id,
                containment = %containment.summary(),
                contained = containment.contained(),
                "tenant deletion completed but its shared runtime disappeared"
            );
            return;
        }
        Err(error) => {
            let containment = super::super::containment::contain_locked(
                state,
                &deleted_from,
                "tenant deletion released capacity but the shared runtime could not be reloaded",
            )
            .await;
            tracing::error!(
                event = "audit shared_runtime_cleanup_failed",
                runtime_id = %deleted_from.runtime_id,
                %error,
                containment = %containment.summary(),
                contained = containment.contained(),
                "tenant deletion completed but the shared runtime could not be reloaded"
            );
            return;
        }
    };
    // Only the empty path persists `Deleting`; doing so for a live pool would
    // let a crash strand its remaining tenants before limits were reapplied.
    let result = match state.placements.tenant_count(&runtime.runtime_id).await {
        Ok(_) => {
            shared_runtime::apply_limits(&state.docker, &state.config, &state.placements, &runtime)
                .await
                .map_err(ApiError::Runtime)
        }
        Err(error) => Err(placement_error(error)),
    };
    if let Err(error) = result {
        let containment = super::super::containment::contain_locked(
            state,
            &runtime,
            "tenant deletion left aggregate shared-pool limits uncertain",
        )
        .await;
        tracing::error!(
            event = "audit shared_runtime_cleanup_failed",
            runtime_id = %runtime.runtime_id,
            %error,
            containment = %containment.summary(),
            contained = containment.contained(),
            "tenant deletion completed but the shared pool required fail-closed containment"
        );
    }
}

/// Delete a physical shared pool only while its durable reservation count is
/// zero. The caller holds the runtime lock across the final count and cleanup.
pub(crate) async fn delete_empty_pool(
    state: &AppState,
    runtime_id: &str,
) -> Result<bool, ApiError> {
    let Some(mut runtime) = state
        .placements
        .get(runtime_id)
        .await
        .map_err(placement_error)?
    else {
        return Ok(false);
    };
    if state
        .placements
        .tenant_count(runtime_id)
        .await
        .map_err(placement_error)?
        != 0
    {
        return Ok(false);
    }
    runtime.status = EngineRuntimeStatus::Deleting;
    runtime.updated_at = crate::shared::time::now_rfc3339();
    state
        .placements
        .save(&runtime)
        .await
        .map_err(placement_error)?;
    match state
        .docker
        .delete(runtime.protocol, &runtime.runtime_id)
        .await
    {
        Ok(_) => {}
        Err(error) if error.is_not_found() => {}
        Err(error) => return Err(docker_error(error)),
    }
    purge_runtime_paths(state, &runtime).await?;
    let deleted = state
        .placements
        .delete(&runtime.runtime_id)
        .await
        .map_err(placement_error)?;
    state
        .instance_runtime_cache
        .remove(&runtime.runtime_id)
        .await;
    state
        .resource_cache
        .invalidate_runtime(&runtime.runtime_id)
        .await;
    state.soft_disk_limiter.remove(&runtime.runtime_id).await;
    state.install_progress.remove(&runtime.runtime_id);
    tracing::info!(
        event = "audit empty_shared_runtime_deleted",
        runtime_id = %runtime.runtime_id,
        protocol = %runtime.protocol,
    );
    Ok(deleted)
}
