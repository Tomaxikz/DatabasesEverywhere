use super::super::{DeleteResponse, purge_shared_tenant_paths};
use super::lifecycle::{same_shared_identity, target};
use super::maintenance::{clear_caches, drain_tenant_sessions, maintain_pool_after_delete};
use super::runtime::{load_runtime, reload_after_runtime_lock, shared_runtime_id};
use crate::routes::http::response::{ApiError, ApiResponse, ApiResult};
use crate::routes::http::router::AppState;
use crate::server::metadata::{DesiredInstanceState, InstanceMetadata, InstanceStatus};
use crate::server::placement::{DeploymentMode, EngineRuntime, tenant};
use crate::utils::time::now_rfc3339;

pub(in super::super) async fn delete(
    state: &AppState,
    mut metadata: InstanceMetadata,
    purge_reason: &str,
) -> ApiResult<DeleteResponse> {
    let runtime_id = shared_runtime_id(&metadata)?.to_string();
    let _runtime_operation = state.instance_locks.lock(&runtime_id).await;
    metadata = reload_after_runtime_lock(state, &metadata).await?;
    let runtime = load_runtime(state, &metadata).await?;
    metadata.status = InstanceStatus::Deleting;
    metadata.desired_state = DesiredInstanceState::Stopped;
    metadata.updated_at = now_rfc3339();
    state
        .manager
        .upsert(metadata.clone())
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let result = finish_delete(state, metadata, runtime, purge_reason).await?;
    Ok(ApiResponse::ok(result))
}

pub(super) async fn finish_delete(
    state: &AppState,
    metadata: InstanceMetadata,
    runtime: EngineRuntime,
    purge_reason: &str,
) -> Result<DeleteResponse, ApiError> {
    drain_tenant_sessions(state, &metadata.instance_id).await?;

    tenant::disk::prepare_drop(&state.config, &runtime, target(&metadata))
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to prepare shared tenant storage deletion: {error}"
            ))
        })?;
    tenant::drop_tenant(&state.docker, &runtime, target(&metadata))
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to drop shared tenant: {error}")))?;
    tenant::disk::remove(&state.config, &runtime, target(&metadata))
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to remove shared tenant disk quota: {error}"
            ))
        })?;
    purge_shared_tenant_paths(state, &metadata.instance_id).await?;
    state
        .import_export_jobs
        .delete_for_instance(&metadata.instance_id)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to purge instance jobs: {error}")))?;
    state
        .import_uploads
        .repo()
        .delete_for_instance(&metadata.instance_id)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to purge import uploads: {error}")))?;
    let deleted = match state.manager.delete(&metadata.instance_id).await {
        Ok(deleted) => deleted,
        Err(error) => match state.manager.get_persisted(&metadata.instance_id).await {
            Ok(None) => {
                state.instances.remove(&metadata.instance_id).await;
                tracing::warn!(
                    event = "audit shared_tenant_delete_commit_ack_lost",
                    instance_id = %metadata.instance_id,
                    runtime_id = %runtime.runtime_id,
                    %error,
                );
                true
            }
            Ok(Some(_)) => {
                return Err(ApiError::Runtime(format!(
                    "failed to delete shared tenant metadata: {error}"
                )));
            }
            Err(read_error) => {
                return Err(ApiError::Runtime(format!(
                    "shared tenant data was dropped, but metadata deletion failed ({error}) and durable state could not be verified ({read_error}); the tenant remains fenced"
                )));
            }
        },
    };
    clear_caches(state, &metadata).await;
    // Network counters are cumulative since daemon boot for live tenants, but
    // a deleted identity must release its counter before the ID can be reused.
    state
        .resource_cache
        .remove_tenant(&metadata.instance_id)
        .await;
    state.soft_disk_limiter.remove(&metadata.instance_id).await;
    state.install_progress.remove(&metadata.instance_id);

    maintain_pool_after_delete(state, runtime).await;
    tracing::info!(
        event = "audit shared_tenant_deleted",
        instance_id = %metadata.instance_id,
        runtime_id = %metadata.runtime_id(),
        protocol = %metadata.protocol,
        purge_reason,
    );
    Ok(DeleteResponse {
        instance_id: metadata.instance_id,
        deleted,
        purged: true,
    })
}

/// Finishes tenant deletion records that were made durable before a daemon
/// restart. The same idempotent finisher is used by the API and recovery, so
/// neither path can leave a second cleanup implementation behind.
pub(crate) async fn recover_deleting(state: &AppState) -> usize {
    let snapshots = state
        .instances
        .list()
        .await
        .into_iter()
        .filter(|metadata| {
            metadata.deployment_mode == DeploymentMode::Shared
                && metadata.status == InstanceStatus::Deleting
        })
        .collect::<Vec<_>>();
    let mut recovered = 0;
    for snapshot in snapshots {
        let instance_id = snapshot.instance_id.clone();
        let runtime_id = snapshot.runtime_id().to_string();
        let _tenant_operation = state.instance_locks.lock(&instance_id).await;
        let Some(current) = state.instances.get(&instance_id).await else {
            continue;
        };
        if !is_same_deleting_tenant(&snapshot, &current) {
            continue;
        }
        let _runtime_operation = state.instance_locks.lock(&runtime_id).await;
        let Some(current) = state.instances.get(&instance_id).await else {
            continue;
        };
        if !is_same_deleting_tenant(&snapshot, &current) {
            continue;
        }
        let runtime = match load_runtime(state, &current).await {
            Ok(runtime) => runtime,
            Err(error) => {
                tracing::error!(
                    event = "audit shared_tenant_delete_recovery_failed",
                    %instance_id,
                    %runtime_id,
                    %error,
                    "retained a fenced deleting tenant because its runtime could not be loaded"
                );
                continue;
            }
        };
        match finish_delete(
            state,
            current,
            runtime,
            "daemon boot resumed interrupted shared tenant deletion",
        )
        .await
        {
            Ok(_) => recovered += 1,
            Err(error) => tracing::error!(
                event = "audit shared_tenant_delete_recovery_failed",
                %instance_id,
                %runtime_id,
                %error,
                "retained a fenced deleting tenant so cleanup can be retried on the next boot"
            ),
        }
    }
    recovered
}

pub(super) fn is_same_deleting_tenant(
    snapshot: &InstanceMetadata,
    current: &InstanceMetadata,
) -> bool {
    same_shared_identity(snapshot, current) && current.status == InstanceStatus::Deleting
}
