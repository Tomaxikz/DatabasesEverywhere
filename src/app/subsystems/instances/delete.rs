use super::docker_error;
use super::purge::purge_instance_paths;
use super::runtime_info::{DeleteInstanceQuery, DeleteResponse};
use super::{deployment, shared};
use crate::auth::scopes;
use crate::routes::http::policy::{
    ApiRequestContext, DestructiveActionConfirmation, DestructiveActionPolicy,
};
use crate::routes::http::response::{ApiError, ApiPath, ApiQuery, ApiResponse, ApiResult};
use crate::routes::http::router::AppState;
use crate::server::metadata::{DesiredInstanceState, InstanceStatus};
use crate::utils::time::now_rfc3339;
use axum::extract::State;

pub async fn delete_instance(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<DeleteInstanceQuery>,
) -> ApiResult<DeleteResponse> {
    auth.require_scope(scopes::INSTANCES_WRITE)?;
    let _operation = state.instance_locks.lock(&instance_id).await;
    let mut metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let purge_authorization = DestructiveActionPolicy::authorize(
        "instance deletion",
        &DestructiveActionConfirmation {
            confirm: query.confirm,
            reason: query.reason,
        },
    )?;
    deployment::ensure_no_active_migration(&state, &instance_id).await?;

    if metadata.deployment_mode == crate::server::placement::DeploymentMode::Shared {
        return shared::delete(&state, metadata, purge_authorization.reason()).await;
    }

    metadata.status = deletion_status(metadata.status);
    metadata.desired_state = DesiredInstanceState::Stopped;
    metadata.updated_at = now_rfc3339();
    state
        .manager
        .upsert(metadata.clone())
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;

    match state
        .docker
        .delete(metadata.protocol, &metadata.instance_id)
        .await
    {
        Ok(_) => {}
        Err(error) if error.is_not_found() => {}
        Err(error) => return Err(docker_error(error)),
    }
    if let Err(error) = purge_instance_paths(&state, &metadata.instance_id).await {
        tracing::error!(
            event = "audit instance_purge_failed",
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            error = %error,
            status = metadata.status.as_str(),
            "instance metadata was retained so purge can be retried"
        );
        return Err(error);
    }
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
    let deleted = state
        .manager
        .delete(&metadata.instance_id)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    state.soft_disk_limiter.remove(&metadata.instance_id).await;
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state
        .resource_cache
        .remove_tenant(&metadata.instance_id)
        .await;
    state.install_progress.remove(&metadata.instance_id);
    tracing::info!(
        event = "audit instance_deleted",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        purge = true,
        purge_reason = purge_authorization.reason(),
    );

    Ok(ApiResponse::ok(DeleteResponse {
        instance_id,
        deleted,
        purged: true,
    }))
}

pub(super) fn deletion_status(current: InstanceStatus) -> InstanceStatus {
    if current == InstanceStatus::Quarantined {
        InstanceStatus::Quarantined
    } else {
        InstanceStatus::Deleting
    }
}
