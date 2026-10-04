pub mod create;
pub mod images;
pub mod progress;
pub mod requests;

pub(crate) use crate::server::placement::containment;
mod deployment;
pub(crate) mod major_upgrade;
mod normal_image_update;
mod password;
mod purge;
pub(crate) mod route_fence;
mod runtime_info;
mod shared;
pub(crate) use shared::{
    delete_empty_pool, recover_deleting as recover_shared_deletions, reload_after_runtime_lock,
};

#[cfg(test)]
use crate::server::compatibility::normalize_database_version;
pub use runtime_info::{
    CreateInstanceAcceptedResponse, DeleteInstanceQuery, DeleteResponse, ImageUpdateStrategy,
    InstanceRuntimeInfoCache, InstanceStatusResponse, LogsQuery, LogsResponse, PowerRequest,
    PowerResponse, ReconcileResponse, UpdateInstanceImageRequest, UpdateInstanceImageResponse,
    create_instance, get_instance, get_instance_status, list_instances,
};

pub use deployment::{
    StartDeploymentMigrationRequest, get_deployment_migration, list_deployment_migrations,
    start_deployment_migration,
};
pub(crate) use deployment::{
    fence_active_routes_on_boot as fence_active_deployment_migration_routes,
    recover_on_boot as recover_deployment_migrations,
};

use normal_image_update::image_update_spec;
#[cfg(test)]
use normal_image_update::quarantine_image_metadata;
pub(crate) use normal_image_update::{run_image_update, spawn_owned_mutation_task};
pub(crate) use password::verify_resp_credential;
pub use password::{
    ResetInstancePasswordRequest, ResetInstancePasswordResponse, reset_instance_password,
};

use axum::extract::State;
use bollard::errors::Error as BollardError;

use crate::{
    auth::scopes,
    routes::http::{
        policy::ApiRequestContext,
        response::{ApiError, ApiJson, ApiPath, ApiResponse, ApiResult},
        router::AppState,
    },
    runtime::docker::DockerError,
    server::{metadata::InstanceMetadata, reconcile},
};
use std::time::Duration;

pub(crate) use purge::{
    purge_instance_paths, purge_provisional_runtime_paths, purge_retired_runtime_paths,
    purge_runtime_paths, purge_shared_tenant_paths, retained_instance_volume_paths,
};

const IMAGE_UPDATE_ROLLBACK_TIMEOUT: Duration = Duration::from_secs(180);
const STARTUP_READINESS_TIMEOUT: Duration = Duration::from_secs(120);

mod delete;
mod image_update;
mod lifecycle;
mod limits;
mod logs;
mod start_checks;
mod startup;
pub use delete::delete_instance;
pub use image_update::update_instance_image;
pub(crate) use image_update::update_instance_image_locked;
pub use lifecycle::LifecycleAction;
use lifecycle::change_instance_state;
pub(crate) use lifecycle::change_instance_state_locked;
pub use limits::update_instance_limits;
pub(crate) use logs::check_logs_available;
pub use logs::instance_logs;

pub async fn reconcile_instance(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
) -> ApiResult<ReconcileResponse> {
    auth.require_scope(scopes::INSTANCES_WRITE)?;
    let _operation = state.instance_locks.lock(&instance_id).await;
    let metadata = reconcile_instance_locked(&state, &instance_id).await?;
    Ok(ApiResponse::ok(ReconcileResponse {
        instance_id,
        status: metadata.status,
    }))
}

pub(crate) async fn reconcile_instance_locked(
    state: &AppState,
    instance_id: &str,
) -> Result<InstanceMetadata, ApiError> {
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    deployment::ensure_no_active_migration(state, instance_id).await?;
    if metadata.deployment_mode == crate::server::placement::DeploymentMode::Shared {
        return shared::reconcile(state, metadata).await;
    }
    let previous = metadata.status;
    let metadata = reconcile::reconcile_one(metadata, &state.docker).await;
    reconcile::persist_reconciled(&state.manager, previous, metadata.clone())
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state
        .resource_cache
        .invalidate_runtime(&metadata.instance_id)
        .await;
    Ok(metadata)
}

pub async fn power_instance(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiJson(request): ApiJson<PowerRequest>,
) -> ApiResult<PowerResponse> {
    auth.require_scope(scopes::INSTANCES_WRITE)?;
    let action = request.action;
    let instance = change_instance_state(&state, &instance_id, action)
        .await?
        .into_body();
    Ok(ApiResponse::ok(PowerResponse { instance, action }))
}

pub(crate) fn docker_error(error: DockerError) -> ApiError {
    match error {
        DockerError::InvalidId(error) => ApiError::BadRequest(error.to_string()),
        error @ DockerError::UntrustedContainerNameCollision { .. } => {
            ApiError::Conflict(error.to_string())
        }
        DockerError::ManagedContainerNotFound { .. } => ApiError::NotFound,
        DockerError::Api(BollardError::DockerResponseServerError {
            status_code: 404, ..
        }) => ApiError::NotFound,
        DockerError::Api(BollardError::DockerResponseServerError {
            status_code: 409,
            message,
            ..
        }) => ApiError::Conflict(message),
        error => ApiError::Runtime(error.to_string()),
    }
}

#[cfg(test)]
mod tests;
