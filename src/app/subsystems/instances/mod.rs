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
use runtime_info::{
    MajorUpgradePrecheck, fail_image_update_api, fail_image_update_bad_request,
    fail_image_update_runtime,
};

pub use deployment::{
    StartDeploymentMigrationRequest, get_deployment_migration, list_deployment_migrations,
    start_deployment_migration,
};
pub(crate) use deployment::{
    fence_active_routes_on_boot as fence_active_deployment_migration_routes,
    recover_on_boot as recover_deployment_migrations,
};
use major_upgrade::*;
#[cfg(test)]
use normal_image_update::quarantine_image_metadata;
use normal_image_update::{image_quarantine_summary, image_update_spec, quarantine_image_update};
pub(crate) use normal_image_update::{run_image_update, spawn_owned_mutation_task};
pub(crate) use password::verify_resp_credential;
pub use password::{
    ResetInstancePasswordRequest, ResetInstancePasswordResponse, reset_instance_password,
};

use axum::extract::State;
use bollard::errors::Error as BollardError;
use futures::{FutureExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::{
    sync::Mutex,
    time::{Duration as TokioDuration, Instant},
};

use crate::{
    auth::scopes,
    databases::engine::{CredentialKind, LifecycleFlow, PostLaunchStep, UpgradePrecheck},
    databases::protocol::Protocol,
    routes::http::{
        diagnostics::PublicDiagnostic,
        policy::{ApiRequestContext, DestructiveActionConfirmation, DestructiveActionPolicy},
        response::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResponse, ApiResult},
        router::AppState,
    },
    runtime::docker::{
        DockerContainerStatus, DockerError, DockerInstanceInspection, DockerInstanceSpec,
        DockerRuntime,
    },
    server::disk::DiskLimiter,
    server::{
        metadata::{
            DesiredInstanceState, InstanceDatabaseVersion, InstanceImageStatus, InstanceMetadata,
            InstanceStatus,
        },
        paths::InstancePaths,
        reconcile,
    },
    subsystems::instances::{
        create::{
            backend_endpoint, create_instance_from_request, enforce_node_allocation_policy,
            flow_maintenance_credential, launch_container_from_spec, missing_credential_error,
            prepare_instance_container_user, protocol_pids_limit, provision_mongodb_tenant_user,
            resolve_image, run_tenant_auth_step,
        },
        images::{check_image_allowed, validate_image},
        progress::{BeginCreationError, InstallProgress, InstallProgressStatus},
        requests::{
            CreateInstanceRequest, LimitsRequest, limits_from_request, validate_create_config,
            validate_create_request, validate_limits, validate_protocol_limits,
        },
    },
    utils::{limits::mib_to_bytes, redaction, time::now_rfc3339},
};
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

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
pub use delete::*;
pub use image_update::*;
pub use lifecycle::*;
pub use limits::*;
pub use logs::*;
use start_checks::*;
use startup::*;

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
