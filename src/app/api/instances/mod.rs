pub mod create;
pub mod images;
pub mod progress;
pub mod requests;

pub(crate) mod containment;
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
use crate::compatibility::normalize_database_version;
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
    api::{
        http::{
            diagnostics::PublicDiagnostic,
            policy::{ApiRequestContext, DestructiveActionConfirmation, DestructiveActionPolicy},
            response::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResponse, ApiResult},
            router::AppState,
        },
        instances::{
            create::{
                backend_endpoint, create_instance_from_request, enforce_node_allocation_policy,
                harden_mysql_tenant_auth, harden_postgres_instance_auth,
                launch_container_from_spec, prepare_instance_container_user, protocol_pids_limit,
                provision_mongodb_tenant_user, provision_mysql_tenant_user,
                provision_postgres_tenant_role, resolve_image,
            },
            images::{check_image_allowed, validate_image},
            progress::{BeginCreationError, InstallProgress, InstallProgressStatus},
            requests::{
                CreateInstanceRequest, LimitsRequest, limits_from_request, validate_create_config,
                validate_create_request, validate_limits, validate_protocol_limits,
            },
        },
    },
    auth::scopes,
    databases,
    disk::DiskLimiter,
    instances::{
        metadata::{
            DesiredInstanceState, InstanceDatabaseVersion, InstanceImageStatus, InstanceMetadata,
            InstanceStatus,
        },
        paths::InstancePaths,
        reconcile,
    },
    runtime::docker::{
        DockerContainerStatus, DockerError, DockerInstanceInspection, DockerInstanceSpec,
        DockerRuntime,
    },
    shared::{limits::mib_to_bytes, protocol::Protocol, redaction, time::now_rfc3339},
};
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

pub(crate) use purge::{
    purge_instance_paths, purge_provisional_runtime_paths, purge_retired_runtime_paths,
    purge_runtime_paths, purge_shared_tenant_paths, retained_instance_volume_paths,
};

const IMAGE_UPDATE_ROLLBACK_TIMEOUT: Duration = Duration::from_secs(180);

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
    if metadata.deployment_mode == crate::placement::DeploymentMode::Shared {
        return shared::reconcile(state, metadata).await;
    }
    let metadata = reconcile::reconcile_one(metadata, &state.docker).await;
    state
        .manager
        .upsert(metadata.clone())
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

pub async fn update_instance_image(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiJson(request): ApiJson<UpdateInstanceImageRequest>,
) -> ApiResult<UpdateInstanceImageResponse> {
    auth.require_scope(scopes::INSTANCES_WRITE)?;
    let image = validate_image(&request.image)?.to_string();
    let _operation = state.instance_locks.lock(&instance_id).await;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    deployment::ensure_no_active_migration(&state, &instance_id).await?;
    if metadata.deployment_mode == crate::placement::DeploymentMode::Shared {
        return Err(ApiError::Conflict(
            "shared tenant images are managed by pool placement; migrate the tenant to a compatible pool instead of recreating its runtime"
                .to_string(),
        ));
    }
    if metadata.status == InstanceStatus::Quarantined {
        return Err(ApiError::Conflict(
            "quarantined instances cannot be updated or migrated; inspect the quarantine cause and repair or recover the instance offline"
                .to_string(),
        ));
    }
    if metadata.desired_state == DesiredInstanceState::Stopped {
        return Err(ApiError::Conflict(
            "stopped instances cannot be updated in place; start the instance before updating its image"
                .to_string(),
        ));
    }
    let current_image = state
        .docker
        .container_image(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(docker_error)
        .map_err(|error| fail_image_update_api(&state, &metadata.instance_id, error))?
        .ok_or_else(|| {
            fail_image_update_api(
                &state,
                &metadata.instance_id,
                ApiError::BadRequest(
                    "current container image could not be inspected; reconcile the instance before updating the image".to_string(),
                ),
            )
        })?;
    update_instance_image_locked(
        state,
        _operation,
        metadata,
        current_image,
        image,
        request.major_upgrade,
        request.password,
    )
    .await
    .map(ApiResponse::ok)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn update_instance_image_locked(
    state: AppState,
    operation: tokio::sync::OwnedMutexGuard<()>,
    metadata: InstanceMetadata,
    current_image: String,
    image: String,
    major_upgrade: bool,
    password: Option<String>,
) -> Result<UpdateInstanceImageResponse, ApiError> {
    check_image_allowed(&state, metadata.protocol, &image)?;
    if major_upgrade {
        return run_upgrade_supervisor(
            state.clone(),
            operation,
            metadata,
            current_image,
            image,
            password,
        )
        .await;
    }
    run_image_update(state, operation, metadata, current_image, image, password).await
}

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

    if metadata.deployment_mode == crate::placement::DeploymentMode::Shared {
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

fn deletion_status(current: InstanceStatus) -> InstanceStatus {
    if current == InstanceStatus::Quarantined {
        InstanceStatus::Quarantined
    } else {
        InstanceStatus::Deleting
    }
}

pub async fn update_instance_limits(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiJson(request): ApiJson<LimitsRequest>,
) -> ApiResult<InstanceMetadata> {
    auth.require_scope(scopes::INSTANCES_WRITE)?;
    if request.disk_mib == 0 || request.disk_mib > u64::MAX / (1024 * 1024) {
        return Err(ApiError::BadRequest("disk_mib must be positive".into()));
    }
    let mutation = state
        .daemon_shutdown
        .try_admit_background_mutation()
        .ok_or_else(|| {
            ApiError::ServiceUnavailable(
                "daemon shutdown has started; limit updates are not accepted".to_string(),
            )
        })?;
    // Waiting for locks is cancellable and changes nothing. Detach only once
    // admitted, so abandoned requests cannot accumulate background waiters.
    let creation = state.instance_locks.lock_creation().await;
    let operation = state.instance_locks.lock(&instance_id).await;
    // The worker owns the locks through commit or ordinary error rollback.
    spawn_owned_mutation_task(async move {
        let _mutation = mutation;
        let _operation = operation;
        let result = resize_instance(&state, &instance_id, request, creation).await;
        if let Err(error) = &result {
            tracing::warn!(event = "audit instance_limits_update_failed", %instance_id, %error,
                "instance limit update failed");
        }
        result
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("limit update worker failed: {error}")))?
}

async fn resize_instance(
    state: &AppState,
    instance_id: &str,
    request: LimitsRequest,
    creation: tokio::sync::OwnedMutexGuard<()>,
) -> ApiResult<InstanceMetadata> {
    let mut metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    deployment::ensure_no_active_migration(state, instance_id).await?;
    if metadata.deployment_mode == crate::placement::DeploymentMode::Dedicated {
        validate_limits(&request)?;
        validate_protocol_limits(metadata.protocol, &request)?;
    }
    let limits = limits_from_request(&request);
    let previous_limits = metadata.limits.clone();
    if metadata.deployment_mode == crate::placement::DeploymentMode::Shared {
        return shared::resize(state, metadata, limits, creation)
            .await
            .map(ApiResponse::ok);
    }
    enforce_node_allocation_policy(state, &limits, Some(&previous_limits)).await?;
    let disk_changed = limits.disk_mib != previous_limits.disk_mib;
    let paths = if disk_changed {
        Some(
            InstancePaths::new(&state.config.paths, &metadata.instance_id)
                .map_err(|error| ApiError::BadRequest(error.to_string()))?,
        )
    } else {
        None
    };
    let effective_disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
            .for_persisted_protocol(metadata.protocol, &metadata.limits.disk_enforcement_method);
    if let Some(paths) = paths.as_ref() {
        effective_disk_limiter
            .check_method_change(&metadata.limits.disk_enforcement_method)
            .map_err(|error| ApiError::Conflict(error.to_string()))?;
        if crate::config::DiskLimitMode::from_persisted_method(
            &metadata.limits.disk_enforcement_method,
        ) != Some(effective_disk_limiter.mode())
        {
            return Err(ApiError::Conflict(format!(
                "instance currently uses {} disk enforcement but this node selects {}; restart dbev to reconcile or safely recreate/migrate the container before changing its disk limit",
                metadata.limits.disk_enforcement_method,
                effective_disk_limiter.mode().method(),
            )));
        }
        let expected_data_source = effective_disk_limiter
            .container_data_path(&paths.data)
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        match state
            .docker
            .verify_data_bind(
                metadata.protocol,
                &metadata.instance_id,
                &expected_data_source,
            )
            .await
        {
            Ok(()) => {}
            Err(error @ crate::runtime::docker::DockerError::DiskBindSourceMismatch { .. }) => {
                return Err(ApiError::Conflict(error.to_string()));
            }
            Err(error) => return Err(docker_error(error)),
        }
        if let Err(error) = effective_disk_limiter
            .update_instance_limit(&metadata.instance_id, &paths.data, limits.disk_mib)
            .await
        {
            let rollback =
                rollback_disk_limit(state, &metadata, paths, previous_limits.disk_mib).await;
            return Err(ApiError::Runtime(format!(
                "failed to update disk limit: {error}; rollback: {rollback}"
            )));
        }
    }

    if let Err(error) = state
        .docker
        .update_limits(
            metadata.protocol,
            &metadata.instance_id,
            limits.cpu_cores,
            limits.memory_mib,
        )
        .await
    {
        let rollback = rollback_instance_limits(
            state,
            &metadata,
            &previous_limits,
            paths.as_ref(),
            disk_changed,
        )
        .await;
        return Err(ApiError::Runtime(format!(
            "failed to update runtime limits: {error}; rollback: {rollback}"
        )));
    }

    metadata.limits.cpu_cores = limits.cpu_cores;
    metadata.limits.memory_mib = limits.memory_mib;
    metadata.limits.disk_mib = limits.disk_mib;
    if disk_changed {
        let effective_disk_mode = effective_disk_limiter.mode();
        metadata.limits.disk_enforced = effective_disk_mode.enforced();
        if effective_disk_mode == crate::config::DiskLimitMode::SoftScanner
            && metadata.disk_limit_blocked
            && limits.disk_mib > previous_limits.disk_mib
        {
            if let Some(paths) = paths.as_ref()
                && state
                    .soft_disk_limiter
                    .ensure_start_allowed(&crate::disk::soft::SoftDiskTarget {
                        instance_id: metadata.instance_id.clone(),
                        created_at: metadata.created_at.clone(),
                        protocol: metadata.protocol,
                        data_path: paths.data.clone(),
                        limit_bytes: mib_to_bytes(limits.disk_mib),
                        durable_blocked: true,
                    })
                    .await
                    .is_ok()
            {
                metadata.disk_limit_blocked = false;
            }
        } else if effective_disk_mode != crate::config::DiskLimitMode::SoftScanner {
            metadata.disk_limit_blocked = false;
        }
    }
    metadata.updated_at = now_rfc3339();
    if let Err(error) = state.manager.upsert(metadata.clone()).await {
        let rollback = rollback_instance_limits(
            state,
            &metadata,
            &previous_limits,
            paths.as_ref(),
            disk_changed,
        )
        .await;
        return Err(ApiError::Runtime(format!(
            "failed to persist updated limits: {error}; rollback: {rollback}"
        )));
    }
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    if metadata.limits.disk_enforcement_method != "soft_scanner"
        && !(metadata.protocol == Protocol::Qdrant
            && metadata.limits.disk_enforcement_method == "fuse_quota")
    {
        state.soft_disk_limiter.remove(&metadata.instance_id).await;
    }

    tracing::info!(
        event = "audit instance_limits_updated",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        cpu_cores = metadata.limits.cpu_cores,
        memory_mib = metadata.limits.memory_mib,
        disk_mib = metadata.limits.disk_mib,
    );

    Ok(ApiResponse::ok(metadata))
}

async fn rollback_instance_limits(
    state: &AppState,
    metadata: &InstanceMetadata,
    previous: &crate::shared::limits::InstanceLimits,
    paths: Option<&InstancePaths>,
    disk_changed: bool,
) -> String {
    let mut failures = Vec::new();
    if let Err(error) = state
        .docker
        .update_limits(
            metadata.protocol,
            &metadata.instance_id,
            previous.cpu_cores,
            previous.memory_mib,
        )
        .await
    {
        failures.push(format!("runtime rollback failed: {error}"));
    }
    if disk_changed
        && let Some(paths) = paths
        && let Err(error) =
            DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
                .for_persisted_protocol(metadata.protocol, &metadata.limits.disk_enforcement_method)
                .update_instance_limit(&metadata.instance_id, &paths.data, previous.disk_mib)
                .await
    {
        failures.push(format!("disk rollback failed: {error}"));
    }
    report_limit_rollback(&metadata.instance_id, failures)
}

async fn rollback_disk_limit(
    state: &AppState,
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    disk_mib: u64,
) -> String {
    let failures =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
            .for_persisted_protocol(metadata.protocol, &metadata.limits.disk_enforcement_method)
            .update_instance_limit(&metadata.instance_id, &paths.data, disk_mib)
            .await
            .err()
            .map(|error| vec![format!("disk rollback failed: {error}")])
            .unwrap_or_default();
    report_limit_rollback(&metadata.instance_id, failures)
}

fn report_limit_rollback(instance_id: &str, failures: Vec<String>) -> String {
    if failures.is_empty() {
        return "completed".to_string();
    }
    let failures = failures.join("; ");
    tracing::error!(
        event = "audit instance_limits_rollback_failed",
        instance_id,
        failures,
        "external limits may require operator reconciliation"
    );
    failures
}

pub async fn instance_logs(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<LogsQuery>,
) -> ApiResult<LogsResponse> {
    auth.require_scope(scopes::LOGS_READ)?;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    check_logs_available(&metadata)?;
    let output = state
        .docker
        .logs(metadata.protocol, &metadata.instance_id, query.tail)
        .await
        .map_err(docker_error)?;
    Ok(ApiResponse::ok(LogsResponse {
        instance_id,
        stdout: redaction::redact_connection_url(&output.stdout),
        stderr: redaction::redact_connection_url(&output.stderr),
    }))
}

pub(crate) fn check_logs_available(metadata: &InstanceMetadata) -> Result<(), ApiError> {
    if metadata.deployment_mode == crate::placement::DeploymentMode::Shared {
        Err(shared::reject_logs())
    } else {
        Ok(())
    }
}

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
    if metadata.deployment_mode == crate::placement::DeploymentMode::Shared {
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
    let mut metadata_changed = false;
    if metadata.status == InstanceStatus::Quarantined
        && matches!(action, LifecycleAction::Start | LifecycleAction::Restart)
    {
        return Err(ApiError::Conflict(
            "instance is quarantined for fail-closed safety; inspect job history and logs, then repair, recover, or delete it before attempting to start it"
                .to_string(),
        ));
    }
    if matches!(action, LifecycleAction::Start | LifecycleAction::Restart) {
        let disk_limiter =
            DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
                .for_persisted_protocol(
                    metadata.protocol,
                    &metadata.limits.disk_enforcement_method,
                );
        disk_limiter
            .check_method_change(&metadata.limits.disk_enforcement_method)
            .map_err(|error| ApiError::Conflict(error.to_string()))?;
        check_disk_method(&disk_limiter, &metadata)?;
        let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
            .map_err(|error| ApiError::BadRequest(error.to_string()))?;
        let expected_data_source = disk_limiter
            .container_data_path(&paths.data)
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        match state
            .docker
            .verify_data_bind(
                metadata.protocol,
                &metadata.instance_id,
                &expected_data_source,
            )
            .await
        {
            Ok(()) => {}
            Err(error @ crate::runtime::docker::DockerError::DiskBindSourceMismatch { .. }) => {
                return Err(ApiError::Conflict(format!(
                    "{error}; repair/recreate the managed container before starting it"
                )));
            }
            Err(error) => return Err(docker_error(error)),
        }
        let scanner_required = crate::disk::soft::SoftDiskLimiter::enforcement_required(
            state.config.disk.mode,
            metadata.protocol,
        ) || (metadata.protocol == Protocol::Qdrant
            && metadata.limits.disk_enforcement_method == "fuse_quota");
        if scanner_required {
            let snapshot = state
                .soft_disk_limiter
                .ensure_start_allowed(&crate::disk::soft::SoftDiskTarget {
                    instance_id: metadata.instance_id.clone(),
                    created_at: metadata.created_at.clone(),
                    protocol: metadata.protocol,
                    data_path: paths.data,
                    limit_bytes: mib_to_bytes(metadata.limits.disk_mib),
                    durable_blocked: metadata.disk_limit_blocked,
                })
                .await
                .map_err(ApiError::Conflict)?;
            if metadata.disk_limit_blocked && !snapshot.blocked {
                metadata.disk_limit_blocked = false;
                metadata.updated_at = now_rfc3339();
                metadata_changed = true;
            }
        }
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

fn check_disk_method(limiter: &DiskLimiter, metadata: &InstanceMetadata) -> Result<(), ApiError> {
    if crate::config::DiskLimitMode::from_persisted_method(&metadata.limits.disk_enforcement_method)
        == Some(limiter.mode())
    {
        return Ok(());
    }
    Err(ApiError::Conflict(format!(
        "instance currently uses {} disk enforcement but this node selects {}; restart dbev to reconcile or safely recreate/migrate it before activation",
        metadata.limits.disk_enforcement_method,
        limiter.mode().method(),
    )))
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

    if metadata.deployment_mode == crate::placement::DeploymentMode::Shared {
        return shared::change_state(state, metadata, action).await;
    }

    if metadata.status == InstanceStatus::Quarantined
        && matches!(action, LifecycleAction::Start | LifecycleAction::Restart)
    {
        return Err(ApiError::Conflict(
            "instance is quarantined for fail-closed safety; inspect job history and logs, then repair, recover, or delete it before attempting to start it"
                .to_string(),
        ));
    }

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

    let mut startup_readiness_failed = false;
    if matches!(action, LifecycleAction::Start | LifecycleAction::Restart) {
        route_fence::fence(state, &metadata.instance_id).await;
    }
    let operation_result: Result<(), ApiError> = async {
        if should_call_docker {
            if matches!(action, LifecycleAction::Start | LifecycleAction::Restart) {
                let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
                    .map_err(|error| ApiError::BadRequest(error.to_string()))?;
                let disk_limiter = DiskLimiter::with_fuse_root(
                    state.config.disk.clone(),
                    state.config.paths.fuse_root(),
                )
                .for_persisted_protocol(
                    metadata.protocol,
                    &metadata.limits.disk_enforcement_method,
                );
                disk_limiter
                    .check_method_change(&metadata.limits.disk_enforcement_method)
                    .map_err(|error| ApiError::Conflict(error.to_string()))?;
                check_disk_method(&disk_limiter, &metadata)?;
                let expected_data_source = disk_limiter
                    .container_data_path(&paths.data)
                    .map_err(|error| ApiError::Runtime(error.to_string()))?;
                match state
                    .docker
                    .verify_data_bind(
                        metadata.protocol,
                        &metadata.instance_id,
                        &expected_data_source,
                    )
                    .await
                {
                    Ok(()) => {}
                    Err(
                        error @ crate::runtime::docker::DockerError::DiskBindSourceMismatch {
                            ..
                        },
                    ) => {
                        return Err(ApiError::Conflict(error.to_string()));
                    }
                    Err(error) => return Err(docker_error(error)),
                }
                let scanner_required = crate::disk::soft::SoftDiskLimiter::enforcement_required(
                    state.config.disk.mode,
                    metadata.protocol,
                ) || (metadata.protocol == Protocol::Qdrant
                    && metadata.limits.disk_enforcement_method == "fuse_quota");
                if scanner_required {
                    let snapshot = state
                        .soft_disk_limiter
                        .ensure_start_allowed(&crate::disk::soft::SoftDiskTarget {
                            instance_id: metadata.instance_id.clone(),
                            created_at: metadata.created_at.clone(),
                            protocol: metadata.protocol,
                            data_path: paths.data.clone(),
                            limit_bytes: mib_to_bytes(metadata.limits.disk_mib),
                            durable_blocked: metadata.disk_limit_blocked,
                        })
                        .await
                        .map_err(ApiError::Conflict)?;
                    if metadata.disk_limit_blocked && !snapshot.blocked {
                        metadata.disk_limit_blocked = false;
                        metadata.updated_at = now_rfc3339();
                        state
                            .manager
                            .upsert(metadata.clone())
                            .await
                            .map_err(|error| {
                                ApiError::Runtime(format!(
                                    "failed to clear recovered disk-limit block: {error}"
                                ))
                            })?;
                    }
                }
                disk_limiter
                    .apply_instance_limit(
                        &metadata.instance_id,
                        &paths.data,
                        metadata.limits.disk_mib,
                    )
                    .await
                    .map_err(|error| ApiError::Runtime(error.to_string()))?;
            }
            let refresh_console = matches!(action, LifecycleAction::Start | LifecycleAction::Restart)
                && !state.docker.log_policy_is_current(metadata.protocol, &metadata.instance_id).await.map_err(docker_error)?;
            if refresh_console {
                let image = state.docker.container_recreation_image(metadata.protocol, &metadata.instance_id).await.map_err(docker_error)?
                    .ok_or_else(|| ApiError::Conflict("console-policy repair cannot preserve the installed image; update the image explicitly first".into()))?;
                metadata = normal_image_update::update_instance_image_normal(state.clone(), metadata.clone(), image.clone(), image, None).await?.instance;
            } else { match action {
                LifecycleAction::Start => {
                    state
                        .docker
                        .start(metadata.protocol, &metadata.instance_id)
                        .await
                }
                LifecycleAction::Stop => {
                    state
                        .docker
                        .stop(metadata.protocol, &metadata.instance_id)
                        .await
                }
                LifecycleAction::Restart => {
                    state
                        .docker
                        .restart(metadata.protocol, &metadata.instance_id)
                        .await
                }
                LifecycleAction::Kill => {
                    state
                        .docker
                        .kill(metadata.protocol, &metadata.instance_id)
                        .await
                }
            }
            .map_err(docker_error)?; }
        }

        if matches!(action, LifecycleAction::Start | LifecycleAction::Restart) {
            if let Err(error) = state
                .docker
                .wait_until_ready(
                    metadata.protocol,
                    &metadata.instance_id,
                    Duration::from_secs(120),
                )
                .await
            {
                startup_readiness_failed = true;
                return Err(docker_error(error));
            }
            if metadata.protocol == Protocol::Postgres {
                let Some(password) = metadata.tenant_password.as_deref() else {
                    startup_readiness_failed = true;
                    return Err(ApiError::Conflict(
                        "the encrypted PostgreSQL tenant credential is missing; reset or recreate this legacy instance before starting it".to_string(),
                    ));
                };
                let Some(admin_password) = metadata.postgres_admin_password.as_deref() else {
                    startup_readiness_failed = true;
                    return Err(ApiError::Conflict(
                        "the encrypted PostgreSQL administrator credential is missing; restart the daemon to migrate this legacy instance before starting it".to_string(),
                    ));
                };
                if let Err(error) = harden_postgres_instance_auth(
                    state,
                    &metadata.instance_id,
                    &metadata.database.name,
                    &metadata.database.username,
                    password,
                    admin_password,
                )
                .await
                {
                    startup_readiness_failed = true;
                    return Err(error);
                }
            }
            if metadata.protocol == Protocol::Mysql {
                let Some(password) = metadata.tenant_password.as_deref() else {
                    startup_readiness_failed = true;
                    return Err(ApiError::Conflict(
                        "the encrypted MySQL tenant credential is missing; reset or recreate this legacy instance before starting it".to_string(),
                    ));
                };
                let Some(root_password) = metadata.mysql_root_password.as_deref() else {
                    startup_readiness_failed = true;
                    return Err(ApiError::Conflict(
                        "the encrypted MySQL maintenance credential is missing; recreate this legacy instance before starting it".to_string(),
                    ));
                };
                if let Err(error) = harden_mysql_tenant_auth(
                    state,
                    &metadata.instance_id,
                    &metadata.database.username,
                    password,
                    root_password,
                )
                .await
                {
                    startup_readiness_failed = true;
                    return Err(error);
                }
            }
            if let Err(error) = verify_resp_credential(state, &metadata).await {
                startup_readiness_failed = true;
                return Err(error);
            }
            let compatibility = crate::compatibility::probe_instance_compatibility(
                &state.manager,
                &state.docker,
                &metadata,
                false,
            )
            .await
            .map_err(|error| {
                startup_readiness_failed = true;
                ApiError::Runtime(format!(
                    "database compatibility attestation failed during activation: {error}"
                ))
            })?;
            if !compatibility.compatible {
                startup_readiness_failed = true;
                return Err(ApiError::Conflict(
                    compatibility
                        .diagnostic
                        .unwrap_or_else(|| "database engine version is unsupported".to_string()),
                ));
            }
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

    let mut metadata = reconcile::reconcile_one(metadata, &state.docker).await;
    if startup_readiness_failed {
        metadata.status = InstanceStatus::Failed;
        metadata.updated_at = now_rfc3339();
    }
    let persistence_result = state.manager.upsert(metadata.clone()).await;
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

async fn rollback_runtime_state(
    state: &AppState,
    metadata: &InstanceMetadata,
    should_be_running: bool,
) -> String {
    let result = if should_be_running {
        state
            .docker
            .start(metadata.protocol, &metadata.instance_id)
            .await
    } else {
        state
            .docker
            .stop(metadata.protocol, &metadata.instance_id)
            .await
    };
    match result {
        Ok(_) => "completed".to_string(),
        Err(error) if !should_be_running && error.is_not_running() => "completed".to_string(),
        Err(error) => {
            tracing::error!(
                event = "audit lifecycle_rollback_failed",
                instance_id = %metadata.instance_id,
                %error,
                "runtime may require operator reconciliation"
            );
            format!("failed: {error}")
        }
    }
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
