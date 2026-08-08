mod major_upgrade;
mod runtime_info;

#[cfg(test)]
use runtime_info::normalize_database_version;
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

use major_upgrade::*;

use axum::extract::State;
use bollard::errors::Error as BollardError;
use futures::StreamExt;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::Mutex,
    time::{Duration as TokioDuration, Instant},
};

use crate::{
    api::{
        api_response::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResponse, ApiResult},
        images::{ensure_image_allowed, validate_image},
        instance_create::{
            backend_endpoint_for_instance, create_instance_from_request,
            enforce_node_allocation_policy, launch_container_from_spec,
            prepare_instance_container_user, protocol_pids_limit, provision_mariadb_tenant_user,
            provision_mongodb_tenant_user, provision_mysql_tenant_user,
            provision_postgres_tenant_role, requested_or_configured_image,
        },
        instance_requests::{
            CreateInstanceRequest, LimitsRequest, limits_from_request, validate_create_request,
            validate_limits, validate_protocol_limits,
        },
        progress::{BeginCreationError, InstallProgress, InstallProgressStatus},
        public_diagnostic::PublicDiagnostic,
        routes::AppState,
        security_policy::{
            ApiRequestContext, DestructiveActionConfirmation, DestructiveActionPolicy,
        },
    },
    auth::scopes,
    databases,
    disk::DiskLimiter,
    instances::paths::InstancePaths,
    instances::{
        metadata::InstanceDatabaseVersion, metadata::InstanceImageStatus,
        metadata::InstanceMetadata, metadata::InstanceStatus, reconcile,
    },
    runtime::docker::{
        DockerContainerStatus, DockerError, DockerInstanceInspection, DockerInstanceSpec,
        DockerRuntime,
    },
    shared::{protocol::Protocol, redaction, time::now_rfc3339},
};
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

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
    state.resource_cache.remove(&metadata.instance_id).await;
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
    let instance = lifecycle_instance(&state, &instance_id, action)
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
    let mut metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    if metadata.status == InstanceStatus::Quarantined {
        return Err(ApiError::Conflict(
            "quarantined instances cannot be updated or migrated; inspect the quarantine cause and repair or recover the instance offline"
                .to_string(),
        ));
    }
    ensure_image_allowed(&state, metadata.protocol, &image)?;
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
    if request.major_upgrade {
        return update_instance_image_by_major_migration(
            &state,
            metadata,
            current_image,
            image,
            request.password,
        )
        .await
        .map(ApiResponse::ok);
    }

    let image_change = classify_image_update(metadata.protocol, &current_image, &image)?;
    if image_change == ImageVersionChange::Major {
        return Err(major_upgrade_required_error(
            metadata.protocol,
            &current_image,
            &image,
        ));
    }
    state
        .install_progress
        .begin_image_update(&metadata.instance_id, metadata.protocol, &image);
    state
        .install_progress
        .stage(&metadata.instance_id, "prepare", "preparing image update");
    let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
        .map_err(|error| fail_image_update_bad_request(&state, &metadata.instance_id, error))?;
    if let Some(user) = state
        .docker
        .rootless_podman_container_user(metadata.protocol)
    {
        tracing::debug!(
            instance_id = metadata.instance_id,
            protocol = %metadata.protocol,
            user,
            "rootless podman detected; using protocol-specific container user for bind mount ownership mapping"
        );
    }
    let container_user = prepare_instance_container_user(&state.docker, &paths, metadata.protocol)
        .await
        .map_err(|error| fail_image_update_runtime(&state, &metadata.instance_id, error))?;
    let disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root());
    disk_limiter
        .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
        .await
        .map_err(|error| fail_image_update_runtime(&state, &metadata.instance_id, error))?;
    let container_data_path = disk_limiter
        .container_data_path(&paths.data)
        .map_err(|error| fail_image_update_runtime(&state, &metadata.instance_id, error))?;
    let requested_password = request.password.clone();
    let mut spec = instance_image_update_spec(
        &metadata,
        &paths,
        container_data_path,
        &image,
        request.password,
        protocol_pids_limit(&state, metadata.protocol),
    )
    .await
    .map_err(|error| fail_image_update_api(&state, &metadata.instance_id, error))?;
    metadata.runtime.network_mode = "none".to_string();
    spec.user = Some(container_user);
    let progress = state.install_progress.clone();
    let progress_instance_id = metadata.instance_id.clone();
    let pull_progress = move |event| progress.docker_pull(&progress_instance_id, event);
    state
        .docker
        .pull_image_with_progress(&image, &pull_progress)
        .await
        .map_err(docker_error)
        .map_err(|error| fail_image_update_api(&state, &metadata.instance_id, error))?;
    state.install_progress.stage(
        &metadata.instance_id,
        "delete_container",
        "removing old container",
    );
    match state
        .docker
        .delete(metadata.protocol, &metadata.instance_id)
        .await
    {
        Ok(_) => {}
        Err(error) if error.is_not_found() => {}
        Err(error) => {
            return Err(fail_image_update_api(
                &state,
                &metadata.instance_id,
                docker_error(error),
            ));
        }
    }
    launch_container_from_spec(
        &state,
        &spec,
        metadata.protocol,
        &metadata.instance_id,
        &pull_progress,
        true,
        || async { Ok(()) },
    )
    .await
    .map_err(|error| {
        fail_image_update_api(&state, &metadata.instance_id, error.into_api_error())
    })?;
    if metadata.protocol == Protocol::Postgres {
        provision_postgres_tenant_role(
            &state,
            &metadata.instance_id,
            &metadata.database.name,
            &metadata.database.username,
        )
        .await
        .map_err(|error| fail_image_update_api(&state, &metadata.instance_id, error))?;
    }
    if metadata.protocol == Protocol::Mariadb {
        let password = requested_password.as_deref().ok_or_else(|| {
            fail_image_update_api(
                &state,
                &metadata.instance_id,
                ApiError::BadRequest(
                    "password is required when recreating mariadb database containers".to_string(),
                ),
            )
        })?;
        let root_password = metadata.mariadb_root_password.as_deref().ok_or_else(|| {
            fail_image_update_api(
                &state,
                &metadata.instance_id,
                ApiError::BadRequest(
                    "mariadb internal root password is missing; old instances must be recreated with purge or repaired manually".to_string(),
                ),
            )
        })?;
        state.install_progress.stage(
            &metadata.instance_id,
            "provision",
            "re-provisioning MariaDB user",
        );
        provision_mariadb_tenant_user(
            &state,
            &metadata.instance_id,
            &metadata.database.name,
            &metadata.database.username,
            password,
            root_password,
        )
        .await
        .map_err(|error| fail_image_update_api(&state, &metadata.instance_id, error))?;
    }
    if metadata.protocol == Protocol::Mysql {
        let password = requested_password.as_deref().ok_or_else(|| {
            fail_image_update_api(
                &state,
                &metadata.instance_id,
                ApiError::BadRequest(
                    "password is required when recreating mysql database containers".to_string(),
                ),
            )
        })?;
        let root_password = metadata.mysql_root_password.as_deref().ok_or_else(|| {
            fail_image_update_api(
                &state,
                &metadata.instance_id,
                ApiError::BadRequest(
                    "mysql internal root password is missing; old instances must be recreated with purge or repaired manually".to_string(),
                ),
            )
        })?;
        state.install_progress.stage(
            &metadata.instance_id,
            "provision",
            "re-provisioning MySQL user",
        );
        provision_mysql_tenant_user(
            &state,
            &metadata.instance_id,
            &metadata.database.name,
            &metadata.database.username,
            password,
            root_password,
        )
        .await
        .map_err(|error| fail_image_update_api(&state, &metadata.instance_id, error))?;
    }
    state.install_progress.stage(
        &metadata.instance_id,
        "backend",
        "resolving backend endpoint",
    );
    metadata.backend =
        backend_endpoint_for_instance(&state, metadata.protocol, &metadata.instance_id)
            .map_err(|error| fail_image_update_api(&state, &metadata.instance_id, error))?;
    if metadata.protocol == Protocol::Mariadb
        && let Some(password) = requested_password.as_deref()
    {
        metadata.mariadb_native_password_sha1_stage2 = Some(
            crate::protocols::mariadb::native_password_sha1_stage2_hex(password),
        );
    }
    if metadata.protocol == Protocol::Mysql
        && let Some(password) = requested_password.as_deref()
    {
        metadata.mysql_native_password_sha1_stage2 = Some(
            crate::protocols::mariadb::native_password_sha1_stage2_hex(password),
        );
    }
    metadata.status = InstanceStatus::Running;
    metadata.updated_at = now_rfc3339();
    state
        .manager
        .upsert(metadata.clone())
        .await
        .map_err(|error| fail_image_update_runtime(&state, &metadata.instance_id, error))?;
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;

    tracing::info!(
        event = "audit instance_image_updated",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        image,
    );
    state
        .install_progress
        .complete(&metadata.instance_id, "image update completed");

    Ok(ApiResponse::ok(UpdateInstanceImageResponse {
        instance: metadata,
        image,
        recreated: true,
        strategy: ImageUpdateStrategy::InPlaceRecreate,
        warnings: Vec::new(),
        export_artifact_id: None,
        old_volume_backup_retained: false,
    }))
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

    metadata.status = deletion_status(metadata.status);
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
    let deleted = state
        .manager
        .delete(&metadata.instance_id)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state.resource_cache.remove(&metadata.instance_id).await;
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
    validate_limits(&request)?;
    let _creation = state.instance_locks.lock_creation().await;
    let _operation = state.instance_locks.lock(&instance_id).await;

    let mut metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    validate_protocol_limits(metadata.protocol, &request)?;
    let limits = limits_from_request(&request);
    let previous_limits = metadata.limits.clone();
    enforce_node_allocation_policy(&state, &limits, Some(&previous_limits)).await?;
    let disk_changed = limits.disk_mib != previous_limits.disk_mib;
    let paths = if disk_changed {
        Some(
            InstancePaths::new(&state.config.paths, &metadata.instance_id)
                .map_err(|error| ApiError::BadRequest(error.to_string()))?,
        )
    } else {
        None
    };
    if let Some(paths) = paths.as_ref()
        && let Err(error) =
            DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
                .update_instance_limit(&metadata.instance_id, &paths.data, limits.disk_mib)
                .await
    {
        let rollback =
            rollback_disk_limit(&state, &metadata, paths, previous_limits.disk_mib).await;
        return Err(ApiError::Runtime(format!(
            "failed to update disk limit: {error}; rollback: {rollback}"
        )));
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
            &state,
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
    metadata.limits.disk_enforced = state.config.disk.mode.enforced();
    metadata.limits.disk_enforcement_method = state.config.disk.mode.method().to_string();
    metadata.updated_at = now_rfc3339();
    if let Err(error) = state.manager.upsert(metadata.clone()).await {
        let rollback = rollback_instance_limits(
            &state,
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

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAction {
    Start,
    Stop,
    Restart,
    Kill,
}

pub(crate) async fn lifecycle_instance(
    state: &AppState,
    instance_id: &str,
    action: LifecycleAction,
) -> ApiResult<InstanceMetadata> {
    let _operation = state.instance_locks.lock(instance_id).await;
    lifecycle_instance_locked(state, instance_id, action).await
}

pub(crate) async fn lifecycle_instance_locked(
    state: &AppState,
    instance_id: &str,
    action: LifecycleAction,
) -> ApiResult<InstanceMetadata> {
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;

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
    let operation_result: Result<(), ApiError> = async {
        if should_call_docker {
            if matches!(action, LifecycleAction::Start | LifecycleAction::Restart) {
                let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
                    .map_err(|error| ApiError::BadRequest(error.to_string()))?;
                DiskLimiter::with_fuse_root(
                    state.config.disk.clone(),
                    state.config.paths.fuse_root(),
                )
                .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
                .await
                .map_err(|error| ApiError::Runtime(error.to_string()))?;
            }
            match action {
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
            .map_err(docker_error)?;
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
                provision_postgres_tenant_role(
                    state,
                    &metadata.instance_id,
                    &metadata.database.name,
                    &metadata.database.username,
                )
                .await?;
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
            let rollback = rollback_lifecycle_runtime(
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

async fn rollback_lifecycle_runtime(
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

pub(crate) async fn purge_instance_paths(
    state: &AppState,
    instance_id: &str,
) -> Result<(), ApiError> {
    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
        .purge_instance_data(&paths.data)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let deleted_backups = crate::api::backups::purge_instance_backups(state, instance_id).await?;
    if deleted_backups > 0 {
        tracing::info!(
            event = "audit instance_backups_purged",
            instance_id,
            deleted_backups
        );
    }
    let mut purge_paths = vec![
        paths.data,
        paths.logs,
        paths.sockets,
        paths.artifacts,
        paths.exports,
        paths.imports,
        paths.backups,
        paths.runtime_config,
    ];
    let retained_volumes = retained_instance_volume_paths(&purge_paths[0])
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to discover retained instance volumes: {error}"
            ))
        })?;
    purge_paths.extend(retained_volumes);
    for path in purge_paths {
        cleanup_path_if_exists(&path).await?;
    }
    Ok(())
}

pub(crate) async fn retained_instance_volume_paths(
    data_path: &std::path::Path,
) -> Result<Vec<std::path::PathBuf>, std::io::Error> {
    let Some(parent) = data_path.parent() else {
        return Ok(Vec::new());
    };
    let Some(instance_name) = data_path.file_name().and_then(|name| name.to_str()) else {
        return Ok(Vec::new());
    };
    let prefixes = [
        format!(".dbe-major-upgrade-old-{instance_name}-"),
        format!(".dbe-restore-{instance_name}-"),
    ];
    let mut directory = match tokio::fs::read_dir(parent).await {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut paths = Vec::new();
    while let Some(entry) = directory.next_entry().await? {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| retained_volume_name_matches(name, &prefixes))
        {
            paths.push(entry.path());
        }
    }
    Ok(paths)
}

fn retained_volume_name_matches(name: &str, prefixes: &[String]) -> bool {
    prefixes.iter().any(|prefix| {
        name.strip_prefix(prefix)
            .is_some_and(|suffix| uuid::Uuid::parse_str(suffix).is_ok())
    })
}

async fn instance_image_update_spec(
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    container_data_path: std::path::PathBuf,
    image: &str,
    password: Option<String>,
    pids_limit: i64,
) -> Result<DockerInstanceSpec, ApiError> {
    let password = match metadata.protocol {
        Protocol::Redis | Protocol::Valkey => password.unwrap_or_default(),
        _ => password.ok_or_else(|| {
            ApiError::BadRequest(
                "password is required when recreating non-RESP database containers".to_string(),
            )
        })?,
    };
    let password = SecretString::from(password);

    let mut spec = match metadata.protocol {
        Protocol::Postgres => databases::postgres::docker::instance_spec(
            &metadata.instance_id,
            image,
            &metadata.database.name,
            &metadata.database.username,
            password,
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Redis => databases::redis::docker::instance_spec(
            &metadata.instance_id,
            image,
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Valkey => databases::valkey::docker::instance_spec(
            &metadata.instance_id,
            image,
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mariadb => databases::mariadb::docker::instance_spec(
            &metadata.instance_id,
            image,
            &metadata.database.name,
            &metadata.database.username,
            password,
            SecretString::from(metadata.mariadb_root_password.clone().ok_or_else(|| {
                ApiError::BadRequest(
                    "mariadb internal root password is missing; old instances must be recreated with purge or repaired manually".to_string(),
                )
            })?),
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mysql => databases::mysql::docker::instance_spec(
            &metadata.instance_id,
            image,
            &metadata.database.name,
            SecretString::from(metadata.mysql_root_password.clone().ok_or_else(|| {
                ApiError::BadRequest(
                    "mysql internal root password is missing; old instances must be recreated with purge or repaired manually".to_string(),
                )
            })?),
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mongodb => databases::mongodb::docker::instance_spec(
            &metadata.instance_id,
            image,
            &metadata.database.name,
            databases::mongodb::docker::MongodbAuth {
                username: metadata.database.username.clone(),
                password,
                root_password: SecretString::from(
                    metadata.mongodb_root_password.clone().ok_or_else(|| {
                        ApiError::BadRequest(
                            "mongodb internal root password is missing; old MongoDB instances must be recreated or restored from a manual admin dump before image replacement".to_string(),
                        )
                    })?,
                ),
            },
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Clickhouse => {
            let hosted_config_path =
                databases::clickhouse::docker::write_hosted_config(&paths.runtime_config)
                    .await
                    .map_err(|error| ApiError::Runtime(error.to_string()))?;
            databases::clickhouse::docker::instance_spec(
                &metadata.instance_id,
                image,
                &metadata.database.name,
                &metadata.database.username,
                password,
                container_data_path,
                paths.logs.clone(),
                hosted_config_path,
                paths.sockets.clone(),
                paths.socket_bridge_binary.clone(),
            )
        }
        Protocol::Qdrant => databases::qdrant::docker::instance_spec(
            &metadata.instance_id,
            image,
            password,
            container_data_path,
            paths.logs.clone(),
            paths.sockets.clone(),
            paths.socket_bridge_binary.clone(),
        ),
    };
    spec.cpu_cores = metadata.limits.cpu_cores;
    spec.memory_mib = metadata.limits.memory_mib;
    spec.disk_mib = metadata.limits.disk_mib;
    spec.pids_limit = Some(pids_limit);
    Ok(spec)
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
mod tests {
    use super::*;

    #[tokio::test]
    async fn retained_instance_volume_paths_are_scoped_to_the_exact_instance() {
        let root = tempfile::tempdir().unwrap();
        let data_path = root.path().join("inst_customer_db");
        let old_upgrade = root
            .path()
            .join(".dbe-major-upgrade-old-inst_customer_db-550e8400-e29b-41d4-a716-446655440000");
        let failed_restore = root
            .path()
            .join(".dbe-restore-inst_customer_db-550e8400-e29b-41d4-a716-446655440001");
        let unrelated = root.path().join(
            ".dbe-major-upgrade-old-inst_customer_db-other-550e8400-e29b-41d4-a716-446655440002",
        );
        tokio::fs::create_dir(&old_upgrade).await.unwrap();
        tokio::fs::create_dir(&failed_restore).await.unwrap();
        tokio::fs::create_dir(&unrelated).await.unwrap();

        let mut paths = retained_instance_volume_paths(&data_path).await.unwrap();
        paths.sort();
        let mut expected = vec![old_upgrade, failed_restore];
        expected.sort();

        assert_eq!(paths, expected);
    }

    #[test]
    fn deletion_preserves_quarantine_to_avoid_claiming_a_duplicate_route() {
        assert_eq!(
            deletion_status(InstanceStatus::Quarantined),
            InstanceStatus::Quarantined
        );
        assert_eq!(
            deletion_status(InstanceStatus::Running),
            InstanceStatus::Deleting
        );
        assert_eq!(
            deletion_status(InstanceStatus::Deleting),
            InstanceStatus::Deleting
        );
    }

    #[test]
    fn parses_major_version_from_common_image_tags() {
        assert_eq!(image_major_version("mongo:7.0.37"), Some(7));
        assert_eq!(
            image_major_version("docker.io/library/postgres:18.4"),
            Some(18)
        );
        assert_eq!(
            image_major_version("registry.example.com:5000/db/mariadb:12.3.2"),
            Some(12)
        );
        assert_eq!(image_major_version("mysql:8.4"), Some(8));
    }

    #[test]
    fn rejects_unpinned_images_for_existing_instance_updates() {
        assert!(image_major_version("mongo:latest").is_none());
        assert!(image_major_version("mongo@sha256:abc").is_none());
        assert!(image_major_version("mongo").is_none());
    }

    #[test]
    fn parses_major_version_values() {
        assert_eq!(parse_major_version_value("8.3"), Some(8));
        assert_eq!(parse_major_version_value("v7.0"), None);
        assert_eq!(parse_major_version_value("latest"), None);
    }

    #[test]
    fn classifies_major_version_changes() {
        let change =
            classify_image_update(Protocol::Mongodb, "mongo:7.0.37", "mongo:8.3.4").unwrap();
        assert_eq!(change, ImageVersionChange::Major);

        let change =
            classify_image_update(Protocol::Postgres, "postgres:18.3", "postgres:18.4").unwrap();
        assert_eq!(change, ImageVersionChange::SameMajorOrUnknown);
    }

    #[test]
    fn requires_parseable_tags_for_different_existing_images() {
        let error =
            classify_image_update(Protocol::Mongodb, "mongo:7.0.37", "mongo:latest").unwrap_err();
        assert!(error.to_string().contains("cannot compare requested image"));
    }

    #[test]
    fn major_upgrade_path_blocks_downgrades() {
        let error = validate_major_upgrade_path(Protocol::Postgres, 18, 17).unwrap_err();
        assert!(error.to_string().contains("downgrade is blocked"));
    }

    #[test]
    fn mongodb_major_upgrade_path_blocks_skipped_versions() {
        let error = validate_major_upgrade_path(Protocol::Mongodb, 6, 8).unwrap_err();
        assert!(error.to_string().contains("cannot skip versions"));

        assert!(validate_major_upgrade_path(Protocol::Mongodb, 7, 8).is_ok());
    }

    #[test]
    fn non_mongodb_dump_upgrade_path_allows_skipped_versions() {
        assert!(validate_major_upgrade_path(Protocol::Postgres, 14, 18).is_ok());
    }

    #[test]
    fn major_migration_support_is_limited_to_logical_dump_protocols() {
        assert!(ensure_major_upgrade_supported(Protocol::Postgres).is_ok());
        assert!(ensure_major_upgrade_supported(Protocol::Mysql).is_ok());
        assert!(ensure_major_upgrade_supported(Protocol::Mongodb).is_ok());
        assert!(ensure_major_upgrade_supported(Protocol::Redis).is_err());
        assert!(ensure_major_upgrade_supported(Protocol::Valkey).is_err());
        assert!(ensure_major_upgrade_supported(Protocol::Qdrant).is_err());
    }

    #[test]
    fn replacement_validation_uses_managed_database_unix_sockets() {
        let postgres =
            replacement_validation_command(Protocol::Postgres, "app_user", "app_db").unwrap();
        assert!(postgres.contains("-h /var/run/postgresql"));
        assert!(!postgres.contains("-h 127.0.0.1"));

        let mariadb =
            replacement_validation_command(Protocol::Mariadb, "app_user", "app_db").unwrap();
        assert!(mariadb.contains("--protocol=socket"));
        assert!(mariadb.contains("--socket=/run/mysqld/mysqld.sock"));
        assert!(!mariadb.contains("-h 127.0.0.1"));

        let mysql = replacement_validation_command(Protocol::Mysql, "app_user", "app_db").unwrap();
        assert!(mysql.contains("--protocol=socket"));
        assert!(mysql.contains("--socket=/var/run/mysqld/mysqld.sock"));
    }

    #[test]
    fn normalizes_database_version_outputs() {
        assert_eq!(
            normalize_database_version(Protocol::Postgres, "postgres (PostgreSQL) 18.4\n"),
            Some("18.4".to_string())
        );
        assert_eq!(
            normalize_database_version(
                Protocol::Mariadb,
                "mariadb  Ver 15.1 Distrib 12.3.2-MariaDB, for Linux (x86_64)\n"
            ),
            Some("12.3.2-MariaDB".to_string())
        );
        assert_eq!(
            normalize_database_version(
                Protocol::Mysql,
                "mysqld  Ver 8.4.6 for Linux on x86_64 (MySQL Community Server - GPL)\n"
            ),
            Some("8.4.6".to_string())
        );
        assert_eq!(
            normalize_database_version(
                Protocol::Redis,
                "Redis server v=8.8.0 sha=00000000:0 malloc=jemalloc-5.3.0 bits=64\n"
            ),
            Some("8.8.0".to_string())
        );
        assert_eq!(
            normalize_database_version(
                Protocol::Valkey,
                "Valkey server v=9.1.1 sha=00000000:0 malloc=jemalloc-5.3.0 bits=64\n"
            ),
            Some("9.1.1".to_string())
        );
        assert_eq!(
            normalize_database_version(Protocol::Mongodb, "v8.3.4\n"),
            Some("8.3.4".to_string())
        );
        assert_eq!(
            normalize_database_version(
                Protocol::Clickhouse,
                "ClickHouse server version 25.8.25.37 (official build).\n"
            ),
            Some("25.8.25.37".to_string())
        );
        assert_eq!(
            normalize_database_version(Protocol::Qdrant, "qdrant 1.18.2\n"),
            Some("1.18.2".to_string())
        );
    }
}
