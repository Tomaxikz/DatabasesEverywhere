mod major_upgrade;
mod normal_image_update;
mod password;
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
use normal_image_update::*;
pub use password::{
    ResetInstancePasswordRequest, ResetInstancePasswordResponse, reset_instance_password,
};

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
            enforce_node_allocation_policy, harden_mysql_tenant_auth,
            harden_postgres_instance_auth, launch_container_from_spec,
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
        metadata::DesiredInstanceState, metadata::InstanceDatabaseVersion,
        metadata::InstanceImageStatus, metadata::InstanceMetadata, metadata::InstanceStatus,
        reconcile,
    },
    runtime::docker::{
        DockerContainerStatus, DockerError, DockerInstanceInspection, DockerInstanceSpec,
        DockerRuntime,
    },
    shared::{protocol::Protocol, redaction, time::now_rfc3339},
};
use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

const IMAGE_UPDATE_ROLLBACK_TIMEOUT: Duration = Duration::from_secs(180);
const IMAGE_UPDATE_FAIL_CLOSED_STOP_TIMEOUT: Duration = Duration::from_secs(30);

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
    if metadata.desired_state == DesiredInstanceState::Stopped {
        return Err(ApiError::Conflict(
            "stopped instances cannot be updated in place; start the instance before updating its image"
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
        return run_major_upgrade_supervisor(
            state.clone(),
            _operation,
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
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
            .for_protocol(metadata.protocol);
    disk_limiter
        .validate_persisted_method_transition(&metadata.limits.disk_enforcement_method)
        .map_err(|error| fail_image_update_runtime(&state, &metadata.instance_id, error))?;
    if crate::config::DiskLimitMode::from_persisted_method(&metadata.limits.disk_enforcement_method)
        != Some(disk_limiter.mode())
    {
        return Err(fail_image_update_api(
            &state,
            &metadata.instance_id,
            ApiError::Conflict(format!(
                "instance currently uses {} disk enforcement but this node selects {}; restart dbev to reconcile or safely migrate it before recreating the image",
                metadata.limits.disk_enforcement_method,
                disk_limiter.mode().method(),
            )),
        ));
    }
    disk_limiter
        .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
        .await
        .map_err(|error| fail_image_update_runtime(&state, &metadata.instance_id, error))?;
    let container_data_path = disk_limiter
        .container_data_path(&paths.data)
        .map_err(|error| fail_image_update_runtime(&state, &metadata.instance_id, error))?;
    // The encrypted credential is authoritative once present. The optional
    // request field remains a compatibility fallback for legacy metadata that
    // predates encrypted tenant credential storage.
    let effective_password = metadata
        .tenant_password
        .clone()
        .or_else(|| request.password.clone());
    let rollback_image = state
        .docker
        .container_immutable_image_id(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(docker_error)
        .map_err(|error| fail_image_update_api(&state, &metadata.instance_id, error))?
        .ok_or_else(|| {
            fail_image_update_api(
                &state,
                &metadata.instance_id,
                ApiError::Conflict(
                    "the current container image ID could not be captured; refusing a destructive image replacement without an exact rollback image"
                        .to_string(),
                ),
            )
        })?;
    let project_id = state
        .docker
        .container_project_id(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(docker_error)
        .map_err(|error| fail_image_update_api(&state, &metadata.instance_id, error))?;
    let mut spec = instance_image_update_spec(
        &metadata,
        &paths,
        container_data_path.clone(),
        &image,
        effective_password.clone().map(SecretString::from),
        protocol_pids_limit(&state, metadata.protocol),
    )
    .await
    .map_err(|error| fail_image_update_api(&state, &metadata.instance_id, error))?;
    let mut rollback_spec = instance_image_update_spec(
        &metadata,
        &paths,
        container_data_path,
        &rollback_image,
        effective_password.clone().map(SecretString::from),
        protocol_pids_limit(&state, metadata.protocol),
    )
    .await
    .map_err(|error| fail_image_update_api(&state, &metadata.instance_id, error))?;
    let mut rollback_metadata = metadata.clone();
    rollback_metadata.runtime.network_mode = "none".to_string();
    metadata.runtime.network_mode = "none".to_string();
    for container_spec in [&mut spec, &mut rollback_spec] {
        container_spec.user = Some(container_user.clone());
        container_spec.project_id.clone_from(&project_id);
    }
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
    let replacement_result: Result<(), ApiError> = async {
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
        .map_err(|error| error.into_api_error())?;
        if metadata.protocol == Protocol::Postgres {
            harden_postgres_instance_auth(
                &state,
                &metadata.instance_id,
                &metadata.database.username,
                effective_password.as_deref().ok_or_else(|| {
                    ApiError::Conflict(
                        "the encrypted PostgreSQL tenant credential is missing; reset or recreate this legacy instance before replacing its image".to_string(),
                    )
                })?,
                metadata.postgres_admin_password.as_deref().ok_or_else(|| {
                    ApiError::Conflict(
                        "the encrypted PostgreSQL administrator credential is missing; restart the daemon to migrate this legacy instance before replacing its image".to_string(),
                    )
                })?,
            )
            .await?;
        }
        if metadata.protocol == Protocol::Mariadb {
            let password = effective_password.as_deref().ok_or_else(|| {
                ApiError::BadRequest(
                    "password is required when recreating mariadb database containers".to_string(),
                )
            })?;
            let root_password = metadata.mariadb_root_password.as_deref().ok_or_else(|| {
                ApiError::BadRequest(
                    "mariadb internal root password is missing; old instances must be recreated with purge or repaired manually".to_string(),
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
            .await?;
        }
        if metadata.protocol == Protocol::Mysql {
            let password = effective_password.as_deref().ok_or_else(|| {
                ApiError::BadRequest(
                    "password is required when recreating mysql database containers".to_string(),
                )
            })?;
            let root_password = metadata.mysql_root_password.as_deref().ok_or_else(|| {
                ApiError::BadRequest(
                    "mysql internal root password is missing; old instances must be recreated with purge or repaired manually".to_string(),
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
            .await?;
        }
        state.install_progress.stage(
            &metadata.instance_id,
            "backend",
            "resolving backend endpoint",
        );
        metadata.backend =
            backend_endpoint_for_instance(&state, metadata.protocol, &metadata.instance_id)?;
        if metadata.protocol == Protocol::Mariadb
            && let Some(password) = effective_password.as_deref()
        {
            metadata.mariadb_native_password_sha1_stage2 = Some(
                crate::protocols::mariadb::native_password_sha1_stage2_hex(password),
            );
        }
        if metadata.protocol == Protocol::Mysql
            && let Some(password) = effective_password.as_deref()
        {
            metadata.mysql_native_password_sha1_stage2 = Some(
                crate::protocols::mariadb::native_password_sha1_stage2_hex(password),
            );
        }
        if effective_password.is_some() {
            metadata.tenant_password.clone_from(&effective_password);
        }
        metadata.status = InstanceStatus::Running;
        metadata.limits.disk_enforced = disk_limiter.mode().enforced();
        metadata.updated_at = now_rfc3339();
        state
            .manager
            .upsert(metadata.clone())
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        Ok(())
    }
    .await;
    if let Err(error) = replacement_result {
        let error = rollback_normal_image_update_or_quarantine(
            &state,
            &rollback_metadata,
            &rollback_spec,
            error,
        )
        .await;
        return Err(fail_image_update_api(&state, &metadata.instance_id, error));
    }
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
        .repository()
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
    let effective_disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
            .for_persisted_protocol(metadata.protocol, &metadata.limits.disk_enforcement_method);
    if let Some(paths) = paths.as_ref() {
        effective_disk_limiter
            .validate_persisted_method_transition(&metadata.limits.disk_enforcement_method)
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
            .verify_container_data_bind(
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
                rollback_disk_limit(&state, &metadata, paths, previous_limits.disk_mib).await;
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
                        limit_bytes: limits.disk_mib.saturating_mul(1024 * 1024),
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
    let mut metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
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
            .validate_persisted_method_transition(&metadata.limits.disk_enforcement_method)
            .map_err(|error| ApiError::Conflict(error.to_string()))?;
        ensure_limiter_matches_persisted_method(&disk_limiter, &metadata)?;
        let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
            .map_err(|error| ApiError::BadRequest(error.to_string()))?;
        let expected_data_source = disk_limiter
            .container_data_path(&paths.data)
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        match state
            .docker
            .verify_container_data_bind(
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
                    limit_bytes: metadata.limits.disk_mib.saturating_mul(1024 * 1024),
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
    if metadata_changed {
        state.manager.upsert(metadata).await.map_err(|error| {
            ApiError::Runtime(format!(
                "failed to persist requested lifecycle state before applying it: {error}"
            ))
        })?;
    }
    lifecycle_instance_locked(state, instance_id, action).await
}

fn ensure_limiter_matches_persisted_method(
    limiter: &DiskLimiter,
    metadata: &InstanceMetadata,
) -> Result<(), ApiError> {
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

pub(crate) async fn lifecycle_instance_locked(
    state: &AppState,
    instance_id: &str,
    action: LifecycleAction,
) -> ApiResult<InstanceMetadata> {
    let mut metadata = state
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
                let disk_limiter = DiskLimiter::with_fuse_root(
                    state.config.disk.clone(),
                    state.config.paths.fuse_root(),
                )
                .for_persisted_protocol(
                    metadata.protocol,
                    &metadata.limits.disk_enforcement_method,
                );
                disk_limiter
                    .validate_persisted_method_transition(&metadata.limits.disk_enforcement_method)
                    .map_err(|error| ApiError::Conflict(error.to_string()))?;
                ensure_limiter_matches_persisted_method(&disk_limiter, &metadata)?;
                let expected_data_source = disk_limiter
                    .container_data_path(&paths.data)
                    .map_err(|error| ApiError::Runtime(error.to_string()))?;
                match state
                    .docker
                    .verify_container_data_bind(
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
                            limit_bytes: metadata.limits.disk_mib.saturating_mul(1024 * 1024),
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

pub(crate) async fn purge_instance_paths(
    state: &AppState,
    instance_id: &str,
) -> Result<(), ApiError> {
    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root());
    let disk_limiter = if let Some(metadata) = state.instances.get(instance_id).await {
        disk_limiter.for_persisted_method(&metadata.limits.disk_enforcement_method)
    } else {
        disk_limiter
    };
    disk_limiter
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
    // Retained major-upgrade/restore volumes can themselves be Btrfs
    // subvolumes or ZFS datasets. Remove their native quota object before the
    // generic filesystem cleanup; `remove_dir_all` cannot delete those roots.
    for retained_volume in &retained_volumes {
        disk_limiter
            .purge_instance_data(retained_volume)
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
    }
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
    password: Option<SecretString>,
    pids_limit: i64,
) -> Result<DockerInstanceSpec, ApiError> {
    let password = match metadata.protocol {
        Protocol::Redis | Protocol::Valkey => {
            password.unwrap_or_else(|| SecretString::from(String::new()))
        }
        _ => password.ok_or_else(|| {
            ApiError::BadRequest(
                "password is required when recreating non-RESP database containers".to_string(),
            )
        })?,
    };

    let mut spec = match metadata.protocol {
        Protocol::Postgres => databases::postgres::docker::instance_spec(
            &metadata.instance_id,
            image,
            &metadata.database.name,
            &metadata.database.username,
            password,
            SecretString::from(metadata.postgres_admin_password.clone().ok_or_else(|| {
                ApiError::BadRequest(
                    "PostgreSQL administrator credential is missing; restart the daemon to migrate this legacy instance before recreation".to_string(),
                )
            })?),
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
#[path = "instances/tests.rs"]
mod tests;
