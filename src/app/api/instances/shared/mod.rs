use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use tokio::sync::OwnedMutexGuard;

use super::{
    DeleteResponse, LifecycleAction, ResetInstancePasswordResponse, docker_error,
    purge_runtime_paths, purge_shared_tenant_paths, route_fence,
};
use crate::{
    api::http::{
        response::{ApiError, ApiResponse, ApiResult},
        router::AppState,
    },
    disk::DiskEnforcement,
    instances::metadata::{DesiredInstanceState, InstanceMetadata, InstanceStatus},
    placement::{
        DeploymentMode, EngineRuntime, EngineRuntimeStatus, runtime as shared_runtime,
        tenant::{self, TenantTarget},
    },
    runtime::docker::DockerContainerStatus,
    shared::{
        limits::{InstanceLimits, mib_to_bytes},
        protocol::Protocol,
        time::now_rfc3339,
    },
};

mod lifecycle;
mod maintenance;

use lifecycle::{
    SharedLifecycleError, check_power_state, limits_match, placement_error, route_was_open,
    same_shared_identity, target,
};
pub(crate) use maintenance::delete_empty_pool;
use maintenance::{clear_caches, drain_tenant_sessions, maintain_pool_after_delete};

const SESSION_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const POOL_READY_TIMEOUT: Duration = Duration::from_secs(30);
const TENANT_USAGE_TIMEOUT: Duration = Duration::from_secs(20);

pub(super) async fn reconcile(
    state: &AppState,
    mut metadata: InstanceMetadata,
) -> Result<InstanceMetadata, ApiError> {
    let runtime_id = shared_runtime_id(&metadata)?.to_string();
    let _runtime_operation = state.instance_locks.lock(&runtime_id).await;
    metadata = reload_after_runtime_lock(state, &metadata).await?;
    let route_fenced = state.instances.routes_fenced(&metadata.instance_id).await;
    let runtime = load_runtime(state, &metadata).await?;
    let inspection = state
        .docker
        .inspect_instance(metadata.protocol, &runtime.runtime_id)
        .await
        .map_err(docker_error)?;
    metadata.status = reconciled_tenant_status(
        metadata.status,
        metadata.desired_state,
        runtime.status,
        inspection.status,
        route_fenced,
    );
    if metadata.status != InstanceStatus::Running {
        drain_tenant_sessions(state, &metadata.instance_id).await?;
    }
    metadata.updated_at = now_rfc3339();
    state
        .manager
        .upsert(metadata.clone())
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    Ok(metadata)
}

fn reconciled_tenant_status(
    current: InstanceStatus,
    desired: DesiredInstanceState,
    runtime: EngineRuntimeStatus,
    container: DockerContainerStatus,
    route_fenced: bool,
) -> InstanceStatus {
    if matches!(
        current,
        InstanceStatus::Deleting | InstanceStatus::Quarantined
    ) {
        return current;
    }
    if desired == DesiredInstanceState::Stopped {
        return InstanceStatus::Stopped;
    }
    // A lifecycle or data operation may have deliberately left the route
    // fenced after its session drain or rollback became uncertain. Reconcile
    // must not turn a healthy pool observation into permission to republish
    // that tenant; an explicit Start performs the credential checks needed to
    // reopen it safely.
    if route_fenced {
        return InstanceStatus::Failed;
    }
    if current == InstanceStatus::Running
        && runtime == EngineRuntimeStatus::Running
        && container == DockerContainerStatus::Running
    {
        return InstanceStatus::Running;
    }
    InstanceStatus::Failed
}

pub(super) async fn change_state(
    state: &AppState,
    mut metadata: InstanceMetadata,
    action: LifecycleAction,
) -> ApiResult<InstanceMetadata> {
    check_power_state(&metadata)?;
    let _mutation = state
        .daemon_shutdown
        .try_admit_background_mutation()
        .ok_or_else(|| {
            ApiError::ServiceUnavailable(
                "daemon shutdown has started; lifecycle operations are not accepted".to_string(),
            )
        })?;
    let runtime_id = shared_runtime_id(&metadata)?.to_string();
    let _runtime_operation = state.instance_locks.lock(&runtime_id).await;
    metadata = reload_after_runtime_lock(state, &metadata).await?;
    check_power_state(&metadata)?;
    let runtime = load_runtime(state, &metadata).await?;
    let inspection = state
        .docker
        .inspect_instance(metadata.protocol, &runtime.runtime_id)
        .await
        .map_err(docker_error)?;
    let pool_running = inspection.status == DockerContainerStatus::Running;
    if matches!(action, LifecycleAction::Start | LifecycleAction::Restart)
        && (!pool_running || runtime.status != EngineRuntimeStatus::Running)
    {
        return Err(ApiError::Conflict(
            "the shared database runtime is not running; repair the pool before starting tenants"
                .to_string(),
        ));
    }

    let previous = metadata.clone();
    let reopen_previous_route = route_was_open(
        &previous,
        state.instances.routes_fenced(&metadata.instance_id).await,
    );
    let starting = matches!(action, LifecycleAction::Start | LifecycleAction::Restart);
    drain_tenant_sessions(state, &metadata.instance_id).await?;

    let database = metadata.database.name.clone();
    let username = metadata.database.username.clone();
    let target = TenantTarget {
        database: &database,
        username: &username,
    };
    let start_password = if starting {
        Some(metadata.tenant_password.clone().ok_or_else(|| {
            ApiError::Conflict(
                "the encrypted shared tenant credential is missing; rotate or repair it before starting"
                    .to_string(),
            )
        })?)
    } else {
        None
    };
    let engine_result = async {
        if pool_running {
            tenant::fence(&state.docker, &runtime, target).await?;
        }
        if starting {
            let password = start_password.ok_or(SharedLifecycleError::MissingCredential)?;
            state
                .docker
                .wait_until_ready(metadata.protocol, &runtime.runtime_id, POOL_READY_TIMEOUT)
                .await?;
            apply_tenant_disk_limit(state, &runtime, &mut metadata).await?;
            shared_runtime::apply_root_disk_limit(&state.config, &state.placements, &runtime)
                .await
                .map_err(SharedLifecycleError::RootDisk)?;
            ensure_soft_start_allowed(state, &runtime, &mut metadata).await?;
            tenant::unfence(&state.docker, &runtime, target).await?;
            tenant::verify_password(&state.docker, &runtime, target, &password).await?;
        }
        Ok::<_, SharedLifecycleError>(())
    }
    .await;
    if let Err(error) = engine_result {
        let rollback = restore_access(state, &runtime, &previous, reopen_previous_route).await;
        let message =
            format!("shared tenant lifecycle operation failed: {error}; rollback: {rollback}");
        return Err(if error.is_disk_conflict() {
            ApiError::Conflict(message)
        } else {
            ApiError::Runtime(message)
        });
    }

    metadata.desired_state = if starting {
        DesiredInstanceState::Running
    } else {
        DesiredInstanceState::Stopped
    };
    metadata.status = if starting {
        InstanceStatus::Running
    } else {
        InstanceStatus::Stopped
    };
    metadata.updated_at = now_rfc3339();
    if let Err(error) = state.manager.upsert(metadata.clone()).await {
        match state.manager.get_persisted(&metadata.instance_id).await {
            Ok(Some(persisted))
                if persisted.desired_state == metadata.desired_state
                    && persisted.status == metadata.status =>
            {
                state.instances.upsert(metadata.clone()).await;
                tracing::warn!(
                    event = "audit shared_tenant_power_commit_ack_lost",
                    instance_id = %metadata.instance_id,
                    runtime_id = %runtime.runtime_id,
                    %error,
                );
            }
            Ok(Some(persisted))
                if persisted.desired_state == previous.desired_state
                    && persisted.status == previous.status =>
            {
                let rollback =
                    restore_access(state, &runtime, &previous, reopen_previous_route).await;
                return Err(ApiError::Runtime(format!(
                    "failed to persist shared tenant lifecycle state: {error}; rollback: {rollback}"
                )));
            }
            Ok(Some(mut persisted)) => {
                persisted.status = InstanceStatus::Quarantined;
                persisted.desired_state = DesiredInstanceState::Stopped;
                persisted.updated_at = now_rfc3339();
                route_fence::fence(state, &metadata.instance_id).await;
                let quarantine = state.manager.upsert(persisted).await;
                return Err(ApiError::Runtime(format!(
                    "shared tenant lifecycle changed engine access, but durable state is ambiguous after {error}; tenant remained fenced and quarantine persistence: {}",
                    quarantine
                        .err()
                        .map(|error| error.to_string())
                        .unwrap_or_else(|| "completed".to_string())
                )));
            }
            Ok(None) | Err(_) => {
                route_fence::fence(state, &metadata.instance_id).await;
                return Err(ApiError::Runtime(format!(
                    "shared tenant lifecycle changed engine access, but its durable state could not be verified after {error}; tenant remains fenced"
                )));
            }
        }
    }
    clear_caches(state, &metadata).await;
    tracing::info!(
        event = "audit shared_tenant_power",
        instance_id = %metadata.instance_id,
        runtime_id = %runtime.runtime_id,
        protocol = %metadata.protocol,
        action = ?action,
    );
    Ok(ApiResponse::ok(metadata))
}

pub(super) async fn delete(
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

async fn finish_delete(
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
        if !same_shared_identity(&snapshot, &current) || current.status != InstanceStatus::Deleting
        {
            continue;
        }
        let _runtime_operation = state.instance_locks.lock(&runtime_id).await;
        let Some(current) = state.instances.get(&instance_id).await else {
            continue;
        };
        if !same_shared_identity(&snapshot, &current) || current.status != InstanceStatus::Deleting
        {
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

pub(super) async fn resize(
    state: &AppState,
    metadata: InstanceMetadata,
    mut requested: InstanceLimits,
    creation: OwnedMutexGuard<()>,
) -> Result<InstanceMetadata, ApiError> {
    let runtime_id = shared_runtime_id(&metadata)?.to_string();
    let _runtime_operation = state.instance_locks.lock(&runtime_id).await;
    let metadata = reload_after_runtime_lock(state, &metadata).await?;
    if matches!(
        metadata.status,
        InstanceStatus::Deleting | InstanceStatus::Quarantined
    ) {
        return Err(ApiError::Conflict(
            "deleting or quarantined shared tenants cannot be resized".to_string(),
        ));
    }
    let previous_limits = metadata.limits.clone();
    let previous_runtime = load_runtime(state, &metadata).await?;
    if requested.cpu_cores != 0.0 || requested.memory_mib != 0 {
        return Err(ApiError::BadRequest(
            "shared tenant resize accepts disk_mib only; resize pool CPU/RAM separately".into(),
        ));
    }
    requested.cpu_cores = previous_limits.cpu_cores;
    requested.memory_mib = previous_limits.memory_mib;
    let next_disk = previous_runtime
        .reserved
        .disk_mib
        .checked_sub(previous_limits.disk_mib)
        .and_then(|value| value.checked_add(requested.disk_mib))
        .ok_or_else(|| ApiError::Conflict("shared_pool_full: disk reservation overflow".into()))?;
    if crate::placement::policy::pool_disk_mib(metadata.protocol, next_disk)
        .is_none_or(|disk| disk > previous_runtime.limits.disk_mib)
    {
        return Err(ApiError::Conflict(
            "shared_pool_full: resize the pool before increasing this tenant's disk allowance"
                .into(),
        ));
    }
    if previous_runtime.status != EngineRuntimeStatus::Running {
        return Err(ApiError::Conflict(
            "the shared database runtime is not available".to_string(),
        ));
    }
    let disk_shrinks = requested.disk_mib < previous_limits.disk_mib;
    let disk_changes = requested.disk_mib != previous_limits.disk_mib;
    let disk_mutation = disk_changes;
    let was_open = route_was_open(
        &metadata,
        state.instances.routes_fenced(&metadata.instance_id).await,
    );
    let measured_usage = if disk_mutation {
        drain_tenant_sessions(state, &metadata.instance_id).await?;
        tenant::fence(&state.docker, &previous_runtime, target(&metadata))
            .await
            .map_err(|error| {
                ApiError::Runtime(format!(
                    "failed to fence the shared tenant before changing its disk boundary: {error}"
                ))
            })?;
        if disk_shrinks {
            let used_bytes = match measure_resize_usage(
                state,
                &previous_runtime,
                &metadata,
                previous_limits.disk_enforced,
            )
            .await
            {
                Ok(used_bytes) => used_bytes,
                Err(error) => {
                    let restored =
                        restore_access(state, &previous_runtime, &metadata, was_open).await;
                    return Err(ApiError::Runtime(format!(
                        "failed to measure the shared tenant before shrinking its disk limit: {error}; access restore: {restored}"
                    )));
                }
            };
            let requested_bytes = mib_to_bytes(requested.disk_mib);
            if requested_bytes < used_bytes {
                let restored = restore_access(state, &previous_runtime, &metadata, was_open).await;
                return Err(ApiError::Conflict(format!(
                    "cannot shrink the shared tenant to {requested_bytes} bytes because it currently uses {used_bytes} bytes; access restore: {restored}"
                )));
            }
            Some(used_bytes)
        } else {
            None
        }
    } else {
        None
    };

    if disk_mutation {
        let disk = match tenant::disk::set_limit(
            &state.config,
            &state.docker,
            &previous_runtime,
            target(&metadata),
            requested.disk_mib,
        )
        .await
        {
            Ok(disk) => disk,
            Err(error) => {
                let restored = restore_access(state, &previous_runtime, &metadata, was_open).await;
                return Err(ApiError::Runtime(format!(
                    "failed to update the shared tenant disk boundary: {error}; access restore: {restored}"
                )));
            }
        };
        if let Err(error) = set_requested_disk_state(&previous_limits, &mut requested, &disk) {
            let restored = restore_access(state, &previous_runtime, &metadata, was_open).await;
            return Err(ApiError::Runtime(format!(
                "shared tenant disk enforcement became unsafe: {error}; access restore: {restored}"
            )));
        }
        if disk_shrinks && requested.disk_enforced && !previous_limits.disk_enforced {
            let physical_bytes = match tenant::disk::quota_usage_bytes(
                &state.config,
                &previous_runtime,
                target(&metadata),
            )
            .await
            {
                Ok(physical_bytes) => physical_bytes,
                Err(error) => {
                    let restored =
                        restore_access(state, &previous_runtime, &metadata, was_open).await;
                    return Err(ApiError::Runtime(format!(
                        "failed to verify physical usage after adopting the tenant boundary: {error}; access restore: {restored}"
                    )));
                }
            };
            let requested_bytes = mib_to_bytes(requested.disk_mib);
            if requested_bytes < physical_bytes {
                let restored = restore_access(state, &previous_runtime, &metadata, was_open).await;
                return Err(ApiError::Conflict(format!(
                    "cannot shrink the newly adopted hard tenant boundary to {requested_bytes} bytes because it physically uses {physical_bytes} bytes; access restore: {restored}"
                )));
            }
        }
        if !requested.disk_enforced
            && measured_usage.is_some_and(|used| used >= mib_to_bytes(requested.disk_mib))
        {
            let restored = restore_access(state, &previous_runtime, &metadata, was_open).await;
            return Err(ApiError::Conflict(format!(
                "a soft shared-tenant limit must remain above current usage; access restore: {restored}"
            )));
        }
    } else {
        requested.disk_enforced = previous_limits.disk_enforced;
        requested.disk_enforcement_method = previous_limits.disk_enforcement_method.clone();
    }

    let runtime = match state
        .placements
        .resize(&metadata.instance_id, &requested)
        .await
    {
        Ok(runtime) => runtime,
        Err(error) => {
            let persisted = state.manager.get_persisted(&metadata.instance_id).await;
            match persisted {
                Ok(Some(persisted)) if limits_match(&persisted.limits, &requested) => {
                    let runtime = match state.placements.get(metadata.runtime_id()).await {
                        Ok(Some(runtime)) => runtime,
                        Ok(None) => {
                            route_fence::fence(state, &metadata.instance_id).await;
                            let rollback = rollback_resize(
                                state,
                                &metadata,
                                &previous_runtime,
                                &previous_limits,
                                was_open,
                                &creation,
                            )
                            .await;
                            return Err(ApiError::Runtime(format!(
                                "shared resize committed but its physical runtime is missing; rollback: {rollback}"
                            )));
                        }
                        Err(read_error) => {
                            route_fence::fence(state, &metadata.instance_id).await;
                            let rollback = rollback_resize(
                                state,
                                &metadata,
                                &previous_runtime,
                                &previous_limits,
                                was_open,
                                &creation,
                            )
                            .await;
                            return Err(ApiError::Runtime(format!(
                                "shared resize committed but its physical runtime could not be reloaded ({read_error}); rollback: {rollback}"
                            )));
                        }
                    };
                    tracing::warn!(
                        event = "audit shared_tenant_resize_commit_ack_lost",
                        instance_id = %metadata.instance_id,
                        runtime_id = %runtime.runtime_id,
                        %error,
                    );
                    runtime
                }
                Ok(Some(persisted)) if limits_match(&persisted.limits, &previous_limits) => {
                    let rollback = rollback_resize(
                        state,
                        &metadata,
                        &previous_runtime,
                        &previous_limits,
                        was_open,
                        &creation,
                    )
                    .await;
                    return Err(ApiError::Runtime(format!(
                        "shared resize was not committed: {error}; quota rollback: {rollback}"
                    )));
                }
                persisted => {
                    route_fence::fence(state, &metadata.instance_id).await;
                    let rollback = rollback_resize(
                        state,
                        &metadata,
                        &previous_runtime,
                        &previous_limits,
                        was_open,
                        &creation,
                    )
                    .await;
                    return Err(ApiError::Runtime(format!(
                        "shared resize commit could not be classified after {error}; durable tenant state: {}; rollback: {rollback}",
                        match persisted {
                            Ok(Some(_)) => "unexpected limits",
                            Ok(None) => "missing",
                            Err(_) => "unreadable",
                        }
                    )));
                }
            }
        }
    };
    // Keep node admission serialized until the physical limits and final
    // metadata are settled. In particular, a failed shrink must restore its
    // larger reservation before another admission can consume the capacity it
    // tentatively released.

    let apply = async {
        shared_runtime::apply_limits(&state.docker, &state.config, &state.placements, &runtime)
            .await
            .map_err(ApiError::Runtime)?;
        tenant::set_quota(&state.docker, &runtime, target(&metadata), &requested)
            .await
            .map_err(|error| ApiError::Runtime(format!("tenant quota update failed: {error}")))?;
        Ok::<_, ApiError>(())
    }
    .await;
    if let Err(error) = apply {
        let rollback = rollback_resize(
            state,
            &metadata,
            &previous_runtime,
            &previous_limits,
            was_open,
            &creation,
        )
        .await;
        return Err(ApiError::Runtime(format!(
            "shared tenant limit update failed: {error}; rollback: {rollback}"
        )));
    }

    let mut updated = match state.manager.get_persisted(&metadata.instance_id).await {
        Ok(Some(persisted)) => persisted,
        Ok(None) => {
            route_fence::fence(state, &metadata.instance_id).await;
            return Err(ApiError::Runtime(
                "placement committed the shared resize, but its tenant metadata row disappeared; the route remains fenced"
                    .to_string(),
            ));
        }
        Err(error) => {
            tracing::warn!(
                event = "audit shared_tenant_limits_commit_read_failed",
                instance_id = %metadata.instance_id,
                runtime_id = %runtime.runtime_id,
                %error,
                "placement committed the resize; publishing the known committed limits from the request"
            );
            metadata.clone()
        }
    };
    updated.limits = requested;
    if updated.limits.disk_enforced {
        updated.disk_limit_blocked = false;
    }
    updated.updated_at = now_rfc3339();
    let persist_result = if disk_mutation && was_open {
        state.manager.upsert_fenced(updated.clone()).await
    } else {
        state.manager.upsert_preserving_fence(updated.clone()).await
    };
    if let Err(error) = persist_result {
        route_fence::fence(state, &metadata.instance_id).await;
        let rollback = rollback_resize(
            state,
            &metadata,
            &previous_runtime,
            &previous_limits,
            was_open,
            &creation,
        )
        .await;
        return Err(ApiError::Runtime(format!(
            "shared tenant limits were applied, but their final metadata could not be persisted ({error}); rollback: {rollback}"
        )));
    }
    if disk_mutation && was_open {
        let restored = restore_access(state, &runtime, &updated, true).await;
        if restored != "completed" {
            let rollback = rollback_resize(
                state,
                &metadata,
                &previous_runtime,
                &previous_limits,
                was_open,
                &creation,
            )
            .await;
            return Err(ApiError::Runtime(format!(
                "shared tenant limits were updated, but access could not be restored ({restored}); rollback: {rollback}"
            )));
        }
    }
    drop(creation);
    clear_caches(state, &updated).await;
    tracing::info!(
        event = "audit shared_tenant_limits_updated",
        instance_id = %updated.instance_id,
        runtime_id = %updated.runtime_id(),
        cpu_cores = updated.limits.cpu_cores,
        memory_mib = updated.limits.memory_mib,
        disk_mib = updated.limits.disk_mib,
    );
    Ok(updated)
}

pub(super) async fn reset_password(
    state: &AppState,
    mut metadata: InstanceMetadata,
    new_password: SecretString,
) -> ApiResult<ResetInstancePasswordResponse> {
    let runtime_id = shared_runtime_id(&metadata)?.to_string();
    let _runtime_operation = state.instance_locks.lock(&runtime_id).await;
    metadata = reload_after_runtime_lock(state, &metadata).await?;
    let route_fenced = state.instances.routes_fenced(&metadata.instance_id).await;
    if !route_was_open(&metadata, route_fenced) {
        return Err(ApiError::Conflict(
            "password reset requires a running, unfenced shared tenant".to_string(),
        ));
    }
    let previous_password = metadata.tenant_password.clone().ok_or_else(|| {
        ApiError::Conflict(
            "the encrypted tenant credential is missing; shared password rotation cannot be rolled back"
                .to_string(),
        )
    })?;
    let previous = metadata.clone();
    let runtime = load_running_runtime(state, &metadata).await?;
    drain_tenant_sessions(state, &metadata.instance_id).await?;
    let password = new_password.expose_secret();
    let target = target(&metadata);
    let rotated = match tenant::rotate_password(&state.docker, &runtime, target, password).await {
        Ok(()) => tenant::verify_password(&state.docker, &runtime, target, password).await,
        Err(error) => Err(error),
    };
    if let Err(error) = rotated {
        return rollback_password(
            state,
            &runtime,
            &previous,
            &previous_password,
            error.to_string(),
        )
        .await;
    }

    metadata.tenant_password = Some(password.to_string());
    match metadata.protocol {
        Protocol::Mariadb => {
            metadata.mariadb_native_password_sha1_stage2 = Some(
                crate::protocols::mariadb::native_password_sha1_stage2_hex(password),
            );
        }
        Protocol::Mysql => {
            metadata.mysql_native_password_sha1_stage2 = Some(
                crate::protocols::mariadb::native_password_sha1_stage2_hex(password),
            );
        }
        _ => {}
    }
    metadata.updated_at = now_rfc3339();
    if let Err(error) = state
        .manager
        .upsert_recovered_secrets(metadata.clone())
        .await
    {
        match state.manager.get_persisted(&metadata.instance_id).await {
            Ok(Some(persisted)) if persisted.tenant_password.as_deref() == Some(password) => {
                state.instances.upsert(metadata.clone()).await;
                tracing::warn!(
                    event = "audit shared_tenant_password_commit_ack_lost",
                    instance_id = %metadata.instance_id,
                    runtime_id = %runtime.runtime_id,
                    %error,
                );
            }
            Ok(Some(persisted))
                if persisted.tenant_password.as_deref() == Some(previous_password.as_str()) =>
            {
                return rollback_password(
                    state,
                    &runtime,
                    &previous,
                    &previous_password,
                    format!("failed to persist rotated credential: {error}"),
                )
                .await;
            }
            Ok(Some(mut persisted)) => {
                persisted.status = InstanceStatus::Quarantined;
                persisted.desired_state = DesiredInstanceState::Stopped;
                persisted.updated_at = now_rfc3339();
                let quarantine = state.manager.upsert(persisted).await;
                return Err(ApiError::Runtime(format!(
                    "shared password rotation completed, but durable credential state is ambiguous after {error}; tenant remained fenced and quarantine persistence: {}",
                    quarantine
                        .err()
                        .map(|error| error.to_string())
                        .unwrap_or_else(|| "completed".to_string())
                )));
            }
            Ok(None) | Err(_) => {
                return Err(ApiError::Runtime(format!(
                    "shared password rotation completed, but its durable commit could not be verified after {error}; tenant remains fenced for operator recovery"
                )));
            }
        }
    }
    clear_caches(state, &metadata).await;
    tracing::info!(
        event = "audit shared_tenant_password_reset",
        instance_id = %metadata.instance_id,
        runtime_id = %runtime.runtime_id,
        protocol = %metadata.protocol,
    );
    Ok(ApiResponse::ok(ResetInstancePasswordResponse {
        instance: metadata,
        restarted: false,
    }))
}

pub(super) fn reject_logs() -> ApiError {
    ApiError::Conflict(
        "raw engine logs are pool-wide and are not exposed to shared tenants because they may contain activity from other databases"
            .to_string(),
    )
}

pub(super) async fn recover_lifecycle_panic(state: &AppState, instance_id: &str) -> String {
    route_fence::fence(state, instance_id).await;
    match state.manager.get_persisted(instance_id).await {
        Ok(Some(mut metadata)) => {
            metadata.status = InstanceStatus::Quarantined;
            metadata.desired_state = DesiredInstanceState::Stopped;
            metadata.updated_at = now_rfc3339();
            match state.manager.upsert(metadata).await {
                Ok(()) => "the tenant was fenced and quarantined without mutating its shared pool"
                    .to_string(),
                Err(error) => format!(
                    "the tenant was fenced in memory, but durable quarantine failed: {error}"
                ),
            }
        }
        Ok(None) => {
            state.instances.remove(instance_id).await;
            "the tenant route was removed because its durable metadata is missing".to_string()
        }
        Err(error) => format!(
            "the tenant was fenced in memory, but its durable state could not be read: {error}"
        ),
    }
}

async fn load_runtime(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<EngineRuntime, ApiError> {
    let runtime_id = shared_runtime_id(metadata)?;
    let runtime = state
        .placements
        .get(runtime_id)
        .await
        .map_err(placement_error)?
        .ok_or_else(|| ApiError::Conflict("the shared database runtime is missing".to_string()))?;
    check_runtime_identity(metadata, &runtime)?;
    Ok(runtime)
}

fn check_runtime_identity(
    metadata: &InstanceMetadata,
    runtime: &EngineRuntime,
) -> Result<(), ApiError> {
    let mismatches: Vec<_> = [
        (
            runtime.deployment_mode != DeploymentMode::Shared,
            "runtime_deployment_mode",
        ),
        (runtime.protocol != metadata.protocol, "protocol"),
        (runtime.runtime_id != metadata.runtime_id(), "runtime_id"),
        (metadata.owner.is_none(), "tenant_owner_missing"),
        (runtime.owner.is_none(), "runtime_owner_missing"),
        (runtime.owner != metadata.owner, "owner"),
    ]
    .into_iter()
    .filter_map(|(mismatch, field)| mismatch.then_some(field))
    .collect();
    if mismatches.is_empty() {
        return Ok(());
    }
    // Never infer ownership from an instance name or silently attach data to
    // another pool. Field names are actionable without exposing another owner.
    tracing::error!(
        event = "audit tenant_runtime_identity_conflict",
        instance_id = metadata.instance_id,
        runtime_id = metadata.runtime_id(),
        mismatched_fields = ?mismatches,
        "shared tenant placement needs operator inspection; ownership and routing were not changed"
    );
    Err(ApiError::Conflict(format!(
        "tenant placement does not match its shared runtime; check fields: {}",
        mismatches.join(", ")
    )))
}

fn shared_runtime_id(metadata: &InstanceMetadata) -> Result<&str, ApiError> {
    if metadata.deployment_mode != DeploymentMode::Shared {
        return Err(ApiError::Runtime(
            "shared lifecycle dispatch received a dedicated instance".to_string(),
        ));
    }
    if metadata.runtime_id() == metadata.instance_id {
        return Err(ApiError::Conflict(
            "a shared tenant cannot own its physical runtime identity".to_string(),
        ));
    }
    Ok(metadata.runtime_id())
}

async fn apply_tenant_disk_limit(
    state: &AppState,
    runtime: &EngineRuntime,
    metadata: &mut InstanceMetadata,
) -> Result<(), SharedLifecycleError> {
    let disk = tenant::disk::set_limit(
        &state.config,
        &state.docker,
        runtime,
        target(metadata),
        metadata.limits.disk_mib,
    )
    .await?;
    if tenant::disk::update_state(
        &mut metadata.limits,
        &mut metadata.disk_limit_blocked,
        &disk,
    )? {
        metadata.updated_at = now_rfc3339();
        state
            .manager
            .upsert_fenced(metadata.clone())
            .await
            .map_err(|error| SharedLifecycleError::Persistence(error.to_string()))?;
    }
    Ok(())
}

fn set_requested_disk_state(
    previous: &InstanceLimits,
    requested: &mut InstanceLimits,
    enforcement: &DiskEnforcement,
) -> Result<(), SharedLifecycleError> {
    tenant::disk::check_transition(previous.disk_enforced, enforcement)?;
    requested.disk_enforced = enforcement.enforced;
    requested.disk_enforcement_method = enforcement.method.clone();
    Ok(())
}

async fn ensure_soft_start_allowed(
    state: &AppState,
    runtime: &EngineRuntime,
    metadata: &mut InstanceMetadata,
) -> Result<(), SharedLifecycleError> {
    if metadata.limits.disk_enforced {
        return Ok(());
    }
    let used_bytes = measure_tenant_usage(state, runtime, metadata).await?;
    let (limit_bytes, _) = tenant::disk::soft_limit_bytes(metadata.limits.disk_mib);
    if tenant::disk::soft_limit_blocked(
        used_bytes,
        metadata.limits.disk_mib,
        metadata.disk_limit_blocked,
    ) {
        if !metadata.disk_limit_blocked {
            metadata.disk_limit_blocked = true;
            metadata.updated_at = now_rfc3339();
            state
                .manager
                .upsert_fenced(metadata.clone())
                .await
                .map_err(|error| SharedLifecycleError::Persistence(error.to_string()))?;
        }
        return Err(SharedLifecycleError::SoftDiskLimit {
            used_bytes,
            limit_bytes,
        });
    }
    if metadata.disk_limit_blocked {
        metadata.disk_limit_blocked = false;
        metadata.updated_at = now_rfc3339();
        state
            .manager
            .upsert_fenced(metadata.clone())
            .await
            .map_err(|error| SharedLifecycleError::Persistence(error.to_string()))?;
    }
    Ok(())
}

async fn measure_tenant_usage(
    state: &AppState,
    runtime: &EngineRuntime,
    metadata: &InstanceMetadata,
) -> Result<u64, SharedLifecycleError> {
    let targets = [target(metadata)];
    let values = tokio::time::timeout(
        TENANT_USAGE_TIMEOUT,
        tenant::measure_storage(&state.docker, runtime, &targets),
    )
    .await
    .map_err(|_| SharedLifecycleError::StorageUsage("measurement timed out".to_string()))??;
    match values.as_slice() {
        [used_bytes] => Ok(*used_bytes),
        _ => Err(SharedLifecycleError::StorageUsage(format!(
            "engine returned {} rows for one tenant",
            values.len()
        ))),
    }
}

async fn measure_resize_usage(
    state: &AppState,
    runtime: &EngineRuntime,
    metadata: &InstanceMetadata,
    physical_boundary: bool,
) -> Result<u64, SharedLifecycleError> {
    if !physical_boundary {
        return measure_tenant_usage(state, runtime, metadata).await;
    }
    tenant::disk::quota_usage_bytes(&state.config, runtime, target(metadata))
        .await
        .map_err(SharedLifecycleError::from)
}

/// A caller owns the logical tenant lock before entering this module, then
/// waits for the shared runtime lock. Pool-wide monitors intentionally own
/// only the runtime lock, so they can persist a disk block or failed pool state
/// while the caller is waiting. Always reload after acquiring the runtime lock
/// instead of later writing the stale pre-lock snapshot back over that state.
pub(crate) async fn reload_after_runtime_lock(
    state: &AppState,
    snapshot: &InstanceMetadata,
) -> Result<InstanceMetadata, ApiError> {
    let current = state
        .instances
        .get(&snapshot.instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    if !same_shared_identity(snapshot, &current) {
        return Err(ApiError::Conflict(
            "shared tenant identity changed while waiting for its runtime lock; retry the operation"
                .to_string(),
        ));
    }
    Ok(current)
}

async fn load_running_runtime(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<EngineRuntime, ApiError> {
    let runtime = load_runtime(state, metadata).await?;
    if runtime.status != EngineRuntimeStatus::Running {
        return Err(ApiError::Conflict(
            "the shared database runtime is not available".to_string(),
        ));
    }
    let inspection = state
        .docker
        .inspect_instance(runtime.protocol, &runtime.runtime_id)
        .await
        .map_err(docker_error)?;
    if inspection.status != DockerContainerStatus::Running {
        return Err(ApiError::Conflict(
            "the shared database runtime is not running".to_string(),
        ));
    }
    Ok(runtime)
}

async fn restore_access(
    state: &AppState,
    runtime: &EngineRuntime,
    previous: &InstanceMetadata,
    reopen_route: bool,
) -> String {
    let mut restored = previous.clone();
    let result = async {
        if restored.desired_state == DesiredInstanceState::Running {
            apply_tenant_disk_limit(state, runtime, &mut restored).await?;
            shared_runtime::apply_root_disk_limit(&state.config, &state.placements, runtime)
                .await
                .map_err(SharedLifecycleError::RootDisk)?;
            ensure_soft_start_allowed(state, runtime, &mut restored).await?;
            if reopen_route {
                let password = restored.tenant_password.clone().ok_or_else(|| {
                    tenant::TenantEngineError::MissingTenantCredential(restored.instance_id.clone())
                })?;
                tenant::open_verified(&state.docker, runtime, target(&restored), &password).await?;
            } else {
                tenant::fence(&state.docker, runtime, target(&restored)).await?;
            }
        } else {
            tenant::fence(&state.docker, runtime, target(&restored)).await?;
        }
        Ok::<_, SharedLifecycleError>(())
    }
    .await;
    match result {
        Ok(()) => {
            if reopen_route {
                state.instances.upsert(restored).await;
            } else {
                state.instances.upsert_fenced(restored).await;
            }
            "completed".to_string()
        }
        Err(error) => {
            route_fence::fence(state, &previous.instance_id).await;
            if previous.limits.disk_enforced
                && apply_tenant_disk_limit(state, runtime, &mut restored)
                    .await
                    .is_err()
            {
                let containment = super::containment::contain_locked(
                    state,
                    runtime,
                    "hard shared tenant disk boundary could not be restored",
                )
                .await;
                let report = format!(
                    "failed ({error}); hard disk boundary remained unverified; pool containment: {} ({})",
                    containment.summary(),
                    if containment.contained() {
                        "completed"
                    } else {
                        "incomplete"
                    }
                );
                tracing::error!(
                    event = "audit shared_tenant_power_rollback_contained",
                    instance_id = %previous.instance_id,
                    runtime_id = %runtime.runtime_id,
                    rollback = %report,
                );
                return report;
            }
            let mut quarantined = restored;
            quarantined.status = InstanceStatus::Quarantined;
            quarantined.desired_state = DesiredInstanceState::Stopped;
            quarantined.updated_at = now_rfc3339();
            let persisted = state.manager.upsert(quarantined).await;
            let report = format!(
                "failed ({error}); tenant remained fenced and quarantine persistence: {}",
                persisted
                    .err()
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| "completed".to_string())
            );
            tracing::error!(
                event = "audit shared_tenant_power_rollback_failed",
                instance_id = %previous.instance_id,
                runtime_id = %runtime.runtime_id,
                rollback = %report,
            );
            report
        }
    }
}

async fn rollback_resize(
    state: &AppState,
    metadata: &InstanceMetadata,
    previous_runtime: &EngineRuntime,
    previous_limits: &InstanceLimits,
    reopen_route: bool,
    _allocation_guard: &OwnedMutexGuard<()>,
) -> String {
    let mut failures = Vec::new();
    let mut restored_metadata = metadata.clone();
    let mut restored_limits = previous_limits.clone();
    let disk_restored = match tenant::disk::set_limit(
        &state.config,
        &state.docker,
        previous_runtime,
        target(metadata),
        previous_limits.disk_mib,
    )
    .await
    {
        Ok(disk) => match set_requested_disk_state(previous_limits, &mut restored_limits, &disk) {
            Ok(()) => true,
            Err(error) => {
                failures.push(format!("disk quota rollback became unsafe: {error}"));
                false
            }
        },
        Err(error) => {
            failures.push(format!("disk quota rollback failed: {error}"));
            false
        }
    };
    restored_metadata.limits = restored_limits.clone();
    if restored_metadata.limits.disk_enforced {
        restored_metadata.disk_limit_blocked = false;
    }
    restored_metadata.updated_at = now_rfc3339();

    let reservation_restored = match state
        .placements
        .resize(&metadata.instance_id, &restored_limits)
        .await
    {
        Ok(_) => true,
        Err(error) => {
            failures.push(format!("reservation rollback failed: {error}"));
            false
        }
    };
    let restored = match state.placements.get(&previous_runtime.runtime_id).await {
        Ok(Some(runtime)) => runtime,
        Ok(None) => {
            failures.push("shared runtime disappeared during rollback".to_string());
            previous_runtime.clone()
        }
        Err(error) => {
            failures.push(format!("failed to reload shared runtime: {error}"));
            previous_runtime.clone()
        }
    };
    if let Err(error) =
        shared_runtime::apply_limits(&state.docker, &state.config, &state.placements, &restored)
            .await
    {
        failures.push(format!("pool limit rollback failed: {error}"));
    }
    if let Err(error) =
        tenant::set_quota(&state.docker, &restored, target(metadata), &restored_limits).await
    {
        failures.push(format!("tenant quota rollback failed: {error}"));
    }
    if disk_restored
        && reservation_restored
        && let Err(error) = state.manager.upsert_fenced(restored_metadata.clone()).await
    {
        failures.push(format!("tenant metadata rollback failed: {error}"));
    }
    if failures.is_empty() {
        let access = restore_access(state, &restored, &restored_metadata, reopen_route).await;
        if access != "completed" {
            failures.push(format!("tenant access rollback {access}"));
        }
    }
    if failures.is_empty() {
        "completed".to_string()
    } else {
        let report = failures.join("; ");
        quarantine_resize_failure(state, metadata, &restored).await;
        tracing::error!(
            event = "audit shared_tenant_limits_rollback_failed",
            instance_id = %metadata.instance_id,
            runtime_id = %metadata.runtime_id(),
            failures = %report,
        );
        report
    }
}

async fn quarantine_resize_failure(
    state: &AppState,
    metadata: &InstanceMetadata,
    fallback_runtime: &EngineRuntime,
) {
    let report = super::containment::contain_locked(
        state,
        fallback_runtime,
        "shared tenant limit rollback could not restore the pool aggregate",
    )
    .await;
    if !report.contained() {
        tracing::error!(
            event = "audit shared_runtime_limits_containment_incomplete",
            instance_id = %metadata.instance_id,
            runtime_id = %fallback_runtime.runtime_id,
            errors = %report.summary(),
        );
    }
}

async fn rollback_password(
    state: &AppState,
    runtime: &EngineRuntime,
    previous: &InstanceMetadata,
    previous_password: &str,
    original_error: String,
) -> ApiResult<ResetInstancePasswordResponse> {
    let target = target(previous);
    let rollback = tenant::rotate_password(&state.docker, runtime, target, previous_password).await;
    let verified = match rollback {
        Ok(()) => tenant::verify_password(&state.docker, runtime, target, previous_password).await,
        Err(error) => Err(error),
    };
    if let Err(rollback_error) = verified {
        let mut quarantined = previous.clone();
        quarantined.status = InstanceStatus::Quarantined;
        quarantined.desired_state = DesiredInstanceState::Stopped;
        quarantined.updated_at = now_rfc3339();
        let persist = state.manager.upsert(quarantined).await;
        return Err(ApiError::Runtime(format!(
            "shared password reset failed ({original_error}) and rollback failed ({rollback_error}); tenant was fenced and quarantine persistence: {}",
            persist
                .err()
                .map(|error| error.to_string())
                .unwrap_or_else(|| "completed".to_string())
        )));
    }
    state.instances.upsert(previous.clone()).await;
    Err(ApiError::Runtime(format!(
        "shared password reset failed and the previous credential was restored: {original_error}"
    )))
}

#[cfg(test)]
mod tests;
