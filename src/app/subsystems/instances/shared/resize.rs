use super::super::route_fence;
use super::lifecycle::{SharedLifecycleError, limits_match, route_was_open, target};
use super::maintenance::{clear_caches, drain_tenant_sessions};
use super::runtime::{
    load_runtime, measure_tenant_usage, reload_after_runtime_lock, restore_access,
    set_requested_disk_state, shared_runtime_id,
};
use crate::routes::http::response::ApiError;
use crate::routes::http::router::AppState;
use crate::server::metadata::{InstanceMetadata, InstanceStatus};
use crate::server::placement::runtime as shared_runtime;
use crate::server::placement::{EngineRuntime, EngineRuntimeStatus, tenant};
use crate::utils::limits::{InstanceLimits, mib_to_bytes};
use crate::utils::time::now_rfc3339;
use tokio::sync::OwnedMutexGuard;

pub(in super::super) async fn resize(
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
    if crate::server::placement::policy::pool_disk_mib(metadata.protocol, next_disk)
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
    let disk_mutation = requested.disk_mib != previous_limits.disk_mib;
    let was_open = route_was_open(
        &metadata,
        state.instances.routes_fenced(&metadata.instance_id).await,
    );
    let mut measured_usage = None;
    if disk_mutation {
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
            measured_usage = Some(used_bytes);
        }
    }

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

    let rollback_this_resize = || {
        rollback_resize(
            state,
            &metadata,
            &previous_runtime,
            &previous_limits,
            was_open,
            &creation,
        )
    };
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
                            let rollback = rollback_this_resize().await;
                            return Err(ApiError::Runtime(format!(
                                "shared resize committed but its physical runtime is missing; rollback: {rollback}"
                            )));
                        }
                        Err(read_error) => {
                            route_fence::fence(state, &metadata.instance_id).await;
                            let rollback = rollback_this_resize().await;
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
                    let rollback = rollback_this_resize().await;
                    return Err(ApiError::Runtime(format!(
                        "shared resize was not committed: {error}; quota rollback: {rollback}"
                    )));
                }
                persisted => {
                    route_fence::fence(state, &metadata.instance_id).await;
                    let rollback = rollback_this_resize().await;
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
        let rollback = rollback_this_resize().await;
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
        let rollback = rollback_this_resize().await;
        return Err(ApiError::Runtime(format!(
            "shared tenant limits were applied, but their final metadata could not be persisted ({error}); rollback: {rollback}"
        )));
    }
    if disk_mutation && was_open {
        let restored = restore_access(state, &runtime, &updated, true).await;
        if restored != "completed" {
            let rollback = rollback_this_resize().await;
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

pub(super) async fn measure_resize_usage(
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

pub(super) async fn rollback_resize(
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

pub(super) async fn quarantine_resize_failure(
    state: &AppState,
    metadata: &InstanceMetadata,
    fallback_runtime: &EngineRuntime,
) {
    let report = super::super::containment::contain_locked(
        state,
        fallback_runtime,
        "shared tenant limit rollback could not restore the pool aggregate",
        Some(crate::storage::quarantine::QuarantineKind::StorageBoundary),
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
