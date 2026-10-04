use super::super::{docker_error, route_fence};
use super::TENANT_USAGE_TIMEOUT;
use super::lifecycle::{
    SharedLifecycleError, completion_report, mark_quarantined, placement_error,
    same_shared_identity, target,
};
use crate::routes::http::response::ApiError;
use crate::routes::http::router::AppState;
use crate::runtime::docker::DockerContainerStatus;
use crate::server::disk::DiskEnforcement;
use crate::server::metadata::{DesiredInstanceState, InstanceMetadata};
use crate::server::placement::runtime as shared_runtime;
use crate::server::placement::{DeploymentMode, EngineRuntime, EngineRuntimeStatus, tenant};
use crate::utils::limits::InstanceLimits;
use crate::utils::time::now_rfc3339;

pub(super) async fn load_runtime(
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

pub(super) fn check_runtime_identity(
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

pub(super) fn shared_runtime_id(metadata: &InstanceMetadata) -> Result<&str, ApiError> {
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

pub(super) async fn apply_tenant_disk_limit(
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

pub(super) fn set_requested_disk_state(
    previous: &InstanceLimits,
    requested: &mut InstanceLimits,
    enforcement: &DiskEnforcement,
) -> Result<(), SharedLifecycleError> {
    tenant::disk::check_transition(previous.disk_enforced, enforcement)?;
    requested.disk_enforced = enforcement.enforced;
    requested.disk_enforcement_method = enforcement.method.clone();
    Ok(())
}

pub(super) async fn ensure_soft_start_allowed(
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

pub(super) async fn measure_tenant_usage(
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

pub(super) async fn load_running_runtime(
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

pub(super) async fn restore_access(
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
                let containment = super::super::containment::contain_locked(
                    state,
                    runtime,
                    "hard shared tenant disk boundary could not be restored",
                    Some(crate::storage::quarantine::QuarantineKind::StorageBoundary),
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
            mark_quarantined(&mut quarantined);
            let persisted = state
                .manager
                .quarantine(
                    quarantined,
                    crate::storage::quarantine::QuarantineKind::StorageBoundary,
                )
                .await;
            let report = format!(
                "failed ({error}); tenant remained fenced and quarantine persistence: {}",
                completion_report(persisted)
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
