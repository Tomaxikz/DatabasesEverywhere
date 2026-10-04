use super::super::{LifecycleAction, docker_error, route_fence};
use super::POOL_READY_TIMEOUT;
use super::lifecycle::{
    SharedLifecycleError, check_power_state, completion_report, mark_quarantined, route_was_open,
};
use super::maintenance::{clear_caches, drain_tenant_sessions};
use super::runtime::{
    apply_tenant_disk_limit, ensure_soft_start_allowed, load_runtime, reload_after_runtime_lock,
    restore_access, shared_runtime_id,
};
use crate::routes::http::response::{ApiError, ApiResponse, ApiResult};
use crate::routes::http::router::AppState;
use crate::runtime::docker::DockerContainerStatus;
use crate::server::metadata::{DesiredInstanceState, InstanceMetadata, InstanceStatus};
use crate::server::placement::runtime as shared_runtime;
use crate::server::placement::tenant::TenantTarget;
use crate::server::placement::{EngineRuntimeStatus, tenant};
use crate::utils::time::now_rfc3339;

pub(in super::super) async fn change_state(
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
    let starting = matches!(action, LifecycleAction::Start | LifecycleAction::Restart);
    if starting && (!pool_running || runtime.status != EngineRuntimeStatus::Running) {
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

    (metadata.desired_state, metadata.status) = if starting {
        (DesiredInstanceState::Running, InstanceStatus::Running)
    } else {
        (DesiredInstanceState::Stopped, InstanceStatus::Stopped)
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
                mark_quarantined(&mut persisted);
                route_fence::fence(state, &metadata.instance_id).await;
                let quarantine = state
                    .manager
                    .quarantine(
                        persisted,
                        crate::storage::quarantine::QuarantineKind::MetadataUncertain,
                    )
                    .await;
                return Err(ApiError::Runtime(format!(
                    "shared tenant lifecycle changed engine access, but durable state is ambiguous after {error}; tenant remained fenced and quarantine persistence: {}",
                    completion_report(quarantine)
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
