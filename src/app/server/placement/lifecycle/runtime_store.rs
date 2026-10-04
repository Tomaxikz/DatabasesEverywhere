use super::{report_missing_tenant, runtime_tenants, store_tenants, tenant_status};
use crate::{
    server::{
        manager::InstanceManager,
        metadata::DesiredInstanceState,
        placement::{DeploymentMode, EngineRuntime, EngineRuntimeStatus, PlacementRepository},
    },
    state::AppState,
    utils::time::now_rfc3339,
};

pub(crate) async fn save_runtime(
    placements: &PlacementRepository,
    manager: &InstanceManager,
    runtime: EngineRuntime,
) -> anyhow::Result<()> {
    placements.save(&runtime).await?;
    let tenants = runtime_tenants(placements, manager, &runtime.runtime_id).await;
    for (instance_id, reservation_state) in tenants {
        let Some(mut metadata) = manager.get_persisted(&instance_id).await? else {
            report_missing_tenant(&runtime.runtime_id, &instance_id, reservation_state);
            continue;
        };
        if metadata.deployment_mode != DeploymentMode::Shared
            || metadata.runtime_id() != runtime.runtime_id
            || metadata.protocol != runtime.protocol
            || metadata.owner != runtime.owner
        {
            tracing::error!(
                event = "audit shared_runtime_tenant_mismatch",
                runtime_id = %runtime.runtime_id,
                instance_id,
                "refused to propagate pool state to mismatched tenant metadata"
            );
            continue;
        }
        metadata.status = tenant_status(runtime.status, metadata.desired_state, metadata.status);
        if runtime.status == EngineRuntimeStatus::Quarantined {
            metadata.desired_state = DesiredInstanceState::Stopped;
        }
        if let Some(version) = &runtime.database_version
            && let Some(database_version) = &mut metadata.database_version
        {
            database_version.current = Some(version.clone());
            database_version.error = None;
        }
        if let Some(image) = &mut metadata.image {
            image.current = Some(runtime.image.clone());
        }
        metadata.updated_at = now_rfc3339();
        manager.upsert_preserving_fence(metadata).await?;
    }
    Ok(())
}

pub(super) async fn shared_runtimes(
    placements: &PlacementRepository,
) -> anyhow::Result<Vec<EngineRuntime>> {
    Ok(placements
        .list()
        .await?
        .into_iter()
        .filter(|runtime| runtime.deployment_mode == DeploymentMode::Shared)
        .collect())
}

pub(crate) async fn fence_runtime(state: &AppState, runtime_id: &str) -> bool {
    let mut all_fenced = true;
    for instance_id in store_tenants(&state.manager, runtime_id).await {
        all_fenced &= crate::server::sessions::fence(
            &state.instances,
            &state.gateway_supervisor.tenant_sessions(),
            &instance_id,
        )
        .await;
    }
    all_fenced
}

pub(crate) async fn clear_runtime_caches(state: &AppState, runtime_id: &str) {
    let tenant_ids = store_tenants(&state.manager, runtime_id).await;
    state.instance_runtime_cache.remove(runtime_id).await;
    state.resource_cache.invalidate_runtime(runtime_id).await;
    for instance_id in tenant_ids {
        state.instance_runtime_cache.remove(&instance_id).await;
        state.resource_cache.invalidate_runtime(&instance_id).await;
    }
}
