use axum::extract::State;

use crate::{
    api::http::{
        policy::ApiRequestContext,
        response::{ApiError, ApiJson, ApiPath, ApiResponse, ApiResult},
        router::AppState,
    },
    auth::scopes,
    placement::{DeploymentMode, EngineRuntime, EngineRuntimeStatus, PoolLimits, runtime},
};

#[derive(serde::Serialize)]
pub(crate) struct PoolConfig {
    pub runtime_id: String,
    pub owner: crate::placement::PoolOwner,
    pub limits: PoolLimits,
}

/// Resizes the engine, never an individual tenant. Pool capacity is persisted
/// before runtime mutation so restart recovery reapplies the same budget.
pub(crate) async fn resize_pool(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(runtime_id): ApiPath<String>,
    ApiJson(limits): ApiJson<PoolLimits>,
) -> ApiResult<PoolConfig> {
    auth.require_scope(scopes::POOLS_WRITE)?;
    limits.check().map_err(ApiError::BadRequest)?;
    let mutation = state
        .daemon_shutdown
        .try_admit_background_mutation()
        .ok_or_else(|| ApiError::ServiceUnavailable("daemon is shutting down".into()))?;
    let creation = state.instance_locks.lock_creation().await;
    let operation = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        state.instance_locks.lock(&runtime_id),
    )
    .await
    .map_err(|_| ApiError::Conflict("pool is busy; retry the resize".into()))?;
    crate::api::instances::spawn_owned_mutation_task(async move {
        let _mutation = mutation;
        let creation = creation;
        let _operation = operation;
        let mut pool = state
            .placements
            .get(&runtime_id)
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?
            .filter(|pool| pool.deployment_mode == DeploymentMode::Shared)
            .ok_or(ApiError::NotFound)?;
        check_resize(&pool, &limits)?;
        crate::api::instances::requests::validate_protocol_limits(
            pool.protocol,
            &crate::api::instances::requests::LimitsRequest {
                cpu_cores: limits.cpu_cores,
                memory_mib: limits.memory_mib,
                disk_mib: limits.disk_mib,
            },
        )?;
        crate::api::instances::create::enforce_node_allocation_policy(
            &state,
            &limits.limits(),
            Some(&pool.limits),
        )
        .await?;
        pool.limits.cpu_cores = limits.cpu_cores;
        pool.limits.memory_mib = limits.memory_mib;
        pool.limits.disk_mib = limits.disk_mib;
        pool.max_tenants = limits.max_tenants;
        pool.updated_at = crate::shared::time::now_rfc3339();
        state
            .placements
            .save(&pool)
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        drop(creation);
        if let Err(error) =
            runtime::apply_limits(&state.docker, &state.config, &state.placements, &pool).await
        {
            let containment = crate::api::instances::containment::contain_locked(
                &state,
                &pool,
                "pool resize runtime update failed",
            )
            .await;
            return Err(ApiError::Runtime(format!(
                "pool limits were saved but could not be applied: {error}; containment: {}",
                containment.summary()
            )));
        }
        state.instance_runtime_cache.remove(&runtime_id).await;
        state.resource_cache.invalidate_disk(&runtime_id).await;
        tracing::info!(event = "audit shared_pool_resized", %runtime_id, owner = ?pool.owner,
            cpu_cores = pool.limits.cpu_cores, memory_mib = pool.limits.memory_mib,
            disk_mib = pool.limits.disk_mib, max_tenants = pool.max_tenants);
        Ok(ApiResponse::ok(PoolConfig {
            runtime_id: pool.runtime_id,
            owner: pool
                .owner
                .ok_or_else(|| ApiError::Conflict("shared_pool_owner_required".into()))?,
            limits,
        }))
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("pool resize worker failed: {error}")))?
}

fn check_resize(pool: &EngineRuntime, limits: &PoolLimits) -> Result<(), ApiError> {
    if pool.owner.is_none() || pool.status != EngineRuntimeStatus::Running {
        return Err(ApiError::Conflict(
            "shared_pool_unavailable: repair the server pool before resizing".into(),
        ));
    }
    // Shrinking live shared storage or memory requires a separate drained
    // maintenance operation, not an optimistic sample of current usage.
    if limits.memory_mib < pool.limits.memory_mib || limits.disk_mib < pool.limits.disk_mib {
        return Err(ApiError::Conflict(
            "live pool memory/disk shrinking is not supported; migrate tenants to reduce capacity"
                .into(),
        ));
    }
    if limits.max_tenants < pool.reserved.tenants {
        return Err(ApiError::Conflict(
            "pool max_tenants cannot be smaller than its reserved database count".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_resize_preserves_storage_and_reservations() {
        let mut pool = crate::placement::test_support::runtime(
            "server-a",
            crate::shared::protocol::Protocol::Postgres,
            "postgres:18",
        );
        pool.reserved.tenants = 2;
        let mut limits = PoolLimits {
            cpu_cores: pool.limits.cpu_cores,
            memory_mib: pool.limits.memory_mib,
            disk_mib: pool.limits.disk_mib,
            max_tenants: 2,
        };
        assert!(check_resize(&pool, &limits).is_ok());
        limits.max_tenants = 1;
        assert!(check_resize(&pool, &limits).is_err());
        limits.max_tenants = 2;
        limits.memory_mib -= 1;
        assert!(check_resize(&pool, &limits).is_err());
        limits.memory_mib += 1;
        pool.owner = None;
        assert!(check_resize(&pool, &limits).is_err());
    }
}
