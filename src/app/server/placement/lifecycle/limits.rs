use super::*;

/// Restores hard limits for physical shared pools. Tenant ids never reach a
/// container or filesystem-limit API here: each placement row is visited once
/// and all physical work is keyed by `runtime_id`.
pub(crate) async fn restore_shared_limits(
    state: &AppState,
    disk_limiter: &DiskLimiter,
) -> anyhow::Result<()> {
    let runtimes = shared_runtimes(&state.placements).await?;
    let outcomes = futures::stream::iter(runtimes)
        .map(|runtime| restore_runtime_limits(state, disk_limiter, runtime.runtime_id))
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    for outcome in outcomes {
        outcome?;
    }
    Ok(())
}

async fn restore_runtime_limits(
    state: &AppState,
    disk_limiter: &DiskLimiter,
    runtime_id: String,
) -> anyhow::Result<()> {
    let _operation = state.instance_locks.lock(&runtime_id).await;
    let Some(mut runtime) = state.placements.get(&runtime_id).await? else {
        return Ok(());
    };
    if runtime.deployment_mode != DeploymentMode::Shared
        || runtime.status == EngineRuntimeStatus::Deleting
    {
        return Ok(());
    }
    let restored =
        restore_one_limit(&state.config, &state.docker, disk_limiter, &mut runtime).await;
    let Err(error) = restored else {
        return save_runtime(&state.placements, &state.manager, runtime).await;
    };
    let containment = containment::contain_locked(
        state,
        &runtime,
        "aggregate shared-pool limit recovery failed",
        Some(QuarantineKind::StorageBoundary),
    )
    .await;
    tracing::error!(
        event = "audit shared_runtime_limit_recovery_failed",
        runtime_id,
        %error,
        containment = %containment.summary(),
        contained = containment.contained(),
        "quarantined one shared pool and all of its tenants after aggregate limit recovery failed"
    );
    anyhow::ensure!(
        containment.contained(),
        "shared pool {runtime_id} could not be contained after limit recovery failed: {}",
        containment.summary()
    );
    Ok(())
}

/// Finishes deletion of pools that have no durable tenant reservations. This
/// runs after migration recovery and before limits, reconciliation, or route
/// publication, so an interrupted cleanup cannot revive an orphaned engine.
pub(crate) async fn recover_pool_deletions(state: &AppState) -> usize {
    let runtimes = match shared_runtimes(&state.placements).await {
        Ok(runtimes) => runtimes,
        Err(error) => {
            tracing::error!(%error, "failed to load shared pools for empty-pool recovery");
            return 0;
        }
    };
    let outcomes = futures::stream::iter(runtimes)
        .map(|snapshot| recover_pool_deletion(state, snapshot))
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    outcomes.into_iter().filter(|deleted| *deleted).count()
}

async fn recover_pool_deletion(state: &AppState, snapshot: EngineRuntime) -> bool {
    // Unowned pools are quarantined for operator handling, not
    // guessed empty or automatically adopted/deleted during upgrade.
    if snapshot.owner.is_none() || snapshot.status != EngineRuntimeStatus::Deleting {
        return false;
    }
    let runtime_id = snapshot.runtime_id.clone();
    let _operation = state.instance_locks.lock(&runtime_id).await;
    match state.placements.tenant_count(&runtime_id).await {
        Ok(0) => {}
        Ok(_) => return false,
        Err(error) => {
            tracing::error!(
                event = "audit empty_shared_runtime_recovery_failed",
                runtime_id,
                %error,
                "could not verify whether a shared pool is empty"
            );
            return false;
        }
    }
    let error = match crate::subsystems::instances::delete_empty_pool(state, &runtime_id).await {
        Ok(deleted) => return deleted,
        Err(error) => error,
    };
    let containment = containment::contain_locked(
        state,
        &snapshot,
        "interrupted empty shared-pool cleanup failed",
        Some(QuarantineKind::ProvisioningIncomplete),
    )
    .await;
    tracing::error!(
        event = "audit empty_shared_runtime_recovery_failed",
        runtime_id,
        %error,
        containment = %containment.summary(),
        contained = containment.contained(),
        "retained and quarantined an empty shared pool whose cleanup could not finish"
    );
    false
}

async fn restore_one_limit(
    config: &Config,
    docker: &DockerRuntime,
    disk_limiter: &DiskLimiter,
    runtime: &mut EngineRuntime,
) -> anyhow::Result<()> {
    let paths = InstancePaths::new(&config.paths, &runtime.runtime_id).with_context(|| {
        format!(
            "failed to build paths for shared pool {}",
            runtime.runtime_id
        )
    })?;
    if let Some((uid, gid)) = docker.rootless_podman_host_owner() {
        paths.create_dirs().await?;
        paths.apply_rootless_owner(uid, gid).await?;
    }
    let limiter = disk_limiter
        .for_persisted_protocol(runtime.protocol, &runtime.limits.disk_enforcement_method);
    limiter.check_method_change(&runtime.limits.disk_enforcement_method)?;
    let expected_source = limiter.container_data_path(&paths.data)?;
    match docker
        .verify_data_bind(runtime.protocol, &runtime.runtime_id, &expected_source)
        .await
    {
        Ok(_) => {}
        Err(error) if error.is_not_found() => {}
        Err(error) => return Err(error.into()),
    }
    let adopting_pool =
        needs_pool_adoption(limiter.mode(), &runtime.limits.disk_enforcement_method);
    let limiter_healthy = limiter.runtime_is_healthy(&paths.data).await?;
    if adopting_pool || !limiter_healthy {
        // Native project adoption rewrites inode ownership throughout the
        // existing pool. Freeze the engine even when its old soft limiter is
        // healthy so no database write can race that one-time transition.
        match docker.stop(runtime.protocol, &runtime.runtime_id).await {
            Ok(_) => {}
            Err(error) if error.is_not_found() || error.is_not_running() => {}
            Err(error) => return Err(error.into()),
        }
    }
    if !limiter_healthy {
        limiter.teardown_instance_mount(&paths.data).await?;
    }
    if adopting_pool {
        // Pools persisted under the legacy soft guard have no native root
        // project. Adopt that root once, before tenant quotas are replayed.
        let enforcement = limiter
            .apply_instance_limit(&runtime.runtime_id, &paths.data, runtime.limits.disk_mib)
            .await
            .with_context(|| {
                format!(
                    "failed to adopt legacy shared pool {} into native project quotas; the pool was stopped before adoption and remains isolated",
                    runtime.runtime_id
                )
            })?;
        runtime.limits.disk_enforced = enforcement.enforced;
        runtime.limits.disk_enforcement_method = enforcement.method;
    } else {
        // An adopted pool may only receive a quota-value update. Recursively
        // re-adopting its root would overwrite tenant child project IDs.
        limiter
            .update_shared_pool_limit(&runtime.runtime_id, &paths.data, runtime.limits.disk_mib)
            .await?;
    }
    match docker
        .update_limits(
            runtime.protocol,
            &runtime.runtime_id,
            runtime.limits.cpu_cores,
            runtime.limits.memory_mib,
        )
        .await
    {
        Ok(_) => {}
        Err(error) if error.is_not_found() => {}
        Err(error) => return Err(error.into()),
    }
    runtime.updated_at = now_rfc3339();
    Ok(())
}

pub(super) fn needs_pool_adoption(current: DiskLimitMode, persisted_method: &str) -> bool {
    current == DiskLimitMode::ProjectQuota
        && DiskLimitMode::from_persisted_method(persisted_method)
            != Some(DiskLimitMode::ProjectQuota)
}

pub(super) fn pool_is_isolated(runtime: &EngineRuntime, network_mode: Option<&str>) -> bool {
    network_mode == Some(ISOLATED_NETWORK_MODE)
        && matches!(&runtime.backend, BackendEndpoint::UnixSocket { .. })
}

pub(crate) async fn sync_shared_cpu_burst(
    placements: &PlacementRepository,
    docker: &DockerRuntime,
    locks: &InstanceLocks,
) -> anyhow::Result<()> {
    let runtimes = shared_runtimes(placements)
        .await?
        .into_iter()
        .filter(|runtime| runtime.status == EngineRuntimeStatus::Running);
    let outcomes = futures::stream::iter(runtimes)
        .map(|runtime| async move {
            let _operation = locks.lock(&runtime.runtime_id).await;
            let result = docker
                .apply_cpu_burst_policy(runtime.protocol, &runtime.runtime_id)
                .await;
            (runtime, result)
        })
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    for (runtime, result) in outcomes {
        if let Err(error) = result {
            tracing::warn!(
                event = "shared_cpu_burst_reconciliation_failed",
                runtime_id = %runtime.runtime_id,
                protocol = %runtime.protocol,
                %error,
                "failed to reconcile shared-pool CPU burst credit; the hard aggregate CPU quota remains active"
            );
        }
    }
    Ok(())
}
