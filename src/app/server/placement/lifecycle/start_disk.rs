use super::*;

pub(crate) async fn check_shared_start_disk(
    state: &AppState,
    runtime: &EngineRuntime,
) -> anyhow::Result<()> {
    let paths = InstancePaths::new(&state.config.paths, &runtime.runtime_id)?;
    let limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
            .for_persisted_protocol(runtime.protocol, &runtime.limits.disk_enforcement_method);
    limiter.check_method_change(&runtime.limits.disk_enforcement_method)?;
    let expected = limiter.container_data_path(&paths.data)?;
    state
        .docker
        .verify_data_bind(runtime.protocol, &runtime.runtime_id, &expected)
        .await?;
    if !crate::server::disk::soft::SoftDiskLimiter::enforcement_required(
        state.config.disk.mode,
        runtime.protocol,
    ) {
        return Ok(());
    }
    crate::server::disk::soft::SoftDiskLimiter::new(state.config.disk.soft_scanner.clone())
        .ensure_start_allowed(&SoftDiskTarget {
            instance_id: runtime.runtime_id.clone(),
            created_at: runtime.created_at.clone(),
            protocol: runtime.protocol,
            data_path: paths.data,
            limit_bytes: mib_to_bytes(runtime.limits.disk_mib),
            durable_blocked: false,
        })
        .await
        .map_err(anyhow::Error::msg)
        .context(failure::CapacityUnavailable)?;
    Ok(())
}

pub(crate) async fn isolate_runtime(
    state: &AppState,
    runtime: EngineRuntime,
    reason: &str,
    kind: QuarantineKind,
) -> bool {
    containment::contain_locked(state, &runtime, reason, Some(kind))
        .await
        .contained()
}

pub(crate) async fn mark_shared_disk_blocked(
    state: &AppState,
    target: &SoftDiskTarget,
) -> Result<bool, String> {
    let Some(mut runtime) = state
        .placements
        .get(&target.instance_id)
        .await
        .map_err(|error| error.to_string())?
    else {
        return Ok(false);
    };
    if !shared_disk_target_is_current(&runtime, target) {
        return Ok(false);
    }
    runtime.status = EngineRuntimeStatus::Failed;
    runtime.updated_at = now_rfc3339();
    fence_runtime(state, &runtime.runtime_id).await;
    save_runtime(&state.placements, &state.manager, runtime.clone())
        .await
        .map_err(|error| error.to_string())?;
    clear_runtime_caches(state, &runtime.runtime_id).await;
    Ok(true)
}

pub(super) fn shared_disk_target_is_current(
    runtime: &EngineRuntime,
    target: &SoftDiskTarget,
) -> bool {
    runtime.deployment_mode == DeploymentMode::Shared
        && runtime.runtime_id == target.instance_id
        && runtime.created_at == target.created_at
        && runtime.protocol == target.protocol
        && matches!(
            runtime.status,
            EngineRuntimeStatus::Running | EngineRuntimeStatus::Booting
        )
        && mib_to_bytes(runtime.limits.disk_mib) == target.limit_bytes
}
