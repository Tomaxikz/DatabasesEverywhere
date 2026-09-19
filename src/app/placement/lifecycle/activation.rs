use super::failure::Phase;
use super::*;

/// Caller holds the pool lock. Both boot and API power use this path.
pub(crate) async fn activate_locked(
    state: &AppState,
    runtime: &mut EngineRuntime,
    restart: bool,
) -> anyhow::Result<()> {
    if runtime.owner.is_none()
        || matches!(
            runtime.status,
            EngineRuntimeStatus::Quarantined | EngineRuntimeStatus::Deleting
        )
    {
        anyhow::bail!("pool is not eligible for activation");
    }
    if runtime.pending_image.is_none() {
        runtime.desired_state = DesiredInstanceState::Running;
    }
    runtime.status = EngineRuntimeStatus::Booting;
    runtime.updated_at = now_rfc3339();
    fence_runtime(state, &runtime.runtime_id).await;
    let mut phase = Phase::Metadata;
    let result = async {
        save_runtime(&state.placements, &state.manager, runtime.clone()).await?;
        phase = Phase::StorageBoundary;
        check_shared_start_disk(state, runtime).await?;
        // Verify isolation before starting anything, not only after readiness.
        phase = Phase::Isolation;
        let inspection = state
            .docker
            .inspect_instance(runtime.protocol, &runtime.runtime_id)
            .await?;
        anyhow::ensure!(
            inspection.network_mode.as_deref() == Some("none")
                && matches!(
                    &runtime.backend,
                    crate::shared::backend::BackendEndpoint::UnixSocket { .. }
                ),
            "pool network isolation or backend changed"
        );
        phase = Phase::SocketDirectory;
        paths::prepare_socket_directory(state, runtime)
            .await
            .context("failed to prepare shared pool socket directory")?;
        phase = Phase::ResourceLimits;
        state
            .docker
            .update_limits(
                runtime.protocol,
                &runtime.runtime_id,
                runtime.limits.cpu_cores,
                runtime.limits.memory_mib,
            )
            .await?;
        phase = Phase::StorageBoundary;
        crate::placement::runtime::apply_root_disk_limit(&state.config, &state.placements, runtime)
            .await
            .map_err(anyhow::Error::msg)?;
        phase = Phase::EngineStart;
        if restart {
            state
                .docker
                .restart(runtime.protocol, &runtime.runtime_id)
                .await?;
        } else {
            state
                .docker
                .start(runtime.protocol, &runtime.runtime_id)
                .await?;
        }
        phase = Phase::Readiness;
        state
            .docker
            .wait_until_ready(runtime.protocol, &runtime.runtime_id, POOL_READY_TIMEOUT)
            .await?;
        phase = Phase::PoolSecurity;
        attest_runtime_locked(state, runtime)
            .await
            .map_err(anyhow::Error::msg)?;
        phase = Phase::Isolation;
        let inspection = state
            .docker
            .inspect_instance(runtime.protocol, &runtime.runtime_id)
            .await?;
        if inspection.network_mode.as_deref() != Some("none") {
            anyhow::bail!("pool network isolation changed");
        }
        phase = Phase::Metadata;
        runtime.status = EngineRuntimeStatus::Running;
        runtime.updated_at = now_rfc3339();
        save_runtime(&state.placements, &state.manager, runtime.clone()).await?;
        if runtime.pending_image.is_none() {
            phase = Phase::TenantSecurity;
            let recovery = crate::placement::tenant::recovery::reconcile_runtime_tenants_locked(
                state, runtime,
            )
            .await?;
            anyhow::ensure!(recovery.pools_contained == 0, "pool failed tenant recovery");
        }
        state
            .docker
            .enforce_cpu_burst_policy(runtime.protocol, &runtime.runtime_id)
            .await;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(error) = &result {
        failure::handle(state, runtime, phase, error).await?;
    }
    clear_runtime_caches(state, &runtime.runtime_id).await;
    result
}
