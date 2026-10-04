use futures::StreamExt;

use super::{
    POOL_READY_TIMEOUT, attest_runtime_locked, classify_runtime_status, clear_runtime_caches,
    failure, fence_runtime, honor_stop, pool_is_isolated, save_runtime, shared_runtimes,
};
use crate::{
    runtime::docker::DockerContainerStatus,
    server::placement::{EngineRuntimeStatus, containment},
    state::AppState,
    storage::quarantine::QuarantineKind,
    utils::{constants::MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY, time::now_rfc3339},
};

pub(crate) async fn reconcile_shared_snapshot(state: &AppState) {
    let runtimes = match shared_runtimes(&state.placements).await {
        Ok(runtimes) => runtimes,
        Err(error) => {
            tracing::error!(%error, "failed to load shared pools for event snapshot reconciliation");
            return;
        }
    };
    let outcomes = futures::stream::iter(runtimes)
        .map(|snapshot| reconcile_snapshot_runtime(state, snapshot.runtime_id))
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    for outcome in outcomes {
        if let Err(error) = outcome {
            tracing::error!(%error, "failed to reconcile shared-pool event snapshot");
        }
    }
}

async fn reconcile_snapshot_runtime(state: &AppState, runtime_id: String) -> anyhow::Result<()> {
    let _operation = state.instance_locks.lock(&runtime_id).await;
    let Some(mut runtime) = state.placements.get(&runtime_id).await? else {
        return Ok(());
    };
    if honor_stop(state, &mut runtime).await? {
        return Ok(());
    }
    let previous = runtime.status;
    if runtime.status == EngineRuntimeStatus::Deleting {
        return Ok(());
    }
    if runtime.status == EngineRuntimeStatus::Quarantined {
        let containment = containment::contain_locked(
            state,
            &runtime,
            "snapshot reconciliation found a durably quarantined shared pool",
            None,
        )
        .await;
        clear_runtime_caches(state, &runtime_id).await;
        anyhow::ensure!(
            containment.contained(),
            "quarantined shared pool {runtime_id} could not be contained during snapshot reconciliation: {}",
            containment.summary()
        );
        return Ok(());
    }
    let inspection = match state
        .docker
        .inspect_instance(runtime.protocol, &runtime_id)
        .await
    {
        Ok(inspection) => inspection,
        Err(error) => {
            failure::handle(
                state,
                &mut runtime,
                failure::Phase::Isolation,
                &error.into(),
            )
            .await?;
            return Ok(());
        }
    };
    if !pool_is_isolated(&runtime, inspection.network_mode.as_deref()) {
        let containment = containment::contain_locked(
            state,
            &runtime,
            "snapshot reconciliation found invalid physical shared-pool isolation",
            Some(QuarantineKind::IsolationMismatch),
        )
        .await;
        tracing::error!(
            event = "audit shared_runtime_snapshot_isolation_mismatch",
            runtime_id,
            protocol = %runtime.protocol,
            network_mode = ?inspection.network_mode,
            containment = %containment.summary(),
            contained = containment.contained(),
            "quarantined a shared pool discovered with invalid physical isolation"
        );
        clear_runtime_caches(state, &runtime_id).await;
        anyhow::ensure!(
            containment.contained(),
            "shared pool {runtime_id} had invalid isolation and could not be contained during snapshot reconciliation: {}",
            containment.summary()
        );
        return Ok(());
    }
    let replay_running = inspection.status == DockerContainerStatus::Running;
    if replay_running {
        // A snapshot is taken only after the container-event
        // stream disconnects. Events may have been lost while it
        // was down, and a Docker restart keeps the same container
        // ID. Fence every live pool before probing, then replay
        // tenant quotas and credentials before routes reopen.
        fence_runtime(state, &runtime_id).await;
        if let Err(error) = state
            .docker
            .wait_until_ready(runtime.protocol, &runtime_id, POOL_READY_TIMEOUT)
            .await
        {
            failure::handle(
                state,
                &mut runtime,
                failure::Phase::Readiness,
                &error.into(),
            )
            .await?;
            clear_runtime_caches(state, &runtime_id).await;
            return Ok(());
        }
        if let Err(error) = attest_runtime_locked(state, &mut runtime).await {
            failure::handle(
                state,
                &mut runtime,
                failure::Phase::PoolSecurity,
                &anyhow::Error::msg(error),
            )
            .await?;
            clear_runtime_caches(state, &runtime_id).await;
            return Ok(());
        }
        runtime.status = EngineRuntimeStatus::Running;
    } else {
        runtime.status = classify_runtime_status(inspection.status);
        if runtime.status != EngineRuntimeStatus::Running {
            fence_runtime(state, &runtime_id).await;
            if matches!(
                previous,
                EngineRuntimeStatus::Running | EngineRuntimeStatus::Booting
            ) {
                let error = failure::engine_exit(inspection.oom_killed, runtime.limits.memory_mib);
                failure::handle(state, &mut runtime, failure::Phase::Readiness, &error).await?;
                return Ok(());
            }
        }
    }
    runtime.updated_at = now_rfc3339();
    save_runtime(&state.placements, &state.manager, runtime.clone()).await?;
    if replay_running && runtime.status == EngineRuntimeStatus::Running {
        crate::server::placement::tenant::recovery::reconcile_runtime_tenants_locked(
            state, &runtime,
        )
        .await?;
    }
    clear_runtime_caches(state, &runtime_id).await;
    tracing::debug!(
        runtime_id,
        previous_status = previous.as_str(),
        current_status = runtime.status.as_str(),
        "shared pool runtime snapshot reconciled"
    );
    Ok(())
}
