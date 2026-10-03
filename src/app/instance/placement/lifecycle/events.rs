use super::*;

pub(crate) async fn reconcile_shared_event(
    state: &AppState,
    event: ManagedContainerEvent,
) -> anyhow::Result<()> {
    let runtime_id = event.instance_id.clone();
    let deactivation = event.action.deactivates_container();
    let _operation = state.instance_locks.lock(&runtime_id).await;
    let mut runtime = match state.placements.get(&runtime_id).await {
        Ok(Some(runtime)) => runtime,
        Ok(None) => {
            if deactivation {
                fence_runtime(state, &runtime_id).await;
            }
            return Ok(());
        }
        Err(error) => {
            if deactivation {
                fence_runtime(state, &runtime_id).await;
            }
            return Err(error.into());
        }
    };
    if runtime.deployment_mode != DeploymentMode::Shared {
        return Ok(());
    }
    if runtime.protocol != event.protocol {
        tracing::error!(
            event = "audit shared_runtime_event_label_mismatch",
            runtime_id,
            stored_protocol = %runtime.protocol,
            event_protocol = %event.protocol,
            "ignored a shared-pool event whose ownership labels disagree with placement metadata"
        );
        return Ok(());
    }
    if runtime.status == EngineRuntimeStatus::Deleting {
        return Ok(());
    }
    if let Some(event_container_id) = event.container_id.as_deref() {
        let current = match state
            .docker
            .verified_managed_container_id(runtime.protocol, &runtime_id)
            .await
        {
            Ok(current) => current,
            Err(error) => {
                if deactivation {
                    fence_runtime(state, &runtime_id).await;
                }
                return Err(error.into());
            }
        };
        if container_event_is_known_stale(Some(event_container_id), current.as_deref()) {
            return Ok(());
        }
    }
    // A deactivation is authoritative even when the following SQLite write
    // commits but its acknowledgement is lost. Close every tenant route
    // before fallible reconciliation so stale in-memory metadata cannot keep
    // publishing a stopped, paused, or destroyed pool. The preserving upsert
    // below deliberately cannot clear this fence.
    if deactivation {
        fence_runtime(state, &runtime_id).await;
    }
    if runtime.status == EngineRuntimeStatus::Quarantined {
        let containment = containment::contain_locked(
            state,
            &runtime,
            "a container event targeted a durably quarantined shared pool",
            None,
        )
        .await;
        clear_runtime_caches(state, &runtime_id).await;
        anyhow::ensure!(
            containment.contained(),
            "quarantined shared pool {runtime_id} could not be contained after a container event: {}",
            containment.summary()
        );
        return Ok(());
    }

    if honor_stop(state, &mut runtime).await? {
        return Ok(());
    }
    let previous = runtime.status;
    let activation = event.action.activates_container();
    let mut activation_error = if activation {
        verify_event_activation(state, &mut runtime, &runtime_id).await
    } else {
        None
    };
    let inspection = state
        .docker
        .inspect_instance(runtime.protocol, &runtime_id)
        .await;
    let oom_killed = event.action == crate::runtime::docker::ManagedContainerAction::OutOfMemory
        || inspection
            .as_ref()
            .is_ok_and(|inspection| inspection.oom_killed);
    runtime.status = match inspection {
        Ok(inspection) if pool_is_isolated(&runtime, inspection.network_mode.as_deref()) => {
            classify_runtime_status(inspection.status)
        }
        Ok(inspection) => {
            activation_error.get_or_insert_with(|| {
                (
                    failure::Phase::Isolation,
                    anyhow::anyhow!(
                        "shared pool isolation mismatch: network_mode={:?}",
                        inspection.network_mode
                    ),
                )
            });
            EngineRuntimeStatus::Quarantined
        }
        Err(error) if error.is_not_found() => EngineRuntimeStatus::Failed,
        Err(error) => {
            activation_error.get_or_insert_with(|| (failure::Phase::Isolation, error.into()));
            EngineRuntimeStatus::Failed
        }
    };
    if runtime.status == EngineRuntimeStatus::Quarantined {
        let containment = containment::contain_locked(
            state,
            &runtime,
            "a container event exposed invalid physical shared-pool isolation",
            Some(QuarantineKind::IsolationMismatch),
        )
        .await;
        clear_runtime_caches(state, &runtime_id).await;
        anyhow::ensure!(
            containment.contained(),
            "shared pool {runtime_id} had invalid isolation and could not be contained: {}",
            containment.summary()
        );
        return Ok(());
    }
    let unexpected_failure = event.action.indicates_unexpected_failure()
        && matches!(
            previous,
            EngineRuntimeStatus::Booting
                | EngineRuntimeStatus::Running
                | EngineRuntimeStatus::Failed
        );
    if unexpected_failure && activation_error.is_none() {
        activation_error = Some((
            failure::Phase::Readiness,
            failure::engine_exit(oom_killed, runtime.limits.memory_mib),
        ));
    }
    if let Some((phase, error)) = &activation_error {
        failure::handle(state, &mut runtime, *phase, error).await?;
        clear_runtime_caches(state, &runtime_id).await;
        return Ok(());
    }
    runtime.updated_at = now_rfc3339();
    save_runtime(&state.placements, &state.manager, runtime.clone()).await?;
    if activation && runtime.status == EngineRuntimeStatus::Running {
        crate::instance::placement::tenant::recovery::reconcile_runtime_tenants_locked(
            state, &runtime,
        )
        .await?;
    }
    clear_runtime_caches(state, &runtime_id).await;
    tracing::info!(
        event = "audit shared_runtime_event_reconciled",
        runtime_id,
        protocol = %runtime.protocol,
        action = event.action.as_str(),
        previous_status = previous.as_str(),
        current_status = runtime.status.as_str(),
        unexpected_failure,
        "reconciled one physical shared-pool lifecycle event and propagated it to all tenants"
    );
    Ok(())
}

async fn verify_event_activation(
    state: &AppState,
    runtime: &mut EngineRuntime,
    runtime_id: &str,
) -> Option<(failure::Phase, anyhow::Error)> {
    fence_runtime(state, runtime_id).await;
    state
        .docker
        .enforce_cpu_burst_policy(runtime.protocol, runtime_id)
        .await;
    if let Err(error) = state
        .docker
        .wait_until_ready(runtime.protocol, runtime_id, POOL_READY_TIMEOUT)
        .await
    {
        return Some((failure::Phase::Readiness, anyhow::Error::from(error)));
    }
    if let Err(error) = attest_runtime_locked(state, runtime).await {
        return Some((failure::Phase::PoolSecurity, anyhow::Error::msg(error)));
    }
    None
}
