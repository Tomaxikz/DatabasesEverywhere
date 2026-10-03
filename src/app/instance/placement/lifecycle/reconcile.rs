use super::*;

pub(crate) async fn reconcile_shared_runtimes(
    state: &AppState,
) -> anyhow::Result<SharedReconcileSummary> {
    let runtimes = shared_runtimes(&state.placements).await?;
    let outcomes = futures::stream::iter(runtimes)
        .map(|snapshot| async move {
            let runtime_id = snapshot.runtime_id.clone();
            let _operation = state.instance_locks.lock(&runtime_id).await;
            let Some(runtime) = state.placements.get(&runtime_id).await? else {
                return Ok::<_, anyhow::Error>(None);
            };
            if runtime.deployment_mode != DeploymentMode::Shared {
                return Ok(None);
            }
            reconcile_one_runtime(state, runtime).await.map(Some)
        })
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut summary = SharedReconcileSummary::default();
    for outcome in outcomes {
        let Some(runtime) = outcome? else { continue };
        summary.checked += 1;
        match runtime.status {
            EngineRuntimeStatus::Booting | EngineRuntimeStatus::Creating => summary.booting += 1,
            EngineRuntimeStatus::Running => summary.running += 1,
            EngineRuntimeStatus::Stopped | EngineRuntimeStatus::Deleting => summary.stopped += 1,
            EngineRuntimeStatus::Failed => summary.failed += 1,
            EngineRuntimeStatus::Quarantined => summary.quarantined += 1,
        }
    }
    Ok(summary)
}

pub(crate) async fn reconcile_one_runtime(
    state: &AppState,
    mut runtime: EngineRuntime,
) -> anyhow::Result<EngineRuntime> {
    if runtime.status == EngineRuntimeStatus::Deleting {
        return Ok(runtime);
    }
    if runtime.status == EngineRuntimeStatus::Quarantined {
        let containment = containment::contain_locked(
            state,
            &runtime,
            "reconciled a durably quarantined shared pool",
            None,
        )
        .await;
        anyhow::ensure!(
            containment.contained(),
            "durably quarantined shared pool {} could not be physically contained: {}",
            runtime.runtime_id,
            containment.summary()
        );
        return Ok(runtime);
    }
    if honor_stop(state, &mut runtime).await? {
        return Ok(runtime);
    }
    match state
        .docker
        .inspect_instance(runtime.protocol, &runtime.runtime_id)
        .await
    {
        Ok(inspection) if pool_is_isolated(&runtime, inspection.network_mode.as_deref()) => {
            runtime.status = classify_runtime_status(inspection.status);
            runtime.runtime.network_mode = ISOLATED_NETWORK_MODE.to_string();
        }
        Ok(inspection) => {
            let containment = containment::contain_locked(
                state,
                &runtime,
                "physical shared-pool isolation no longer matched durable placement",
                Some(QuarantineKind::IsolationMismatch),
            )
            .await;
            tracing::error!(
                event = "audit shared_runtime_isolation_mismatch",
                runtime_id = %runtime.runtime_id,
                protocol = %runtime.protocol,
                network_mode = ?inspection.network_mode,
                containment = %containment.summary(),
                contained = containment.contained(),
                "quarantined one shared pool and all tenants because its physical isolation no longer matches durable placement"
            );
            anyhow::ensure!(
                containment.contained(),
                "shared pool {} had invalid isolation and could not be contained: {}",
                runtime.runtime_id,
                containment.summary()
            );
            let quarantined = state
                .placements
                .get(&runtime.runtime_id)
                .await?
                .context("contained shared pool disappeared from durable placement")?;
            return Ok(quarantined);
        }
        Err(error) if error.is_not_found() => runtime.status = EngineRuntimeStatus::Failed,
        Err(error) => {
            tracing::warn!(
                runtime_id = %runtime.runtime_id,
                protocol = %runtime.protocol,
                %error,
                "failed to inspect shared pool during reconciliation"
            );
            runtime.status = EngineRuntimeStatus::Failed;
        }
    }
    runtime.updated_at = now_rfc3339();
    save_runtime(&state.placements, &state.manager, runtime.clone()).await?;
    Ok(runtime)
}

pub(crate) async fn honor_stop(
    state: &AppState,
    runtime: &mut EngineRuntime,
) -> anyhow::Result<bool> {
    if runtime.pending_image.is_some() {
        let report = containment::contain_locked(
            state,
            runtime,
            "interrupted pool image update",
            Some(QuarantineKind::ImageChangeIncomplete),
        )
        .await;
        anyhow::ensure!(
            report.contained(),
            "pool image recovery containment failed: {}",
            report.summary()
        );
        runtime.status = EngineRuntimeStatus::Quarantined;
        return Ok(true);
    }
    let stop_requested = runtime.desired_state == DesiredInstanceState::Stopped;
    let already_contained = matches!(
        runtime.status,
        EngineRuntimeStatus::Quarantined | EngineRuntimeStatus::Deleting
    );
    if !stop_requested || already_contained {
        return Ok(false);
    }
    fence_runtime(state, &runtime.runtime_id).await;
    if let Err(error) = containment::stop_pool(state, runtime).await {
        failure::handle(
            state,
            runtime,
            failure::Phase::Isolation,
            &anyhow::Error::msg(error),
        )
        .await?;
        return Ok(true);
    }
    // Keep the diagnostic failure state while honoring its stopped intent.
    // A queued stop event or daemon reboot must not disguise a failed start.
    if runtime.status != EngineRuntimeStatus::Failed {
        runtime.status = EngineRuntimeStatus::Stopped;
    }
    runtime.updated_at = now_rfc3339();
    save_runtime(&state.placements, &state.manager, runtime.clone()).await?;
    clear_runtime_caches(state, &runtime.runtime_id).await;
    Ok(true)
}

pub(crate) async fn start_shared_runtimes(state: &AppState) -> anyhow::Result<()> {
    let runtimes = shared_runtimes(&state.placements).await?;
    let outcomes = futures::stream::iter(runtimes)
        .map(|snapshot| start_shared_runtime(state, snapshot))
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut attempted = 0_usize;
    let mut running = 0_usize;
    let mut failed = 0_usize;
    for outcome in outcomes {
        match outcome? {
            Some(EngineRuntimeStatus::Running) => {
                attempted += 1;
                running += 1;
            }
            Some(_) => {
                attempted += 1;
                failed += 1;
            }
            None => {}
        }
    }
    tracing::info!(
        attempted,
        running,
        failed,
        "shared pool boot activation complete"
    );
    Ok(())
}

async fn start_shared_runtime(
    state: &AppState,
    snapshot: EngineRuntime,
) -> anyhow::Result<Option<EngineRuntimeStatus>> {
    if shared_boot_action(snapshot.status, snapshot.desired_state).is_none() {
        return Ok(None);
    }
    let runtime_id = snapshot.runtime_id.clone();
    let _operation = state.instance_locks.lock(&runtime_id).await;
    let Some(mut runtime) = state.placements.get(&runtime_id).await? else {
        return Ok(None);
    };
    if honor_stop(state, &mut runtime).await? {
        return Ok(None);
    }
    let Some(action) = shared_boot_action(runtime.status, runtime.desired_state) else {
        return Ok(None);
    };
    if let Err(error) = state.docker.check_autostart(&runtime_id).await {
        tracing::warn!(event = "audit container_autostart_blocked", runtime_id, %error);
        failure::handle(
            state,
            &mut runtime,
            failure::Phase::EngineStart,
            &error.into(),
        )
        .await?;
        return Ok(Some(runtime.status));
    }
    let restart = matches!(action, SharedBootAction::Restart);
    if let Err(error) = activate_locked(state, &mut runtime, restart).await {
        tracing::error!(runtime_id, %error, "shared pool boot activation failed");
        return Ok(Some(EngineRuntimeStatus::Failed));
    }
    Ok(Some(EngineRuntimeStatus::Running))
}
