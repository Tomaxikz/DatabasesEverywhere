use std::collections::HashMap;
use std::time::Duration;

use anyhow::Context;
use futures::StreamExt;

mod compatibility;

use compatibility::attest_runtime_locked;
pub(super) use compatibility::sync_shared_compatibility;

use crate::{
    api::http::router::AppState,
    config::{Config, DiskLimitMode},
    constants::MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY,
    disk::{DiskLimiter, soft::SoftDiskTarget},
    instances::{
        locks::InstanceLocks,
        manager::InstanceManager,
        metadata::{DesiredInstanceState, InstanceStatus},
        paths::InstancePaths,
    },
    placement::{
        DeploymentMode, EngineRuntime, EngineRuntimeStatus, PlacementRepository,
        TenantReservationState,
    },
    runtime::docker::{DockerContainerStatus, DockerRuntime, ManagedContainerEvent},
    shared::{limits::mib_to_bytes, time::now_rfc3339},
};

const POOL_READY_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug, Clone, Default)]
pub(super) struct SharedReconcileSummary {
    pub checked: usize,
    pub booting: usize,
    pub running: usize,
    pub stopped: usize,
    pub failed: usize,
    pub quarantined: usize,
}

/// Restores hard limits for physical shared pools. Tenant ids never reach a
/// container or filesystem-limit API here: each placement row is visited once
/// and all physical work is keyed by `runtime_id`.
pub(super) async fn restore_shared_limits(
    state: &AppState,
    disk_limiter: &DiskLimiter,
) -> anyhow::Result<()> {
    let runtimes = shared_runtimes(&state.placements).await?;
    let outcomes = futures::stream::iter(runtimes)
        .map(|runtime| async move {
            let runtime_id = runtime.runtime_id.clone();
            let _operation = state.instance_locks.lock(&runtime_id).await;
            let Some(mut runtime) = state.placements.get(&runtime_id).await? else {
                return Ok::<_, anyhow::Error>(());
            };
            if runtime.deployment_mode != DeploymentMode::Shared
                || runtime.status == EngineRuntimeStatus::Deleting
            {
                return Ok(());
            }
            let result = restore_one_limit(
                &state.config,
                &state.docker,
                disk_limiter,
                &mut runtime,
            )
            .await;
            match result {
                Ok(()) => save_runtime(&state.placements, &state.manager, runtime).await,
                Err(error) => {
                    let containment = crate::api::instances::containment::contain_locked(
                        state,
                        &runtime,
                        "aggregate shared-pool limit recovery failed",
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
                    if !containment.contained() {
                        anyhow::bail!(
                            "shared pool {runtime_id} could not be contained after limit recovery failed: {}",
                            containment.summary()
                        );
                    }
                    Ok(())
                }
            }
        })
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    for outcome in outcomes {
        outcome?;
    }
    Ok(())
}

/// Finishes deletion of pools that have no durable tenant reservations. This
/// runs after migration recovery and before limits, reconciliation, or route
/// publication, so an interrupted cleanup cannot revive an orphaned engine.
pub(super) async fn cleanup_empty_shared_runtimes(state: &AppState) -> usize {
    let runtimes = match shared_runtimes(&state.placements).await {
        Ok(runtimes) => runtimes,
        Err(error) => {
            tracing::error!(%error, "failed to load shared pools for empty-pool recovery");
            return 0;
        }
    };
    let outcomes = futures::stream::iter(runtimes)
        .map(|snapshot| async move {
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
            match crate::api::instances::delete_empty_pool(state, &runtime_id).await {
                Ok(deleted) => deleted,
                Err(error) => {
                    let containment = crate::api::instances::containment::contain_locked(
                        state,
                        &snapshot,
                        "interrupted empty shared-pool cleanup failed",
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
            }
        })
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    outcomes.into_iter().filter(|deleted| *deleted).count()
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

fn needs_pool_adoption(current: DiskLimitMode, persisted_method: &str) -> bool {
    current == DiskLimitMode::ProjectQuota
        && DiskLimitMode::from_persisted_method(persisted_method)
            != Some(DiskLimitMode::ProjectQuota)
}

pub(super) async fn reconcile_shared_runtimes(
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

async fn reconcile_one_runtime(
    state: &AppState,
    mut runtime: EngineRuntime,
) -> anyhow::Result<EngineRuntime> {
    if runtime.status == EngineRuntimeStatus::Deleting {
        return Ok(runtime);
    }
    if runtime.status == EngineRuntimeStatus::Quarantined {
        let containment = crate::api::instances::containment::contain_locked(
            state,
            &runtime,
            "reconciled a durably quarantined shared pool",
        )
        .await;
        if !containment.contained() {
            anyhow::bail!(
                "durably quarantined shared pool {} could not be physically contained: {}",
                runtime.runtime_id,
                containment.summary()
            );
        }
        return Ok(runtime);
    }
    match state
        .docker
        .inspect_instance(runtime.protocol, &runtime.runtime_id)
        .await
    {
        Ok(inspection) => {
            if inspection.network_mode.as_deref() != Some("none")
                || !matches!(
                    &runtime.backend,
                    crate::shared::backend::BackendEndpoint::UnixSocket { .. }
                )
            {
                let containment = crate::api::instances::containment::contain_locked(
                    state,
                    &runtime,
                    "physical shared-pool isolation no longer matched durable placement",
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
                if !containment.contained() {
                    anyhow::bail!(
                        "shared pool {} had invalid isolation and could not be contained: {}",
                        runtime.runtime_id,
                        containment.summary()
                    );
                }
                let quarantined = state
                    .placements
                    .get(&runtime.runtime_id)
                    .await?
                    .context("contained shared pool disappeared from durable placement")?;
                return Ok(quarantined);
            } else {
                runtime.status = classify_runtime_status(inspection.status);
                runtime.runtime.network_mode = "none".to_string();
            }
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

pub(super) async fn start_shared_runtimes(state: &AppState) -> anyhow::Result<()> {
    let runtimes = shared_runtimes(&state.placements).await?;
    let outcomes = futures::stream::iter(runtimes)
        .map(|snapshot| async move {
            if shared_boot_action(snapshot.status).is_none() {
                return Ok::<_, anyhow::Error>(None);
            }
            let runtime_id = snapshot.runtime_id.clone();
            let _operation = state.instance_locks.lock(&runtime_id).await;
            let Some(mut runtime) = state.placements.get(&runtime_id).await? else {
                return Ok(None);
            };
            let Some(action) = shared_boot_action(runtime.status) else {
                return Ok(None);
            };
            if let Err(error) = check_shared_start_disk(state, &runtime).await {
                runtime.status = EngineRuntimeStatus::Failed;
                runtime.updated_at = now_rfc3339();
                save_runtime(&state.placements, &state.manager, runtime).await?;
                tracing::error!(
                    event = "audit shared_runtime_disk_start_blocked",
                    runtime_id,
                    %error,
                    "refused to activate a shared pool whose aggregate disk limit could not be verified"
                );
                return Ok(Some(EngineRuntimeStatus::Failed));
            }
            let activation = match action {
                SharedBootAction::Start => state.docker.start(runtime.protocol, &runtime_id).await,
                SharedBootAction::Restart => {
                    state.docker.restart(runtime.protocol, &runtime_id).await
                }
            };
            let result = match activation {
                Ok(_) => state
                    .docker
                    .wait_until_ready(runtime.protocol, &runtime_id, POOL_READY_TIMEOUT)
                    .await
                    .map(|_| ()),
                Err(error) => Err(error),
            };
            if let Err(error) = result {
                if let Err(stop) = state.docker.stop(runtime.protocol, &runtime_id).await
                    && !stop.is_not_found()
                    && !stop.is_not_running()
                {
                    tracing::error!(
                        event = "audit shared_runtime_boot_cleanup_failed",
                        runtime_id,
                        %stop,
                        "failed to stop a shared pool after boot activation failed"
                    );
                }
                runtime.status = EngineRuntimeStatus::Failed;
                runtime.updated_at = now_rfc3339();
                save_runtime(&state.placements, &state.manager, runtime).await?;
                tracing::error!(
                    event = "audit shared_runtime_boot_failed",
                    runtime_id,
                    %error,
                    "shared pool activation failed; all of its tenant routes remain isolated"
                );
                return Ok(Some(EngineRuntimeStatus::Failed));
            }
            runtime.status = EngineRuntimeStatus::Running;
            runtime.updated_at = now_rfc3339();
            save_runtime(&state.placements, &state.manager, runtime.clone()).await?;
            state
                .docker
                .enforce_cpu_burst_policy(runtime.protocol, &runtime_id)
                .await;
            Ok(Some(EngineRuntimeStatus::Running))
        })
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

pub(super) async fn sync_shared_cpu_burst(
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

pub(super) async fn reconcile_shared_event(
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
        let containment = crate::api::instances::containment::contain_locked(
            state,
            &runtime,
            "a container event targeted a durably quarantined shared pool",
        )
        .await;
        clear_runtime_caches(state, &runtime_id).await;
        if !containment.contained() {
            anyhow::bail!(
                "quarantined shared pool {runtime_id} could not be contained after a container event: {}",
                containment.summary()
            );
        }
        return Ok(());
    }

    let previous = runtime.status;
    let activation = event.action.activates_container();
    let mut activation_error = None;
    if activation {
        fence_runtime(state, &runtime_id).await;
        state
            .docker
            .enforce_cpu_burst_policy(runtime.protocol, &runtime_id)
            .await;
        if let Err(error) = state
            .docker
            .wait_until_ready(runtime.protocol, &runtime_id, POOL_READY_TIMEOUT)
            .await
        {
            activation_error = Some(error.to_string());
        } else if let Err(error) = attest_runtime_locked(state, &mut runtime).await {
            activation_error = Some(error);
        }
    }
    let inspection = state
        .docker
        .inspect_instance(runtime.protocol, &runtime_id)
        .await;
    runtime.status = match inspection {
        Ok(inspection)
            if inspection.network_mode.as_deref() == Some("none")
                && matches!(
                    &runtime.backend,
                    crate::shared::backend::BackendEndpoint::UnixSocket { .. }
                ) =>
        {
            classify_runtime_status(inspection.status)
        }
        Ok(inspection) => {
            activation_error.get_or_insert_with(|| {
                format!(
                    "shared pool isolation mismatch: network_mode={:?}",
                    inspection.network_mode
                )
            });
            EngineRuntimeStatus::Quarantined
        }
        Err(error) if error.is_not_found() => EngineRuntimeStatus::Failed,
        Err(error) => {
            activation_error.get_or_insert_with(|| error.to_string());
            EngineRuntimeStatus::Failed
        }
    };
    if runtime.status == EngineRuntimeStatus::Quarantined {
        let containment = crate::api::instances::containment::contain_locked(
            state,
            &runtime,
            "a container event exposed invalid physical shared-pool isolation",
        )
        .await;
        clear_runtime_caches(state, &runtime_id).await;
        if !containment.contained() {
            anyhow::bail!(
                "shared pool {runtime_id} had invalid isolation and could not be contained: {}",
                containment.summary()
            );
        }
        return Ok(());
    }
    let unexpected_failure = event.action.indicates_unexpected_failure()
        && matches!(
            previous,
            EngineRuntimeStatus::Booting
                | EngineRuntimeStatus::Running
                | EngineRuntimeStatus::Failed
        );
    if activation_error.is_some() || unexpected_failure {
        if runtime.status != EngineRuntimeStatus::Quarantined {
            runtime.status = EngineRuntimeStatus::Failed;
        }
        if let Err(error) = state.docker.stop(runtime.protocol, &runtime_id).await
            && !error.is_not_found()
            && !error.is_not_running()
        {
            tracing::error!(runtime_id, %error, "failed to stop an unhealthy shared pool");
        }
        fence_runtime(state, &runtime_id).await;
    }
    runtime.updated_at = now_rfc3339();
    save_runtime(&state.placements, &state.manager, runtime.clone()).await?;
    if activation && runtime.status == EngineRuntimeStatus::Running {
        super::shared_tenant_boot::reconcile_runtime_tenants_locked(state, &runtime).await?;
    }
    clear_runtime_caches(state, &runtime_id).await;
    tracing::info!(
        event = "audit shared_runtime_event_reconciled",
        runtime_id,
        protocol = %runtime.protocol,
        action = event.action.as_str(),
        previous_status = previous.as_str(),
        current_status = runtime.status.as_str(),
        readiness_error = activation_error,
        unexpected_failure,
        "reconciled one physical shared-pool lifecycle event and propagated it to all tenants"
    );
    Ok(())
}

pub(super) async fn reconcile_shared_snapshot(state: &AppState) {
    let runtimes = match shared_runtimes(&state.placements).await {
        Ok(runtimes) => runtimes,
        Err(error) => {
            tracing::error!(%error, "failed to load shared pools for event snapshot reconciliation");
            return;
        }
    };
    let outcomes = futures::stream::iter(runtimes)
        .map(|snapshot| async move {
            let runtime_id = snapshot.runtime_id.clone();
            let _operation = state.instance_locks.lock(&runtime_id).await;
            let Some(mut runtime) = state.placements.get(&runtime_id).await? else {
                return Ok::<_, anyhow::Error>(());
            };
            let previous = runtime.status;
            if runtime.status == EngineRuntimeStatus::Deleting {
                return Ok(());
            }
            if runtime.status == EngineRuntimeStatus::Quarantined {
                let containment = crate::api::instances::containment::contain_locked(
                    state,
                    &runtime,
                    "snapshot reconciliation found a durably quarantined shared pool",
                )
                .await;
                clear_runtime_caches(state, &runtime_id).await;
                if !containment.contained() {
                    anyhow::bail!(
                        "quarantined shared pool {runtime_id} could not be contained during snapshot reconciliation: {}",
                        containment.summary()
                    );
                }
                return Ok(());
            }
            let mut replay_running = false;
            match state
                .docker
                .inspect_instance(runtime.protocol, &runtime_id)
                .await
            {
                Ok(inspection)
                    if inspection.status == DockerContainerStatus::Running
                        && inspection.network_mode.as_deref() == Some("none")
                        && matches!(
                            &runtime.backend,
                            crate::shared::backend::BackendEndpoint::UnixSocket { .. }
                        ) =>
                {
                    // A snapshot is taken only after the container-event
                    // stream disconnects. Events may have been lost while it
                    // was down, and a Docker restart keeps the same container
                    // ID. Fence every live pool before probing, then replay
                    // tenant quotas and credentials before routes reopen.
                    fence_runtime(state, &runtime_id).await;
                    replay_running = true;
                    if let Err(error) = state
                        .docker
                        .wait_until_ready(runtime.protocol, &runtime_id, POOL_READY_TIMEOUT)
                        .await
                    {
                        runtime.status = EngineRuntimeStatus::Failed;
                        fence_runtime(state, &runtime_id).await;
                        let _ = state.docker.stop(runtime.protocol, &runtime_id).await;
                        tracing::error!(runtime_id, %error, "shared pool snapshot readiness failed");
                    } else if let Err(error) = attest_runtime_locked(state, &mut runtime).await {
                        runtime.status = EngineRuntimeStatus::Failed;
                        fence_runtime(state, &runtime_id).await;
                        let _ = state.docker.stop(runtime.protocol, &runtime_id).await;
                        tracing::error!(runtime_id, %error, "shared pool snapshot compatibility failed");
                    } else {
                        runtime.status = EngineRuntimeStatus::Running;
                    }
                }
                Ok(inspection) => {
                    if inspection.network_mode.as_deref() != Some("none")
                        || !matches!(
                            &runtime.backend,
                            crate::shared::backend::BackendEndpoint::UnixSocket { .. }
                        )
                    {
                        let containment = crate::api::instances::containment::contain_locked(
                            state,
                            &runtime,
                            "snapshot reconciliation found invalid physical shared-pool isolation",
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
                        if !containment.contained() {
                            anyhow::bail!(
                                "shared pool {runtime_id} had invalid isolation and could not be contained during snapshot reconciliation: {}",
                                containment.summary()
                            );
                        }
                        return Ok(());
                    } else {
                        runtime.status = classify_runtime_status(inspection.status);
                        if runtime.status != EngineRuntimeStatus::Running {
                            fence_runtime(state, &runtime_id).await;
                        }
                    }
                }
                Err(error) if error.is_not_found() => {
                    runtime.status = EngineRuntimeStatus::Failed;
                    fence_runtime(state, &runtime_id).await;
                }
                Err(error) => {
                    runtime.status = EngineRuntimeStatus::Failed;
                    fence_runtime(state, &runtime_id).await;
                    tracing::error!(runtime_id, %error, "failed to inspect shared pool snapshot");
                }
            }
            runtime.updated_at = now_rfc3339();
            save_runtime(&state.placements, &state.manager, runtime.clone()).await?;
            if replay_running && runtime.status == EngineRuntimeStatus::Running {
                super::shared_tenant_boot::reconcile_runtime_tenants_locked(state, &runtime)
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
        })
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    for outcome in outcomes {
        if let Err(error) = outcome {
            tracing::error!(%error, "failed to reconcile shared-pool event snapshot");
        }
    }
}

async fn check_shared_start_disk(state: &AppState, runtime: &EngineRuntime) -> Result<(), String> {
    let paths = InstancePaths::new(&state.config.paths, &runtime.runtime_id)
        .map_err(|error| error.to_string())?;
    let limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
            .for_persisted_protocol(runtime.protocol, &runtime.limits.disk_enforcement_method);
    limiter
        .check_method_change(&runtime.limits.disk_enforcement_method)
        .map_err(|error| error.to_string())?;
    let expected = limiter
        .container_data_path(&paths.data)
        .map_err(|error| error.to_string())?;
    state
        .docker
        .verify_data_bind(runtime.protocol, &runtime.runtime_id, &expected)
        .await
        .map_err(|error| error.to_string())?;
    if crate::disk::soft::SoftDiskLimiter::enforcement_required(
        state.config.disk.mode,
        runtime.protocol,
    ) {
        crate::disk::soft::SoftDiskLimiter::new(state.config.disk.soft_scanner.clone())
            .ensure_start_allowed(&crate::disk::soft::SoftDiskTarget {
                instance_id: runtime.runtime_id.clone(),
                created_at: runtime.created_at.clone(),
                protocol: runtime.protocol,
                data_path: paths.data,
                limit_bytes: mib_to_bytes(runtime.limits.disk_mib),
                durable_blocked: false,
            })
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

pub(super) async fn isolate_runtime(
    state: &AppState,
    runtime: EngineRuntime,
    reason: &str,
) -> bool {
    crate::api::instances::containment::contain_locked(state, &runtime, reason)
        .await
        .contained()
}

pub(super) async fn mark_shared_disk_blocked(
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

fn shared_disk_target_is_current(runtime: &EngineRuntime, target: &SoftDiskTarget) -> bool {
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

async fn save_runtime(
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
        metadata.updated_at = now_rfc3339();
        manager.upsert_preserving_fence(metadata).await?;
    }
    Ok(())
}

async fn shared_runtimes(placements: &PlacementRepository) -> anyhow::Result<Vec<EngineRuntime>> {
    Ok(placements
        .list()
        .await?
        .into_iter()
        .filter(|runtime| runtime.deployment_mode == DeploymentMode::Shared)
        .collect())
}

async fn fence_runtime(state: &AppState, runtime_id: &str) -> bool {
    let mut all_fenced = true;
    for instance_id in store_tenants(&state.manager, runtime_id).await {
        all_fenced &= crate::instances::sessions::fence(
            &state.instances,
            &state.gateway_supervisor.tenant_sessions(),
            &instance_id,
        )
        .await;
    }
    all_fenced
}

async fn clear_runtime_caches(state: &AppState, runtime_id: &str) {
    let tenant_ids = store_tenants(&state.manager, runtime_id).await;
    state.instance_runtime_cache.remove(runtime_id).await;
    state.resource_cache.invalidate_runtime(runtime_id).await;
    for instance_id in tenant_ids {
        state.instance_runtime_cache.remove(&instance_id).await;
        state.resource_cache.invalidate_runtime(&instance_id).await;
    }
}

async fn runtime_tenants(
    placements: &PlacementRepository,
    manager: &InstanceManager,
    runtime_id: &str,
) -> HashMap<String, Option<TenantReservationState>> {
    let mut tenants = store_tenants(manager, runtime_id)
        .await
        .into_iter()
        .map(|instance_id| (instance_id, None))
        .collect::<HashMap<_, _>>();
    match placements.reservations(runtime_id).await {
        Ok(reservations) => {
            for reservation in reservations {
                tenants.insert(reservation.instance_id, Some(reservation.state));
            }
        }
        Err(error) => tracing::error!(
            event = "audit shared_runtime_tenant_lookup_failed",
            runtime_id,
            %error,
            "used the loaded tenant metadata to preserve fail-closed pool state propagation"
        ),
    }
    tenants
}

fn report_missing_tenant(
    runtime_id: &str,
    instance_id: &str,
    reservation_state: Option<TenantReservationState>,
) {
    match reservation_state {
        Some(TenantReservationState::Reserved) => {}
        Some(TenantReservationState::Provisioned) => tracing::error!(
            event = "audit shared_runtime_missing_tenant_metadata",
            runtime_id,
            instance_id,
            "a provisioned shared tenant is missing its instance metadata"
        ),
        None => tracing::warn!(
            event = "audit shared_runtime_stale_loaded_tenant",
            runtime_id,
            instance_id,
            "loaded shared tenant metadata disappeared before pool state propagation"
        ),
    }
}

async fn store_tenants(manager: &InstanceManager, runtime_id: &str) -> Vec<String> {
    manager
        .store()
        .list()
        .await
        .into_iter()
        .filter(|metadata| {
            metadata.deployment_mode == DeploymentMode::Shared
                && metadata.runtime_id() == runtime_id
        })
        .map(|metadata| metadata.instance_id)
        .collect()
}

fn classify_runtime_status(status: DockerContainerStatus) -> EngineRuntimeStatus {
    match status {
        DockerContainerStatus::Running => EngineRuntimeStatus::Running,
        DockerContainerStatus::Created | DockerContainerStatus::Stopped => {
            EngineRuntimeStatus::Stopped
        }
        DockerContainerStatus::Starting => EngineRuntimeStatus::Booting,
        DockerContainerStatus::Failed => EngineRuntimeStatus::Failed,
    }
}

fn tenant_status(
    runtime: EngineRuntimeStatus,
    desired: DesiredInstanceState,
    current: InstanceStatus,
) -> InstanceStatus {
    if matches!(
        current,
        InstanceStatus::Deleting | InstanceStatus::Quarantined
    ) {
        return current;
    }
    if runtime == EngineRuntimeStatus::Quarantined {
        return InstanceStatus::Quarantined;
    }
    if desired == DesiredInstanceState::Stopped {
        return InstanceStatus::Stopped;
    }
    match runtime {
        EngineRuntimeStatus::Creating => InstanceStatus::Creating,
        EngineRuntimeStatus::Booting => InstanceStatus::Booting,
        EngineRuntimeStatus::Running => InstanceStatus::Running,
        EngineRuntimeStatus::Stopped => InstanceStatus::Stopped,
        EngineRuntimeStatus::Failed | EngineRuntimeStatus::Deleting => InstanceStatus::Failed,
        EngineRuntimeStatus::Quarantined => InstanceStatus::Quarantined,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SharedBootAction {
    Start,
    Restart,
}

fn shared_boot_action(status: EngineRuntimeStatus) -> Option<SharedBootAction> {
    match status {
        EngineRuntimeStatus::Stopped => Some(SharedBootAction::Start),
        EngineRuntimeStatus::Failed => Some(SharedBootAction::Restart),
        EngineRuntimeStatus::Creating
        | EngineRuntimeStatus::Booting
        | EngineRuntimeStatus::Running
        | EngineRuntimeStatus::Quarantined
        | EngineRuntimeStatus::Deleting => None,
    }
}

fn container_ids_match(left: &str, right: &str) -> bool {
    let left = left.trim().strip_prefix("sha256:").unwrap_or(left.trim());
    let right = right.trim().strip_prefix("sha256:").unwrap_or(right.trim());
    left == right
        || (left.len().min(right.len()) >= 12
            && (left.starts_with(right) || right.starts_with(left)))
}

fn container_event_is_known_stale(
    event_container_id: Option<&str>,
    current_container_id: Option<&str>,
) -> bool {
    matches!(
        (event_container_id, current_container_id),
        (Some(event), Some(current)) if !container_ids_match(event, current)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compatibility::COMPATIBILITY_PROBE_REVISION,
        instances::{
            manager::InstanceManager,
            metadata::{RuntimeKind, RuntimeMetadata},
            state::InstanceStore,
        },
        placement::{
            ENGINE_RUNTIME_SCHEMA_VERSION, ReserveTenant, RuntimeCompatibility, RuntimeReservation,
            TenantReservationState,
        },
        shared::{backend::BackendEndpoint, limits::InstanceLimits, protocol::Protocol},
        storage::{repositories::InstanceRepository, sqlite},
    };

    #[tokio::test]
    async fn runtime_tenant_lookup_preserves_provisioning_state() {
        let directory = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(directory.path()).await.unwrap();
        let placements = PlacementRepository::new(pool.clone());
        let manager = InstanceManager::new(
            InstanceStore::default(),
            InstanceRepository::new(pool.clone()),
        );
        let runtime = runtime();
        placements.save(&runtime).await.unwrap();
        let limits = InstanceLimits {
            cpu_cores: 0.1,
            memory_mib: 128,
            disk_mib: 256,
            ..InstanceLimits::default()
        };
        placements
            .reserve(ReserveTenant {
                instance_id: "tenant-in-progress",
                runtime_id: &runtime.runtime_id,
                database: "tenant_db",
                username: "tenant_user",
                limits: &limits,
            })
            .await
            .unwrap();

        let tenants = runtime_tenants(&placements, &manager, &runtime.runtime_id).await;
        assert_eq!(
            tenants.get("tenant-in-progress"),
            Some(&Some(TenantReservationState::Reserved))
        );

        placements
            .mark_provisioned("tenant-in-progress")
            .await
            .unwrap();
        let tenants = runtime_tenants(&placements, &manager, &runtime.runtime_id).await;
        assert_eq!(
            tenants.get("tenant-in-progress"),
            Some(&Some(TenantReservationState::Provisioned))
        );
    }

    #[test]
    fn pool_root_is_adopted_once_when_upgrading_from_soft_enforcement() {
        for (mode, method, expected) in [
            (DiskLimitMode::ProjectQuota, "soft_scanner", true),
            (DiskLimitMode::ProjectQuota, "shared_pool_reservation", true),
            (DiskLimitMode::ProjectQuota, "host_xfs_project_quota", false),
            (DiskLimitMode::FuseQuota, "soft_scanner", false),
        ] {
            assert_eq!(needs_pool_adoption(mode, method), expected, "{method}");
        }
    }

    #[test]
    fn shared_boot_actions_never_activate_quarantined_or_deleting_pools() {
        for (status, action) in [
            (EngineRuntimeStatus::Stopped, Some(SharedBootAction::Start)),
            (EngineRuntimeStatus::Failed, Some(SharedBootAction::Restart)),
            (EngineRuntimeStatus::Quarantined, None),
            (EngineRuntimeStatus::Deleting, None),
        ] {
            assert_eq!(shared_boot_action(status), action);
        }
    }

    #[test]
    fn tenant_status_follows_pool_and_desired_state_without_losing_quarantine() {
        for (pool, desired, current, expected) in [
            (
                EngineRuntimeStatus::Running,
                DesiredInstanceState::Stopped,
                InstanceStatus::Stopped,
                InstanceStatus::Stopped,
            ),
            (
                EngineRuntimeStatus::Running,
                DesiredInstanceState::Running,
                InstanceStatus::Failed,
                InstanceStatus::Running,
            ),
            (
                EngineRuntimeStatus::Failed,
                DesiredInstanceState::Running,
                InstanceStatus::Running,
                InstanceStatus::Failed,
            ),
            (
                EngineRuntimeStatus::Running,
                DesiredInstanceState::Running,
                InstanceStatus::Quarantined,
                InstanceStatus::Quarantined,
            ),
        ] {
            assert_eq!(tenant_status(pool, desired, current), expected);
        }
    }

    #[test]
    fn container_identity_and_event_staleness_handle_docker_short_ids() {
        assert!(container_ids_match(
            "0123456789abcdef",
            "sha256:0123456789abcdef0123456789abcdef"
        ));
        assert!(!container_ids_match("old-container", "new-container"));
        for (event, current, stale) in [
            (Some("old-container"), Some("new-container"), true),
            (
                Some("0123456789abcdef"),
                Some("sha256:0123456789abcdef0123456789abcdef"),
                false,
            ),
            (Some("destroyed-container"), None, false),
            (None, Some("current-container"), false),
        ] {
            assert_eq!(container_event_is_known_stale(event, current), stale);
        }
    }

    #[test]
    fn shared_attestation_reuse_requires_exact_container_image_and_revision() {
        let mut runtime = runtime();
        for (container, image, expected) in [
            ("container-id", "sha256:image-id", true),
            ("replacement-id", "sha256:image-id", false),
            ("container-id", "sha256:new-image", false),
        ] {
            assert_eq!(
                compatibility::attestation_matches(&runtime, container, image),
                expected
            );
        }
        runtime.compatibility.as_mut().unwrap().probe_revision =
            COMPATIBILITY_PROBE_REVISION.saturating_add(1);
        assert!(!compatibility::attestation_matches(
            &runtime,
            "container-id",
            "sha256:image-id"
        ));
    }

    #[test]
    fn docker_observation_maps_to_pool_status_without_tenant_identity() {
        for (docker, runtime) in [
            (DockerContainerStatus::Running, EngineRuntimeStatus::Running),
            (DockerContainerStatus::Created, EngineRuntimeStatus::Stopped),
            (
                DockerContainerStatus::Starting,
                EngineRuntimeStatus::Booting,
            ),
            (DockerContainerStatus::Failed, EngineRuntimeStatus::Failed),
        ] {
            assert_eq!(classify_runtime_status(docker), runtime);
        }
    }

    #[test]
    fn aggregate_soft_disk_target_is_keyed_only_by_runtime_id() {
        let runtime = runtime();
        let target = SoftDiskTarget {
            instance_id: runtime.runtime_id.clone(),
            created_at: runtime.created_at.clone(),
            protocol: runtime.protocol,
            data_path: std::path::PathBuf::from("/var/lib/dbev/pool-postgres"),
            limit_bytes: mib_to_bytes(runtime.limits.disk_mib),
            durable_blocked: false,
        };
        assert!(shared_disk_target_is_current(&runtime, &target));

        let tenant_target = SoftDiskTarget {
            instance_id: "tenant-postgres".to_string(),
            ..target
        };
        assert!(!shared_disk_target_is_current(&runtime, &tenant_target));
    }

    fn runtime() -> EngineRuntime {
        EngineRuntime {
            schema_version: ENGINE_RUNTIME_SCHEMA_VERSION,
            runtime_id: "pool-postgres".to_string(),
            protocol: Protocol::Postgres,
            deployment_mode: DeploymentMode::Shared,
            status: EngineRuntimeStatus::Running,
            backend: BackendEndpoint::UnixSocket {
                socket_path: "/run/dbev/pool-postgres/postgres.sock".to_string(),
            },
            runtime: RuntimeMetadata {
                kind: RuntimeKind::Docker,
                container_name: "dbe-postgres-pool-postgres".to_string(),
                network_mode: "none".to_string(),
            },
            limits: InstanceLimits::default(),
            image: "postgres:18".to_string(),
            database_version: Some("18.4".to_string()),
            compatibility: Some(RuntimeCompatibility {
                container_id: "container-id".to_string(),
                image_id: "sha256:image-id".to_string(),
                probe_revision: COMPATIBILITY_PROBE_REVISION,
            }),
            compatibility_key: "postgres:18:default".to_string(),
            max_tenants: 32,
            reserved: RuntimeReservation::default(),
            admin_secret: None,
            created_at: "2026-08-27T00:00:00Z".to_string(),
            updated_at: "2026-08-27T00:00:00Z".to_string(),
        }
    }
}
