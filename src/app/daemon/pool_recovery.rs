use std::{collections::HashSet, path::Path, time::Duration};

use anyhow::{Context, ensure};

use crate::{
    api::{http::state::AppState, instances::containment::contain_locked},
    instances::{
        metadata::{DesiredInstanceState, InstanceMetadata, InstanceStatus},
        paths::InstancePaths,
    },
    placement::{
        DeploymentMode, EngineRuntime, EngineRuntimeStatus, TenantReservation,
        TenantReservationState, lifecycle, tenant,
    },
    runtime::docker::DockerContainerStatus,
    shared::{
        backend::{BackendEndpoint, backend_socket_path},
        time::now_rfc3339,
    },
};

/// Called synchronously at boot before the API or gateway workers exist. The
/// daemon lock excludes offline writers; the pool lock spans the whole attempt.
pub(super) async fn recover_dead_pools(state: &AppState) -> anyhow::Result<RecoverySummary> {
    if !state.config.daemon.recover_shared_pools.is_empty() {
        tracing::warn!(
            event = "legacy_pool_recovery_setting_ignored",
            "daemon.recover_shared_pools is obsolete; boot recovery scans all failed and quarantined shared pools"
        );
    }
    let candidates: Vec<_> = state
        .placements
        .list()
        .await?
        .into_iter()
        .filter(is_candidate)
        .collect();
    let mut summary = RecoverySummary {
        candidates: candidates.len(),
        ..Default::default()
    };
    tracing::info!(
        event = "shared_pool_recovery_scan",
        candidates = summary.candidates,
        "scanned all shared pools for automatic boot recovery"
    );
    if candidates.is_empty() {
        return Ok(summary);
    }
    let blocked = retained_recovery_targets(&state.config).await?;
    for snapshot in candidates {
        let id = &snapshot.runtime_id;
        let _operation = state.instance_locks.lock(id).await;
        let Some(mut runtime) = state.placements.get(id).await? else {
            tracing::warn!(
                event = "audit shared_pool_recovery_skipped",
                runtime_id = id,
                "recovery candidate disappeared"
            );
            continue;
        };
        if !is_candidate(&runtime) || runtime.created_at != snapshot.created_at {
            continue;
        }
        let tenants = match preflight(state, &runtime, &blocked).await {
            Ok(tenants) => tenants,
            Err(error) => {
                summary.refused += 1;
                if runtime.status == EngineRuntimeStatus::Failed {
                    // The ordinary startup pass runs later in this boot. It
                    // must not bypass this refusal or retry the same candidate.
                    runtime.desired_state = DesiredInstanceState::Stopped;
                    runtime.updated_at = now_rfc3339();
                    state.placements.save(&runtime).await?;
                }
                tracing::error!(event = "audit shared_pool_recovery_refused", runtime_id = id, %error, "automatic recovery refused; pool remains down");
                continue;
            }
        };
        tracing::warn!(
            event = "audit shared_pool_recovery_started",
            runtime_id = id,
            tenants = tenants.len(),
            "attempting automatic boot recovery; tenant routes remain closed until validation"
        );
        summary.attempted += 1;
        let was_quarantined = runtime.status == EngineRuntimeStatus::Quarantined;
        let result = if was_quarantined {
            recover_locked(state, runtime.clone(), &tenants).await
        } else {
            // Reuse the normal activation policy. Operational failures remain
            // Failed; a validated retry preserves each tenant's saved intent.
            lifecycle::activate_locked(state, &mut runtime, false).await
        };
        if let Err(error) = result {
            summary.failed += 1;
            if was_quarantined {
                let containment = contain_locked(
                    state,
                    &runtime,
                    "automatic boot recovery failed",
                    Some(crate::storage::quarantine::QuarantineKind::RecoveryFailed),
                )
                .await;
                tracing::error!(event = "audit shared_pool_recovery_failed", runtime_id = id, %error, containment = %containment.summary());
                ensure!(
                    containment.contained(),
                    "could not contain failed recovery of {id}"
                );
            } else {
                tracing::error!(event = "audit shared_pool_recovery_failed", runtime_id = id, %error,
                    "pool retry failed; lifecycle failure policy keeps it down");
                crate::api::instances::containment::stop_pool(state, &runtime)
                    .await
                    .map_err(anyhow::Error::msg)
                    .context("could not verify shutdown after automatic pool retry")?;
                let stored = state
                    .placements
                    .get(id)
                    .await?
                    .context("failed retry lost its durable pool")?;
                ensure!(
                    stored.created_at == runtime.created_at
                        && (stored.status == EngineRuntimeStatus::Quarantined
                            || (stored.status == EngineRuntimeStatus::Failed
                                && stored.desired_state == DesiredInstanceState::Stopped)),
                    "failed recovery did not persist a safe inactive state for {id}"
                );
            }
            continue;
        }
        summary.recovered += 1;
        tracing::warn!(
            event = "audit shared_pool_recovery_completed",
            runtime_id = id,
            tenants = tenants.len(),
            previously_quarantined = was_quarantined,
            "pool recovered automatically; saved tenant intent is preserved, previously quarantined tenants remain stopped"
        );
    }
    tracing::info!(
        event = "shared_pool_recovery_summary",
        candidates = summary.candidates,
        attempted = summary.attempted,
        recovered = summary.recovered,
        refused = summary.refused,
        failed = summary.failed,
        "automatic shared pool recovery finished"
    );
    Ok(summary)
}

#[derive(Debug, Default)]
pub(super) struct RecoverySummary {
    candidates: usize,
    attempted: usize,
    recovered: usize,
    refused: usize,
    failed: usize,
}

fn is_candidate(runtime: &EngineRuntime) -> bool {
    runtime.deployment_mode == DeploymentMode::Shared
        && matches!(
            runtime.status,
            EngineRuntimeStatus::Failed | EngineRuntimeStatus::Quarantined
        )
}

fn check_pool(runtime: &EngineRuntime, panel_id: &str) -> anyhow::Result<()> {
    runtime.check()?;
    ensure!(
        runtime.deployment_mode == DeploymentMode::Shared,
        "not a shared pool"
    );
    ensure!(
        is_candidate(runtime),
        "pool is not a failed or quarantined shared pool"
    );
    ensure!(
        runtime.status == EngineRuntimeStatus::Failed
            || runtime.desired_state == DesiredInstanceState::Running,
        "pool has explicit stopped intent"
    );
    ensure!(
        runtime.pending_image.is_none(),
        "pool has an interrupted image change"
    );
    ensure!(
        runtime
            .owner
            .as_ref()
            .is_some_and(|owner| owner.panel_id == panel_id),
        "pool ownership does not match this panel"
    );
    ensure!(
        runtime
            .admin_secret
            .as_ref()
            .is_some_and(|secret| !secret.is_empty()),
        "pool admin credential is unavailable"
    );
    Ok(())
}

fn check_tenant(
    runtime: &EngineRuntime,
    tenant: &InstanceMetadata,
    reservation: &TenantReservation,
) -> anyhow::Result<()> {
    ensure!(
        tenant.deployment_mode == DeploymentMode::Shared
            && tenant.runtime_id() == runtime.runtime_id
            && tenant.protocol == runtime.protocol
            && tenant.owner == runtime.owner
            && tenant.backend == runtime.backend
            && tenant.runtime.kind == runtime.runtime.kind
            && tenant.runtime.container_name == runtime.runtime.container_name
            && tenant.runtime.network_mode == "none",
        "tenant ownership or backend does not match pool"
    );
    let recoverable_state = match runtime.status {
        EngineRuntimeStatus::Failed => {
            matches!(
                tenant.status,
                InstanceStatus::Failed | InstanceStatus::Stopped
            ) || (tenant.status == InstanceStatus::Quarantined
                && tenant.desired_state == DesiredInstanceState::Stopped)
        }
        _ => {
            matches!(
                tenant.status,
                InstanceStatus::Quarantined | InstanceStatus::Stopped
            ) && tenant.desired_state == DesiredInstanceState::Stopped
        }
    };
    ensure!(
        recoverable_state,
        "tenant has an independent lifecycle operation"
    );
    ensure!(
        tenant
            .tenant_password
            .as_ref()
            .is_some_and(|password| !password.is_empty()),
        "tenant credential is unavailable"
    );
    ensure!(
        reservation.state == TenantReservationState::Provisioned
            && reservation.runtime_id == runtime.runtime_id
            && reservation.instance_id == tenant.instance_id
            && reservation.database == tenant.database.name
            && reservation.username == tenant.database.username
            && reservation.limits.disk_mib == tenant.limits.disk_mib
            && reservation.limits.memory_mib == tenant.limits.memory_mib
            && reservation.limits.cpu_cores.to_bits() == tenant.limits.cpu_cores.to_bits(),
        "tenant reservation does not match durable metadata"
    );
    Ok(())
}

async fn preflight(
    state: &AppState,
    runtime: &EngineRuntime,
    blocked: &HashSet<String>,
) -> anyhow::Result<Vec<String>> {
    check_pool(runtime, &state.config.token_id)?;
    ensure!(
        !blocked.contains(&runtime.runtime_id),
        "pool has retained restore state"
    );
    for job in state.placements.migrations().list_active().await? {
        ensure!(
            job.source_runtime_id != runtime.runtime_id
                && job.target_runtime_id.as_deref() != Some(&runtime.runtime_id)
                && job.target_pool_id.as_deref() != Some(&runtime.runtime_id),
            "pool has an unresolved deployment migration"
        );
    }
    let reservations = state.placements.reservations(&runtime.runtime_id).await?;
    let loaded: HashSet<_> = state
        .instances
        .list()
        .await
        .into_iter()
        .filter(|tenant| tenant.runtime_id() == runtime.runtime_id)
        .map(|tenant| tenant.instance_id)
        .collect();
    let reserved: HashSet<_> = reservations
        .iter()
        .map(|reservation| reservation.instance_id.clone())
        .collect();
    ensure!(
        loaded == reserved && reservations.len() == runtime.reserved.tenants as usize,
        "pool membership does not match its reservations"
    );
    let mut ids = Vec::new();
    for reservation in reservations {
        let id = &reservation.instance_id;
        ensure!(
            !blocked.contains(id) && !state.placements.tenant_recovery_blocked(id).await?,
            "tenant {id} requires separate import, restore, or protected-secret recovery"
        );
        let tenant = state
            .manager
            .get_persisted(id)
            .await?
            .context("tenant metadata disappeared")?;
        check_tenant(runtime, &tenant, &reservation)?;
        ids.push(id.clone());
    }
    let paths = InstancePaths::new(&state.config.paths, &runtime.runtime_id)?;
    ensure!(
        runtime.backend
            == BackendEndpoint::UnixSocket {
                socket_path: backend_socket_path(&paths.sockets, runtime.protocol)
                    .to_string_lossy()
                    .into_owned(),
            },
        "pool backend path does not match configuration"
    );
    let data = tokio::fs::symlink_metadata(&paths.data).await?;
    ensure!(
        data.is_dir() && !data.file_type().is_symlink(),
        "pool data directory is missing or unsafe"
    );
    lifecycle::check_shared_start_disk(state, runtime).await?;
    let inspection = state
        .docker
        .inspect_instance(runtime.protocol, &runtime.runtime_id)
        .await?;
    ensure!(
        inspection.network_mode.as_deref() == Some("none"),
        "pool network isolation changed"
    );
    let reference = state
        .docker
        .container_image(runtime.protocol, &runtime.runtime_id)
        .await?;
    let identity = state
        .docker
        .verified_compatibility_identity(runtime.protocol, &runtime.runtime_id)
        .await?
        .context("pool container identity is unavailable")?;
    ensure!(
        recovery_image_matches(
            runtime,
            reference.as_deref(),
            &identity.id,
            &identity.image_id
        ),
        "pool container image does not match durable metadata"
    );
    ensure!(
        matches!(
            inspection.status,
            DockerContainerStatus::Stopped
                | DockerContainerStatus::Created
                | DockerContainerStatus::Failed
        ),
        "quarantined pool is not stopped"
    );
    // This is the single validated recovery attempt for this pool in this boot,
    // not an ongoing autostart loop. Do not let an old exhausted start budget
    // permanently prevent recovery after the operator repairs its cause.
    Ok(ids)
}

fn recovery_image_matches(
    runtime: &EngineRuntime,
    reference: Option<&str>,
    container_id: &str,
    image_id: &str,
) -> bool {
    reference == Some(runtime.image.as_str())
        || (reference == Some(image_id)
            && lifecycle::attestation_matches(runtime, container_id, image_id))
}

async fn recover_locked(
    state: &AppState,
    mut runtime: EngineRuntime,
    ids: &[String],
) -> anyhow::Result<()> {
    ensure!(
        lifecycle::fence_runtime(state, &runtime.runtime_id).await,
        "could not fence every pool tenant before recovery"
    );
    lifecycle::paths::prepare_socket_directory(state, &runtime).await?;
    crate::placement::runtime::apply_limits(
        &state.docker,
        &state.config,
        &state.placements,
        &runtime,
    )
    .await
    .map_err(anyhow::Error::msg)?;
    // Keep the durable pool quarantined while the engine is inspected. A crash
    // anywhere before final publication is contained by ordinary boot logic.
    state
        .docker
        .start(runtime.protocol, &runtime.runtime_id)
        .await?;
    state
        .docker
        .wait_until_ready(
            runtime.protocol,
            &runtime.runtime_id,
            Duration::from_secs(180),
        )
        .await?;
    lifecycle::attest_runtime_locked(state, &mut runtime)
        .await
        .map_err(anyhow::Error::msg)?;
    runtime.status = EngineRuntimeStatus::Running;
    let summary = tenant::recovery::reconcile_runtime_tenants_locked(state, &runtime).await?;
    ensure!(
        summary.checked == ids.len()
            && summary.fenced == ids.len()
            && summary.opened == 0
            && summary.quarantined == 0
            && summary.pools_contained == 0,
        "tenant security reconciliation did not validate every tenant"
    );
    publish_recovery(state, runtime, ids).await
}

async fn publish_recovery(
    state: &AppState,
    mut runtime: EngineRuntime,
    ids: &[String],
) -> anyhow::Result<()> {
    // All credentials/quotas have been verified with access fenced. Do not infer
    // old running intent: containment deliberately persisted Stopped for tenants.
    for id in ids {
        let mut metadata = state
            .manager
            .get_persisted(id)
            .await?
            .context("verified tenant disappeared")?;
        let reservation = state
            .placements
            .get_reservation(id)
            .await?
            .context("verified tenant reservation disappeared")?;
        check_tenant(&runtime, &metadata, &reservation)?;
        ensure!(
            !state.placements.tenant_recovery_blocked(id).await?,
            "tenant recovery state changed"
        );
        metadata.status = InstanceStatus::Stopped;
        metadata.desired_state = DesiredInstanceState::Stopped;
        metadata.updated_at = now_rfc3339();
        state.manager.upsert_fenced(metadata).await?;
    }
    let current = state
        .placements
        .get(&runtime.runtime_id)
        .await?
        .context("recovering pool disappeared")?;
    ensure!(
        current.status == EngineRuntimeStatus::Quarantined
            && current.created_at == runtime.created_at
            && current.owner == runtime.owner
            && current.image == runtime.image
            && current.pending_image.is_none()
            && current.desired_state == DesiredInstanceState::Running,
        "pool changed during recovery"
    );
    runtime.updated_at = now_rfc3339();
    state.placements.save(&runtime).await?;
    lifecycle::clear_runtime_caches(state, &runtime.runtime_id).await;
    Ok(())
}

async fn retained_recovery_targets(
    config: &crate::config::Config,
) -> anyhow::Result<HashSet<String>> {
    let tmp = std::path::PathBuf::from(config.paths.tmp_root());
    let mut manifests = Vec::new();
    super::boot_recovery::collect_logical_manifests(
        &tmp.join("import-export"),
        &mut manifests,
        1024,
        4096,
    )
    .await?;
    super::boot_recovery::collect_remote_manifests(
        &tmp.join("remote-import"),
        &mut manifests,
        1024,
        4096,
    )
    .await?;
    let mut blocked = HashSet::new();
    for path in manifests {
        let bytes = tokio::task::spawn_blocking(move || {
            crate::shared::files::read_bounded_private_file(&path, 1024 * 1024)
        })
        .await??;
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        let id = value
            .get("instance_id")
            .and_then(|value| value.as_str())
            .context("recovery manifest has no instance ID")?;
        blocked.insert(id.to_owned());
    }
    let volumes = config.paths.volumes_root();
    let mut entries = tokio::fs::read_dir(Path::new(&volumes)).await?;
    let mut scanned = 0;
    while let Some(entry) = entries.next_entry().await? {
        scanned += 1;
        ensure!(scanned <= 4096, "pool recovery volumes scan limit exceeded");
        if let Some(id) = super::boot_recovery::workspace_instance_id(&entry.file_name()) {
            blocked.insert(id);
        }
    }
    Ok(blocked)
}

#[cfg(test)]
mod tests;
