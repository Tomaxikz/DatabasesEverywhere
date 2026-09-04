use anyhow::Context;

use crate::{
    api::http::router::AppState,
    placement::{EngineRuntime, EngineRuntimeStatus, TenantReservation, tenant::TenantTarget},
};

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct OrphanRecoverySummary {
    pub checked: usize,
    pub cleaned: usize,
    pub quarantined: usize,
}

/// Removes tenants left between durable capacity reservation and metadata
/// attachment. Deployment migration recovery runs first; the repository also
/// excludes every reservation still owned by an active migration.
pub(super) async fn recover_orphan_reservations(
    state: &AppState,
) -> anyhow::Result<OrphanRecoverySummary> {
    let snapshots = state
        .placements
        .list_orphans()
        .await
        .context("failed to list interrupted shared tenant creations")?;
    let mut summary = OrphanRecoverySummary::default();
    for snapshot in snapshots {
        summary.checked += 1;
        let _runtime_operation = state.instance_locks.lock(&snapshot.runtime_id).await;
        let Some(orphan) = state
            .placements
            .get_orphan(&snapshot.instance_id)
            .await
            .with_context(|| {
                format!(
                    "failed to reload orphan reservation {}",
                    snapshot.instance_id
                )
            })?
        else {
            continue;
        };
        let Some(runtime) = state
            .placements
            .get(&orphan.runtime_id)
            .await
            .with_context(|| format!("failed to reload shared runtime {}", orphan.runtime_id))?
        else {
            anyhow::bail!(
                "orphan reservation {} references missing runtime {}",
                orphan.instance_id,
                orphan.runtime_id
            );
        };

        match cleanup_orphan(state, &runtime, &orphan).await {
            Ok(()) => {
                summary.cleaned += 1;
                tracing::info!(
                    event = "audit orphan_shared_tenant_recovered",
                    instance_id = %orphan.instance_id,
                    runtime_id = %orphan.runtime_id,
                    database = %orphan.database,
                    username = %orphan.username,
                    reservation_state = orphan.state.as_str(),
                    "removed an interrupted shared tenant creation"
                );
            }
            Err(error) => {
                quarantine(state, runtime, &orphan, &error).await?;
                summary.quarantined += 1;
            }
        }
    }
    Ok(summary)
}

async fn cleanup_orphan(
    state: &AppState,
    runtime: &EngineRuntime,
    orphan: &TenantReservation,
) -> anyhow::Result<()> {
    // A new pool persists its first reservation before Docker is asked to
    // create the container, and does not become Running until its engine-wide
    // bootstrap has completed. A crash anywhere in that window therefore
    // leaves a pool that has never accepted a logical tenant. Release its sole
    // claim so the following empty-pool pass can delete the whole container
    // and volume instead of trying to connect to a half-started engine. Any
    // established or multi-tenant pool keeps the normal fail-closed path.
    if can_release_unlaunched_pool(runtime) {
        let released = state
            .placements
            .release(&orphan.instance_id)
            .await
            .context("failed to release an unlaunched shared-pool reservation")?;
        anyhow::ensure!(
            released,
            "the unlaunched pool reservation disappeared during cleanup"
        );
        return Ok(());
    }

    let target = TenantTarget {
        database: &orphan.database,
        username: &orphan.username,
    };
    crate::placement::tenant::disk::prepare_drop(&state.config, runtime, target)
        .await
        .context("failed to prepare interrupted tenant storage cleanup")?;
    crate::placement::tenant::drop_tenant(&state.docker, runtime, target)
        .await
        .context("failed to remove the interrupted tenant from its shared engine")?;
    crate::placement::tenant::disk::remove(&state.config, runtime, target)
        .await
        .context("failed to remove the interrupted tenant disk quota")?;
    let released = state
        .placements
        .release(&orphan.instance_id)
        .await
        .context("failed to release interrupted shared capacity")?;
    anyhow::ensure!(
        released,
        "the orphan reservation disappeared during cleanup"
    );
    Ok(())
}

fn can_release_unlaunched_pool(runtime: &EngineRuntime) -> bool {
    runtime.status == EngineRuntimeStatus::Creating && runtime.reserved.tenants == 1
}

async fn quarantine(
    state: &AppState,
    runtime: EngineRuntime,
    orphan: &TenantReservation,
    error: &anyhow::Error,
) -> anyhow::Result<()> {
    let containment = crate::api::instances::containment::contain_locked(
        state,
        &runtime,
        "an interrupted shared tenant could not be removed safely",
    )
    .await;
    tracing::error!(
        event = "audit orphan_shared_tenant_recovery_failed",
        instance_id = %orphan.instance_id,
        runtime_id = %runtime.runtime_id,
        database = %orphan.database,
        username = %orphan.username,
        reservation_state = orphan.state.as_str(),
        %error,
        containment = %containment.summary(),
        contained = containment.contained(),
        "retained the reservation and quarantined its shared runtime"
    );
    anyhow::ensure!(
        containment.contained(),
        "shared runtime {} could not be contained after orphan cleanup failed: {}",
        runtime.runtime_id,
        containment.summary()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::{backend::BackendEndpoint, protocol::Protocol};

    fn runtime(status: EngineRuntimeStatus, tenants: u32) -> EngineRuntime {
        let mut runtime = crate::placement::test_support::runtime(
            "pool_postgres_boot_claim",
            Protocol::Postgres,
            "postgres:18.4",
        );
        runtime.status = status;
        runtime.backend = BackendEndpoint::UnixSocket {
            socket_path: "/run/dbev/pool.sock".to_string(),
        };
        runtime.runtime.container_name = "dbe-postgres-pool".to_string();
        runtime.max_tenants = 64;
        runtime.reserved.tenants = tenants;
        runtime.admin_secret = Some("admin".to_string());
        runtime
    }

    #[test]
    fn only_the_first_claim_of_a_creating_pool_can_skip_engine_cleanup() {
        assert!(can_release_unlaunched_pool(&runtime(
            EngineRuntimeStatus::Creating,
            1,
        )));
        assert!(!can_release_unlaunched_pool(&runtime(
            EngineRuntimeStatus::Creating,
            2,
        )));
        for status in [
            EngineRuntimeStatus::Booting,
            EngineRuntimeStatus::Running,
            EngineRuntimeStatus::Stopped,
            EngineRuntimeStatus::Failed,
            EngineRuntimeStatus::Quarantined,
            EngineRuntimeStatus::Deleting,
        ] {
            assert!(!can_release_unlaunched_pool(&runtime(status, 1)));
        }
    }
}
