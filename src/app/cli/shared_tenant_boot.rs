use futures::{StreamExt, stream};
use std::time::Duration;

use crate::{
    api::http::router::AppState,
    constants::MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY,
    instances::metadata::{DesiredInstanceState, InstanceMetadata, InstanceStatus},
    placement::{
        DeploymentMode, EngineRuntime, EngineRuntimeStatus, TenantReservation,
        TenantReservationState, runtime as runtime_ops,
        tenant::{self, TenantTarget},
    },
    shared::time::now_rfc3339,
};

const SOFT_USAGE_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct SharedTenantBootSummary {
    pub checked: usize,
    pub opened: usize,
    pub fenced: usize,
    pub quarantined: usize,
    pub pools_contained: usize,
}

impl SharedTenantBootSummary {
    fn merge(&mut self, other: Self) {
        self.checked += other.checked;
        self.opened += other.opened;
        self.fenced += other.fenced;
        self.quarantined += other.quarantined;
        self.pools_contained += other.pools_contained;
    }
}

/// Replays each shared tenant's durable state after its physical pool is ready.
///
/// Shared lifecycle, password, and quota updates necessarily touch the engine
/// and SQLite in separate steps. A daemon exit between those steps can leave
/// the engine ahead of durable metadata. Gateway listeners stay closed until
/// this pass has made the durable row authoritative again.
pub(super) async fn reconcile_shared_tenants(
    state: &AppState,
) -> anyhow::Result<SharedTenantBootSummary> {
    let runtimes = state
        .placements
        .list()
        .await?
        .into_iter()
        .filter(|runtime| runtime.deployment_mode == DeploymentMode::Shared)
        .collect::<Vec<_>>();
    let outcomes = stream::iter(runtimes)
        .map(|snapshot| reconcile_pool(state, snapshot))
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut summary = SharedTenantBootSummary::default();
    for outcome in outcomes {
        summary.merge(outcome?);
    }
    Ok(summary)
}

async fn reconcile_pool(
    state: &AppState,
    snapshot: EngineRuntime,
) -> anyhow::Result<SharedTenantBootSummary> {
    let runtime_id = snapshot.runtime_id.clone();
    let _runtime_operation = state.instance_locks.lock(&runtime_id).await;
    let Some(runtime) = state.placements.get(&runtime_id).await? else {
        return Ok(SharedTenantBootSummary::default());
    };
    if runtime.deployment_mode != DeploymentMode::Shared
        || runtime.protocol != snapshot.protocol
        || runtime.created_at != snapshot.created_at
        || runtime.status != EngineRuntimeStatus::Running
    {
        return Ok(SharedTenantBootSummary::default());
    }

    reconcile_runtime_tenants_locked(state, &runtime).await
}

/// Replays tenant security state while the caller holds the pool runtime lock.
///
/// Pool activation uses the same path as daemon boot so a restarted or
/// reconstructed engine cannot publish routes after only a health check.
pub(super) async fn reconcile_runtime_tenants_locked(
    state: &AppState,
    runtime: &EngineRuntime,
) -> anyhow::Result<SharedTenantBootSummary> {
    if runtime.deployment_mode != DeploymentMode::Shared
        || runtime.status != EngineRuntimeStatus::Running
    {
        return Ok(SharedTenantBootSummary::default());
    }

    let snapshots = state
        .instances
        .list()
        .await
        .into_iter()
        .filter(|metadata| {
            metadata.deployment_mode == DeploymentMode::Shared
                && metadata.runtime_id() == runtime.runtime_id
                && metadata.protocol == runtime.protocol
        })
        .collect::<Vec<_>>();
    let mut summary = SharedTenantBootSummary::default();
    let mut ready = Vec::new();
    for snapshot in snapshots {
        let Some(mut metadata) = state.manager.get_persisted(&snapshot.instance_id).await? else {
            crate::instances::sessions::fence(
                &state.instances,
                &state.gateway_supervisor.tenant_sessions(),
                &snapshot.instance_id,
            )
            .await;
            state.instances.remove(&snapshot.instance_id).await;
            contain_pool(
                state,
                runtime,
                "shared tenant durable metadata disappeared during boot reconciliation",
                &mut summary,
            )
            .await?;
            break;
        };
        if !same_tenant(&snapshot, &metadata, runtime) {
            tracing::error!(
                event = "audit shared_tenant_boot_identity_changed",
                instance_id = %snapshot.instance_id,
                runtime_id = %runtime.runtime_id,
                "shared tenant identity changed during boot reconciliation; containing its pool"
            );
            contain_pool(
                state,
                runtime,
                "shared tenant identity changed during boot reconciliation",
                &mut summary,
            )
            .await?;
            break;
        }
        let reservation = state
            .placements
            .get_reservation(&metadata.instance_id)
            .await?;
        if !reservation
            .as_ref()
            .is_some_and(|reservation| reservation_matches(reservation, &metadata))
        {
            let reason = "shared tenant reservation does not match its durable database identity";
            contain_pool(state, runtime, reason, &mut summary).await?;
            break;
        }

        summary.checked += 1;
        let route_fenced = crate::instances::sessions::fence(
            &state.instances,
            &state.gateway_supervisor.tenant_sessions(),
            &metadata.instance_id,
        )
        .await;
        if !route_fenced {
            let reason = "shared tenant route disappeared before boot reconciliation";
            quarantine_tenant(state, runtime, metadata, reason, &mut summary).await?;
            if summary.pools_contained > 0 {
                break;
            }
            continue;
        }
        match secure_tenant(state, runtime, &mut metadata).await {
            Ok(()) => match access_for(&metadata) {
                TenantAccess::Open => {
                    // Keep the route fenced until every tenant hard-quota fact
                    // is durable and the root quota has been lowered around
                    // those child projects.
                    ready.push(metadata);
                }
                TenantAccess::Fenced => summary.fenced += 1,
            },
            Err(error) => {
                let reason = format!("shared tenant boot reconciliation failed: {error}");
                quarantine_tenant(state, runtime, metadata, &reason, &mut summary).await?;
                if summary.pools_contained > 0 {
                    break;
                }
            }
        }
    }
    if summary.pools_contained == 0 {
        ready = admit_soft_tenants(state, runtime, ready, &mut summary).await?;
    }
    if summary.pools_contained == 0 {
        match runtime_ops::apply_root_disk_limit(&state.config, &state.placements, runtime).await {
            Ok(root_disk_mib) => {
                for metadata in ready {
                    let password = metadata.tenant_password.as_deref().ok_or_else(|| {
                        tenant::TenantEngineError::MissingTenantCredential(
                            metadata.instance_id.clone(),
                        )
                    });
                    let opened = match password {
                        Ok(password) => {
                            tenant::open_verified(
                                &state.docker,
                                runtime,
                                target(&metadata),
                                password,
                            )
                            .await
                        }
                        Err(error) => Err(error),
                    };
                    match opened {
                        Ok(()) => {
                            state.instances.upsert(metadata).await;
                            summary.opened += 1;
                        }
                        Err(error) => {
                            let reason =
                                format!("shared tenant access verification failed: {error}");
                            quarantine_tenant(state, runtime, metadata, &reason, &mut summary)
                                .await?;
                            if summary.pools_contained > 0 {
                                break;
                            }
                        }
                    }
                }
                tracing::debug!(
                    event = "shared_runtime_root_disk_reconciled",
                    runtime_id = %runtime.runtime_id,
                    root_disk_mib,
                    aggregate_disk_mib = runtime.limits.disk_mib,
                    "reconciled the shared-pool root quota before publishing tenant routes"
                );
            }
            Err(error) => {
                tracing::error!(
                    event = "audit shared_runtime_root_disk_reconciliation_failed",
                    runtime_id = %runtime.runtime_id,
                    %error,
                    "shared-pool root quota reconciliation failed before route publication"
                );
                contain_pool(
                    state,
                    runtime,
                    "shared-pool root quota reconciliation failed",
                    &mut summary,
                )
                .await?;
            }
        }
    }
    Ok(summary)
}

async fn secure_tenant(
    state: &AppState,
    runtime: &EngineRuntime,
    metadata: &mut InstanceMetadata,
) -> anyhow::Result<()> {
    for step in SECURE_STEPS {
        match step {
            ReconcileStep::Fence => tenant::fence(&state.docker, runtime, target(metadata)).await?,
            ReconcileStep::RotateCredential => {
                let password = metadata.tenant_password.as_deref().ok_or_else(|| {
                    tenant::TenantEngineError::MissingTenantCredential(metadata.instance_id.clone())
                })?;
                tenant::rotate_password(&state.docker, runtime, target(metadata), password).await?;
            }
            ReconcileStep::ApplyDiskQuota => {
                let disk_state = tenant::disk::set_limit(
                    &state.config,
                    &state.docker,
                    runtime,
                    target(metadata),
                    metadata.limits.disk_mib,
                )
                .await?;
                if tenant::disk::update_state(
                    &mut metadata.limits,
                    &mut metadata.disk_limit_blocked,
                    &disk_state,
                )? {
                    metadata.updated_at = now_rfc3339();
                    state.manager.upsert_fenced(metadata.clone()).await?;
                }
            }
            ReconcileStep::ApplyTenantQuota => {
                tenant::set_quota(&state.docker, runtime, target(metadata), &metadata.limits)
                    .await?
            }
        }
    }
    Ok(())
}

/// Measures every catalog-enforced tenant in one engine query while the
/// caller still holds the runtime lock. Tenants that are full or cannot be
/// measured stay fenced; a pool restart can therefore never create a brief
/// write window before the periodic sampler catches up.
async fn admit_soft_tenants(
    state: &AppState,
    runtime: &EngineRuntime,
    tenants: Vec<InstanceMetadata>,
    summary: &mut SharedTenantBootSummary,
) -> anyhow::Result<Vec<InstanceMetadata>> {
    let (mut ready, soft): (Vec<_>, Vec<_>) = tenants
        .into_iter()
        .partition(|metadata| metadata.limits.disk_enforced);
    if soft.is_empty() {
        return Ok(ready);
    }

    let targets = soft.iter().map(target).collect::<Vec<_>>();
    let measured = tokio::time::timeout(
        SOFT_USAGE_TIMEOUT,
        tenant::measure_storage(&state.docker, runtime, &targets),
    )
    .await;
    let usage = match measured {
        Ok(Ok(usage)) => usage,
        Ok(Err(error)) => {
            let reason = format!("shared tenant storage query failed: {error}");
            block_unmeasured_tenants(state, runtime, soft, &reason, summary).await?;
            return Ok(ready);
        }
        Err(_) => {
            let reason = format!(
                "shared tenant storage query exceeded {} seconds",
                SOFT_USAGE_TIMEOUT.as_secs()
            );
            block_unmeasured_tenants(state, runtime, soft, &reason, summary).await?;
            return Ok(ready);
        }
    };
    if usage.len() != soft.len() {
        let reason = format!(
            "shared tenant storage query returned {} rows for {} tenants",
            usage.len(),
            soft.len()
        );
        block_unmeasured_tenants(state, runtime, soft, &reason, summary).await?;
        return Ok(ready);
    }

    for (metadata, used_bytes) in soft.into_iter().zip(usage) {
        if tenant::disk::soft_limit_blocked(
            used_bytes,
            metadata.limits.disk_mib,
            metadata.disk_limit_blocked,
        ) {
            let (limit_bytes, _) = tenant::disk::soft_limit_bytes(metadata.limits.disk_mib);
            let reason = format!(
                "shared tenant uses {used_bytes} bytes against its {limit_bytes}-byte soft limit"
            );
            block_soft_tenant(state, runtime, metadata, &reason, summary).await?;
        } else {
            ready.push(metadata);
        }
    }
    Ok(ready)
}

async fn block_unmeasured_tenants(
    state: &AppState,
    runtime: &EngineRuntime,
    tenants: Vec<InstanceMetadata>,
    reason: &str,
    summary: &mut SharedTenantBootSummary,
) -> anyhow::Result<()> {
    for metadata in tenants {
        block_soft_tenant(state, runtime, metadata, reason, summary).await?;
        if summary.pools_contained > 0 {
            break;
        }
    }
    Ok(())
}

async fn block_soft_tenant(
    state: &AppState,
    runtime: &EngineRuntime,
    mut metadata: InstanceMetadata,
    reason: &str,
    summary: &mut SharedTenantBootSummary,
) -> anyhow::Result<()> {
    metadata.disk_limit_blocked = true;
    metadata.updated_at = now_rfc3339();
    if let Err(error) = state.manager.upsert_fenced(metadata.clone()).await {
        tracing::error!(
            event = "audit shared_tenant_disk_block_persist_failed",
            instance_id = %metadata.instance_id,
            runtime_id = %runtime.runtime_id,
            %error,
            %reason,
            "soft tenant remained engine-fenced but its durable block could not be recorded"
        );
        contain_pool(
            state,
            runtime,
            "shared tenant soft disk block could not be persisted",
            summary,
        )
        .await?;
        return Ok(());
    }
    summary.fenced += 1;
    tracing::warn!(
        event = "audit shared_tenant_disk_activation_blocked",
        instance_id = %metadata.instance_id,
        runtime_id = %runtime.runtime_id,
        %reason,
        "kept a catalog-enforced tenant fenced while activating its shared pool"
    );
    Ok(())
}

async fn verify_hard_disk_boundary(
    state: &AppState,
    runtime: &EngineRuntime,
    metadata: &mut InstanceMetadata,
) -> anyhow::Result<()> {
    if !metadata.limits.disk_enforced {
        return Ok(());
    }

    let disk_state = tenant::disk::set_limit(
        &state.config,
        &state.docker,
        runtime,
        target(metadata),
        metadata.limits.disk_mib,
    )
    .await?;
    if tenant::disk::update_state(
        &mut metadata.limits,
        &mut metadata.disk_limit_blocked,
        &disk_state,
    )? {
        metadata.updated_at = now_rfc3339();
        state.manager.upsert_fenced(metadata.clone()).await?;
    }
    Ok(())
}

async fn quarantine_tenant(
    state: &AppState,
    runtime: &EngineRuntime,
    mut metadata: InstanceMetadata,
    reason: &str,
    summary: &mut SharedTenantBootSummary,
) -> anyhow::Result<()> {
    if let Err(error) = verify_hard_disk_boundary(state, runtime, &mut metadata).await {
        tracing::error!(
            event = "audit shared_tenant_hard_disk_boundary_unverified",
            instance_id = %metadata.instance_id,
            runtime_id = %runtime.runtime_id,
            reconciliation_error = %reason,
            boundary_error = %error,
            "a durable hard tenant quota could not be verified; containing the whole shared pool"
        );
        contain_pool(
            state,
            runtime,
            "shared tenant hard disk boundary could not be verified",
            summary,
        )
        .await?;
        return Ok(());
    }

    let route_fenced = crate::instances::sessions::fence(
        &state.instances,
        &state.gateway_supervisor.tenant_sessions(),
        &metadata.instance_id,
    )
    .await;
    let engine_fence = tenant::fence(&state.docker, runtime, target(&metadata)).await;
    metadata.status = InstanceStatus::Quarantined;
    metadata.desired_state = DesiredInstanceState::Stopped;
    metadata.updated_at = now_rfc3339();
    let persistence = state.manager.upsert(metadata.clone()).await;

    if isolation_confirmed(route_fenced, engine_fence.is_ok(), persistence.is_ok()) {
        summary.quarantined += 1;
        tracing::error!(
            event = "audit shared_tenant_boot_quarantined",
            instance_id = %metadata.instance_id,
            runtime_id = %runtime.runtime_id,
            %reason,
            "fenced and quarantined one shared tenant while leaving its pool available"
        );
        return Ok(());
    }

    tracing::error!(
        event = "audit shared_tenant_boot_containment_required",
        instance_id = %metadata.instance_id,
        runtime_id = %runtime.runtime_id,
        %reason,
        engine_fence_error = engine_fence.as_ref().err().map(ToString::to_string),
        route_fenced,
        persistence_error = persistence.as_ref().err().map(ToString::to_string),
        "tenant isolation could not be confirmed; containing the whole shared pool"
    );
    contain_pool(
        state,
        runtime,
        "shared tenant boot reconciliation could not confirm tenant isolation",
        summary,
    )
    .await?;
    Ok(())
}

async fn contain_pool(
    state: &AppState,
    runtime: &EngineRuntime,
    reason: &str,
    summary: &mut SharedTenantBootSummary,
) -> anyhow::Result<()> {
    summary.pools_contained += 1;
    let contained =
        super::shared_runtime_boot::isolate_runtime(state, runtime.clone(), reason).await;
    anyhow::ensure!(
        contained,
        "shared pool {} could not be contained during boot reconciliation",
        runtime.runtime_id
    );
    Ok(())
}

fn same_tenant(
    snapshot: &InstanceMetadata,
    current: &InstanceMetadata,
    runtime: &EngineRuntime,
) -> bool {
    snapshot.instance_id == current.instance_id
        && snapshot.created_at == current.created_at
        && current.deployment_mode == DeploymentMode::Shared
        && current.runtime_id() == runtime.runtime_id
        && current.protocol == runtime.protocol
        && snapshot.database.name == current.database.name
        && snapshot.database.username == current.database.username
}

fn reservation_matches(reservation: &TenantReservation, metadata: &InstanceMetadata) -> bool {
    reservation.instance_id == metadata.instance_id
        && reservation.runtime_id == metadata.runtime_id()
        && reservation.database == metadata.database.name
        && reservation.username == metadata.database.username
        && reservation.state == TenantReservationState::Provisioned
        && reservation.limits.cpu_cores.to_bits() == metadata.limits.cpu_cores.to_bits()
        && reservation.limits.memory_mib == metadata.limits.memory_mib
        && reservation.limits.disk_mib == metadata.limits.disk_mib
}

fn target(metadata: &InstanceMetadata) -> TenantTarget<'_> {
    TenantTarget {
        database: &metadata.database.name,
        username: &metadata.database.username,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TenantAccess {
    Open,
    Fenced,
}

fn access_for(metadata: &InstanceMetadata) -> TenantAccess {
    access_from_state(
        metadata.status,
        metadata.desired_state,
        metadata.disk_limit_blocked,
    )
}

fn access_from_state(
    status: InstanceStatus,
    desired: DesiredInstanceState,
    disk_blocked: bool,
) -> TenantAccess {
    if status == InstanceStatus::Running
        && desired == DesiredInstanceState::Running
        && !disk_blocked
    {
        TenantAccess::Open
    } else {
        TenantAccess::Fenced
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileStep {
    Fence,
    RotateCredential,
    ApplyDiskQuota,
    ApplyTenantQuota,
}

const SECURE_STEPS: &[ReconcileStep] = &[
    ReconcileStep::Fence,
    ReconcileStep::RotateCredential,
    ReconcileStep::ApplyDiskQuota,
    ReconcileStep::ApplyTenantQuota,
];

fn isolation_confirmed(route_fenced: bool, engine_fenced: bool, quarantined: bool) -> bool {
    route_fenced && engine_fenced && quarantined
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{disk::DiskEnforcement, instances::test_support::shared_metadata};

    #[test]
    fn running_state_replays_password_and_quota_before_opening() {
        let access = access_from_state(
            InstanceStatus::Running,
            DesiredInstanceState::Running,
            false,
        );
        assert_eq!(access, TenantAccess::Open);
        assert_eq!(
            SECURE_STEPS,
            &[
                ReconcileStep::Fence,
                ReconcileStep::RotateCredential,
                ReconcileStep::ApplyDiskQuota,
                ReconcileStep::ApplyTenantQuota,
            ]
        );
        // Route publication is a separate final phase after soft-disk
        // admission and the shared root quota have both succeeded.
        assert_eq!(SECURE_STEPS.len(), 4);
    }

    #[test]
    fn stopped_state_is_refenced_after_an_interrupted_start() {
        let access = access_from_state(
            InstanceStatus::Stopped,
            DesiredInstanceState::Stopped,
            false,
        );
        assert_eq!(access, TenantAccess::Fenced);
        assert_eq!(SECURE_STEPS.first(), Some(&ReconcileStep::Fence));
        assert_eq!(SECURE_STEPS.first(), Some(&ReconcileStep::Fence));
    }

    #[test]
    fn restored_hard_quota_clears_the_legacy_soft_fence() {
        let mut metadata = shared_metadata();
        metadata.disk_limit_blocked = true;
        let enforcement = DiskEnforcement {
            enforced: true,
            method: "host_xfs_project_quota".to_string(),
            container_data_path: None,
        };

        assert!(
            tenant::disk::update_state(
                &mut metadata.limits,
                &mut metadata.disk_limit_blocked,
                &enforcement,
            )
            .unwrap()
        );
        assert!(metadata.limits.disk_enforced);
        assert!(!metadata.disk_limit_blocked);
        assert_eq!(access_for(&metadata), TenantAccess::Open);
    }

    #[test]
    fn unsafe_durable_states_never_reopen_a_tenant() {
        for (status, desired, disk_blocked) in [
            (InstanceStatus::Running, DesiredInstanceState::Running, true),
            (
                InstanceStatus::Quarantined,
                DesiredInstanceState::Stopped,
                false,
            ),
            (
                InstanceStatus::Deleting,
                DesiredInstanceState::Stopped,
                false,
            ),
            (InstanceStatus::Failed, DesiredInstanceState::Running, false),
        ] {
            assert_eq!(
                access_from_state(status, desired, disk_blocked),
                TenantAccess::Fenced
            );
        }
    }

    #[test]
    fn incomplete_isolation_requires_pool_containment() {
        assert!(isolation_confirmed(true, true, true));
        assert!(!isolation_confirmed(false, true, true));
        assert!(!isolation_confirmed(true, false, true));
        assert!(!isolation_confirmed(true, true, false));
    }
}
