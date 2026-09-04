use std::{collections::HashMap, future::Future, time::Duration};

use futures::{StreamExt, stream};
use tokio::time::{Instant, MissedTickBehavior};

use super::{AppState, CachedDiskUsage, DeploymentMode, InstanceMetadata, InstanceStatus};
use crate::{
    instances::metadata::DesiredInstanceState,
    placement::{
        EngineRuntime, EngineRuntimeStatus,
        tenant::{self, TenantTarget},
    },
    shared::time::now_rfc3339,
};

const SAMPLE_INTERVAL: Duration = Duration::from_secs(15);
const SAMPLE_STALE_AFTER: Duration = Duration::from_secs(30);
const QUERY_TIMEOUT: Duration = Duration::from_secs(20);
const SAMPLE_CONCURRENCY: usize = 4;
const HARD_SAMPLE_CONCURRENCY: usize = 16;

pub(super) fn uses_soft_guard(deployment_mode: DeploymentMode, disk_enforced: bool) -> bool {
    deployment_mode == DeploymentMode::Shared && !disk_enforced
}

pub(super) async fn reported_disk_used_bytes<F, Fut>(
    scanner: Option<&crate::disk::soft::SoftDiskSnapshot>,
    fallback: F,
) -> Result<u64, String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<u64, String>>,
{
    match scanner {
        Some(snapshot) => Ok(snapshot.usage.physical_bytes),
        None => fallback().await,
    }
}

pub(super) async fn usage(state: &AppState, metadata: &InstanceMetadata) -> Result<u64, String> {
    if metadata.deployment_mode != DeploymentMode::Shared {
        return Err("shared storage measurement requires a shared tenant".to_string());
    }
    if let Some(sample) = state
        .resource_cache
        .cached_disk_usage(&metadata.instance_id)
        .await
        && sample.sampled_at.elapsed() < SAMPLE_STALE_AFTER
    {
        return Ok(sample.used_bytes);
    }
    if metadata.limits.disk_enforced {
        let runtime = load_runtime(state, metadata.runtime_id(), metadata.protocol).await?;
        refresh_hard_usage(state, &runtime, metadata, SAMPLE_STALE_AFTER).await?;
    } else {
        sample_runtime(state, vec![metadata.clone()], false).await?;
    }
    match state
        .resource_cache
        .cached_disk_usage(&metadata.instance_id)
        .await
    {
        Some(sample) if sample.sampled_at.elapsed() < SAMPLE_STALE_AFTER => Ok(sample.used_bytes),
        Some(_) => {
            Err("shared tenant storage refresh did not produce a current sample".to_string())
        }
        None => Err("shared tenant storage sample was not recorded".to_string()),
    }
}

pub(super) fn start(state: AppState) {
    let mut shutdown = state.gateway_supervisor.subscribe_shutdown();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        tracing::info!("shared tenant storage monitor stopped");
                        break;
                    }
                }
                _ = ticker.tick() => sample_all(&state).await,
            }
        }
    });
}

async fn sample_all(state: &AppState) {
    let groups = tenant_groups(state).await;
    stream::iter(groups.into_values())
        .for_each_concurrent(SAMPLE_CONCURRENCY, |tenants| async move {
            if let Err(error) = sample_runtime(state, tenants.clone(), true).await {
                tracing::warn!(%error, "failed to sample shared tenant storage");
                if let Some(runtime_id) = sample_group_runtime(&tenants) {
                    fence_unmeasured_runtime(state, &runtime_id, &error).await;
                }
            }
        })
        .await;
}

pub(super) async fn prime(state: &AppState) -> usize {
    let groups = tenant_groups(state).await;
    let outcomes = stream::iter(groups.into_values())
        .map(|tenants| async move {
            // Native hard quotas already reject writes in the kernel and do
            // not need telemetry before a route can open. Prime only the soft
            // guards whose safety depends on a successful catalog query.
            match sample_runtime(state, tenants.clone(), false).await {
                Ok(()) => false,
                Err(error) => {
                    tracing::error!(
                        %error,
                        "shared tenant storage could not be measured before gateway startup"
                    );
                    match sample_group_runtime(&tenants) {
                        Some(runtime_id) => {
                            fence_unmeasured_runtime(state, &runtime_id, &error).await > 0
                        }
                        None => false,
                    }
                }
            }
        })
        .buffer_unordered(SAMPLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    outcomes.into_iter().filter(|failed| *failed).count()
}

async fn tenant_groups(state: &AppState) -> HashMap<String, Vec<InstanceMetadata>> {
    let mut groups = HashMap::<String, Vec<InstanceMetadata>>::new();
    for metadata in state.instances.list().await.into_iter().filter(|metadata| {
        metadata.deployment_mode == DeploymentMode::Shared
            && metadata.status != InstanceStatus::Deleting
    }) {
        groups
            .entry(metadata.runtime_id().to_string())
            .or_default()
            .push(metadata);
    }
    groups
}

async fn sample_runtime(
    state: &AppState,
    tenants: Vec<InstanceMetadata>,
    include_hard: bool,
) -> Result<(), String> {
    let Some(first) = tenants.first() else {
        return Ok(());
    };
    let runtime_id = first.runtime_id().to_string();
    if tenants
        .iter()
        .any(|metadata| metadata.runtime_id() != runtime_id || metadata.protocol != first.protocol)
    {
        return Err(format!(
            "shared runtime {runtime_id} has inconsistent tenant metadata"
        ));
    }
    let protocol = first.protocol;

    if include_hard {
        let runtime = load_runtime(state, &runtime_id, protocol).await?;
        stream::iter(
            tenants
                .iter()
                .filter(|metadata| metadata.limits.disk_enforced),
        )
        .for_each_concurrent(HARD_SAMPLE_CONCURRENCY, |metadata| {
            let runtime = &runtime;
            let runtime_id = &runtime_id;
            async move {
                if let Err(error) =
                    refresh_hard_usage(state, runtime, metadata, SAMPLE_INTERVAL).await
                {
                    tracing::warn!(
                        instance_id = %metadata.instance_id,
                        %runtime_id,
                        %error,
                        "failed to sample hard shared tenant disk usage"
                    );
                }
            }
        })
        .await;
    }

    // Soft enforcement is a measurement-and-fence transaction. Keep it under
    // the physical runtime lock, then reload the complete pool so lifecycle
    // changes made after the initial grouping cannot escape the decision.
    let _runtime_operation = state.instance_locks.lock(&runtime_id).await;
    let tenants = state
        .instances
        .list()
        .await
        .into_iter()
        .filter(|metadata| {
            metadata.deployment_mode == DeploymentMode::Shared
                && metadata.runtime_id() == runtime_id
                && metadata.protocol == protocol
                && metadata.status != InstanceStatus::Deleting
        })
        .collect::<Vec<_>>();
    if tenants.is_empty() {
        return Ok(());
    }
    let runtime = load_runtime(state, &runtime_id, protocol).await?;
    if runtime.status != EngineRuntimeStatus::Running {
        return Ok(());
    }

    let soft = tenants
        .into_iter()
        .filter(|metadata| !metadata.limits.disk_enforced)
        .collect::<Vec<_>>();

    if soft.is_empty() {
        return Ok(());
    }
    let targets = soft
        .iter()
        .map(|metadata| TenantTarget {
            database: &metadata.database.name,
            username: &metadata.database.username,
        })
        .collect::<Vec<_>>();
    let values = tokio::time::timeout(
        QUERY_TIMEOUT,
        tenant::measure_storage(&state.docker, &runtime, &targets),
    )
    .await
    .map_err(|_| format!("shared runtime {runtime_id} storage query timed out"))?
    .map_err(|error| format!("shared runtime {runtime_id} storage query failed: {error}"))?;
    check_sample_count(&runtime_id, soft.len(), values.len())?;

    for (metadata, used_bytes) in soft.into_iter().zip(values) {
        store_sample(state, &metadata, used_bytes).await;
        enforce_quota_locked(state, metadata, used_bytes).await;
    }
    Ok(())
}

async fn load_runtime(
    state: &AppState,
    runtime_id: &str,
    protocol: crate::shared::protocol::Protocol,
) -> Result<EngineRuntime, String> {
    let runtime = state
        .placements
        .get(runtime_id)
        .await
        .map_err(|error| format!("failed to load shared runtime {runtime_id}: {error}"))?
        .ok_or_else(|| format!("shared runtime {runtime_id} is missing"))?;
    if runtime.deployment_mode != DeploymentMode::Shared || runtime.protocol != protocol {
        return Err(format!(
            "shared runtime {runtime_id} does not match its tenant metadata"
        ));
    }
    Ok(runtime)
}

/// Reads one hard tenant's O(1) kernel project-quota counter. This deliberately
/// does not take the runtime lifecycle lock: quota accounting is independent
/// of the database engine, while an identity recheck prevents a late sample
/// from being published after delete, migration, or recreation.
async fn refresh_hard_usage(
    state: &AppState,
    runtime: &EngineRuntime,
    snapshot: &InstanceMetadata,
    fresh_for: Duration,
) -> Result<(), String> {
    let refresh_lock = state
        .resource_cache
        .disk_refresh_lock(&snapshot.instance_id)
        .await;
    let _refresh = refresh_lock.lock().await;
    if state
        .resource_cache
        .cached_disk_usage(&snapshot.instance_id)
        .await
        .is_some_and(|sample| sample.sampled_at.elapsed() < fresh_for)
    {
        return Ok(());
    }

    let used_bytes = tenant::disk::quota_usage_bytes(
        &state.config,
        runtime,
        TenantTarget {
            database: &snapshot.database.name,
            username: &snapshot.database.username,
        },
    )
    .await
    .map_err(|error| error.to_string())?;

    let current = state.instances.get(&snapshot.instance_id).await;
    let current_runtime = state
        .placements
        .get(runtime.runtime_id.as_str())
        .await
        .map_err(|error| format!("failed to recheck shared runtime identity: {error}"))?;
    if !current
        .as_ref()
        .is_some_and(|metadata| same_hard_identity(metadata, snapshot))
        || !current_runtime.as_ref().is_some_and(|candidate| {
            candidate.runtime_id == runtime.runtime_id
                && candidate.created_at == runtime.created_at
                && candidate.protocol == runtime.protocol
                && candidate.deployment_mode == DeploymentMode::Shared
        })
    {
        return Err("shared tenant identity changed during disk sampling".to_string());
    }

    let stored = state
        .resource_cache
        .store_disk_usage_if_current_lock(
            &snapshot.instance_id,
            &refresh_lock,
            CachedDiskUsage {
                used_bytes,
                sampled_at: Instant::now(),
            },
        )
        .await;
    if !stored {
        return Err("shared tenant disk cache was invalidated during sampling".to_string());
    }
    Ok(())
}

fn same_hard_identity(current: &InstanceMetadata, snapshot: &InstanceMetadata) -> bool {
    current.deployment_mode == DeploymentMode::Shared
        && current.limits.disk_enforced
        && current.status != InstanceStatus::Deleting
        && current.instance_id == snapshot.instance_id
        && current.created_at == snapshot.created_at
        && current.runtime_id() == snapshot.runtime_id()
        && current.protocol == snapshot.protocol
        && current.database.name == snapshot.database.name
        && current.database.username == snapshot.database.username
}

async fn store_sample(state: &AppState, metadata: &InstanceMetadata, used_bytes: u64) {
    state
        .resource_cache
        .store_disk_usage(
            metadata.instance_id.clone(),
            CachedDiskUsage {
                used_bytes,
                sampled_at: Instant::now(),
            },
        )
        .await;
}

fn check_sample_count(runtime_id: &str, expected: usize, actual: usize) -> Result<(), String> {
    if expected == actual {
        return Ok(());
    }
    Err(format!(
        "shared runtime {runtime_id} returned {actual} storage rows for {expected} tenants"
    ))
}

/// The caller holds the physical runtime lock from measurement through the
/// fence/unfence decision, so this usage sample cannot race an import or a
/// stale recovery decision.
async fn enforce_quota_locked(state: &AppState, snapshot: InstanceMetadata, used_bytes: u64) {
    let runtime_id = snapshot.runtime_id().to_string();
    let Some(mut metadata) = state.instances.get(&snapshot.instance_id).await else {
        return;
    };
    if metadata.deployment_mode != DeploymentMode::Shared
        || !uses_soft_guard(metadata.deployment_mode, metadata.limits.disk_enforced)
        || metadata.runtime_id() != runtime_id
        || metadata.created_at != snapshot.created_at
        || metadata.database.name != snapshot.database.name
        || metadata.database.username != snapshot.database.username
        || metadata.status == InstanceStatus::Deleting
    {
        return;
    }
    let (limit_bytes, recovery_bytes) = tenant::disk::soft_limit_bytes(metadata.limits.disk_mib);
    let should_block = tenant::disk::soft_limit_blocked(
        used_bytes,
        metadata.limits.disk_mib,
        metadata.disk_limit_blocked,
    );
    if should_block == metadata.disk_limit_blocked {
        return;
    }
    let Some(runtime) = state
        .placements
        .get(&runtime_id)
        .await
        .map_err(|error| {
            tracing::error!(%error, %runtime_id, "failed to load shared runtime for disk enforcement");
        })
        .ok()
        .flatten()
    else {
        return;
    };
    let target = TenantTarget {
        database: &metadata.database.name,
        username: &metadata.database.username,
    };

    if should_block && !metadata.disk_limit_blocked {
        crate::api::instances::route_fence::fence(state, &metadata.instance_id).await;
        if let Err(error) = tenant::fence(&state.docker, &runtime, target).await {
            tracing::error!(
                event = "audit shared_tenant_disk_engine_fence_failed",
                instance_id = %metadata.instance_id,
                %runtime_id,
                %error,
                "gateway access remains fenced"
            );
        }
        metadata.disk_limit_blocked = true;
        metadata.updated_at = now_rfc3339();
        if let Err(error) = state.manager.upsert(metadata.clone()).await {
            // Keep the blocked fact in memory even when durable storage is
            // temporarily unavailable. The explicit route fence remains the
            // authority, and a later low-usage sample can now recover instead
            // of leaving this process permanently stuck closed.
            state.instances.upsert_fenced(metadata.clone()).await;
            tracing::error!(
                event = "audit shared_tenant_disk_block_persist_failed",
                instance_id = %metadata.instance_id,
                %runtime_id,
                %error,
                "tenant remains fenced in memory and at the engine"
            );
            return;
        }
        tracing::warn!(
            event = "audit shared_tenant_disk_limit_reached",
            instance_id = %metadata.instance_id,
            %runtime_id,
            used_bytes,
            limit_bytes,
            "tenant access was fenced without stopping the shared runtime"
        );
        return;
    }

    if !should_block && metadata.disk_limit_blocked {
        if metadata.status == InstanceStatus::Running
            && metadata.desired_state == DesiredInstanceState::Running
        {
            let opened = match metadata.tenant_password.as_deref() {
                Some(password) => tenant::open_verified(&state.docker, &runtime, target, password)
                    .await
                    .map_err(|error| error.to_string()),
                None => Err("the encrypted tenant credential is missing".to_string()),
            };
            if let Err(error) = opened {
                tracing::warn!(
                    event = "audit shared_tenant_disk_recovery_deferred",
                    instance_id = %metadata.instance_id,
                    %runtime_id,
                    %error,
                );
                return;
            }
        }
        metadata.disk_limit_blocked = false;
        metadata.updated_at = now_rfc3339();
        if let Err(error) = state.manager.upsert(metadata.clone()).await {
            let _ = tenant::fence(&state.docker, &runtime, target).await;
            crate::api::instances::route_fence::fence(state, &metadata.instance_id).await;
            metadata.disk_limit_blocked = true;
            state.instances.upsert_fenced(metadata.clone()).await;
            tracing::error!(
                event = "audit shared_tenant_disk_recovery_persist_failed",
                instance_id = %metadata.instance_id,
                %runtime_id,
                %error,
                "rolled engine access back to fenced"
            );
            return;
        }
        tracing::info!(
            event = "audit shared_tenant_disk_limit_recovered",
            instance_id = %metadata.instance_id,
            %runtime_id,
            used_bytes,
            recovery_bytes,
        );
    }
}

fn sample_group_runtime(tenants: &[InstanceMetadata]) -> Option<String> {
    tenants
        .first()
        .map(|tenant| tenant.runtime_id().to_string())
}

/// Re-reads the whole pool after the failed sampler releases its runtime
/// lock. This catches tenants created or changed to soft enforcement between
/// the initial grouping and the failed query; using the stale input snapshot
/// here could otherwise leave a newly soft tenant reachable without a
/// measurable limit.
async fn fence_unmeasured_runtime(state: &AppState, runtime_id: &str, reason: &str) -> usize {
    let _runtime_operation = state.instance_locks.lock(runtime_id).await;
    let tenants = state
        .instances
        .list()
        .await
        .into_iter()
        .filter(|metadata| {
            metadata.runtime_id() == runtime_id
                && uses_soft_guard(metadata.deployment_mode, metadata.limits.disk_enforced)
                && metadata.status == InstanceStatus::Running
                && metadata.desired_state == DesiredInstanceState::Running
        })
        .collect::<Vec<_>>();
    if tenants.is_empty() {
        return 0;
    }
    let runtime = state.placements.get(runtime_id).await.ok().flatten();
    if let Some(runtime) = &runtime
        && tenants
            .iter()
            .any(|metadata| metadata.protocol != runtime.protocol)
    {
        for metadata in &tenants {
            crate::api::instances::route_fence::fence(state, &metadata.instance_id).await;
        }
        let containment = crate::api::instances::containment::contain_locked(
            state,
            runtime,
            "shared-pool tenant metadata disagreed on protocol during disk sampling",
        )
        .await;
        tracing::error!(
            event = "audit shared_tenant_disk_identity_mismatch",
            %runtime_id,
            containment = %containment.summary(),
            contained = containment.contained(),
            "contained a shared pool instead of applying protocol-specific fencing to corrupt tenant metadata"
        );
        return tenants.len();
    }
    for mut metadata in tenants.iter().cloned() {
        crate::api::instances::route_fence::fence(state, &metadata.instance_id).await;
        if let Some(runtime) = &runtime {
            let target = TenantTarget {
                database: &metadata.database.name,
                username: &metadata.database.username,
            };
            if let Err(error) = tenant::fence(&state.docker, runtime, target).await {
                tracing::error!(
                    event = "audit shared_tenant_disk_prime_engine_fence_failed",
                    instance_id = %metadata.instance_id,
                    %runtime_id,
                    %error,
                    "gateway route remains fenced"
                );
            }
        }
        metadata.disk_limit_blocked = true;
        metadata.updated_at = now_rfc3339();
        if let Err(error) = state.manager.upsert(metadata.clone()).await {
            state.instances.upsert_fenced(metadata.clone()).await;
            tracing::error!(
                event = "audit shared_tenant_disk_prime_persist_failed",
                instance_id = %metadata.instance_id,
                %runtime_id,
                %error,
                "tenant remains fenced in the in-memory route index"
            );
        }
        tracing::error!(
            event = "audit shared_tenant_disk_prime_blocked",
            instance_id = %metadata.instance_id,
            %runtime_id,
            %reason,
            "tenant remained fail-closed because its storage quota could not be initialized before gateway startup"
        );
    }
    tenants.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hard_tenant() -> InstanceMetadata {
        let mut metadata: InstanceMetadata = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "instance_id": "tenant-a",
            "deployment_mode": "shared",
            "runtime_id": "pool-a",
            "protocol": "mysql",
            "status": "running",
            "public": {"host": "db.example.com", "port": 3306},
            "backend": {"kind": "unix_socket", "socket_path": "/run/mysql.sock"},
            "runtime": {"kind": "docker", "container_name": "pool-a", "network_mode": "none"},
            "database": {"name": "app_a", "username": "tenant_a"},
            "limits": {"cpu_cores": 1.0, "memory_mib": 256, "disk_mib": 1024,
                "disk_enforced": true, "disk_enforcement_method": "host_linux_project_quota"},
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z"
        }))
        .unwrap();
        metadata.desired_state = DesiredInstanceState::Running;
        metadata
    }

    #[test]
    fn quota_hysteresis_leaves_recovery_headroom() {
        let limit = 100_u64 * 1024 * 1024;
        let recovery = tenant::disk::soft_limit_bytes(100).1;

        assert_eq!(recovery, 90 * 1024 * 1024);
        assert!(recovery < limit);
    }

    #[test]
    fn incomplete_storage_samples_fail_closed() {
        assert!(check_sample_count("pool-a", 2, 2).is_ok());
        let error = check_sample_count("pool-a", 2, 1).unwrap_err();
        assert!(error.contains("1 storage rows for 2 tenants"));
    }

    #[test]
    fn hard_shared_quotas_do_not_use_the_soft_guard() {
        assert!(uses_soft_guard(DeploymentMode::Shared, false));
        assert!(!uses_soft_guard(DeploymentMode::Shared, true));
        assert!(!uses_soft_guard(DeploymentMode::Dedicated, false));
    }

    #[test]
    fn hard_sample_is_published_only_for_the_same_live_boundary() {
        let snapshot = hard_tenant();
        assert!(same_hard_identity(&snapshot, &snapshot));

        for changed in [
            {
                let mut value = snapshot.clone();
                value.status = InstanceStatus::Deleting;
                value
            },
            {
                let mut value = snapshot.clone();
                value.limits.disk_enforced = false;
                value
            },
            {
                let mut value = snapshot.clone();
                value.runtime_id = "pool-b".to_string();
                value
            },
            {
                let mut value = snapshot.clone();
                value.database.name = "replacement".to_string();
                value
            },
            {
                let mut value = snapshot.clone();
                value.created_at = "2026-01-02T00:00:00Z".to_string();
                value
            },
        ] {
            assert!(!same_hard_identity(&changed, &snapshot));
        }
    }

    #[tokio::test]
    async fn invalidation_rejects_a_late_hard_quota_sample() {
        let cache = crate::api::monitoring::resources::ResourceCache::default();
        let old_lock = cache.disk_refresh_lock("tenant-a").await;

        cache.invalidate_runtime("tenant-a").await;
        assert!(
            !cache
                .store_disk_usage_if_current_lock(
                    "tenant-a",
                    &old_lock,
                    CachedDiskUsage {
                        used_bytes: 99,
                        sampled_at: Instant::now(),
                    },
                )
                .await
        );
        assert!(cache.cached_disk_usage("tenant-a").await.is_none());

        let current_lock = cache.disk_refresh_lock("tenant-a").await;
        assert!(
            cache
                .store_disk_usage_if_current_lock(
                    "tenant-a",
                    &current_lock,
                    CachedDiskUsage {
                        used_bytes: 7,
                        sampled_at: Instant::now(),
                    },
                )
                .await
        );
        assert_eq!(
            cache
                .cached_disk_usage("tenant-a")
                .await
                .map(|sample| sample.used_bytes),
            Some(7)
        );
    }
}
