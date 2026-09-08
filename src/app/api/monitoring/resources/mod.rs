use std::{
    collections::HashMap,
    io::{Error as IoError, ErrorKind},
    path::{Path as FsPath, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::extract::State;
use bollard::models::ContainerStatsResponse;
use serde::Serialize;
use tokio::{
    sync::{Mutex, Semaphore},
    time::{Instant, MissedTickBehavior},
};

use crate::{
    api::http::{
        policy::ApiRequestContext,
        response::{ApiError, ApiPath, ApiResponse, ApiResult},
        router::AppState,
    },
    auth::scopes,
    config::Config,
    disk::{DiskLimiter, soft::SoftDiskTarget},
    instances::{
        metadata::{InstanceMetadata, InstanceStatus},
        paths::InstancePaths,
    },
    monitoring::ActivityStore,
    placement::DeploymentMode,
    shared::{limits::mib_to_bytes, protocol::Protocol},
    storage::activity::ActivityRepository,
};

use futures::{StreamExt, TryStreamExt};

mod runtime_metrics;

mod activity;

mod network;

mod sampler;

mod pools;

mod shared_disk;

use runtime_metrics::{
    container_cpu_total, cpu_percent_over_wall_time, docker_compatible_memory_usage,
};
use sampler::{CachedHostCpuUsage, HostCpuSample};
#[cfg(test)]
use sampler::{SharedRuntimeUsage, aggregate_managed_usage, summarize_allocations};
pub(crate) use sampler::{read_host_cpu_cores, read_host_disk, read_host_memory};

pub(crate) use network::NetworkCounter;
pub(crate) use pools::{
    SharedPoolReport, get_shared_pool, list_pool_tenants, list_shared_pools, pool_reports,
};

const RUNTIME_STATS_STALE_AFTER: Duration = Duration::from_secs(3);
const RUNTIME_STATS_POLL_INTERVAL: Duration = Duration::from_secs(1);
const DISK_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const INITIAL_DISK_SCAN_TIMEOUT: Duration = Duration::from_millis(750);
const BACKGROUND_DISK_SCAN_TIMEOUT: Duration = Duration::from_secs(30);
const RESOURCE_FANOUT_LIMIT: usize = 16;
const DISK_SCAN_CONCURRENCY: usize = 4;

#[derive(Debug, Clone)]
pub struct ResourceCache {
    inner: Arc<Mutex<ResourceCacheInner>>,
    activity: ActivityStore,
    activity_repository: Option<ActivityRepository>,
    active_monitors: Arc<AtomicUsize>,
    disk_scan_permits: Arc<Semaphore>,
}

impl Default for ResourceCache {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ResourceCacheInner::default())),
            activity: ActivityStore::default(),
            activity_repository: None,
            active_monitors: Arc::new(AtomicUsize::new(0)),
            disk_scan_permits: Arc::new(Semaphore::new(DISK_SCAN_CONCURRENCY)),
        }
    }
}

#[derive(Debug, Default)]
struct ResourceCacheInner {
    stats: HashMap<String, CachedRuntimeStats>,
    runtime_stats_workers: HashMap<String, u64>,
    next_runtime_stats_worker: u64,
    network: HashMap<String, NetworkCounter>,
    disk: HashMap<String, CachedDiskUsage>,
    disk_refreshing: HashMap<String, bool>,
    disk_refresh_locks: HashMap<String, Arc<Mutex<()>>>,
    host_cpu_sample: Option<HostCpuSample>,
    host_cpu_usage: Option<CachedHostCpuUsage>,
}

#[derive(Debug, Clone)]
struct CachedRuntimeStats {
    cpu_usage_percent: Option<f64>,
    memory_usage_bytes: Option<u64>,
    sampled_at: Instant,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CachedDiskUsage {
    pub used_bytes: u64,
    sampled_at: Instant,
}

#[derive(Debug, Serialize)]
pub struct ResourceReport {
    pub instance_id: String,
    pub runtime_id: String,
    pub deployment_mode: DeploymentMode,
    pub scope: ResourceScope,
    pub protocol: String,
    pub status: String,
    pub cpu: CpuReport,
    pub memory: MemoryReport,
    pub disk: DiskReport,
    pub network: NetworkReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool: Option<PoolUsageReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResourceView {
    Tenant,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceScope {
    DedicatedInstance,
    SharedTenant,
}

#[derive(Debug, Serialize)]
pub struct PoolUsageReport {
    pub runtime_id: String,
    /// Cgroup CPU capacity configured for the complete shared engine.
    pub cpu_limit_cores: f64,
    pub cpu_usage_percent: Option<f64>,
    /// Cgroup memory capacity configured for the complete shared engine.
    pub memory_limit_bytes: u64,
    pub memory_usage_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct CpuReport {
    pub configured_cores: f64,
    pub usage_percent: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct MemoryReport {
    pub configured_mib: u64,
    pub usage_bytes: Option<u64>,
    pub limit_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct DiskReport {
    pub configured_mib: u64,
    pub limit_bytes: u64,
    pub used_bytes: u64,
    pub enforced: bool,
    pub enforcement_method: String,
    /// `hard` means writes are rejected by a filesystem quota; `soft` means
    /// bounded predictive scanning with stop/kill enforcement.
    pub enforcement_strength: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_logical_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_physical_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_growth_bytes_per_second: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_peak_growth_bytes_per_second: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_predicted_seconds_to_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_stop_threshold_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_recovery_threshold_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_restart_blocked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_sample_age_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct NetworkReport {
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct NodeResourceSummary {
    pub node_uuid: String,
    pub sampled_at: String,
    pub cpu: NodeCpuSummary,
    pub memory: NodeMemorySummary,
    pub disk: NodeDiskSummary,
    pub instances: NodeInstanceSummary,
}

#[derive(Debug, Serialize)]
pub struct NodeCpuSummary {
    pub total_cores: u64,
    pub allocated_cores: f64,
    pub host_usage_percent: f64,
    pub managed_usage_cores: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct NodeMemorySummary {
    pub total_bytes: u64,
    pub allocation_limit_bytes: u64,
    pub reserved_bytes: u64,
    pub allocated_bytes: u64,
    pub host_used_bytes: u64,
    pub managed_used_bytes: Option<u64>,
    pub available_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct NodeDiskSummary {
    pub total_bytes: u64,
    pub allocation_limit_bytes: u64,
    pub reserved_bytes: u64,
    pub allocated_bytes: u64,
    pub host_used_bytes: u64,
    pub managed_used_bytes: Option<u64>,
    pub available_bytes: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct NodeInstanceSummary {
    pub total: u64,
    pub creating: u64,
    pub booting: u64,
    pub running: u64,
    pub stopped: u64,
    pub failed: u64,
    pub quarantined: u64,
    pub deleting: u64,
}

pub async fn list_resources(
    State(state): State<AppState>,
    auth: ApiRequestContext,
) -> ApiResult<Vec<ResourceReport>> {
    auth.require_scope(scopes::RESOURCES_ADMIN)?;
    let reports = futures::stream::iter(state.instances.list().await)
        .map(|metadata| {
            let state = state.clone();
            async move { resource_report(&state, &metadata, ResourceView::Admin).await }
        })
        .buffer_unordered(RESOURCE_FANOUT_LIMIT)
        .try_collect()
        .await?;
    Ok(ApiResponse::ok(reports))
}

pub async fn node_resource_summary(
    State(state): State<AppState>,
    auth: ApiRequestContext,
) -> ApiResult<NodeResourceSummary> {
    auth.require_scope(scopes::RESOURCES_ADMIN)?;
    let instances = state.instances.list().await;
    let runtimes = state.placements.list().await.map_err(|error| {
        ApiError::Runtime(format!("failed to load runtime allocation: {error}"))
    })?;
    let allocations = sampler::summarize_allocations(&instances, &runtimes);
    let resource_reports = futures::stream::iter(instances.iter().cloned())
        .map(|metadata| {
            let state = state.clone();
            async move {
                (
                    metadata.deployment_mode,
                    resource_report(&state, &metadata, ResourceView::Tenant).await,
                )
            }
        })
        .buffer_unordered(RESOURCE_FANOUT_LIMIT)
        .collect::<Vec<_>>();
    let shared_runtime_usage = sampler::sample_shared_runtime_usage(&state, &runtimes, &instances);
    let volumes_root = state.config.paths.volumes_root();
    let (host_cpu, host_memory, host_disk, resource_reports, shared_runtime_usage) = tokio::join!(
        state.resource_cache.host_cpu_usage(),
        read_host_memory(),
        read_host_disk(&volumes_root),
        resource_reports,
        shared_runtime_usage,
    );
    let host_cpu = host_cpu
        .map_err(|error| ApiError::Runtime(format!("failed to sample host CPU: {error}")))?;
    let host_memory = host_memory
        .map_err(|error| ApiError::Runtime(format!("failed to sample host memory: {error}")))?;
    let host_disk = host_disk
        .map_err(|error| ApiError::Runtime(format!("failed to sample host disk: {error}")))?;
    let managed = sampler::aggregate_managed_usage(&resource_reports, &shared_runtime_usage);

    Ok(ApiResponse::ok(NodeResourceSummary {
        node_uuid: state.config.uuid.clone(),
        sampled_at: crate::shared::time::now_rfc3339(),
        cpu: NodeCpuSummary {
            total_cores: host_cpu.cores,
            allocated_cores: allocations.allocated_cpu_cores,
            host_usage_percent: host_cpu.usage_percent,
            managed_usage_cores: managed.cpu_usage_cores,
        },
        memory: NodeMemorySummary {
            total_bytes: host_memory.total_bytes,
            allocation_limit_bytes: state
                .config
                .allocation
                .memory_allocation_cap_bytes(host_memory.total_bytes),
            reserved_bytes: state.config.allocation.reserved_memory_bytes(),
            allocated_bytes: allocations.allocated_memory_bytes,
            host_used_bytes: host_memory.used_bytes,
            managed_used_bytes: managed.memory_used_bytes,
            available_bytes: host_memory.available_bytes,
        },
        disk: NodeDiskSummary {
            total_bytes: host_disk.total_bytes,
            allocation_limit_bytes: state
                .config
                .allocation
                .disk_allocation_cap_bytes(host_disk.total_bytes),
            reserved_bytes: state.config.allocation.reserved_disk_bytes(),
            allocated_bytes: allocations.allocated_disk_bytes,
            host_used_bytes: host_disk.used_bytes,
            managed_used_bytes: managed.disk_used_bytes,
            available_bytes: host_disk.available_bytes,
        },
        instances: allocations.instances,
    }))
}

pub async fn instance_resources(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
) -> ApiResult<ResourceReport> {
    auth.require_scope(scopes::RESOURCES_READ)?;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    Ok(ApiResponse::ok(
        resource_report(&state, &metadata, ResourceView::Tenant).await?,
    ))
}

pub(crate) async fn resource_report(
    state: &AppState,
    metadata: &InstanceMetadata,
    view: ResourceView,
) -> Result<ResourceReport, ApiError> {
    let runtime_id = metadata.runtime_id();
    let shared = metadata.deployment_mode == DeploymentMode::Shared;
    let pool_capacity = if view == ResourceView::Admin {
        pools::load_pool_capacity(state, metadata).await?
    } else {
        None
    };
    let stats = state.resource_cache.runtime_stats(runtime_id).await;
    let (network_rx_bytes, network_tx_bytes) = state
        .resource_cache
        .network_usage(&metadata.instance_id)
        .await;
    let soft_enforcement = metadata.limits.disk_enforcement_method == "soft_scanner";
    let shared_soft_guard =
        shared_disk::uses_soft_guard(metadata.deployment_mode, metadata.limits.disk_enforced);
    let legacy_qdrant_safety_monitor = metadata.protocol == Protocol::Qdrant
        && metadata.limits.disk_enforcement_method == "fuse_quota";
    let scanner_active = !shared && (soft_enforcement || legacy_qdrant_safety_monitor);
    let (scanner, disk_used) = if shared {
        let used = shared_disk::usage(state, metadata)
            .await
            .map_err(|error| ApiError::Runtime(format!("failed to measure disk usage: {error}")))?;
        (None, used)
    } else {
        let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
            .map_err(|error| ApiError::BadRequest(error.to_string()))?;
        let scanner_target = SoftDiskTarget {
            instance_id: metadata.instance_id.clone(),
            created_at: metadata.created_at.clone(),
            protocol: metadata.protocol,
            data_path: paths.data.clone(),
            limit_bytes: mib_to_bytes(metadata.limits.disk_mib),
            durable_blocked: metadata.disk_limit_blocked,
        };
        let scanner = if scanner_active {
            state.soft_disk_limiter.snapshot(&scanner_target).await
        } else {
            None
        };
        let used = shared_disk::reported_disk_used_bytes(scanner.as_ref(), || async {
            state
                .resource_cache
                .disk_usage(&state.config, &metadata.instance_id, paths.data)
                .await
                .map(|sample| sample.used_bytes)
        })
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to measure disk usage: {error}")))?;
        (scanner, used)
    };
    let usage = pools::runtime_report_usage(
        metadata.deployment_mode,
        runtime_id,
        metadata.limits.memory_mib,
        stats.as_ref(),
        pool_capacity,
        view,
    )?;
    let report = ResourceReport {
        instance_id: metadata.instance_id.clone(),
        runtime_id: runtime_id.to_string(),
        deployment_mode: metadata.deployment_mode,
        scope: if shared {
            ResourceScope::SharedTenant
        } else {
            ResourceScope::DedicatedInstance
        },
        protocol: metadata.protocol.to_string(),
        status: metadata.status.as_str().to_string(),
        cpu: CpuReport {
            configured_cores: metadata.limits.cpu_cores,
            usage_percent: usage.cpu_usage_percent,
        },
        memory: MemoryReport {
            configured_mib: metadata.limits.memory_mib,
            usage_bytes: usage.memory_usage_bytes,
            limit_bytes: usage.memory_limit_bytes,
        },
        disk: DiskReport {
            configured_mib: metadata.limits.disk_mib,
            limit_bytes: mib_to_bytes(metadata.limits.disk_mib),
            used_bytes: disk_used,
            enforced: metadata.limits.disk_enforced,
            enforcement_method: metadata.limits.disk_enforcement_method.clone(),
            enforcement_strength: disk_enforcement_strength(
                metadata.limits.disk_enforced,
                shared_soft_guard || soft_enforcement,
            ),
            scanner_logical_bytes: scanner.as_ref().map(|sample| sample.usage.logical_bytes),
            scanner_physical_bytes: scanner.as_ref().map(|sample| sample.usage.physical_bytes),
            scanner_growth_bytes_per_second: scanner
                .as_ref()
                .map(|sample| sample.growth_bytes_per_second),
            scanner_peak_growth_bytes_per_second: scanner
                .as_ref()
                .map(|sample| sample.peak_growth_bytes_per_second),
            scanner_predicted_seconds_to_limit: scanner
                .as_ref()
                .and_then(|sample| sample.predicted_seconds_to_limit),
            scanner_stop_threshold_bytes: scanner
                .as_ref()
                .map(|sample| sample.stop_threshold_bytes),
            scanner_recovery_threshold_bytes: scanner
                .as_ref()
                .map(|sample| sample.recovery_threshold_bytes),
            scanner_restart_blocked: (scanner_active || shared_soft_guard).then(|| {
                metadata.disk_limit_blocked || scanner.as_ref().is_some_and(|sample| sample.blocked)
            }),
            scanner_sample_age_seconds: scanner
                .as_ref()
                .map(|sample| sample.sampled_at.elapsed().as_secs()),
        },
        network: NetworkReport {
            // Database containers have no network namespace attachment. Their
            // traffic crosses DBE's authenticated host gateways and Unix
            // sockets, so Docker's optional `networks` stats are not the source
            // of truth. These counters are updated directly by the gateway.
            rx_bytes: Some(network_rx_bytes),
            tx_bytes: Some(network_tx_bytes),
        },
        pool: usage.pool,
    };

    Ok(report)
}

const fn disk_enforcement_strength(hard: bool, soft: bool) -> &'static str {
    if hard {
        "hard"
    } else if soft {
        "soft"
    } else {
        "none"
    }
}

impl ResourceCache {
    /// Invalidates samples tied to a physical runtime generation while keeping
    /// the logical tenant's network/activity counters alive. Existing gateway
    /// sessions may still hold those counters during reconcile or cutover.
    pub async fn invalidate_runtime(&self, instance_id: &str) {
        let mut inner = self.inner.lock().await;
        inner.stats.remove(instance_id);
        inner.runtime_stats_workers.remove(instance_id);
        invalidate_disk_locked(&mut inner, instance_id);
    }

    /// Removes a logical metric identity after its route is fenced, sessions
    /// are drained, and durable instance metadata has been deleted.
    pub async fn remove_tenant(&self, instance_id: &str) {
        let mut inner = self.inner.lock().await;
        inner.stats.remove(instance_id);
        inner.runtime_stats_workers.remove(instance_id);
        inner.network.remove(instance_id);
        invalidate_disk_locked(&mut inner, instance_id);
        drop(inner);
        self.activity.remove(instance_id);
    }

    /// Invalidates only storage telemetry. Shared-tenant operations use this
    /// for their physical pool so one tenant resize cannot tear down the
    /// pool's live CPU/memory sampler or reset unrelated network counters.
    pub(crate) async fn invalidate_disk(&self, instance_id: &str) {
        let mut inner = self.inner.lock().await;
        invalidate_disk_locked(&mut inner, instance_id);
    }

    pub(crate) async fn disk_usage(
        &self,
        config: &Config,
        instance_id: &str,
        path: PathBuf,
    ) -> Result<CachedDiskUsage, String> {
        // The Arc is also the cache generation. Deletion, migration, and
        // recreation remove it, so a late scan from the old identity cannot
        // repopulate the cache for the replacement.
        let refresh_lock = self.disk_refresh_lock(instance_id).await;
        if let Some(sample) = self
            .cached_disk_usage_for_lock(instance_id, &refresh_lock)
            .await
            && sample.sampled_at.elapsed() < DISK_REFRESH_INTERVAL
        {
            return Ok(sample);
        }

        if let Some(sample) = self.quota_disk_usage(config, instance_id, &path).await {
            if self
                .store_disk_usage_if_current_lock(instance_id, &refresh_lock, sample)
                .await
            {
                return Ok(sample);
            }
            return Err("disk usage cache was invalidated during sampling".to_string());
        }

        if let Some(sample) = self
            .cached_disk_usage_for_lock(instance_id, &refresh_lock)
            .await
        {
            if sample.sampled_at.elapsed() < DISK_REFRESH_INTERVAL {
                return Ok(sample);
            }
            self.queue_disk_refresh(
                Arc::new(config.clone()),
                instance_id.to_string(),
                path,
                refresh_lock,
            )
            .await;
            return Ok(sample);
        }

        let _refresh = refresh_lock.lock().await;
        if let Some(sample) = self
            .cached_disk_usage_for_lock(instance_id, &refresh_lock)
            .await
        {
            return Ok(sample);
        }
        if self.disk_refresh_in_progress(instance_id).await {
            return Err("disk usage scan is still in progress".to_string());
        }
        if let Some(sample) = self.quota_disk_usage(config, instance_id, &path).await {
            if self
                .store_disk_usage_if_current_lock(instance_id, &refresh_lock, sample)
                .await
            {
                return Ok(sample);
            }
            return Err("disk usage cache was invalidated during sampling".to_string());
        }

        match self
            .scan_directory(path.clone(), INITIAL_DISK_SCAN_TIMEOUT)
            .await
        {
            Ok(used_bytes) => {
                let sample = CachedDiskUsage {
                    used_bytes,
                    sampled_at: Instant::now(),
                };
                if !self
                    .store_disk_usage_if_current_lock(instance_id, &refresh_lock, sample)
                    .await
                {
                    return Err("disk usage cache was invalidated during sampling".to_string());
                }
                Ok(sample)
            }
            Err(error) if error.kind() == ErrorKind::TimedOut => {
                self.queue_disk_refresh(
                    Arc::new(config.clone()),
                    instance_id.to_string(),
                    path,
                    refresh_lock.clone(),
                )
                .await;
                Err("disk usage scan is still in progress".to_string())
            }
            Err(error) => Err(error.to_string()),
        }
    }

    pub(crate) fn register_monitor(&self) -> ResourceMonitorGuard {
        self.active_monitors.fetch_add(1, Ordering::Relaxed);
        ResourceMonitorGuard {
            active_monitors: self.active_monitors.clone(),
        }
    }

    fn has_active_monitors(&self) -> bool {
        self.active_monitors.load(Ordering::Relaxed) > 0
    }

    pub(crate) async fn network_counter(&self, instance_id: &str) -> NetworkCounter {
        let mut inner = self.inner.lock().await;
        inner
            .network
            .entry(instance_id.to_string())
            .or_default()
            .clone()
    }

    pub(crate) async fn network_usage(&self, instance_id: &str) -> (u64, u64) {
        let inner = self.inner.lock().await;
        inner
            .network
            .get(instance_id)
            .map(NetworkCounter::snapshot)
            .unwrap_or_default()
    }

    async fn begin_runtime_stats_worker(&self, runtime_id: &str) -> u64 {
        let mut inner = self.inner.lock().await;
        inner.next_runtime_stats_worker = inner.next_runtime_stats_worker.wrapping_add(1).max(1);
        let worker = inner.next_runtime_stats_worker;
        inner
            .runtime_stats_workers
            .insert(runtime_id.to_string(), worker);
        worker
    }

    async fn store_runtime_stats(
        &self,
        runtime_id: &str,
        worker: u64,
        cpu_usage_percent: Option<f64>,
        stats: &ContainerStatsResponse,
    ) -> bool {
        let sample = CachedRuntimeStats {
            cpu_usage_percent,
            memory_usage_bytes: docker_compatible_memory_usage(stats),
            sampled_at: Instant::now(),
        };
        let mut inner = self.inner.lock().await;
        if inner.runtime_stats_workers.get(runtime_id) != Some(&worker) {
            return false;
        }
        inner.stats.insert(runtime_id.to_string(), sample);
        true
    }

    async fn finish_stats_worker(&self, runtime_id: &str, worker: u64) {
        let mut inner = self.inner.lock().await;
        if inner.runtime_stats_workers.get(runtime_id) == Some(&worker) {
            inner.runtime_stats_workers.remove(runtime_id);
        }
    }

    async fn clear_runtime_stats(&self, runtime_id: &str) {
        let mut inner = self.inner.lock().await;
        inner.runtime_stats_workers.remove(runtime_id);
        inner.stats.remove(runtime_id);
    }

    /// Measure managed database bytes for a capacity-sensitive operation.
    ///
    /// Dashboard samples may be up to `DISK_REFRESH_INTERVAL` old, which is
    /// desirable for polling but can substantially overstate a database that
    /// was just truncated or restored. Export admission must not reserve from
    /// that stale value, so this path always asks the active quota runtime or
    /// performs a bounded fresh directory scan before returning.
    pub(crate) async fn fresh_disk_usage(
        &self,
        config: &Config,
        instance_id: &str,
        path: PathBuf,
    ) -> Result<CachedDiskUsage, String> {
        let refresh_lock = self.disk_refresh_lock(instance_id).await;
        let _refresh = refresh_lock.lock().await;
        if let Some(sample) = self.quota_disk_usage(config, instance_id, &path).await {
            if self
                .store_disk_usage_if_current_lock(instance_id, &refresh_lock, sample)
                .await
            {
                return Ok(sample);
            }
            return Err("disk usage cache was invalidated during sampling".to_string());
        }
        let used_bytes = self
            .scan_directory(path, BACKGROUND_DISK_SCAN_TIMEOUT)
            .await
            .map_err(|error| error.to_string())?;
        let sample = CachedDiskUsage {
            used_bytes,
            sampled_at: Instant::now(),
        };
        if !self
            .store_disk_usage_if_current_lock(instance_id, &refresh_lock, sample)
            .await
        {
            return Err("disk usage cache was invalidated during sampling".to_string());
        }
        Ok(sample)
    }

    async fn quota_disk_usage(
        &self,
        config: &Config,
        instance_id: &str,
        path: &FsPath,
    ) -> Option<CachedDiskUsage> {
        let disk_limiter =
            DiskLimiter::with_fuse_root(config.disk.clone(), config.paths.fuse_root());
        match disk_limiter.instance_usage_bytes(path).await {
            Ok(Some(used_bytes)) => Some(CachedDiskUsage {
                used_bytes,
                sampled_at: Instant::now(),
            }),
            Ok(None) => None,
            Err(error) => {
                tracing::debug!(
                    %instance_id,
                    %error,
                    "quota disk usage unavailable; falling back to cached directory usage"
                );
                None
            }
        }
    }

    async fn cached_disk_usage(&self, instance_id: &str) -> Option<CachedDiskUsage> {
        let inner = self.inner.lock().await;
        inner.disk.get(instance_id).copied()
    }

    async fn cached_disk_usage_for_lock(
        &self,
        instance_id: &str,
        refresh_lock: &Arc<Mutex<()>>,
    ) -> Option<CachedDiskUsage> {
        let inner = self.inner.lock().await;
        inner
            .disk_refresh_locks
            .get(instance_id)
            .is_some_and(|current| Arc::ptr_eq(current, refresh_lock))
            .then(|| inner.disk.get(instance_id).copied())
            .flatten()
    }

    async fn store_disk_usage_if_current_lock(
        &self,
        instance_id: &str,
        refresh_lock: &Arc<Mutex<()>>,
        sample: CachedDiskUsage,
    ) -> bool {
        let mut inner = self.inner.lock().await;
        if !inner
            .disk_refresh_locks
            .get(instance_id)
            .is_some_and(|current| Arc::ptr_eq(current, refresh_lock))
        {
            return false;
        }
        inner.disk.insert(instance_id.to_string(), sample);
        true
    }

    async fn disk_refresh_lock(&self, instance_id: &str) -> Arc<Mutex<()>> {
        let mut inner = self.inner.lock().await;
        inner
            .disk_refresh_locks
            .entry(instance_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    async fn store_disk_usage(&self, instance_id: String, sample: CachedDiskUsage) {
        let mut inner = self.inner.lock().await;
        inner.disk.insert(instance_id, sample);
    }

    async fn disk_refresh_in_progress(&self, instance_id: &str) -> bool {
        self.inner
            .lock()
            .await
            .disk_refreshing
            .get(instance_id)
            .copied()
            .unwrap_or(false)
    }

    async fn scan_directory(&self, path: PathBuf, budget: Duration) -> Result<u64, std::io::Error> {
        let _permit = self
            .disk_scan_permits
            .acquire()
            .await
            .map_err(|_| IoError::other("disk scan limiter closed"))?;
        crate::disk::usage::scan_directory(
            path,
            crate::disk::usage::ScanLimits {
                timeout: budget,
                ..Default::default()
            },
        )
        .await
        .map(|usage| usage.logical_bytes)
    }

    async fn begin_disk_refresh(&self, instance_id: &str, refresh_lock: &Arc<Mutex<()>>) -> bool {
        let mut inner = self.inner.lock().await;
        if !inner
            .disk_refresh_locks
            .get(instance_id)
            .is_some_and(|current| Arc::ptr_eq(current, refresh_lock))
            || inner
                .disk_refreshing
                .get(instance_id)
                .copied()
                .unwrap_or(false)
        {
            return false;
        }
        inner.disk_refreshing.insert(instance_id.to_string(), true);
        true
    }

    async fn finish_disk_refresh(
        &self,
        instance_id: String,
        refresh_lock: &Arc<Mutex<()>>,
        result: Result<u64, std::io::Error>,
    ) -> Option<(String, std::io::Error)> {
        let mut inner = self.inner.lock().await;
        if !inner
            .disk_refresh_locks
            .get(&instance_id)
            .is_some_and(|current| Arc::ptr_eq(current, refresh_lock))
        {
            return None;
        }
        inner.disk_refreshing.remove(&instance_id);
        match result {
            Ok(used_bytes) => {
                inner.disk.insert(
                    instance_id,
                    CachedDiskUsage {
                        used_bytes,
                        sampled_at: Instant::now(),
                    },
                );
                None
            }
            Err(error) => Some((instance_id, error)),
        }
    }

    async fn queue_disk_refresh(
        &self,
        config: Arc<Config>,
        instance_id: String,
        path: PathBuf,
        refresh_lock: Arc<Mutex<()>>,
    ) {
        if !self.begin_disk_refresh(&instance_id, &refresh_lock).await {
            return;
        }

        let cache = self.clone();
        tokio::spawn(async move {
            let result =
                match DiskLimiter::with_fuse_root(config.disk.clone(), config.paths.fuse_root())
                    .instance_usage_bytes(&path)
                    .await
                {
                    Ok(Some(used_bytes)) => Ok(used_bytes),
                    Ok(None) => {
                        cache
                            .scan_directory(path, BACKGROUND_DISK_SCAN_TIMEOUT)
                            .await
                    }
                    Err(error) => {
                        tracing::debug!(
                            %instance_id,
                            %error,
                            "quota disk usage unavailable during background refresh"
                        );
                        cache
                            .scan_directory(path, BACKGROUND_DISK_SCAN_TIMEOUT)
                            .await
                    }
                };
            if let Some((instance_id, error)) = cache
                .finish_disk_refresh(instance_id, &refresh_lock, result)
                .await
            {
                tracing::warn!(
                    %instance_id,
                    %error,
                    "failed to refresh resource disk usage"
                );
            }
        });
    }

    pub async fn refresh_all_disk_usage(&self, state: &AppState) {
        let instances = state.instances.list().await;
        // Shared tenants have protocol-aware per-tenant sampling in
        // `shared_disk`. Walking a shared runtime root here duplicates that
        // work, cannot be attributed to a tenant, and turns one active monitor
        // into a full-pool scan every five seconds.
        let instance_ids = disk_sample_instance_ids(instances);
        futures::stream::iter(instance_ids)
            .map(|instance_id| {
                let cache = self.clone();
                let config = state.config.clone();
                async move {
                    let paths = match InstancePaths::new(&config.paths, &instance_id) {
                        Ok(paths) => paths,
                        Err(error) => {
                            tracing::debug!(
                                %instance_id,
                                %error,
                                "skipping resource disk sample for invalid instance path"
                            );
                            return;
                        }
                    };
                    cache
                        .refresh_disk_usage_now(config, instance_id, paths.data)
                        .await;
                }
            })
            .buffer_unordered(RESOURCE_FANOUT_LIMIT)
            .collect::<Vec<_>>()
            .await;
    }

    async fn refresh_disk_usage_now(
        &self,
        config: Arc<Config>,
        instance_id: String,
        path: PathBuf,
    ) {
        let refresh_lock = self.disk_refresh_lock(&instance_id).await;
        if !self.begin_disk_refresh(&instance_id, &refresh_lock).await {
            return;
        }

        let result =
            match DiskLimiter::with_fuse_root(config.disk.clone(), config.paths.fuse_root())
                .instance_usage_bytes(&path)
                .await
            {
                Ok(Some(used_bytes)) => Ok(used_bytes),
                Ok(None) => {
                    self.scan_directory(path, BACKGROUND_DISK_SCAN_TIMEOUT)
                        .await
                }
                Err(error) => {
                    tracing::debug!(
                        %instance_id,
                        %error,
                        "quota disk usage unavailable during sampler refresh"
                    );
                    self.scan_directory(path, BACKGROUND_DISK_SCAN_TIMEOUT)
                        .await
                }
            };

        if let Some((instance_id, error)) = self
            .finish_disk_refresh(instance_id, &refresh_lock, result)
            .await
        {
            tracing::warn!(
                %instance_id,
                %error,
                "failed to refresh sampled disk usage"
            );
        }
    }
}

fn invalidate_disk_locked(inner: &mut ResourceCacheInner, instance_id: &str) {
    inner.disk.remove(instance_id);
    inner.disk_refreshing.remove(instance_id);
    // Removing the Arc advances the sampling generation. Any in-flight scan
    // still holding the previous Arc will fail its identity check before it
    // can publish a result.
    inner.disk_refresh_locks.remove(instance_id);
}

fn disk_sample_instance_ids(instances: Vec<InstanceMetadata>) -> std::collections::HashSet<String> {
    instances
        .into_iter()
        .filter(|metadata| {
            metadata.deployment_mode == DeploymentMode::Dedicated
                && metadata.status == InstanceStatus::Running
        })
        .map(|metadata| metadata.instance_id)
        .collect()
}

pub fn start_resource_sampler(state: AppState) {
    sampler::start(state.clone());
    shared_disk::start(state.clone());
    activity::start(state.clone());
    crate::monitoring::start_engine_activity_sampler(state.clone());
    start_disk_usage_sampler(state);
}

pub(crate) async fn prime_shared_disk_quotas(state: &AppState) -> usize {
    shared_disk::prime(state).await
}

fn start_disk_usage_sampler(state: AppState) {
    let mut shutdown = state.gateway_supervisor.subscribe_shutdown();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(DISK_REFRESH_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        tracing::info!("resource disk sampler stopped");
                        break;
                    }
                }
                _ = ticker.tick() => {
                    if state.resource_cache.has_active_monitors() {
                        state.resource_cache.refresh_all_disk_usage(&state).await;
                    }
                }
            }
        }
    });
}

pub(crate) struct ResourceMonitorGuard {
    active_monitors: Arc<AtomicUsize>,
}

impl Drop for ResourceMonitorGuard {
    fn drop(&mut self) {
        self.active_monitors.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod disk_scan_tests;

#[cfg(test)]
mod node_summary_tests;
