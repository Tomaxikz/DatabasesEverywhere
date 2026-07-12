use std::{
    collections::HashMap,
    io::{Error as IoError, ErrorKind},
    path::{Path as FsPath, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::extract::State;
use serde::Serialize;
use serde_json::Value;
use tokio::{sync::Mutex, time::Instant};

use crate::{
    api::{
        api_response::{ApiError, ApiPath, ApiResponse, ApiResult},
        routes::AppState,
        security_policy::ApiRequestContext,
    },
    auth::scopes,
    config::Config,
    disk::DiskLimiter,
    instances::{
        metadata::{InstanceMetadata, InstanceStatus},
        paths::InstancePaths,
    },
    runtime::docker::DockerRuntime,
    shared::protocol::Protocol,
};

use futures::{StreamExt, TryStreamExt};

const STATS_REFRESH_INTERVAL: Duration = Duration::from_millis(400);
const DISK_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const INITIAL_DISK_SCAN_TIMEOUT: Duration = Duration::from_millis(750);
const BACKGROUND_DISK_SCAN_TIMEOUT: Duration = Duration::from_secs(30);
const DISK_SCAN_MAX_ENTRIES: usize = 1_000_000;
const DISK_SCAN_MAX_DEPTH: usize = 128;
const RESOURCE_FANOUT_LIMIT: usize = 16;

#[derive(Debug, Clone, Default)]
pub struct ResourceCache {
    inner: Arc<Mutex<ResourceCacheInner>>,
    active_monitors: Arc<AtomicUsize>,
}

#[derive(Debug, Default)]
struct ResourceCacheInner {
    stats: HashMap<String, CachedRuntimeStats>,
    stats_refresh_locks: HashMap<String, Arc<Mutex<()>>>,
    cpu_samples: HashMap<String, CpuStatsSample>,
    network: HashMap<String, NetworkCounter>,
    disk: HashMap<String, CachedDiskUsage>,
    disk_refreshing: HashMap<String, bool>,
    host_cpu_sample: Option<HostCpuSample>,
    host_cpu_usage: Option<CachedHostCpuUsage>,
}

#[derive(Debug, Clone)]
struct CachedRuntimeStats {
    stats: Value,
    cpu_usage_percent: Option<f64>,
    sampled_at: Instant,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct NetworkCounter {
    rx_bytes: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
}

impl NetworkCounter {
    pub(crate) fn add_rx(&self, bytes: u64) {
        atomic_saturating_add(&self.rx_bytes, bytes);
    }

    pub(crate) fn add_tx(&self, bytes: u64) {
        atomic_saturating_add(&self.tx_bytes, bytes);
    }

    pub(crate) fn snapshot(&self) -> (u64, u64) {
        (
            self.rx_bytes.load(Ordering::Relaxed),
            self.tx_bytes.load(Ordering::Relaxed),
        )
    }
}

fn atomic_saturating_add(counter: &AtomicU64, bytes: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(bytes))
    });
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CachedDiskUsage {
    pub used_bytes: u64,
    sampled_at: Instant,
}

#[derive(Debug, Serialize)]
pub struct ResourceReport {
    pub instance_id: String,
    pub protocol: String,
    pub status: String,
    pub cpu: CpuReport,
    pub memory: MemoryReport,
    pub disk: DiskReport,
    pub network: NetworkReport,
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

#[derive(Debug, Clone, Copy)]
struct HostCpuSample {
    total: u64,
    idle: u64,
    cores: u64,
}

#[derive(Debug, Clone, Copy)]
struct CachedHostCpuUsage {
    usage_percent: f64,
    cores: u64,
    sampled_at: Instant,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct HostMemorySample {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct HostDiskSample {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
}

pub async fn list_resources(
    State(state): State<AppState>,
    auth: ApiRequestContext,
) -> ApiResult<Vec<ResourceReport>> {
    auth.require_scope(scopes::RESOURCES_ADMIN)?;
    let reports = futures::stream::iter(state.instances.list().await)
        .map(|metadata| {
            let state = state.clone();
            async move { resource_report(&state, metadata).await }
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
    let resource_reports = futures::stream::iter(instances.iter().cloned())
        .map(|metadata| {
            let state = state.clone();
            async move { resource_report(&state, metadata).await }
        })
        .buffer_unordered(RESOURCE_FANOUT_LIMIT)
        .collect::<Vec<_>>();
    let volumes_root = state.config.paths.volumes_root();
    let (host_cpu, host_memory, host_disk, resource_reports) = tokio::join!(
        state.resource_cache.host_cpu_usage(),
        read_host_memory(),
        read_host_disk(&volumes_root),
        resource_reports,
    );
    let host_cpu = host_cpu
        .map_err(|error| ApiError::Runtime(format!("failed to sample host CPU: {error}")))?;
    let host_memory = host_memory
        .map_err(|error| ApiError::Runtime(format!("failed to sample host memory: {error}")))?;
    let host_disk = host_disk
        .map_err(|error| ApiError::Runtime(format!("failed to sample host disk: {error}")))?;
    let allocations = aggregate_allocations_and_statuses(&instances);
    let managed = aggregate_managed_usage(&resource_reports);

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
                .effective_memory_limit_bytes(host_memory.total_bytes),
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
                .effective_disk_limit_bytes(host_disk.total_bytes),
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
    Ok(ApiResponse::ok(resource_report(&state, metadata).await?))
}

pub(crate) async fn resource_report(
    state: &AppState,
    metadata: InstanceMetadata,
) -> Result<ResourceReport, ApiError> {
    let stats = state
        .resource_cache
        .runtime_stats(&state.docker, metadata.protocol, &metadata.instance_id)
        .await;
    let stats_value = stats.as_ref().map(|stats| &stats.stats);
    let (network_rx_bytes, network_tx_bytes) = state
        .resource_cache
        .network_usage(&metadata.instance_id)
        .await;
    let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let disk_used = state
        .resource_cache
        .disk_usage(&state.config, &metadata.instance_id, paths.data)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to measure disk usage: {error}")))?
        .used_bytes;

    let report = ResourceReport {
        instance_id: metadata.instance_id,
        protocol: metadata.protocol.to_string(),
        status: metadata.status.as_str().to_string(),
        cpu: CpuReport {
            configured_cores: metadata.limits.cpu_cores,
            usage_percent: stats
                .as_ref()
                .and_then(|stats| stats.cpu_usage_percent)
                .or_else(|| stats_value.and_then(cpu_percent)),
        },
        memory: MemoryReport {
            configured_mib: metadata.limits.memory_mib,
            usage_bytes: stats_value.and_then(memory_usage_bytes),
            limit_bytes: Some(mib_to_bytes(metadata.limits.memory_mib)),
        },
        disk: DiskReport {
            configured_mib: metadata.limits.disk_mib,
            limit_bytes: mib_to_bytes(metadata.limits.disk_mib),
            used_bytes: disk_used,
            enforced: metadata.limits.disk_enforced,
            enforcement_method: metadata.limits.disk_enforcement_method,
        },
        network: NetworkReport {
            // Database containers have no network namespace attachment. Their
            // traffic crosses DBE's authenticated host gateways and Unix
            // sockets, so Docker's optional `networks` stats are not the source
            // of truth. These counters are updated directly by the gateway.
            rx_bytes: Some(network_rx_bytes),
            tx_bytes: Some(network_tx_bytes),
        },
    };

    Ok(report)
}

#[derive(Debug)]
struct AllocationSummary {
    allocated_cpu_cores: f64,
    allocated_memory_bytes: u64,
    allocated_disk_bytes: u64,
    instances: NodeInstanceSummary,
}

#[derive(Debug)]
struct ManagedUsageSummary {
    cpu_usage_cores: Option<f64>,
    memory_used_bytes: Option<u64>,
    disk_used_bytes: Option<u64>,
}

fn aggregate_allocations_and_statuses(instances: &[InstanceMetadata]) -> AllocationSummary {
    let mut allocated_cpu_cores = 0.0;
    let mut allocated_memory_bytes = 0_u64;
    let mut allocated_disk_bytes = 0_u64;
    let mut counts = NodeInstanceSummary::default();

    for instance in instances {
        allocated_cpu_cores += instance.limits.cpu_cores;
        allocated_memory_bytes =
            allocated_memory_bytes.saturating_add(mib_to_bytes(instance.limits.memory_mib));
        allocated_disk_bytes =
            allocated_disk_bytes.saturating_add(mib_to_bytes(instance.limits.disk_mib));
        counts.total = counts.total.saturating_add(1);
        match instance.status {
            InstanceStatus::Creating => counts.creating = counts.creating.saturating_add(1),
            InstanceStatus::Booting => counts.booting = counts.booting.saturating_add(1),
            InstanceStatus::Running => counts.running = counts.running.saturating_add(1),
            InstanceStatus::Stopped => counts.stopped = counts.stopped.saturating_add(1),
            InstanceStatus::Failed => counts.failed = counts.failed.saturating_add(1),
            InstanceStatus::Quarantined => {
                counts.quarantined = counts.quarantined.saturating_add(1)
            }
            InstanceStatus::Deleting => counts.deleting = counts.deleting.saturating_add(1),
        }
    }

    AllocationSummary {
        allocated_cpu_cores,
        allocated_memory_bytes,
        allocated_disk_bytes,
        instances: counts,
    }
}

fn aggregate_managed_usage(reports: &[Result<ResourceReport, ApiError>]) -> ManagedUsageSummary {
    let mut cpu_usage_cores = 0.0;
    let mut memory_used_bytes = 0_u64;
    let mut disk_used_bytes = 0_u64;
    let mut cpu_complete = true;
    let mut memory_complete = true;
    let mut disk_complete = true;

    for report in reports {
        let Ok(report) = report else {
            cpu_complete = false;
            memory_complete = false;
            disk_complete = false;
            continue;
        };
        let expects_live_sample = matches!(report.status.as_str(), "running" | "booting");
        match report.cpu.usage_percent {
            Some(percent) => cpu_usage_cores += percent / 100.0,
            None if expects_live_sample => cpu_complete = false,
            None => {}
        }
        match report.memory.usage_bytes {
            Some(bytes) => memory_used_bytes = memory_used_bytes.saturating_add(bytes),
            None if expects_live_sample => memory_complete = false,
            None => {}
        }
        disk_used_bytes = disk_used_bytes.saturating_add(report.disk.used_bytes);
    }

    ManagedUsageSummary {
        cpu_usage_cores: cpu_complete.then_some(cpu_usage_cores),
        memory_used_bytes: memory_complete.then_some(memory_used_bytes),
        disk_used_bytes: disk_complete.then_some(disk_used_bytes),
    }
}

impl ResourceCache {
    async fn host_cpu_usage(&self) -> Result<CachedHostCpuUsage, std::io::Error> {
        {
            let inner = self.inner.lock().await;
            if let Some(cached) = inner
                .host_cpu_usage
                .filter(|cached| cached.sampled_at.elapsed() < STATS_REFRESH_INTERVAL)
            {
                return Ok(cached);
            }
        }

        let first = read_host_cpu().await?;
        if let Some(usage) = self.record_host_cpu_sample(first).await {
            return Ok(usage);
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
        let second = read_host_cpu().await?;
        self.record_host_cpu_sample(second).await.ok_or_else(|| {
            IoError::new(
                ErrorKind::InvalidData,
                "host CPU counters did not advance during sampling",
            )
        })
    }

    async fn record_host_cpu_sample(&self, current: HostCpuSample) -> Option<CachedHostCpuUsage> {
        let mut inner = self.inner.lock().await;
        let usage_percent = inner
            .host_cpu_sample
            .and_then(|previous| host_cpu_percent_between(previous, current));
        inner.host_cpu_sample = Some(current);
        let cached = usage_percent.map(|usage_percent| CachedHostCpuUsage {
            usage_percent,
            cores: current.cores,
            sampled_at: Instant::now(),
        });
        if let Some(cached) = cached {
            inner.host_cpu_usage = Some(cached);
        }
        cached
    }
}

async fn read_host_cpu() -> Result<HostCpuSample, std::io::Error> {
    let contents = tokio::fs::read_to_string("/proc/stat").await?;
    parse_host_cpu(&contents)
}

fn parse_host_cpu(contents: &str) -> Result<HostCpuSample, std::io::Error> {
    let aggregate = contents
        .lines()
        .find(|line| line.starts_with("cpu "))
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "missing aggregate CPU counters"))?;
    let values = aggregate
        .split_whitespace()
        .skip(1)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|error| IoError::new(ErrorKind::InvalidData, error))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.len() < 4 {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "aggregate CPU counters are incomplete",
        ));
    }
    // Linux user/nice counters already include guest time, so exclude the guest
    // fields and sum user through steal only to avoid counting them twice.
    let total = values
        .iter()
        .take(8)
        .try_fold(0_u64, |total, value| total.checked_add(*value))
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "CPU counters overflowed"))?;
    let idle = values[3]
        .checked_add(values.get(4).copied().unwrap_or_default())
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "CPU idle counters overflowed"))?;
    let cores = contents
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| {
            name.strip_prefix("cpu").is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
            })
        })
        .count() as u64;
    if cores == 0 {
        return Err(IoError::new(
            ErrorKind::InvalidData,
            "missing per-core CPU counters",
        ));
    }
    Ok(HostCpuSample { total, idle, cores })
}

fn host_cpu_percent_between(previous: HostCpuSample, current: HostCpuSample) -> Option<f64> {
    let total_delta = current.total.checked_sub(previous.total)?;
    let idle_delta = current.idle.checked_sub(previous.idle)?;
    if total_delta == 0 || idle_delta > total_delta {
        return None;
    }
    Some(((total_delta - idle_delta) as f64 / total_delta as f64) * 100.0)
}

pub(crate) async fn read_host_memory() -> Result<HostMemorySample, std::io::Error> {
    let contents = tokio::fs::read_to_string("/proc/meminfo").await?;
    parse_host_memory(&contents)
}

fn parse_host_memory(contents: &str) -> Result<HostMemorySample, std::io::Error> {
    let value_kib = |name: &str| -> Result<u64, std::io::Error> {
        let line = contents
            .lines()
            .find(|line| line.starts_with(name))
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, format!("missing {name}")))?;
        let mut fields = line.split_whitespace();
        let _ = fields.next();
        let value = fields
            .next()
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, format!("missing {name} value")))?
            .parse::<u64>()
            .map_err(|error| IoError::new(ErrorKind::InvalidData, error))?;
        match fields.next() {
            Some("kB") => value
                .checked_mul(1024)
                .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "memory value overflowed")),
            _ => Err(IoError::new(
                ErrorKind::InvalidData,
                format!("{name} is not reported in kB"),
            )),
        }
    };
    let total_bytes = value_kib("MemTotal:")?;
    let available_bytes = value_kib("MemAvailable:")?;
    let used_bytes = total_bytes.checked_sub(available_bytes).ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidData,
            "available memory exceeds total memory",
        )
    })?;
    Ok(HostMemorySample {
        total_bytes,
        used_bytes,
        available_bytes,
    })
}

pub(crate) async fn read_host_disk(path: &str) -> Result<HostDiskSample, std::io::Error> {
    let path = path.to_string();
    tokio::task::spawn_blocking(move || {
        let stats = rustix::fs::statvfs(path.as_str()).map_err(std::io::Error::from)?;
        host_disk_from_statvfs(&stats)
    })
    .await
    .map_err(std::io::Error::other)?
}

fn host_disk_from_statvfs(stats: &rustix::fs::StatVfs) -> Result<HostDiskSample, std::io::Error> {
    let block_size = if stats.f_frsize == 0 {
        stats.f_bsize
    } else {
        stats.f_frsize
    };
    let total_bytes = stats
        .f_blocks
        .checked_mul(block_size)
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "disk total overflowed"))?;
    let free_bytes = stats
        .f_bfree
        .checked_mul(block_size)
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "disk free space overflowed"))?;
    let available_bytes = stats
        .f_bavail
        .checked_mul(block_size)
        .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "disk available space overflowed"))?;
    let used_bytes = total_bytes.checked_sub(free_bytes).ok_or_else(|| {
        IoError::new(
            ErrorKind::InvalidData,
            "disk free space exceeds total space",
        )
    })?;
    Ok(HostDiskSample {
        total_bytes,
        used_bytes,
        available_bytes,
    })
}

async fn directory_size(path: PathBuf, budget: Duration) -> Result<u64, std::io::Error> {
    tokio::task::spawn_blocking(move || directory_size_blocking(&path, budget))
        .await
        .map_err(std::io::Error::other)?
}

impl ResourceCache {
    pub async fn remove(&self, instance_id: &str) {
        let mut inner = self.inner.lock().await;
        inner.stats.remove(instance_id);
        inner.stats_refresh_locks.remove(instance_id);
        inner.cpu_samples.remove(instance_id);
        inner.network.remove(instance_id);
        inner.disk.remove(instance_id);
        inner.disk_refreshing.remove(instance_id);
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

    async fn runtime_stats(
        &self,
        docker: &DockerRuntime,
        protocol: Protocol,
        instance_id: &str,
    ) -> Option<CachedRuntimeStats> {
        let cache_key = instance_id.to_string();
        if let Some(cached) = self.fresh_stats(&cache_key).await {
            return Some(cached);
        }

        // Multiple REST requests and monitoring sockets can ask for the same
        // container simultaneously. Serialize only that instance's refresh,
        // then recheck the cache so one Docker call feeds every consumer.
        let refresh_lock = {
            let mut inner = self.inner.lock().await;
            inner
                .stats_refresh_locks
                .entry(cache_key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let _refresh = refresh_lock.lock().await;
        if let Some(cached) = self.fresh_stats(&cache_key).await {
            return Some(cached);
        }

        let output = match docker.stats(protocol, instance_id).await {
            Ok(output) => output,
            Err(_) => {
                // Keep the last complete sample briefly during transient Docker
                // errors instead of making every waiting client retry at once.
                let mut inner = self.inner.lock().await;
                let stale = inner.stats.get_mut(&cache_key)?;
                stale.sampled_at = Instant::now();
                return Some(stale.clone());
            }
        };
        let stats = serde_json::from_str::<Value>(&output.stdout).ok()?;
        let cpu_usage_percent = self
            .record_cpu_sample(&cache_key, &stats)
            .await
            .or_else(|| cpu_percent(&stats));
        let cached = CachedRuntimeStats {
            stats,
            cpu_usage_percent,
            sampled_at: Instant::now(),
        };
        let mut inner = self.inner.lock().await;
        inner.stats.insert(cache_key, cached.clone());
        Some(cached)
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

    async fn fresh_stats(&self, instance_id: &str) -> Option<CachedRuntimeStats> {
        let inner = self.inner.lock().await;
        inner
            .stats
            .get(instance_id)
            .filter(|sample| sample.sampled_at.elapsed() < STATS_REFRESH_INTERVAL)
            .cloned()
    }

    async fn record_cpu_sample(&self, instance_id: &str, stats: &Value) -> Option<f64> {
        let current = current_cpu_sample(stats)?;
        let mut inner = self.inner.lock().await;
        let usage = inner
            .cpu_samples
            .get(instance_id)
            .copied()
            .and_then(|previous| cpu_percent_between(previous, current));
        inner.cpu_samples.insert(instance_id.to_string(), current);
        usage
    }

    pub(crate) async fn disk_usage(
        &self,
        config: &Config,
        instance_id: &str,
        path: PathBuf,
    ) -> Result<CachedDiskUsage, String> {
        if let Some(sample) = self.cached_disk_usage(instance_id).await
            && sample.sampled_at.elapsed() < DISK_REFRESH_INTERVAL
        {
            return Ok(sample);
        }

        if let Some(sample) = self.quota_disk_usage(config, instance_id, &path).await {
            return Ok(sample);
        }

        if let Some(sample) = self.cached_disk_usage(instance_id).await {
            if sample.sampled_at.elapsed() < DISK_REFRESH_INTERVAL {
                return Ok(sample);
            }
            self.refresh_disk_usage_background(
                Arc::new(config.clone()),
                instance_id.to_string(),
                path,
            );
            return Ok(sample);
        }

        match directory_size(path.clone(), INITIAL_DISK_SCAN_TIMEOUT).await {
            Ok(used_bytes) => {
                let sample = CachedDiskUsage {
                    used_bytes,
                    sampled_at: Instant::now(),
                };
                self.store_disk_usage(instance_id.to_string(), sample).await;
                Ok(sample)
            }
            Err(error) if error.kind() == ErrorKind::TimedOut => {
                self.refresh_disk_usage_background(
                    Arc::new(config.clone()),
                    instance_id.to_string(),
                    path,
                );
                Err("disk usage scan is still in progress".to_string())
            }
            Err(error) => Err(error.to_string()),
        }
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
            Ok(Some(used_bytes)) => {
                let sample = CachedDiskUsage {
                    used_bytes,
                    sampled_at: Instant::now(),
                };
                self.store_disk_usage(instance_id.to_string(), sample).await;
                Some(sample)
            }
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

    async fn store_disk_usage(&self, instance_id: String, sample: CachedDiskUsage) {
        let mut inner = self.inner.lock().await;
        inner.disk.insert(instance_id, sample);
    }

    fn refresh_disk_usage_background(
        &self,
        config: Arc<Config>,
        instance_id: String,
        path: PathBuf,
    ) {
        let cache = self.clone();
        tokio::spawn(async move {
            {
                let mut inner = cache.inner.lock().await;
                if inner
                    .disk_refreshing
                    .get(&instance_id)
                    .copied()
                    .unwrap_or(false)
                {
                    return;
                }
                inner.disk_refreshing.insert(instance_id.clone(), true);
            }

            let result =
                match DiskLimiter::with_fuse_root(config.disk.clone(), config.paths.fuse_root())
                    .instance_usage_bytes(&path)
                    .await
                {
                    Ok(Some(used_bytes)) => Ok(used_bytes),
                    Ok(None) => directory_size(path, BACKGROUND_DISK_SCAN_TIMEOUT).await,
                    Err(error) => {
                        tracing::debug!(
                            %instance_id,
                            %error,
                            "quota disk usage unavailable during background refresh"
                        );
                        directory_size(path, BACKGROUND_DISK_SCAN_TIMEOUT).await
                    }
                };
            let mut inner = cache.inner.lock().await;
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
                }
                Err(error) => {
                    tracing::warn!(
                        %instance_id,
                        %error,
                        "failed to refresh resource disk usage"
                    );
                }
            }
        });
    }

    pub async fn refresh_all_disk_usage(&self, state: &AppState) {
        let instances = state.instances.list().await;
        futures::stream::iter(
            instances
                .into_iter()
                .filter(|metadata| metadata.status == InstanceStatus::Running),
        )
        .map(|metadata| {
            let cache = self.clone();
            let config = state.config.clone();
            async move {
                let paths = match InstancePaths::new(&config.paths, &metadata.instance_id) {
                    Ok(paths) => paths,
                    Err(error) => {
                        tracing::debug!(
                            instance_id = %metadata.instance_id,
                            %error,
                            "skipping resource disk sample for invalid instance path"
                        );
                        return;
                    }
                };
                cache
                    .refresh_disk_usage_now(config, metadata.instance_id, paths.data)
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
        {
            let mut inner = self.inner.lock().await;
            if inner
                .disk_refreshing
                .get(&instance_id)
                .copied()
                .unwrap_or(false)
            {
                return;
            }
            inner.disk_refreshing.insert(instance_id.clone(), true);
        }

        let result =
            match DiskLimiter::with_fuse_root(config.disk.clone(), config.paths.fuse_root())
                .instance_usage_bytes(&path)
                .await
            {
                Ok(Some(used_bytes)) => Ok(used_bytes),
                Ok(None) => directory_size(path, BACKGROUND_DISK_SCAN_TIMEOUT).await,
                Err(error) => {
                    tracing::debug!(
                        %instance_id,
                        %error,
                        "quota disk usage unavailable during sampler refresh"
                    );
                    directory_size(path, BACKGROUND_DISK_SCAN_TIMEOUT).await
                }
            };

        let mut inner = self.inner.lock().await;
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
            }
            Err(error) => {
                tracing::warn!(
                    %instance_id,
                    %error,
                    "failed to refresh sampled disk usage"
                );
            }
        }
    }
}

pub fn start_resource_sampler(state: AppState) {
    let mut shutdown = state.gateway_supervisor.subscribe_shutdown();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(DISK_REFRESH_INTERVAL);
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        tracing::info!("resource sampler stopped");
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

fn directory_size_blocking(path: &FsPath, budget: Duration) -> Result<u64, std::io::Error> {
    use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, open, openat, statat};

    let started = std::time::Instant::now();
    let root = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(IoError::from)?;
    let mut directories = vec![(root, 0_usize)];
    let mut visited_entries = 0_usize;
    let mut total = 0_u64;

    while let Some((directory, depth)) = directories.pop() {
        ensure_scan_budget(started, budget, visited_entries)?;
        let entries = Dir::read_from(&directory).map_err(IoError::from)?;
        for entry in entries {
            ensure_scan_budget(started, budget, visited_entries)?;
            let entry = entry.map_err(IoError::from)?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            visited_entries = visited_entries.checked_add(1).ok_or_else(|| {
                IoError::new(ErrorKind::InvalidData, "disk scan entry count overflow")
            })?;
            if visited_entries > DISK_SCAN_MAX_ENTRIES {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    format!("disk scan exceeded {DISK_SCAN_MAX_ENTRIES} entries"),
                ));
            }

            let stat =
                statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(IoError::from)?;
            match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => {
                    if depth >= DISK_SCAN_MAX_DEPTH {
                        return Err(IoError::new(
                            ErrorKind::InvalidData,
                            format!("disk scan exceeded depth {DISK_SCAN_MAX_DEPTH}"),
                        ));
                    }
                    let child = openat(
                        &directory,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(IoError::from)?;
                    directories.push((child, depth + 1));
                }
                FileType::RegularFile => {
                    let size = u64::try_from(stat.st_size).map_err(|_| {
                        IoError::new(ErrorKind::InvalidData, "file reported a negative size")
                    })?;
                    total = total.checked_add(size).ok_or_else(|| {
                        IoError::new(ErrorKind::InvalidData, "disk usage size overflow")
                    })?;
                }
                _ => {}
            }
        }
    }
    Ok(total)
}

fn ensure_scan_budget(
    started: std::time::Instant,
    budget: Duration,
    visited_entries: usize,
) -> Result<(), std::io::Error> {
    if started.elapsed() >= budget {
        return Err(IoError::new(
            ErrorKind::TimedOut,
            format!("disk scan timed out after {visited_entries} entries"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod disk_scan_tests {
    use std::{fs, os::unix::fs::symlink};

    use super::*;

    #[test]
    fn disk_scan_counts_regular_files_without_following_symlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let data = temporary.path().join("data");
        let outside = temporary.path().join("outside");
        fs::create_dir_all(data.join("nested")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(data.join("root.bin"), [0_u8; 7]).unwrap();
        fs::write(data.join("nested/child.bin"), [0_u8; 11]).unwrap();
        fs::write(outside.join("secret.bin"), [0_u8; 101]).unwrap();
        symlink(&outside, data.join("outside-link")).unwrap();

        assert_eq!(
            directory_size_blocking(&data, Duration::from_secs(1)).unwrap(),
            18
        );
    }

    #[test]
    fn disk_scan_rejects_a_symlink_root() {
        let temporary = tempfile::tempdir().unwrap();
        let data = temporary.path().join("data");
        let linked = temporary.path().join("linked");
        fs::create_dir(&data).unwrap();
        symlink(&data, &linked).unwrap();

        assert!(directory_size_blocking(&linked, Duration::from_secs(1)).is_err());
    }
}

#[cfg(test)]
mod node_summary_tests {
    use super::*;
    use crate::{
        instances::metadata::{
            DatabaseIdentity, PublicEndpoint, RuntimeKind, RuntimeMetadata, SCHEMA_VERSION,
        },
        shared::{backend::BackendEndpoint, limits::InstanceLimits},
    };

    #[test]
    fn parses_host_cpu_and_calculates_non_idle_percentage() {
        let previous =
            parse_host_cpu("cpu  100 0 50 850 0 0 0 0 0 0\ncpu0 50 0 25 425\ncpu1 50 0 25 425\n")
                .unwrap();
        let current =
            parse_host_cpu("cpu  150 0 100 950 0 0 0 0 0 0\ncpu0 75 0 50 475\ncpu1 75 0 50 475\n")
                .unwrap();

        assert_eq!(current.cores, 2);
        assert_eq!(host_cpu_percent_between(previous, current), Some(50.0));
    }

    #[test]
    fn container_cpu_counter_resets_do_not_emit_bogus_usage() {
        let previous = CpuStatsSample {
            total_usage: 1_000,
            system_cpu_usage: 10_000,
            online_cpus: 4,
        };
        let reset = CpuStatsSample {
            total_usage: 10,
            system_cpu_usage: 100,
            online_cpus: 4,
        };

        assert_eq!(cpu_percent_between(previous, reset), None);
    }

    #[tokio::test]
    async fn gateway_network_counters_are_shared_and_removed_with_the_instance() {
        let cache = ResourceCache::default();
        let first = cache.network_counter("inst_network").await;
        let second = cache.network_counter("inst_network").await;

        first.add_rx(11);
        second.add_tx(17);
        assert_eq!(cache.network_usage("inst_network").await, (11, 17));

        cache.remove("inst_network").await;
        assert_eq!(cache.network_usage("inst_network").await, (0, 0));
    }

    #[test]
    fn parses_mem_available_as_scheduler_safe_host_memory() {
        let sample = parse_host_memory(
            "MemTotal:       1000 kB\nMemFree:         100 kB\nMemAvailable:    400 kB\n",
        )
        .unwrap();

        assert_eq!(sample.total_bytes, 1_024_000);
        assert_eq!(sample.available_bytes, 409_600);
        assert_eq!(sample.used_bytes, 614_400);
    }

    #[tokio::test]
    async fn host_disk_sample_uses_the_target_filesystem() {
        let directory = tempfile::tempdir().unwrap();
        let sample = read_host_disk(directory.path().to_str().unwrap())
            .await
            .unwrap();

        assert!(sample.total_bytes > 0);
        assert!(sample.used_bytes <= sample.total_bytes);
        assert!(sample.available_bytes <= sample.total_bytes);
    }

    #[test]
    fn allocations_include_running_and_stopped_instances() {
        let running = metadata_with_limits(
            "inst_running",
            InstanceStatus::Running,
            InstanceLimits {
                cpu_cores: 1.5,
                memory_mib: 512,
                disk_mib: 1024,
                ..InstanceLimits::default()
            },
        );
        let stopped = metadata_with_limits(
            "inst_stopped",
            InstanceStatus::Stopped,
            InstanceLimits {
                cpu_cores: 0.5,
                memory_mib: 256,
                disk_mib: 2048,
                ..InstanceLimits::default()
            },
        );

        let summary = aggregate_allocations_and_statuses(&[running, stopped]);

        assert_eq!(summary.allocated_cpu_cores, 2.0);
        assert_eq!(summary.allocated_memory_bytes, mib_to_bytes(768));
        assert_eq!(summary.allocated_disk_bytes, mib_to_bytes(3072));
        assert_eq!(summary.instances.total, 2);
        assert_eq!(summary.instances.running, 1);
        assert_eq!(summary.instances.stopped, 1);
    }

    #[test]
    fn managed_usage_is_null_when_a_running_instance_lacks_a_sample() {
        let reports = vec![Ok(ResourceReport {
            instance_id: "inst_running".to_string(),
            protocol: "mysql".to_string(),
            status: "running".to_string(),
            cpu: CpuReport {
                configured_cores: 1.0,
                usage_percent: None,
            },
            memory: MemoryReport {
                configured_mib: 512,
                usage_bytes: None,
                limit_bytes: Some(mib_to_bytes(512)),
            },
            disk: DiskReport {
                configured_mib: 1024,
                limit_bytes: mib_to_bytes(1024),
                used_bytes: 123,
                enforced: true,
                enforcement_method: "fuse_quota".to_string(),
            },
            network: NetworkReport {
                rx_bytes: None,
                tx_bytes: None,
            },
        })];

        let usage = aggregate_managed_usage(&reports);

        assert_eq!(usage.cpu_usage_cores, None);
        assert_eq!(usage.memory_used_bytes, None);
        assert_eq!(usage.disk_used_bytes, Some(123));
    }

    fn metadata_with_limits(
        instance_id: &str,
        status: InstanceStatus,
        limits: InstanceLimits,
    ) -> InstanceMetadata {
        InstanceMetadata {
            schema_version: SCHEMA_VERSION,
            instance_id: instance_id.to_string(),
            protocol: Protocol::Mysql,
            status,
            public: PublicEndpoint {
                host: "127.0.0.1".to_string(),
                port: 3308,
            },
            backend: BackendEndpoint::UnixSocket {
                socket_path: format!("/run/dbev/sockets/{instance_id}/mysqld.sock"),
            },
            runtime: RuntimeMetadata {
                kind: RuntimeKind::Docker,
                container_name: format!("dbe-mysql-{instance_id}"),
                network_mode: "none".to_string(),
            },
            database: DatabaseIdentity {
                name: format!("db_{instance_id}"),
                username: format!("user_{instance_id}"),
            },
            route_key_sha256: None,
            mariadb_native_password_sha1_stage2: None,
            mariadb_root_password: None,
            mysql_native_password_sha1_stage2: None,
            mysql_root_password: None,
            mongodb_root_password: None,
            limits,
            image: None,
            database_version: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }
}

pub(crate) fn cpu_percent(stats: &Value) -> Option<f64> {
    let current = cpu_sample_from_path(stats, "cpu_stats")?;
    let previous = cpu_sample_from_path(stats, "precpu_stats")?;
    cpu_percent_between(previous, current)
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CpuStatsSample {
    total_usage: u64,
    system_cpu_usage: u64,
    online_cpus: u64,
}

pub(crate) fn current_cpu_sample(stats: &Value) -> Option<CpuStatsSample> {
    cpu_sample_from_path(stats, "cpu_stats")
}

pub(crate) fn cpu_percent_between(
    previous: CpuStatsSample,
    current: CpuStatsSample,
) -> Option<f64> {
    let cpu_delta = current.total_usage.checked_sub(previous.total_usage)?;
    let system_delta = current
        .system_cpu_usage
        .checked_sub(previous.system_cpu_usage)?;
    if system_delta == 0 {
        return None;
    }
    Some((cpu_delta as f64 / system_delta as f64) * current.online_cpus as f64 * 100.0)
}

fn cpu_sample_from_path(stats: &Value, root: &str) -> Option<CpuStatsSample> {
    Some(CpuStatsSample {
        total_usage: value_u64(stats, &[root, "cpu_usage", "total_usage"])?,
        system_cpu_usage: value_u64(stats, &[root, "system_cpu_usage"])?,
        online_cpus: value_u64(stats, &[root, "online_cpus"]).unwrap_or(1).max(1),
    })
}

pub(crate) fn memory_usage_bytes(stats: &Value) -> Option<u64> {
    value_u64(stats, &["memory_stats", "usage"])
}

pub(crate) fn mib_to_bytes(mib: u64) -> u64 {
    mib.saturating_mul(1024 * 1024)
}

pub(crate) fn value_u64(value: &Value, path: &[&str]) -> Option<u64> {
    let mut value = value;
    for key in path {
        value = value.get(*key)?;
    }
    value.as_u64()
}
