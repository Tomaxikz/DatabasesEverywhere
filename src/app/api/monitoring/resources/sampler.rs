use std::{
    collections::{HashMap, HashSet},
    io::{Error as IoError, ErrorKind},
    time::Duration,
};

use futures::StreamExt;
use tokio::{
    task::JoinHandle,
    time::{Instant, MissedTickBehavior},
};

use super::{
    ApiError, AppState, CachedRuntimeStats, InstanceMetadata, InstancePaths, InstanceStatus,
    NodeInstanceSummary, Protocol, RESOURCE_FANOUT_LIMIT, RUNTIME_STATS_POLL_INTERVAL,
    RUNTIME_STATS_STALE_AFTER, ResourceCache, ResourceReport, container_cpu_total,
    cpu_percent_over_wall_time, mib_to_bytes,
};
use crate::placement::{DeploymentMode, EngineRuntime, EngineRuntimeStatus};

const HOST_CPU_REFRESH_INTERVAL: Duration = Duration::from_millis(400);

#[derive(Debug, Clone, Copy)]
pub(super) struct HostCpuSample {
    pub(super) total: u64,
    pub(super) idle: u64,
    pub(super) cores: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct CachedHostCpuUsage {
    pub(super) usage_percent: f64,
    pub(super) cores: u64,
    pub(super) sampled_at: Instant,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RuntimeSampleTarget {
    pub protocol: Protocol,
}

#[derive(Debug)]
pub(super) struct SharedRuntimeUsage {
    pub(super) runtime_id: String,
    pub(super) expects_live_sample: bool,
    pub(super) cpu_usage_percent: Option<f64>,
    pub(super) memory_usage_bytes: Option<u64>,
    pub(super) runtime_stats: RuntimeStatsSnapshot,
    pub(super) disk_usage: Result<SharedDiskUsage, String>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct RuntimeStatsSnapshot {
    pub(super) sample: Option<CachedRuntimeStats>,
    pub(super) worker_active: bool,
}

impl RuntimeStatsSnapshot {
    pub(super) fn sample(&self) -> Option<&CachedRuntimeStats> {
        self.sample.as_ref()
    }

    pub(super) fn fresh_sample(&self) -> Option<&CachedRuntimeStats> {
        self.sample()
            .filter(|sample| sample.sampled_at.elapsed() < RUNTIME_STATS_STALE_AFTER)
    }

    pub(super) fn worker_active(&self) -> bool {
        self.worker_active
    }
}

impl ResourceCache {
    pub(super) async fn runtime_stats_snapshot(&self, runtime_id: &str) -> RuntimeStatsSnapshot {
        let inner = self.inner.lock().await;
        RuntimeStatsSnapshot {
            sample: inner.stats.get(runtime_id).cloned(),
            worker_active: inner.runtime_stats_workers.contains_key(runtime_id),
        }
    }

    pub(super) async fn runtime_stats(&self, runtime_id: &str) -> Option<CachedRuntimeStats> {
        self.runtime_stats_snapshot(runtime_id)
            .await
            .fresh_sample()
            .cloned()
    }
}

impl ResourceCache {
    pub(super) async fn host_cpu_usage(&self) -> Result<CachedHostCpuUsage, std::io::Error> {
        {
            let inner = self.inner.lock().await;
            if let Some(cached) = inner
                .host_cpu_usage
                .filter(|cached| cached.sampled_at.elapsed() < HOST_CPU_REFRESH_INTERVAL)
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

pub(crate) async fn read_host_cpu_cores() -> Result<u64, std::io::Error> {
    Ok(read_host_cpu().await?.cores)
}

pub(super) fn parse_host_cpu(contents: &str) -> Result<HostCpuSample, std::io::Error> {
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

pub(super) fn host_cpu_percent_between(
    previous: HostCpuSample,
    current: HostCpuSample,
) -> Option<f64> {
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

pub(super) fn parse_host_memory(contents: &str) -> Result<HostMemorySample, std::io::Error> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SharedDiskUsageSource {
    FilesystemQuota,
    FuseQuota,
    ResourceDiskSampler,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct SharedDiskUsage {
    pub(super) bytes: u64,
    pub(super) sampled_at: Instant,
    pub(super) source: SharedDiskUsageSource,
}

#[derive(Debug)]
pub(super) struct AllocationSummary {
    pub(super) allocated_cpu_cores: f64,
    pub(super) allocated_memory_bytes: u64,
    pub(super) allocated_disk_bytes: u64,
    pub(super) instances: NodeInstanceSummary,
}

pub(super) fn summarize_allocations(
    instances: &[InstanceMetadata],
    runtimes: &[crate::placement::EngineRuntime],
) -> AllocationSummary {
    let allocated = crate::placement::policy::sum_runtime_limits(
        runtimes.iter().map(|runtime| &runtime.limits),
    );
    let mut counts = NodeInstanceSummary::default();

    for instance in instances {
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
        allocated_cpu_cores: allocated.cpu_cores,
        allocated_memory_bytes: mib_to_bytes(allocated.memory_mib),
        allocated_disk_bytes: mib_to_bytes(allocated.disk_mib),
        instances: counts,
    }
}

#[derive(Debug)]
pub(super) struct ManagedUsageSummary {
    pub(super) cpu_usage_cores: Option<f64>,
    pub(super) memory_used_bytes: Option<u64>,
    pub(super) disk_used_bytes: Option<u64>,
}

#[derive(Debug, Default)]
struct RuntimeUsage {
    expects_live_sample: bool,
    cpu_usage_percent: Option<f64>,
    memory_usage_bytes: Option<u64>,
}

/// Collapses logical tenants onto their physical engine runtime. Dedicated
/// instances still produce one target each because their runtime ID is their
/// instance ID.
pub(super) fn runtime_targets(
    instances: &[InstanceMetadata],
    runtimes: &[EngineRuntime],
) -> HashMap<String, RuntimeSampleTarget> {
    let mut targets = HashMap::<String, RuntimeSampleTarget>::new();
    let mut invalid = HashSet::new();
    for metadata in instances.iter().filter(|metadata| {
        matches!(
            metadata.status,
            InstanceStatus::Booting | InstanceStatus::Running
        )
    }) {
        let runtime_id = metadata.runtime_id().to_string();
        if invalid.contains(&runtime_id) {
            continue;
        }
        if let Some(existing) = targets.get(&runtime_id) {
            if existing.protocol != metadata.protocol {
                tracing::error!(
                    %runtime_id,
                    expected_protocol = %existing.protocol,
                    tenant_protocol = %metadata.protocol,
                    tenant_id = %metadata.instance_id,
                    "tenants assigned to one runtime disagree on protocol; ignoring the invalid target"
                );
                targets.remove(&runtime_id);
                invalid.insert(runtime_id);
            }
            continue;
        }
        targets.insert(
            runtime_id,
            RuntimeSampleTarget {
                protocol: metadata.protocol,
            },
        );
    }
    for runtime in runtimes.iter().filter(|runtime| {
        runtime.deployment_mode == DeploymentMode::Shared
            && matches!(
                runtime.status,
                EngineRuntimeStatus::Booting | EngineRuntimeStatus::Running
            )
    }) {
        if invalid.contains(&runtime.runtime_id) {
            continue;
        }
        if let Some(existing) = targets.get(&runtime.runtime_id) {
            if existing.protocol != runtime.protocol {
                tracing::error!(
                    runtime_id = %runtime.runtime_id,
                    expected_protocol = %existing.protocol,
                    runtime_protocol = %runtime.protocol,
                    "shared runtime and tenant metadata disagree on protocol; ignoring the invalid target"
                );
                targets.remove(&runtime.runtime_id);
                invalid.insert(runtime.runtime_id.clone());
            }
            continue;
        }
        targets.insert(
            runtime.runtime_id.clone(),
            RuntimeSampleTarget {
                protocol: runtime.protocol,
            },
        );
    }
    targets
}

pub(super) async fn sample_shared_runtime_usage(
    state: &AppState,
    runtimes: &[EngineRuntime],
    instances: &[InstanceMetadata],
) -> Vec<SharedRuntimeUsage> {
    let shared = runtimes
        .iter()
        .filter(|runtime| runtime.deployment_mode == DeploymentMode::Shared)
        .cloned()
        .collect::<Vec<_>>();
    futures::stream::iter(shared)
        .map(|runtime| {
            let state = state.clone();
            let hard_tenants = instances
                .iter()
                .filter(|metadata| {
                    metadata.deployment_mode == DeploymentMode::Shared
                        && metadata.runtime_id() == runtime.runtime_id
                        && metadata.limits.disk_enforced
                })
                .cloned()
                .collect::<Vec<_>>();
            async move {
                let runtime_stats = state
                    .resource_cache
                    .runtime_stats_snapshot(&runtime.runtime_id)
                    .await;
                let stats = runtime_stats.fresh_sample();
                let disk_usage = shared_runtime_disk_usage(&state, &runtime, hard_tenants).await;
                SharedRuntimeUsage {
                    runtime_id: runtime.runtime_id,
                    expects_live_sample: matches!(
                        runtime.status,
                        EngineRuntimeStatus::Booting | EngineRuntimeStatus::Running
                    ),
                    cpu_usage_percent: stats.and_then(|stats| stats.cpu_usage_percent),
                    memory_usage_bytes: stats.and_then(|stats| stats.memory_usage_bytes),
                    runtime_stats,
                    disk_usage,
                }
            }
        })
        .buffer_unordered(RESOURCE_FANOUT_LIMIT)
        .collect()
        .await
}

/// A native project counter on the shared-pool root deliberately excludes
/// nested hard tenant projects. Add each hard child exactly once so node-level
/// managed disk usage still describes the complete physical pool. Soft and
/// FUSE-only pools have no hard children and are already complete at the root.
async fn shared_runtime_disk_usage(
    state: &AppState,
    runtime: &EngineRuntime,
    hard_tenants: Vec<InstanceMetadata>,
) -> Result<SharedDiskUsage, String> {
    let paths = InstancePaths::new(&state.config.paths, &runtime.runtime_id)
        .map_err(|error| error.to_string())?;
    let (root_bytes, sampled_at, source) = if runtime.limits.disk_enforced {
        let root_bytes = crate::disk::DiskLimiter::with_fuse_root(
            state.config.disk.clone(),
            state.config.paths.fuse_root(),
        )
        .for_persisted_protocol(runtime.protocol, &runtime.limits.disk_enforcement_method)
        .instance_usage_bytes(&paths.data)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            format!(
                "shared runtime {} claims a hard disk boundary without an authoritative usage counter",
                runtime.runtime_id
            )
        })?;
        let source = if runtime.limits.disk_enforcement_method == "fuse_quota" {
            SharedDiskUsageSource::FuseQuota
        } else {
            SharedDiskUsageSource::FilesystemQuota
        };
        (root_bytes, Instant::now(), source)
    } else {
        let sample = state
            .resource_cache
            .disk_usage(&state.config, &runtime.runtime_id, paths.data)
            .await?;
        (
            sample.used_bytes,
            sample.sampled_at,
            SharedDiskUsageSource::ResourceDiskSampler,
        )
    };

    let child_usage = futures::stream::iter(hard_tenants)
        .map(|metadata| {
            let state = state.clone();
            async move {
                if metadata.protocol != runtime.protocol {
                    return Err(format!(
                        "shared runtime {} has a hard tenant with a mismatched protocol",
                        runtime.runtime_id
                    ));
                }
                super::shared_disk::usage(&state, &metadata).await
            }
        })
        .buffer_unordered(RESOURCE_FANOUT_LIMIT)
        .collect::<Vec<_>>()
        .await;
    let bytes = managed_disk_total(
        root_bytes,
        &runtime.limits.disk_enforcement_method,
        child_usage,
    )?;
    Ok(SharedDiskUsage {
        bytes,
        sampled_at,
        source,
    })
}

fn managed_disk_total(
    root_bytes: u64,
    root_method: &str,
    children: impl IntoIterator<Item = Result<u64, String>>,
) -> Result<u64, String> {
    // A FUSE boundary and non-nested native backends already account for the
    // complete tree at the root. Only Linux project counters exclude files
    // relabelled into child tenant projects.
    if !matches!(
        root_method,
        "host_xfs_project_quota" | "host_linux_project_quota"
    ) {
        return Ok(root_bytes);
    }
    children.into_iter().try_fold(root_bytes, |total, child| {
        total
            .checked_add(child?)
            .ok_or_else(|| "managed shared-pool disk usage overflowed u64".to_string())
    })
}

pub(super) fn aggregate_managed_usage(
    reports: &[(DeploymentMode, Result<ResourceReport, ApiError>)],
    shared_runtimes: &[SharedRuntimeUsage],
) -> ManagedUsageSummary {
    let mut disk_used_bytes = 0_u64;
    let mut disk_complete = true;
    let mut runtime_reports_complete = true;
    let mut runtimes = HashMap::<String, RuntimeUsage>::new();

    for (deployment_mode, report) in reports {
        let Ok(report) = report else {
            if *deployment_mode == DeploymentMode::Dedicated {
                runtime_reports_complete = false;
                disk_complete = false;
            }
            continue;
        };
        if report.deployment_mode == DeploymentMode::Shared {
            continue;
        }
        let expects_live_sample = matches!(report.status.as_str(), "running" | "booting");
        let runtime = runtimes.entry(report.runtime_id.clone()).or_default();
        runtime.expects_live_sample |= expects_live_sample;
        runtime.cpu_usage_percent = runtime.cpu_usage_percent.or(report.cpu.usage_percent);
        runtime.memory_usage_bytes = runtime.memory_usage_bytes.or(report.memory.usage_bytes);
        disk_used_bytes = disk_used_bytes.saturating_add(report.disk.used_bytes);
    }

    let mut seen_shared = HashSet::new();
    for shared in shared_runtimes {
        if !seen_shared.insert(&shared.runtime_id) {
            disk_complete = false;
            runtime_reports_complete = false;
            continue;
        }
        let runtime = runtimes.entry(shared.runtime_id.clone()).or_default();
        runtime.expects_live_sample = shared.expects_live_sample;
        runtime.cpu_usage_percent = shared.cpu_usage_percent;
        runtime.memory_usage_bytes = shared.memory_usage_bytes;
        match &shared.disk_usage {
            Ok(sample) => disk_used_bytes = disk_used_bytes.saturating_add(sample.bytes),
            Err(_) => disk_complete = false,
        }
    }

    let mut cpu_usage_cores = 0.0;
    let mut memory_used_bytes = 0_u64;
    let mut cpu_complete = runtime_reports_complete;
    let mut memory_complete = runtime_reports_complete;
    for runtime in runtimes.into_values() {
        match runtime.cpu_usage_percent {
            Some(percent) => cpu_usage_cores += percent / 100.0,
            None if runtime.expects_live_sample => cpu_complete = false,
            None => {}
        }
        match runtime.memory_usage_bytes {
            Some(bytes) => memory_used_bytes = memory_used_bytes.saturating_add(bytes),
            None if runtime.expects_live_sample => memory_complete = false,
            None => {}
        }
    }

    ManagedUsageSummary {
        cpu_usage_cores: cpu_complete.then_some(cpu_usage_cores),
        memory_used_bytes: memory_complete.then_some(memory_used_bytes),
        disk_used_bytes: disk_complete.then_some(disk_used_bytes),
    }
}

pub(super) fn start(state: AppState) {
    let mut shutdown = state.gateway_supervisor.subscribe_shutdown();
    tokio::spawn(async move {
        let mut tasks = HashMap::<String, RuntimeStatsTask>::new();
        let mut ticker = tokio::time::interval(RUNTIME_STATS_POLL_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        tracing::info!(
            sample_source = "docker_one_shot_wall_clock_delta",
            sample_interval_ms = 1_000_u64,
            websocket_publish_interval_ms = 1_000_u64,
            "container resource monitoring started with Calagopus wings-rs sampling semantics"
        );
        loop {
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                _ = ticker.tick() => sync_tasks(&state, &mut tasks).await,
            }
        }
        for (runtime_id, task) in tasks {
            state.resource_cache.clear_runtime_stats(&runtime_id).await;
            task.handle.abort();
            let _ = task.handle.await;
        }
        tracing::info!("container resource monitoring stopped");
    });
}

struct RuntimeStatsTask {
    worker: u64,
    handle: JoinHandle<()>,
}

async fn sync_tasks(state: &AppState, tasks: &mut HashMap<String, RuntimeStatsTask>) {
    let instances = state.instances.list().await;
    let runtimes = match state.placements.list().await {
        Ok(runtimes) => runtimes,
        Err(error) => {
            tracing::warn!(
                %error,
                "could not load shared runtimes for resource sampling; dedicated sampling continues"
            );
            Vec::new()
        }
    };
    let desired = runtime_targets(&instances, &runtimes);
    let finished_or_stopped = tasks
        .iter()
        .filter_map(|(runtime_id, task)| {
            (task.handle.is_finished() || !desired.contains_key(runtime_id))
                .then_some(runtime_id.clone())
        })
        .collect::<Vec<_>>();

    for runtime_id in finished_or_stopped {
        let Some(task) = tasks.remove(&runtime_id) else {
            continue;
        };
        if !desired.contains_key(&runtime_id) {
            state.resource_cache.clear_runtime_stats(&runtime_id).await;
            task.handle.abort();
        } else {
            state
                .resource_cache
                .finish_stats_worker(&runtime_id, task.worker)
                .await;
        }
        if let Err(error) = task.handle.await
            && !error.is_cancelled()
        {
            tracing::warn!(
                %runtime_id,
                %error,
                "container resource stream task stopped unexpectedly; it will be restarted"
            );
        }
    }

    for (runtime_id, target) in desired {
        if tasks.contains_key(&runtime_id) {
            continue;
        }
        let worker = state
            .resource_cache
            .begin_runtime_stats_worker(&runtime_id)
            .await;
        let cache = state.resource_cache.clone();
        let docker = state.docker.clone();
        let protocol = target.protocol;
        let task_runtime_id = runtime_id.clone();
        let handle = tokio::spawn(async move {
            let sampler = match docker.stats_sampler(protocol, &task_runtime_id).await {
                Ok(sampler) => sampler,
                Err(error) => {
                    tracing::debug!(
                        runtime_id = %task_runtime_id,
                        %protocol,
                        %error,
                        "could not bind the container resource sampler; retrying"
                    );
                    cache.finish_stats_worker(&task_runtime_id, worker).await;
                    return;
                }
            };
            let mut previous_cpu = None::<(u64, Instant)>;
            loop {
                // Take one one-shot counter snapshot per second. Sleeping in
                // parallel prevents a slow runtime request adding another full
                // interval to the sample cadence.
                let (result, _) = tokio::join!(
                    sampler.sample(),
                    tokio::time::sleep(RUNTIME_STATS_POLL_INTERVAL)
                );
                let stats = match result {
                    Ok(stats) => stats,
                    Err(error) => {
                        tracing::debug!(
                            runtime_id = %task_runtime_id,
                            %protocol,
                            %error,
                            "one-shot container resource sample failed; rebinding the sampler"
                        );
                        break;
                    }
                };
                let sampled_at = Instant::now();
                let current_cpu = container_cpu_total(&stats);
                let cpu_usage_percent = current_cpu.and_then(|current_total| {
                    previous_cpu.map(|(previous_total, previous_at)| {
                        cpu_percent_over_wall_time(
                            previous_total,
                            current_total,
                            sampled_at.duration_since(previous_at),
                        )
                    })
                });
                previous_cpu = current_cpu.map(|total| (total, sampled_at));
                if !cache
                    .store_runtime_stats(&task_runtime_id, worker, cpu_usage_percent, &stats)
                    .await
                {
                    break;
                }
            }
            cache.finish_stats_worker(&task_runtime_id, worker).await;
        });
        tasks.insert(runtime_id, RuntimeStatsTask { worker, handle });
    }
}

#[cfg(test)]
mod tests {
    use super::managed_disk_total;

    #[test]
    fn shared_disk_total_counts_root_and_each_hard_child_once() {
        assert_eq!(
            managed_disk_total(100, "host_linux_project_quota", [Ok(20), Ok(30)]).unwrap(),
            150
        );
    }

    #[test]
    fn complete_root_quota_is_not_double_counted() {
        assert_eq!(
            managed_disk_total(100, "fuse_quota", [Ok(20), Ok(30)]).unwrap(),
            100
        );
    }

    #[test]
    fn incomplete_or_overflowing_shared_disk_totals_fail_closed() {
        assert!(
            managed_disk_total(
                100,
                "host_xfs_project_quota",
                [Err("missing child".to_string())]
            )
            .is_err()
        );
        assert!(managed_disk_total(u64::MAX, "host_xfs_project_quota", [Ok(1)]).is_err());
    }
}
