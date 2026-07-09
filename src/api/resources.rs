use std::{
    collections::HashMap,
    path::{Path as FsPath, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, Uri},
};
use serde::Serialize;
use serde_json::Value;
use tokio::{
    sync::Mutex,
    time::{Instant, timeout},
};

use crate::{
    api::{
        handlers::{ApiError, ApiResult, authorize_scope},
        routes::AppState,
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

const STATS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const DISK_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const INITIAL_DISK_SCAN_TIMEOUT: Duration = Duration::from_millis(750);
const RESOURCE_FANOUT_LIMIT: usize = 16;

#[derive(Debug, Clone, Default)]
pub struct ResourceCache {
    inner: Arc<Mutex<ResourceCacheInner>>,
    active_monitors: Arc<AtomicUsize>,
}

#[derive(Debug, Default)]
struct ResourceCacheInner {
    stats: HashMap<String, CachedRuntimeStats>,
    cpu_samples: HashMap<String, CpuStatsSample>,
    disk: HashMap<String, CachedDiskUsage>,
    disk_refreshing: HashMap<String, bool>,
}

#[derive(Debug, Clone)]
struct CachedRuntimeStats {
    stats: Value,
    raw: String,
    cpu_usage_percent: Option<f64>,
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

pub async fn list_resources(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<Vec<ResourceReport>> {
    authorize_scope(&state, &headers, &uri, scopes::RESOURCES_READ)?;
    let reports = futures::stream::iter(state.instances.list().await)
        .map(|metadata| {
            let state = state.clone();
            async move { resource_report(&state, metadata).await }
        })
        .buffer_unordered(RESOURCE_FANOUT_LIMIT)
        .try_collect()
        .await?;
    Ok(Json(reports))
}

pub async fn instance_resources(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<ResourceReport> {
    authorize_scope(&state, &headers, &uri, scopes::RESOURCES_READ)?;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    Ok(Json(resource_report(&state, metadata).await?))
}

pub(crate) async fn resource_report(
    state: &AppState,
    metadata: InstanceMetadata,
) -> Result<ResourceReport, ApiError> {
    resource_report_with_docker_stats(state, metadata)
        .await
        .map(|(report, _)| report)
}

pub(crate) async fn resource_report_with_docker_stats(
    state: &AppState,
    metadata: InstanceMetadata,
) -> Result<(ResourceReport, Option<String>), ApiError> {
    let stats = state
        .resource_cache
        .runtime_stats(&state.docker, metadata.protocol, &metadata.instance_id)
        .await;
    let stats_value = stats.as_ref().map(|stats| &stats.stats);
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
            rx_bytes: stats_value.and_then(network_rx_bytes),
            tx_bytes: stats_value.and_then(network_tx_bytes),
        },
    };

    Ok((report, stats.map(|stats| stats.raw)))
}

async fn directory_size(path: PathBuf) -> Result<u64, std::io::Error> {
    tokio::task::spawn_blocking(move || directory_size_blocking(&path))
        .await
        .map_err(std::io::Error::other)?
}

impl ResourceCache {
    pub async fn remove(&self, instance_id: &str) {
        let mut inner = self.inner.lock().await;
        inner.stats.remove(instance_id);
        inner.cpu_samples.remove(instance_id);
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

        let output = docker.stats(protocol, instance_id).await.ok()?;
        let raw = output.stdout;
        let stats = serde_json::from_str::<Value>(&raw).ok()?;
        let cpu_usage_percent = self
            .record_cpu_sample(&cache_key, &stats)
            .await
            .or_else(|| cpu_percent(&stats));
        let cached = CachedRuntimeStats {
            stats,
            raw,
            cpu_usage_percent,
            sampled_at: Instant::now(),
        };
        let mut inner = self.inner.lock().await;
        inner.stats.insert(cache_key, cached.clone());
        Some(cached)
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

        match timeout(INITIAL_DISK_SCAN_TIMEOUT, directory_size(path.clone())).await {
            Ok(Ok(used_bytes)) => {
                let sample = CachedDiskUsage {
                    used_bytes,
                    sampled_at: Instant::now(),
                };
                self.store_disk_usage(instance_id.to_string(), sample).await;
                Ok(sample)
            }
            Ok(Err(error)) => Err(error.to_string()),
            Err(_) => {
                self.refresh_disk_usage_background(
                    Arc::new(config.clone()),
                    instance_id.to_string(),
                    path,
                );
                Ok(CachedDiskUsage {
                    used_bytes: 0,
                    sampled_at: Instant::now(),
                })
            }
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
                    Ok(None) => directory_size(path).await,
                    Err(error) => {
                        tracing::debug!(
                            %instance_id,
                            %error,
                            "quota disk usage unavailable during background refresh"
                        );
                        directory_size(path).await
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
                Ok(None) => directory_size(path).await,
                Err(error) => {
                    tracing::debug!(
                        %instance_id,
                        %error,
                        "quota disk usage unavailable during sampler refresh"
                    );
                    directory_size(path).await
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
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(DISK_REFRESH_INTERVAL);
        loop {
            ticker.tick().await;
            if !state.resource_cache.has_active_monitors() {
                continue;
            }
            state.resource_cache.refresh_all_disk_usage(&state).await;
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

fn directory_size_blocking(path: &FsPath) -> Result<u64, std::io::Error> {
    let mut total = 0;
    let Ok(entries) = std::fs::read_dir(path) else {
        return Ok(0);
    };
    for entry in entries {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            total += directory_size_blocking(&entry.path())?;
        } else if metadata.is_file() {
            total += metadata.len();
        }
    }
    Ok(total)
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
    let cpu_delta = current.total_usage.saturating_sub(previous.total_usage);
    let system_delta = current
        .system_cpu_usage
        .saturating_sub(previous.system_cpu_usage);
    if system_delta == 0 {
        return None;
    }
    Some((cpu_delta as f64 / system_delta as f64) * current.online_cpus as f64 * 100.0)
}

fn cpu_sample_from_path(stats: &Value, root: &str) -> Option<CpuStatsSample> {
    Some(CpuStatsSample {
        total_usage: value_u64(stats, &[root, "cpu_usage", "total_usage"])?,
        system_cpu_usage: value_u64(stats, &[root, "system_cpu_usage"])?,
        online_cpus: value_u64(stats, &[root, "online_cpus"]).unwrap_or(1),
    })
}

pub(crate) fn memory_usage_bytes(stats: &Value) -> Option<u64> {
    value_u64(stats, &["memory_stats", "usage"])
}

pub(crate) fn network_rx_bytes(stats: &Value) -> Option<u64> {
    network_sum(stats, "rx_bytes")
}

pub(crate) fn network_tx_bytes(stats: &Value) -> Option<u64> {
    network_sum(stats, "tx_bytes")
}

pub(crate) fn mib_to_bytes(mib: u64) -> u64 {
    mib.saturating_mul(1024 * 1024)
}

pub(crate) fn network_sum(stats: &Value, key: &str) -> Option<u64> {
    let networks = stats.get("networks")?.as_object()?;
    Some(
        networks
            .values()
            .filter_map(|network| network.get(key).and_then(Value::as_u64))
            .sum(),
    )
}

pub(crate) fn value_u64(value: &Value, path: &[&str]) -> Option<u64> {
    let mut value = value;
    for key in path {
        value = value.get(*key)?;
    }
    value.as_u64()
}
