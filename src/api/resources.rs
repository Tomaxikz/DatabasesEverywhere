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

const STATS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
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

async fn directory_size(path: PathBuf, budget: Duration) -> Result<u64, std::io::Error> {
    tokio::task::spawn_blocking(move || directory_size_blocking(&path, budget))
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
