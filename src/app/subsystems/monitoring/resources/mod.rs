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
    auth::scopes,
    config::Config,
    databases::protocol::Protocol,
    routes::http::{
        policy::ApiRequestContext,
        response::{ApiError, ApiPath, ApiResponse, ApiResult},
        router::AppState,
    },
    server::disk::{
        DiskLimiter,
        soft::{SoftDiskSnapshot, SoftDiskTarget},
    },
    server::monitoring::ActivityStore,
    server::placement::DeploymentMode,
    server::{
        metadata::{InstanceMetadata, InstanceStatus},
        paths::InstancePaths,
    },
    storage::activity::ActivityRepository,
    utils::limits::mib_to_bytes,
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

mod background;
mod cache;
mod disk;
mod handlers;
mod reports;
pub use background::*;
use disk::*;
pub use handlers::*;
pub use reports::*;

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
