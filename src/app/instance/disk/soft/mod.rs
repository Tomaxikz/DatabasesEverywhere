use std::{
    collections::HashMap,
    future::Future,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::sync::{Mutex, Semaphore};

use sha2::Digest;

use crate::{
    config::{DiskLimitMode, SoftDiskScannerConfig},
    utils::{limits::mib_to_bytes, protocol::Protocol},
};

use super::usage::{DirectoryUsage, ScanLimits, scan_directory_with_id};

// Bound tenant-controlled incremental state; larger trees stream full scans.
const DEFAULT_MAX_CACHED_DIRECTORIES_PER_TARGET: usize = 4_096;
const MAX_SCAN_DEPTH: usize = 128;
const WARNING_USAGE_PERCENT: u64 = 75;
const OUTER_SCAN_DEADLINE_SLACK: Duration = Duration::from_secs(1);

type ScanMeasurement = (DirectoryUsage, PerformedScanKind, usage_tree::RootIdentity);

pub(crate) mod planner;
pub(crate) mod usage_tree;
pub(crate) mod watcher;

mod growth;

#[cfg(test)]
mod hybrid_tests;

mod cache;
mod enforcement;
mod scan;
#[cfg(test)]
mod tests;
mod thresholds;
mod types;

use self::cache::*;
pub(crate) use self::enforcement::*;
use self::thresholds::*;
pub use self::types::*;

pub(crate) type RuntimeFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
pub(crate) type StopRuntimeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<StopOutcome, String>> + Send + 'a>>;

#[derive(Debug, Clone)]
pub struct SoftDiskLimiter {
    config: SoftDiskScannerConfig,
    states: Arc<Mutex<HashMap<String, TrackerState>>>,
    scan_failures: Arc<Mutex<HashMap<String, TargetScanFailures>>>,
    capacity_outage_failures: Arc<Mutex<u8>>,
    usage_trees: Arc<Mutex<HashMap<String, UsageTreeState>>>,
    cached_directories: Arc<AtomicUsize>,
    usage_cache_limits: UsageCacheLimits,
    permits: Arc<Semaphore>,
}

impl SoftDiskLimiter {
    pub fn new(config: SoftDiskScannerConfig) -> Self {
        let global_directories = config.max_cached_directories_global;
        Self::with_usage_cache_limits(
            config,
            UsageCacheLimits {
                per_target_directories: DEFAULT_MAX_CACHED_DIRECTORIES_PER_TARGET,
                global_directories,
            },
        )
    }

    fn with_usage_cache_limits(
        config: SoftDiskScannerConfig,
        usage_cache_limits: UsageCacheLimits,
    ) -> Self {
        let permits = config.max_concurrent_scans.max(1);
        Self {
            config,
            states: Arc::default(),
            scan_failures: Arc::default(),
            capacity_outage_failures: Arc::default(),
            usage_trees: Arc::default(),
            cached_directories: Arc::default(),
            usage_cache_limits,
            permits: Arc::new(Semaphore::new(permits)),
        }
    }

    pub fn scan_interval(&self) -> Duration {
        Duration::from_secs(self.config.scan_interval_seconds.max(1))
    }

    pub fn max_concurrent_scans(&self) -> usize {
        self.config.max_concurrent_scans.max(1)
    }

    pub fn is_capacity_outage(error: &str) -> bool {
        error.starts_with("soft disk scanner capacity outage:")
    }

    pub fn shutdown_grace(&self) -> Duration {
        Duration::from_secs(self.config.shutdown_grace_seconds.max(1))
    }

    pub fn enforcement_required(global_mode: DiskLimitMode, protocol: Protocol) -> bool {
        global_mode == DiskLimitMode::SoftScanner
            || (global_mode == DiskLimitMode::FuseQuota
                && protocol.engine().fuse_quota_unsupported())
    }

    /// Return only samples matching the current target fingerprint.
    pub async fn snapshot(&self, target: &SoftDiskTarget) -> Option<SoftDiskSnapshot> {
        let fingerprint = TargetFingerprint::from(target);
        self.states
            .lock()
            .await
            .get(&target.instance_id)
            .filter(|state| state.target == fingerprint)
            .map(|state| state.snapshot.clone())
    }

    pub async fn remove(&self, instance_id: &str) {
        self.states.lock().await.remove(instance_id);
        self.scan_failures.lock().await.remove(instance_id);
        self.evict_usage_cache(instance_id).await;
    }
}
