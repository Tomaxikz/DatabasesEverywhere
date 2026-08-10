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
    shared::protocol::Protocol,
};

use super::usage::{DirectoryUsage, ScanLimits, scan_directory_blocking_identified};

// Bound tenant-controlled incremental state; larger trees stream full scans.
const DEFAULT_MAX_CACHED_DIRECTORIES_PER_TARGET: usize = 4_096;
const DEFAULT_MAX_CACHED_DIRECTORIES_GLOBAL: usize = 32_768;

pub(crate) mod planner;
pub(crate) mod usage_tree;
pub(crate) mod watcher;

#[path = "soft/growth.rs"]
mod growth;

#[cfg(test)]
#[path = "soft/hybrid_tests.rs"]
mod hybrid_tests;

pub(crate) type RuntimeFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
pub(crate) type StopRuntimeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<StopOutcome, String>> + Send + 'a>>;

#[derive(Debug, Clone)]
pub struct SoftDiskTarget {
    pub instance_id: String,
    pub created_at: String,
    pub protocol: Protocol,
    pub data_path: PathBuf,
    pub limit_bytes: u64,
    /// Durable restart hysteresis owned by the disk limiter.
    pub durable_blocked: bool,
}

impl SoftDiskTarget {
    /// Process-local fingerprint of the instance generation and disk policy.
    pub(crate) fn scanner_fingerprint(&self) -> String {
        let mut digest = sha2::Sha256::new();
        for component in [
            self.created_at.as_bytes(),
            self.protocol.as_str().as_bytes(),
            self.data_path.as_os_str().as_bytes(),
            &self.limit_bytes.to_le_bytes(),
        ] {
            digest.update(component.len().to_le_bytes());
            digest.update(component);
        }
        format!("{:x}", digest.finalize())
    }
}

#[derive(Debug, Clone)]
pub struct SoftDiskSnapshot {
    pub usage: DirectoryUsage,
    pub limit_bytes: u64,
    pub stop_threshold_bytes: u64,
    pub recovery_threshold_bytes: u64,
    pub growth_bytes_per_second: f64,
    pub peak_growth_bytes_per_second: f64,
    pub predicted_seconds_to_limit: Option<u64>,
    pub blocked: bool,
    pub sampled_at: Instant,
}

#[derive(Debug, Clone)]
pub struct SoftDiskLimitExceeded {
    pub snapshot: SoftDiskSnapshot,
    pub reason: SoftDiskBlockReason,
}

#[derive(Debug, Clone)]
pub enum SoftDiskBlockReason {
    UsageThreshold,
    Unmeasurable {
        consecutive_failures: u8,
        error: String,
    },
    ScannerCapacityOutage {
        consecutive_failures: u8,
        error: String,
    },
}

impl SoftDiskBlockReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UsageThreshold => "usage_threshold",
            Self::Unmeasurable { .. } => "scan_unmeasurable",
            Self::ScannerCapacityOutage { .. } => "scanner_capacity_outage",
        }
    }

    pub fn scan_error(&self) -> Option<&str> {
        match self {
            Self::UsageThreshold => None,
            Self::Unmeasurable { error, .. } | Self::ScannerCapacityOutage { error, .. } => {
                Some(error)
            }
        }
    }
}

pub trait SoftDiskRuntime: Send + Sync {
    /// Persist stopped intent before touching the runtime.
    fn mark_disk_blocked<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
        exceeded: &'a SoftDiskLimitExceeded,
    ) -> RuntimeFuture<'a>;

    fn graceful_stop<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
        grace: Duration,
    ) -> RuntimeFuture<'a>;

    fn force_kill<'a>(&'a self, target: &'a SoftDiskTarget) -> RuntimeFuture<'a>;

    /// Clear only the limiter-owned block after crossing recovery hysteresis.
    fn clear_disk_blocked<'a>(&'a self, _target: &'a SoftDiskTarget) -> RuntimeFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    /// Persist and enforce stop intent; production wraps this in a lifecycle lock.
    fn enforce_disk_stop<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
        exceeded: &'a SoftDiskLimitExceeded,
        grace: Duration,
    ) -> StopRuntimeFuture<'a> {
        Box::pin(async move {
            self.mark_disk_blocked(target, exceeded).await?;
            stop_with_kill_fallback(self, target, grace).await
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopOutcome {
    Graceful,
    Forced,
    SkippedStale,
}

#[derive(Debug, Clone)]
pub enum ScanOutcome {
    Healthy(SoftDiskSnapshot),
    Warning(SoftDiskSnapshot),
    Recovered(SoftDiskSnapshot),
    AlreadyBlocked(SoftDiskSnapshot),
    Stopped {
        snapshot: SoftDiskSnapshot,
        outcome: StopOutcome,
    },
}

#[derive(Debug, Clone)]
pub(crate) enum HybridScanRequest {
    /// Authoritative O(depth) scan that does not retain incremental state.
    StreamingFull,
    Full,
    Partial {
        relative_directories: Vec<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PerformedScanKind {
    Full,
    Partial,
}

#[derive(Debug, Clone)]
pub(crate) struct HybridScanExecution {
    pub(crate) outcome: ScanOutcome,
    pub(crate) performed: PerformedScanKind,
    /// False when fail-closed enforcement used an older trustworthy sample.
    pub(crate) measurement_succeeded: bool,
    pub(crate) root_identity: Option<usage_tree::RootIdentity>,
}

impl ScanOutcome {
    pub fn snapshot(&self) -> &SoftDiskSnapshot {
        match self {
            Self::Healthy(snapshot)
            | Self::Warning(snapshot)
            | Self::Recovered(snapshot)
            | Self::AlreadyBlocked(snapshot)
            | Self::Stopped { snapshot, .. } => snapshot,
        }
    }
}

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

#[derive(Debug, Clone, Copy)]
struct UsageCacheLimits {
    per_target_directories: usize,
    global_directories: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TargetFingerprint {
    created_at: String,
    protocol: Protocol,
    data_path: PathBuf,
    limit_bytes: u64,
}

#[derive(Debug, Clone)]
struct UsageTreeState {
    target: TargetFingerprint,
    slot: Arc<UsageTreeSlot>,
}

#[derive(Debug)]
struct UsageTreeSlot {
    state: std::sync::Mutex<UsageTreeSlotState>,
    cached_directories: Arc<AtomicUsize>,
    global_directory_limit: usize,
}

#[derive(Debug, Default)]
struct UsageTreeSlotState {
    cache: Option<usage_tree::UsageTreeCache>,
    cached_directory_count: usize,
    streaming_only: bool,
}

impl UsageTreeSlot {
    fn new(cached_directories: Arc<AtomicUsize>, global_directory_limit: usize) -> Self {
        Self {
            state: std::sync::Mutex::new(UsageTreeSlotState::default()),
            cached_directories,
            global_directory_limit,
        }
    }

    fn install_cache(
        &self,
        state: &mut UsageTreeSlotState,
        cache: usage_tree::UsageTreeCache,
    ) -> bool {
        if state.streaming_only {
            return false;
        }
        let old_count = state.cached_directory_count;
        let new_count = cache.directory_count();
        if new_count > old_count
            && !reserve_cached_directories(
                &self.cached_directories,
                new_count - old_count,
                self.global_directory_limit,
            )
        {
            self.switch_to_streaming(state);
            return false;
        }
        if old_count > new_count {
            release_cached_directories(&self.cached_directories, old_count - new_count);
        }
        state.cached_directory_count = new_count;
        state.cache = Some(cache);
        true
    }

    /// Reserve the reconciled cache size before publishing it.
    fn account_reconciled_cache(&self, state: &mut UsageTreeSlotState) -> bool {
        let Some(new_count) = state
            .cache
            .as_ref()
            .map(usage_tree::UsageTreeCache::directory_count)
        else {
            return false;
        };
        let old_count = state.cached_directory_count;
        if new_count > old_count
            && !reserve_cached_directories(
                &self.cached_directories,
                new_count - old_count,
                self.global_directory_limit,
            )
        {
            self.switch_to_streaming(state);
            return false;
        }
        if old_count > new_count {
            release_cached_directories(&self.cached_directories, old_count - new_count);
        }
        state.cached_directory_count = new_count;
        true
    }

    fn switch_to_streaming(&self, state: &mut UsageTreeSlotState) {
        release_cached_directories(&self.cached_directories, state.cached_directory_count);
        state.cached_directory_count = 0;
        state.cache = None;
        state.streaming_only = true;
    }
}

impl Drop for UsageTreeSlot {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        release_cached_directories(&self.cached_directories, state.cached_directory_count);
        state.cached_directory_count = 0;
    }
}

fn reserve_cached_directories(counter: &AtomicUsize, additional: usize, limit: usize) -> bool {
    if additional == 0 {
        return true;
    }
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let Some(updated) = current.checked_add(additional) else {
            return false;
        };
        if updated > limit {
            return false;
        }
        match counter.compare_exchange_weak(current, updated, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

fn release_cached_directories(counter: &AtomicUsize, released: usize) {
    if released == 0 {
        return;
    }
    let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        Some(current.saturating_sub(released))
    });
}

impl From<&SoftDiskTarget> for TargetFingerprint {
    fn from(target: &SoftDiskTarget) -> Self {
        Self {
            created_at: target.created_at.clone(),
            protocol: target.protocol,
            data_path: target.data_path.clone(),
            limit_bytes: target.limit_bytes,
        }
    }
}

#[derive(Debug, Clone)]
struct TrackerState {
    target: TargetFingerprint,
    snapshot: SoftDiskSnapshot,
    warned: bool,
}

#[derive(Debug, Clone)]
struct TargetScanFailures {
    target: TargetFingerprint,
    consecutive: u8,
}

impl SoftDiskLimiter {
    pub fn new(config: SoftDiskScannerConfig) -> Self {
        Self::with_usage_cache_limits(
            config,
            UsageCacheLimits {
                per_target_directories: DEFAULT_MAX_CACHED_DIRECTORIES_PER_TARGET,
                global_directories: DEFAULT_MAX_CACHED_DIRECTORIES_GLOBAL,
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
            || (global_mode == DiskLimitMode::FuseQuota && protocol == Protocol::Qdrant)
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

    pub async fn scan_and_enforce<R: SoftDiskRuntime>(
        &self,
        runtime: &R,
        target: &SoftDiskTarget,
    ) -> Result<ScanOutcome, String> {
        Ok(self
            .scan_hybrid_and_enforce(runtime, target, HybridScanRequest::StreamingFull)
            .await?
            .outcome)
    }

    pub(crate) async fn scan_hybrid_and_enforce<R: SoftDiskRuntime>(
        &self,
        runtime: &R,
        target: &SoftDiskTarget,
        request: HybridScanRequest,
    ) -> Result<HybridScanExecution, String> {
        let (usage, performed, root_identity) = match self.scan_hybrid(target, request).await {
            Ok(measurement) => {
                self.scan_failures.lock().await.remove(&target.instance_id);
                *self.capacity_outage_failures.lock().await = 0;
                measurement
            }
            Err(ScanFailure::Capacity(error)) => {
                let outcome = self.enforce_capacity_outage(runtime, target, error).await?;
                return Ok(HybridScanExecution {
                    outcome,
                    performed: PerformedScanKind::Full,
                    measurement_succeeded: false,
                    root_identity: None,
                });
            }
            Err(ScanFailure::Measurement(error)) => {
                let outcome = self.enforce_unmeasurable(runtime, target, error).await?;
                return Ok(HybridScanExecution {
                    outcome,
                    performed: PerformedScanKind::Full,
                    measurement_succeeded: false,
                    root_identity: None,
                });
            }
        };
        let outcome = self.enforce_measured_usage(runtime, target, usage).await?;
        Ok(HybridScanExecution {
            outcome,
            performed,
            measurement_succeeded: true,
            root_identity: Some(root_identity),
        })
    }

    async fn enforce_measured_usage<R: SoftDiskRuntime>(
        &self,
        runtime: &R,
        target: &SoftDiskTarget,
        usage: DirectoryUsage,
    ) -> Result<ScanOutcome, String> {
        let decision = self.record_sample(target, usage).await;
        let snapshot = decision.snapshot;

        if decision.recovered {
            runtime.clear_disk_blocked(target).await?;
            return Ok(ScanOutcome::Recovered(snapshot));
        }
        if !decision.must_stop && !decision.already_blocked {
            return Ok(if decision.warning {
                ScanOutcome::Warning(snapshot)
            } else {
                ScanOutcome::Healthy(snapshot)
            });
        }

        let exceeded = SoftDiskLimitExceeded {
            snapshot: snapshot.clone(),
            reason: SoftDiskBlockReason::UsageThreshold,
        };
        let stop_outcome = runtime
            .enforce_disk_stop(target, &exceeded, self.shutdown_grace())
            .await?;
        Ok(ScanOutcome::Stopped {
            snapshot,
            outcome: stop_outcome,
        })
    }

    /// Perform a fresh scan before admitting a soft-limited start.
    pub async fn ensure_start_allowed(
        &self,
        target: &SoftDiskTarget,
    ) -> Result<SoftDiskSnapshot, String> {
        let measurement = self
            .scan_hybrid(target, HybridScanRequest::StreamingFull)
            .await;
        // A rejected start will not enter the monitor to evict this tree later.
        self.evict_usage_cache(&target.instance_id).await;
        let (usage, _, _) = measurement.map_err(ScanFailure::into_message)?;
        *self.capacity_outage_failures.lock().await = 0;
        self.scan_failures.lock().await.remove(&target.instance_id);
        let decision = self.record_sample(target, usage).await;
        if decision.snapshot.blocked {
            return Err(format!(
                "instance is blocked by the soft disk limiter: physical usage {} bytes must fall below the recovery threshold {} bytes (configured limit {} bytes)",
                decision.snapshot.usage.physical_bytes,
                decision.snapshot.recovery_threshold_bytes,
                decision.snapshot.limit_bytes,
            ));
        }
        Ok(decision.snapshot)
    }

    async fn scan_hybrid(
        &self,
        target: &SoftDiskTarget,
        request: HybridScanRequest,
    ) -> Result<(DirectoryUsage, PerformedScanKind, usage_tree::RootIdentity), ScanFailure> {
        let scan_timeout = Duration::from_secs(self.config.scan_timeout_seconds.max(1));
        let permit = tokio::time::timeout(scan_timeout, self.permits.clone().acquire_owned())
            .await
            .map_err(|_| {
                ScanFailure::Capacity(format!(
                    "soft disk scan capacity was unavailable for {} seconds",
                    scan_timeout.as_secs()
                ))
            })?
            .map_err(|_| ScanFailure::Capacity("soft disk scan limiter closed".to_string()))?;
        let scan_path = target.data_path.clone();
        let generation = target.scanner_fingerprint();
        // Qdrant mmap writes are not reliably observable through inotify.
        let cache_allowed = self.config.use_inotify
            && target.protocol != Protocol::Qdrant
            && !matches!(&request, HybridScanRequest::StreamingFull);
        let cache = if cache_allowed {
            Some(self.usage_tree_slot(target).await)
        } else {
            self.evict_usage_cache(&target.instance_id).await;
            None
        };
        let limits = ScanLimits {
            timeout: scan_timeout,
            max_entries: self.config.max_entries_per_scan.max(1),
            max_depth: 128,
        };
        let per_target_cache_limit = self
            .usage_cache_limits
            .per_target_directories
            .min(limits.max_entries.saturating_add(1));
        // A wedged worker keeps its permit, bounding leaked blocking workers.
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let Some(cache) = cache else {
                return scan_directory_blocking_identified(&scan_path, limits)
                    .map(|(usage, identity)| (usage, PerformedScanKind::Full, identity));
            };
            let mut state = cache
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.streaming_only {
                return scan_directory_blocking_identified(&scan_path, limits)
                    .map(|(usage, identity)| (usage, PerformedScanKind::Full, identity));
            }
            match request {
                HybridScanRequest::StreamingFull => {
                    scan_directory_blocking_identified(&scan_path, limits)
                        .map(|(usage, identity)| (usage, PerformedScanKind::Full, identity))
                }
                HybridScanRequest::Full => scan_full_with_bounded_cache(
                    &cache,
                    &mut state,
                    &scan_path,
                    generation,
                    limits,
                    per_target_cache_limit,
                ),
                HybridScanRequest::Partial {
                    relative_directories,
                } => {
                    let reconcile = state.cache.as_mut().map(|existing| {
                        existing.reconcile(&scan_path, &generation, &relative_directories, limits)
                    });
                    match reconcile {
                        Some(Ok(usage)) => {
                            let identity = state
                                .cache
                                .as_ref()
                                .expect("successful reconciliation retains its cache")
                                .root_identity();
                            cache.account_reconciled_cache(&mut state);
                            Ok((usage, PerformedScanKind::Partial, identity))
                        }
                        Some(Err(error)) if !error.requires_full_scan() => match error {
                            usage_tree::ReconcileError::Io(error) => Err(error),
                            usage_tree::ReconcileError::FullScanRequired(_) => {
                                unreachable!("full reconciliation was handled above")
                            }
                        },
                        Some(Err(_)) | None => scan_full_with_bounded_cache(
                            &cache,
                            &mut state,
                            &scan_path,
                            generation,
                            limits,
                            per_target_cache_limit,
                        ),
                    }
                }
            }
        });
        tokio::time::timeout(scan_timeout.saturating_add(Duration::from_secs(1)), worker)
            .await
            .map_err(|_| {
                ScanFailure::Measurement(format!(
                    "soft disk scan of {} exceeded its outer {} second deadline",
                    target.data_path.display(),
                    scan_timeout
                        .saturating_add(Duration::from_secs(1))
                        .as_secs()
                ))
            })?
            .map_err(|error| {
                ScanFailure::Measurement(format!(
                    "soft disk scan worker failed for {}: {error}",
                    target.data_path.display()
                ))
            })?
            .map_err(|error| {
                ScanFailure::Measurement(format!(
                    "failed to scan {}: {error}",
                    target.data_path.display()
                ))
            })
    }

    async fn usage_tree_slot(&self, target: &SoftDiskTarget) -> Arc<UsageTreeSlot> {
        let fingerprint = TargetFingerprint::from(target);
        let mut states = self.usage_trees.lock().await;
        let state = states
            .entry(target.instance_id.clone())
            .or_insert_with(|| UsageTreeState {
                target: fingerprint.clone(),
                slot: Arc::new(UsageTreeSlot::new(
                    Arc::clone(&self.cached_directories),
                    self.usage_cache_limits.global_directories,
                )),
            });
        if state.target != fingerprint {
            *state = UsageTreeState {
                target: fingerprint,
                slot: Arc::new(UsageTreeSlot::new(
                    Arc::clone(&self.cached_directories),
                    self.usage_cache_limits.global_directories,
                )),
            };
        }
        Arc::clone(&state.slot)
    }

    pub(crate) async fn evict_usage_cache(&self, instance_id: &str) {
        self.usage_trees.lock().await.remove(instance_id);
    }

    async fn record_sample(
        &self,
        target: &SoftDiskTarget,
        usage: DirectoryUsage,
    ) -> SampleDecision {
        let now = Instant::now();
        let fingerprint = TargetFingerprint::from(target);
        let mut states = self.states.lock().await;
        let previous = states
            .get(&target.instance_id)
            .filter(|state| state.target == fingerprint);
        let growth_bytes_per_second = growth::growth_rate(
            previous,
            usage.physical_bytes,
            now,
            Duration::from_secs(self.config.scan_interval_seconds.max(1)),
        );
        let peak_growth_bytes_per_second = previous.map_or(growth_bytes_per_second, |state| {
            state
                .snapshot
                .peak_growth_bytes_per_second
                .max(growth_bytes_per_second)
        });
        let (stop_threshold_bytes, recovery_threshold_bytes) = thresholds(
            &self.config,
            target.protocol,
            target.limit_bytes,
            growth_bytes_per_second,
        );
        let was_blocked =
            target.durable_blocked || previous.is_some_and(|state| state.snapshot.blocked);
        let recovered = was_blocked && usage.physical_bytes < recovery_threshold_bytes;
        let blocked = if recovered {
            false
        } else {
            was_blocked || usage.physical_bytes >= stop_threshold_bytes
        };
        let must_stop = !was_blocked && blocked;
        let predicted_seconds_to_limit = predict_seconds_to_limit(
            usage.physical_bytes,
            target.limit_bytes,
            growth_bytes_per_second,
        );
        let warning_now = !blocked
            && (usage.physical_bytes >= target.limit_bytes.saturating_mul(75) / 100
                || predicted_seconds_to_limit.is_some_and(|seconds| {
                    seconds
                        <= authoritative_scan_interval_seconds(&self.config, target.protocol)
                            .saturating_mul(2)
                }));
        let previously_warned = previous.is_some_and(|state| state.warned);
        let warning = warning_now && !previously_warned;
        let warned = warning_now;
        let snapshot = SoftDiskSnapshot {
            usage,
            limit_bytes: target.limit_bytes,
            stop_threshold_bytes,
            recovery_threshold_bytes,
            growth_bytes_per_second,
            peak_growth_bytes_per_second,
            predicted_seconds_to_limit,
            blocked,
            sampled_at: now,
        };
        states.insert(
            target.instance_id.clone(),
            TrackerState {
                target: fingerprint,
                snapshot: snapshot.clone(),
                warned,
            },
        );
        SampleDecision {
            snapshot,
            warning,
            must_stop,
            already_blocked: was_blocked && !recovered,
            recovered,
        }
    }

    async fn enforce_unmeasurable<R: SoftDiskRuntime>(
        &self,
        runtime: &R,
        target: &SoftDiskTarget,
        error: String,
    ) -> Result<ScanOutcome, String> {
        let consecutive_failures = {
            let mut failures = self.scan_failures.lock().await;
            let fingerprint = TargetFingerprint::from(target);
            let state = failures
                .entry(target.instance_id.clone())
                .or_insert_with(|| TargetScanFailures {
                    target: fingerprint.clone(),
                    consecutive: 0,
                });
            if state.target != fingerprint {
                *state = TargetScanFailures {
                    target: fingerprint,
                    consecutive: 0,
                };
            }
            state.consecutive = state.consecutive.saturating_add(1);
            state.consecutive
        };
        let threshold = self.config.max_consecutive_scan_failures.max(1);
        if consecutive_failures < threshold {
            return Err(format!(
                "{error}; soft disk usage is unmeasurable ({consecutive_failures}/{threshold} consecutive failures before fail-closed stop)"
            ));
        }

        let snapshot = self.blocked_snapshot_after_scan_failure(target).await;
        let reason = SoftDiskBlockReason::Unmeasurable {
            consecutive_failures,
            error,
        };
        let exceeded = SoftDiskLimitExceeded {
            snapshot: snapshot.clone(),
            reason,
        };
        let outcome = runtime
            .enforce_disk_stop(target, &exceeded, self.shutdown_grace())
            .await?;
        Ok(ScanOutcome::Stopped { snapshot, outcome })
    }

    async fn enforce_capacity_outage<R: SoftDiskRuntime>(
        &self,
        runtime: &R,
        target: &SoftDiskTarget,
        error: String,
    ) -> Result<ScanOutcome, String> {
        let consecutive_failures = {
            let mut failures = self.capacity_outage_failures.lock().await;
            *failures = failures.saturating_add(1);
            *failures
        };
        let threshold = self.config.max_consecutive_scan_failures.max(1);
        if consecutive_failures < threshold {
            return Err(format!(
                "soft disk scanner capacity outage: {error} ({consecutive_failures}/{threshold} global failures before fail-closed fleet stop)"
            ));
        }

        let snapshot = self.blocked_snapshot_after_scan_failure(target).await;
        let exceeded = SoftDiskLimitExceeded {
            snapshot: snapshot.clone(),
            reason: SoftDiskBlockReason::ScannerCapacityOutage {
                consecutive_failures,
                error,
            },
        };
        let outcome = runtime
            .enforce_disk_stop(target, &exceeded, self.shutdown_grace())
            .await?;
        Ok(ScanOutcome::Stopped { snapshot, outcome })
    }

    async fn blocked_snapshot_after_scan_failure(
        &self,
        target: &SoftDiskTarget,
    ) -> SoftDiskSnapshot {
        let now = Instant::now();
        let fingerprint = TargetFingerprint::from(target);
        let mut states = self.states.lock().await;
        let previous = states
            .get(&target.instance_id)
            .filter(|state| state.target == fingerprint);
        let usage = previous.map_or_else(DirectoryUsage::default, |state| state.snapshot.usage);
        let growth_bytes_per_second =
            previous.map_or(0.0, |state| state.snapshot.growth_bytes_per_second);
        let peak_growth_bytes_per_second =
            previous.map_or(0.0, |state| state.snapshot.peak_growth_bytes_per_second);
        let (stop_threshold_bytes, recovery_threshold_bytes) = thresholds(
            &self.config,
            target.protocol,
            target.limit_bytes,
            growth_bytes_per_second,
        );
        let snapshot = SoftDiskSnapshot {
            usage,
            limit_bytes: target.limit_bytes,
            stop_threshold_bytes,
            recovery_threshold_bytes,
            growth_bytes_per_second,
            peak_growth_bytes_per_second,
            predicted_seconds_to_limit: predict_seconds_to_limit(
                usage.physical_bytes,
                target.limit_bytes,
                growth_bytes_per_second,
            ),
            blocked: true,
            sampled_at: now,
        };
        states.insert(
            target.instance_id.clone(),
            TrackerState {
                target: fingerprint,
                snapshot: snapshot.clone(),
                warned: false,
            },
        );
        snapshot
    }
}

fn scan_full_with_bounded_cache(
    slot: &UsageTreeSlot,
    state: &mut UsageTreeSlotState,
    scan_path: &std::path::Path,
    generation: String,
    limits: ScanLimits,
    per_target_cache_limit: usize,
) -> Result<(DirectoryUsage, PerformedScanKind, usage_tree::RootIdentity), std::io::Error> {
    match usage_tree::UsageTreeCache::scan_full_bounded(
        scan_path,
        generation,
        limits,
        per_target_cache_limit,
    )? {
        usage_tree::BoundedFullScan::Cached(replacement) => {
            let identity = replacement.root_identity();
            if slot.install_cache(state, replacement) {
                let usage = state
                    .cache
                    .as_ref()
                    .map_or_else(DirectoryUsage::default, usage_tree::UsageTreeCache::usage);
                return Ok((usage, PerformedScanKind::Full, identity));
            }
        }
        usage_tree::BoundedFullScan::DirectoryLimitExceeded => {
            slot.switch_to_streaming(state);
        }
    }
    scan_directory_blocking_identified(scan_path, limits)
        .map(|(usage, identity)| (usage, PerformedScanKind::Full, identity))
}

enum ScanFailure {
    Capacity(String),
    Measurement(String),
}

impl ScanFailure {
    fn into_message(self) -> String {
        match self {
            Self::Capacity(error) => format!("soft disk scanner capacity outage: {error}"),
            Self::Measurement(error) => error,
        }
    }
}

#[derive(Debug)]
struct SampleDecision {
    snapshot: SoftDiskSnapshot,
    warning: bool,
    must_stop: bool,
    already_blocked: bool,
    recovered: bool,
}

fn safety_reserve_bytes(
    config: &SoftDiskScannerConfig,
    protocol: Protocol,
    limit_bytes: u64,
    growth_bytes_per_second: f64,
) -> u64 {
    let maximum = limit_bytes / 5;
    let configured = config
        .safety_reserve_mib
        .saturating_mul(1024 * 1024)
        .min(maximum);
    let exposure_seconds = authoritative_scan_interval_seconds(config, protocol)
        .saturating_add(config.scan_timeout_seconds)
        .saturating_add(config.shutdown_grace_seconds)
        .saturating_add(1);
    let predicted =
        (growth_bytes_per_second * exposure_seconds as f64).clamp(0.0, maximum as f64) as u64;
    configured.max(predicted).min(maximum)
}

fn thresholds(
    config: &SoftDiskScannerConfig,
    protocol: Protocol,
    limit_bytes: u64,
    growth_bytes_per_second: f64,
) -> (u64, u64) {
    let reserve = safety_reserve_bytes(config, protocol, limit_bytes, growth_bytes_per_second);
    let stop_threshold_bytes = limit_bytes.saturating_sub(reserve);
    let configured_recovery =
        limit_bytes.saturating_mul(u64::from(config.recovery_percent.min(99))) / 100;
    let hysteresis_margin = (limit_bytes / 20).max(1);
    let recovery_threshold_bytes =
        configured_recovery.min(stop_threshold_bytes.saturating_sub(hysteresis_margin));
    (stop_threshold_bytes, recovery_threshold_bytes)
}

fn authoritative_scan_interval_seconds(config: &SoftDiskScannerConfig, protocol: Protocol) -> u64 {
    if config.use_inotify && protocol != Protocol::Qdrant {
        config
            .full_scan_interval_seconds
            .max(config.scan_interval_seconds)
    } else {
        config.scan_interval_seconds
    }
}

fn predict_seconds_to_limit(current: u64, limit: u64, growth: f64) -> Option<u64> {
    if current >= limit {
        return Some(0);
    }
    if !growth.is_finite() || growth <= 0.0 {
        return None;
    }
    Some(((limit - current) as f64 / growth).ceil() as u64)
}

pub(crate) async fn stop_with_kill_fallback<R: SoftDiskRuntime + ?Sized>(
    runtime: &R,
    target: &SoftDiskTarget,
    grace: Duration,
) -> Result<StopOutcome, String> {
    match tokio::time::timeout(grace, runtime.graceful_stop(target, grace)).await {
        Ok(Ok(())) => Ok(StopOutcome::Graceful),
        Ok(Err(graceful_error)) => {
            runtime.force_kill(target).await.map_err(|kill_error| {
                format!(
                    "graceful stop failed ({graceful_error}); force kill also failed ({kill_error})"
                )
            })?;
            Ok(StopOutcome::Forced)
        }
        Err(_) => {
            runtime.force_kill(target).await?;
            Ok(StopOutcome::Forced)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    #[derive(Clone, Default)]
    struct HangingRuntime {
        blocked: Arc<AtomicUsize>,
        graceful: Arc<AtomicUsize>,
        killed: Arc<AtomicUsize>,
    }

    #[derive(Clone, Default)]
    struct RetryRuntime {
        blocked: Arc<AtomicUsize>,
        killed: Arc<AtomicUsize>,
    }

    impl SoftDiskRuntime for RetryRuntime {
        fn mark_disk_blocked<'a>(
            &'a self,
            _target: &'a SoftDiskTarget,
            _exceeded: &'a SoftDiskLimitExceeded,
        ) -> RuntimeFuture<'a> {
            Box::pin(async move {
                self.blocked.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }

        fn graceful_stop<'a>(
            &'a self,
            _target: &'a SoftDiskTarget,
            _grace: Duration,
        ) -> RuntimeFuture<'a> {
            Box::pin(async { Err("simulated graceful stop failure".to_string()) })
        }

        fn force_kill<'a>(&'a self, _target: &'a SoftDiskTarget) -> RuntimeFuture<'a> {
            Box::pin(async move {
                let attempt = self.killed.fetch_add(1, Ordering::SeqCst);
                if attempt == 0 {
                    Err("simulated first kill failure".to_string())
                } else {
                    Ok(())
                }
            })
        }
    }

    impl SoftDiskRuntime for HangingRuntime {
        fn mark_disk_blocked<'a>(
            &'a self,
            _target: &'a SoftDiskTarget,
            _exceeded: &'a SoftDiskLimitExceeded,
        ) -> RuntimeFuture<'a> {
            Box::pin(async move {
                self.blocked.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }

        fn graceful_stop<'a>(
            &'a self,
            _target: &'a SoftDiskTarget,
            _grace: Duration,
        ) -> RuntimeFuture<'a> {
            Box::pin(async move {
                self.graceful.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<()>().await;
                Ok(())
            })
        }

        fn force_kill<'a>(&'a self, _target: &'a SoftDiskTarget) -> RuntimeFuture<'a> {
            Box::pin(async move {
                self.killed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
    }

    fn test_config() -> SoftDiskScannerConfig {
        SoftDiskScannerConfig {
            scan_interval_seconds: 1,
            use_inotify: false,
            full_scan_interval_seconds: 4,
            inotify_debounce_milliseconds: 1,
            max_dirty_paths_per_instance: 32,
            max_concurrent_scans: 1,
            max_entries_per_scan: 100,
            scan_timeout_seconds: 2,
            max_consecutive_scan_failures: 3,
            safety_reserve_mib: 0,
            recovery_percent: 80,
            shutdown_grace_seconds: 1,
        }
    }

    #[tokio::test]
    async fn over_limit_write_is_blocked_and_a_hung_stop_is_force_killed() {
        let temporary = tempfile::tempdir().unwrap();
        let data = temporary.path().join("data");
        std::fs::create_dir(&data).unwrap();
        std::fs::write(data.join("growth.bin"), vec![7_u8; 2 * 1024 * 1024]).unwrap();
        let runtime = HangingRuntime::default();
        let limiter = SoftDiskLimiter::new(test_config());
        let target = SoftDiskTarget {
            instance_id: "inst_over_limit".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            protocol: Protocol::Qdrant,
            data_path: data,
            limit_bytes: 1024 * 1024,
            durable_blocked: false,
        };

        // Exercise the production timeout/kill path with a short test deadline.
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            limiter.scan_and_enforce(&runtime, &target),
        )
        .await
        .unwrap()
        .unwrap();

        assert!(matches!(
            outcome,
            ScanOutcome::Stopped {
                outcome: StopOutcome::Forced,
                ..
            }
        ));
        assert_eq!(runtime.blocked.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.graceful.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.killed.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn restart_block_clears_only_below_hysteresis() {
        let temporary = tempfile::tempdir().unwrap();
        let data = temporary.path().join("data");
        std::fs::create_dir(&data).unwrap();
        let file = data.join("growth.bin");
        std::fs::write(&file, vec![1_u8; 2 * 1024 * 1024]).unwrap();
        let runtime = HangingRuntime::default();
        let mut config = test_config();
        config.shutdown_grace_seconds = 1;
        let limiter = SoftDiskLimiter::new(config);
        let target = SoftDiskTarget {
            instance_id: "inst_hysteresis".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            protocol: Protocol::Qdrant,
            data_path: data,
            limit_bytes: 1024 * 1024,
            durable_blocked: false,
        };

        limiter.scan_and_enforce(&runtime, &target).await.unwrap();
        assert!(limiter.ensure_start_allowed(&target).await.is_err());
        std::fs::remove_file(file).unwrap();
        assert!(limiter.ensure_start_allowed(&target).await.is_ok());
    }

    #[tokio::test]
    async fn active_blocked_instance_retries_enforcement_after_a_failed_kill() {
        let temporary = tempfile::tempdir().unwrap();
        let data = temporary.path().join("data");
        std::fs::create_dir(&data).unwrap();
        std::fs::write(data.join("growth.bin"), vec![9_u8; 2 * 1024 * 1024]).unwrap();
        let runtime = RetryRuntime::default();
        let limiter = SoftDiskLimiter::new(test_config());
        let target = SoftDiskTarget {
            instance_id: "inst_retry".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            protocol: Protocol::Qdrant,
            data_path: data,
            limit_bytes: 1024 * 1024,
            durable_blocked: false,
        };

        assert!(limiter.scan_and_enforce(&runtime, &target).await.is_err());
        let retry = limiter.scan_and_enforce(&runtime, &target).await.unwrap();

        assert!(matches!(
            retry,
            ScanOutcome::Stopped {
                outcome: StopOutcome::Forced,
                ..
            }
        ));
        assert_eq!(runtime.blocked.load(Ordering::SeqCst), 2);
        assert_eq!(runtime.killed.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn recovery_threshold_stays_below_predictive_stop_threshold() {
        let mut config = test_config();
        config.safety_reserve_mib = 64;
        config.recovery_percent = 85;
        let limiter = SoftDiskLimiter::new(config);
        let target = SoftDiskTarget {
            instance_id: "inst_small_limit".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            protocol: Protocol::Qdrant,
            data_path: PathBuf::from("/var/lib/dbev/volumes/inst_small_limit"),
            limit_bytes: 1024 * 1024,
            durable_blocked: false,
        };
        let decision = limiter
            .record_sample(&target, DirectoryUsage::default())
            .await;

        assert!(
            decision.snapshot.recovery_threshold_bytes < decision.snapshot.stop_threshold_bytes
        );
    }

    #[tokio::test]
    async fn recreated_target_does_not_inherit_blocked_hysteresis_or_growth() {
        let limiter = SoftDiskLimiter::new(test_config());
        let old_target = SoftDiskTarget {
            instance_id: "inst_reused".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            protocol: Protocol::Qdrant,
            data_path: PathBuf::from("/var/lib/dbev/volumes/inst_reused-old"),
            limit_bytes: 1_000,
            durable_blocked: false,
        };
        let blocked = limiter
            .record_sample(
                &old_target,
                DirectoryUsage {
                    logical_bytes: 1_000,
                    physical_bytes: 1_000,
                    entries: 1,
                },
            )
            .await;
        assert!(blocked.snapshot.blocked);
        assert!(blocked.must_stop);

        let new_target = SoftDiskTarget {
            created_at: "2026-02-01T00:00:00Z".to_string(),
            data_path: PathBuf::from("/var/lib/dbev/volumes/inst_reused-new"),
            limit_bytes: 2_000,
            ..old_target.clone()
        };
        // 1,700 is between this target's recovery and stop thresholds.
        let current = limiter
            .record_sample(
                &new_target,
                DirectoryUsage {
                    logical_bytes: 1_700,
                    physical_bytes: 1_700,
                    entries: 1,
                },
            )
            .await;

        assert!(!current.snapshot.blocked);
        assert!(!current.must_stop);
        assert!(!current.already_blocked);
        assert_eq!(current.snapshot.growth_bytes_per_second, 0.0);
        assert!(limiter.snapshot(&old_target).await.is_none());
        assert_eq!(
            limiter
                .snapshot(&new_target)
                .await
                .unwrap()
                .usage
                .physical_bytes,
            1_700
        );
    }

    #[tokio::test]
    async fn durable_restart_block_survives_a_fresh_limiter_until_recovery() {
        let temporary = tempfile::tempdir().unwrap();
        let data = temporary.path().join("data");
        std::fs::create_dir(&data).unwrap();
        let file = data.join("between-thresholds.bin");
        std::fs::write(&file, vec![3_u8; 3_600_000]).unwrap();
        let limiter = SoftDiskLimiter::new(test_config());
        let target = SoftDiskTarget {
            instance_id: "inst_durable_hysteresis".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            protocol: Protocol::Qdrant,
            data_path: data,
            limit_bytes: 4 * 1024 * 1024,
            durable_blocked: true,
        };

        assert!(limiter.ensure_start_allowed(&target).await.is_err());
        std::fs::remove_file(file).unwrap();
        assert!(limiter.ensure_start_allowed(&target).await.is_ok());
    }

    #[tokio::test]
    async fn repeated_unmeasurable_scans_fail_closed() {
        let temporary = tempfile::tempdir().unwrap();
        std::fs::write(temporary.path().join("one"), b"1").unwrap();
        std::fs::write(temporary.path().join("two"), b"2").unwrap();
        let runtime = HangingRuntime::default();
        let mut config = test_config();
        config.max_entries_per_scan = 1;
        config.max_consecutive_scan_failures = 2;
        let limiter = SoftDiskLimiter::new(config);
        let target = SoftDiskTarget {
            instance_id: "inst_unmeasurable".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            protocol: Protocol::Qdrant,
            data_path: temporary.path().to_path_buf(),
            limit_bytes: 128 * 1024 * 1024,
            durable_blocked: false,
        };

        assert!(limiter.scan_and_enforce(&runtime, &target).await.is_err());
        let second = limiter.scan_and_enforce(&runtime, &target).await.unwrap();
        assert!(matches!(
            second,
            ScanOutcome::Stopped {
                outcome: StopOutcome::Forced,
                ..
            }
        ));
        assert_eq!(runtime.blocked.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.killed.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn global_scanner_capacity_outage_stops_targets_after_bounded_failures() {
        let temporary = tempfile::tempdir().unwrap();
        let runtime = HangingRuntime::default();
        let mut config = test_config();
        config.max_consecutive_scan_failures = 2;
        let limiter = SoftDiskLimiter::new(config);
        let target = SoftDiskTarget {
            instance_id: "inst_capacity_outage".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            protocol: Protocol::Qdrant,
            data_path: temporary.path().to_path_buf(),
            limit_bytes: 128 * 1024 * 1024,
            durable_blocked: false,
        };

        assert!(
            limiter
                .enforce_capacity_outage(&runtime, &target, "all workers wedged".to_string())
                .await
                .is_err()
        );
        let second = limiter
            .enforce_capacity_outage(&runtime, &target, "all workers wedged".to_string())
            .await
            .unwrap();
        assert!(matches!(
            second,
            ScanOutcome::Stopped {
                outcome: StopOutcome::Forced,
                ..
            }
        ));
        assert_eq!(runtime.blocked.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.killed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn qdrant_is_scanned_when_the_node_uses_fuse_quota() {
        assert!(SoftDiskLimiter::enforcement_required(
            DiskLimitMode::FuseQuota,
            Protocol::Qdrant
        ));
        assert!(!SoftDiskLimiter::enforcement_required(
            DiskLimitMode::FuseQuota,
            Protocol::Postgres
        ));
    }

    #[test]
    fn reserve_covers_the_authoritative_full_scan_window_and_qdrant_base_window() {
        let mut config = test_config();
        config.scan_interval_seconds = 10;
        config.use_inotify = true;
        config.full_scan_interval_seconds = 100;
        config.scan_timeout_seconds = 20;
        config.shutdown_grace_seconds = 30;
        let limit = 10 * 1024 * 1024;

        assert_eq!(
            safety_reserve_bytes(&config, Protocol::Postgres, limit, 1_000.0),
            151_000
        );
        assert_eq!(
            safety_reserve_bytes(&config, Protocol::Qdrant, limit, 1_000.0),
            61_000
        );
    }
}
