use std::{path::PathBuf, sync::Arc, time::Duration};

use super::{
    MAX_SCAN_DEPTH, OUTER_SCAN_DEADLINE_SLACK, ScanMeasurement, SoftDiskLimiter,
    cache::{TargetFingerprint, UsageTreeSlot, UsageTreeSlotState, UsageTreeState},
    types::{
        HybridScanExecution, HybridScanRequest, PerformedScanKind, ScanOutcome,
        SoftDiskBlockReason, SoftDiskLimitExceeded, SoftDiskRuntime, SoftDiskSnapshot,
        SoftDiskTarget,
    },
    usage_tree,
};
use crate::server::disk::usage::{DirectoryUsage, ScanLimits, scan_directory_with_id};

impl SoftDiskLimiter {
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
                return Ok(HybridScanExecution::unmeasured(outcome));
            }
            Err(ScanFailure::Measurement(error)) => {
                let outcome = self.enforce_unmeasurable(runtime, target, error).await?;
                return Ok(HybridScanExecution::unmeasured(outcome));
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
    ) -> Result<ScanMeasurement, ScanFailure> {
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
            && !target.protocol.engine().mmap_writes_bypass_inotify()
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
            max_depth: MAX_SCAN_DEPTH,
        };
        let per_target_cache_limit = self
            .usage_cache_limits
            .per_target_directories
            .min(limits.max_entries.saturating_add(1));
        // A wedged worker keeps its permit, bounding leaked blocking workers.
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let Some(slot) = cache else {
                return streaming_full_scan(&scan_path, limits);
            };
            let mut state = slot
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.streaming_only {
                return streaming_full_scan(&scan_path, limits);
            }
            let cached_scan = CachedScan {
                slot: &slot,
                scan_path: &scan_path,
                generation,
                limits,
                per_target_cache_limit,
            };
            match request {
                HybridScanRequest::StreamingFull => streaming_full_scan(&scan_path, limits),
                HybridScanRequest::Full => cached_scan.full(&mut state),
                HybridScanRequest::Partial {
                    relative_directories,
                } => cached_scan.partial(&mut state, &relative_directories),
            }
        });
        let outer_deadline = scan_timeout.saturating_add(OUTER_SCAN_DEADLINE_SLACK);
        tokio::time::timeout(outer_deadline, worker)
            .await
            .map_err(|_| {
                ScanFailure::Measurement(format!(
                    "soft disk scan of {} exceeded its outer {} second deadline",
                    target.data_path.display(),
                    outer_deadline.as_secs()
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
            .or_insert_with(|| self.new_usage_tree_state(fingerprint.clone()));
        if state.target != fingerprint {
            *state = self.new_usage_tree_state(fingerprint);
        }
        Arc::clone(&state.slot)
    }

    fn new_usage_tree_state(&self, target: TargetFingerprint) -> UsageTreeState {
        UsageTreeState {
            target,
            slot: Arc::new(UsageTreeSlot::new(
                Arc::clone(&self.cached_directories),
                self.usage_cache_limits.global_directories,
            )),
        }
    }

    pub(crate) async fn evict_usage_cache(&self, instance_id: &str) {
        self.usage_trees.lock().await.remove(instance_id);
    }
}

fn streaming_full_scan(
    scan_path: &std::path::Path,
    limits: ScanLimits,
) -> Result<ScanMeasurement, std::io::Error> {
    scan_directory_with_id(scan_path, limits)
        .map(|(usage, identity)| (usage, PerformedScanKind::Full, identity))
}

struct CachedScan<'a> {
    pub(super) slot: &'a UsageTreeSlot,
    scan_path: &'a std::path::Path,
    pub(super) generation: String,
    pub(super) limits: ScanLimits,
    per_target_cache_limit: usize,
}

impl CachedScan<'_> {
    pub(super) fn full(
        self,
        state: &mut UsageTreeSlotState,
    ) -> Result<ScanMeasurement, std::io::Error> {
        match usage_tree::UsageTreeCache::scan_full_bounded(
            self.scan_path,
            self.generation,
            self.limits,
            self.per_target_cache_limit,
        )? {
            usage_tree::BoundedFullScan::Cached(replacement) => {
                let identity = replacement.root_identity();
                if self.slot.install_cache(state, replacement) {
                    let usage = state
                        .cache
                        .as_ref()
                        .map_or_else(DirectoryUsage::default, usage_tree::UsageTreeCache::usage);
                    return Ok((usage, PerformedScanKind::Full, identity));
                }
            }
            usage_tree::BoundedFullScan::DirectoryLimitExceeded => {
                self.slot.switch_to_streaming(state);
            }
        }
        streaming_full_scan(self.scan_path, self.limits)
    }

    pub(super) fn partial(
        self,
        state: &mut UsageTreeSlotState,
        relative_directories: &[PathBuf],
    ) -> Result<ScanMeasurement, std::io::Error> {
        let reconcile = state.cache.as_mut().map(|existing| {
            existing.reconcile(
                self.scan_path,
                &self.generation,
                relative_directories,
                self.limits,
            )
        });
        match reconcile {
            Some(Ok(usage)) => {
                let identity = state
                    .cache
                    .as_ref()
                    .expect("successful reconciliation retains its cache")
                    .root_identity();
                self.slot.account_reconciled_cache(state);
                Ok((usage, PerformedScanKind::Partial, identity))
            }
            Some(Err(usage_tree::ReconcileError::Io(error))) => Err(error),
            Some(Err(usage_tree::ReconcileError::FullScanRequired(_))) | None => self.full(state),
        }
    }
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
