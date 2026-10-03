use super::*;

pub(super) fn dispatch_due_scans(
    state: &AppState,
    watcher: &Option<Arc<SoftDiskWatcher>>,
    watch_queue: &WatchOperationQueue,
    targets: &HashMap<String, SoftDiskTarget>,
    planner: &mut HybridScanPlanner,
    scans: &mut tokio::task::JoinSet<CompletedSoftDiskScan>,
    now: Duration,
) {
    while scans.len() < state.soft_disk_limiter.max_concurrent_scans() {
        let Some(candidate) = planner.next_candidate(now) else {
            return;
        };
        let Some(target) = targets.get(&candidate.target_id).cloned() else {
            planner.complete(&candidate, now, ScanCompletion::Failed);
            continue;
        };
        let watcher_trusted = watcher
            .as_ref()
            .is_some_and(|watcher| watcher_is_trusted(watcher, watch_queue, &candidate.target_id));
        let batch = watcher_trusted
            .then(|| {
                watcher
                    .as_ref()
                    .and_then(|watcher| watcher.capture(&candidate.target_id))
            })
            .flatten();
        let request = if !watcher_trusted || target.protocol.engine().mmap_writes_bypass_inotify() {
            HybridScanRequest::StreamingFull
        } else if candidate.kind == ScanKind::Full
            || batch
                .as_ref()
                .is_none_or(DirtyBatch::requires_full_reconcile)
        {
            HybridScanRequest::Full
        } else {
            HybridScanRequest::Partial {
                relative_directories: batch
                    .as_ref()
                    .map_or_else(Vec::new, |batch| batch.relative_paths().to_vec()),
            }
        };
        let state = state.clone();
        scans.spawn(async move {
            let started = Instant::now();
            // Serialize supported root mutations with scanning and enforcement.
            let lock_deadline =
                Duration::from_secs(state.config.disk.soft_scanner.scan_timeout_seconds.max(1));
            let _operation = match tokio::time::timeout(
                lock_deadline,
                state.instance_locks.lock(&target.instance_id),
            )
            .await
            {
                Ok(operation) => operation,
                Err(_) => {
                    return CompletedSoftDiskScan {
                        candidate,
                        batch,
                        target,
                        elapsed: started.elapsed(),
                        result: Err(format!(
                            "soft disk scan lifecycle lock was unavailable for {} seconds",
                            lock_deadline.as_secs()
                        )),
                    };
                }
            };
            let runtime = AppStateSoftDiskRuntime {
                state: state.clone(),
                lifecycle_lock_held: true,
            };
            let result = AssertUnwindSafe(
                state
                    .soft_disk_limiter
                    .scan_hybrid_and_enforce(&runtime, &target, request),
            )
            .catch_unwind()
            .await
            .unwrap_or_else(|_| Err("soft disk scan task panicked".to_string()));
            CompletedSoftDiskScan {
                candidate,
                batch,
                target,
                elapsed: started.elapsed(),
                result,
            }
        });
    }
}

pub(super) struct CompletedSoftDiskScan {
    pub(super) candidate: ScanCandidate,
    pub(super) batch: Option<DirtyBatch>,
    pub(super) target: SoftDiskTarget,
    pub(super) elapsed: Duration,
    pub(super) result: Result<HybridScanExecution, String>,
}

pub(super) fn finish_soft_disk_scan(
    result: Result<CompletedSoftDiskScan, tokio::task::JoinError>,
    watcher: &Option<Arc<SoftDiskWatcher>>,
    targets: &HashMap<String, SoftDiskTarget>,
    root_identities: &mut RootIdentityTracker,
    watch_queue: &mut WatchOperationQueue,
    planner: &mut HybridScanPlanner,
    now: Duration,
) {
    match result {
        Ok(completed) => apply_soft_disk_scan(
            completed,
            watcher,
            targets,
            root_identities,
            watch_queue,
            planner,
            now,
        ),
        Err(error) if !error.is_cancelled() => tracing::error!(
            event = "audit soft_disk_scan_task_failed",
            %error,
            "soft disk scan task failed outside its panic boundary"
        ),
        Err(_) => {}
    }
}

pub(super) fn apply_soft_disk_scan(
    completed: CompletedSoftDiskScan,
    watcher: &Option<Arc<SoftDiskWatcher>>,
    targets: &HashMap<String, SoftDiskTarget>,
    root_identities: &mut RootIdentityTracker,
    watch_queue: &mut WatchOperationQueue,
    planner: &mut HybridScanPlanner,
    now: Duration,
) {
    let completion = match &completed.result {
        Ok(execution) if execution.measurement_succeeded => ScanCompletion::Succeeded {
            performed: match execution.performed {
                PerformedScanKind::Full => ScanKind::Full,
                PerformedScanKind::Partial => ScanKind::Partial,
            },
        },
        Ok(_) | Err(_) => ScanCompletion::Failed,
    };
    let disposition = planner.complete(&completed.candidate, now, completion);
    let root_observation = if disposition == CompletionDisposition::Applied
        && matches!(completion, ScanCompletion::Succeeded { .. })
        && let Ok(execution) = &completed.result
        && let Some(identity) = execution.root_identity
    {
        let mut context = RootObservationContext {
            watcher,
            planner,
            targets,
            root_identities,
            watch_queue,
        };
        Some(observe_root_identity(
            &mut context,
            &completed.target.instance_id,
            &completed.target.scanner_fingerprint(),
            identity,
            now,
        ))
    } else {
        None
    };
    if disposition == CompletionDisposition::Applied
        && matches!(completion, ScanCompletion::Succeeded { .. })
        && root_observation == Some(ObservationDisposition::Unchanged)
        && let (Some(watcher), Some(batch)) = (watcher, &completed.batch)
    {
        watcher.acknowledge(batch);
    }

    tracing::debug!(
        instance_id = %completed.target.instance_id,
        protocol = %completed.target.protocol,
        requested_scan = ?completed.candidate.kind,
        scan_reason = ?completed.candidate.reason,
        elapsed_ms = completed.elapsed.as_millis(),
        completion = ?completion,
        disposition = ?disposition,
        "soft disk scanner task completed"
    );
    match completed.result {
        Ok(execution) => log_scan_outcome(&completed.target, execution.outcome),
        Err(error) => tracing::error!(
            event = if crate::server::disk::soft::SoftDiskLimiter::is_capacity_outage(&error) {
                "audit soft_disk_scanner_capacity_outage"
            } else {
                "audit soft_disk_limit_scan_failed"
            },
            instance_id = %completed.target.instance_id,
            protocol = %completed.target.protocol,
            %error,
            "soft disk limiter scan or enforcement failed"
        ),
    }
}

pub(super) fn log_scan_outcome(target: &SoftDiskTarget, outcome: ScanOutcome) {
    match outcome {
        ScanOutcome::Healthy(_) | ScanOutcome::AlreadyBlocked(_) => {}
        ScanOutcome::Warning(snapshot) => tracing::warn!(
            event = "audit soft_disk_limit_warning",
            instance_id = %target.instance_id,
            protocol = %target.protocol,
            physical_bytes = snapshot.usage.physical_bytes,
            logical_bytes = snapshot.usage.logical_bytes,
            limit_bytes = snapshot.limit_bytes,
            growth_bytes_per_second = snapshot.growth_bytes_per_second,
            peak_growth_bytes_per_second = snapshot.peak_growth_bytes_per_second,
            predicted_seconds_to_limit = snapshot.predicted_seconds_to_limit,
            "instance disk usage is approaching its predictive soft-stop threshold"
        ),
        ScanOutcome::Recovered(snapshot) => tracing::info!(
            event = "audit soft_disk_limit_recovered",
            instance_id = %target.instance_id,
            protocol = %target.protocol,
            physical_bytes = snapshot.usage.physical_bytes,
            recovery_threshold_bytes = snapshot.recovery_threshold_bytes,
            "instance disk usage is below hysteresis; an operator may start it again"
        ),
        ScanOutcome::Stopped {
            snapshot,
            outcome: StopOutcome::SkippedStale,
        } => tracing::debug!(
            instance_id = %target.instance_id,
            protocol = %target.protocol,
            physical_bytes = snapshot.usage.physical_bytes,
            "discarded a stale soft disk enforcement decision after instance state changed"
        ),
        ScanOutcome::Stopped { snapshot, outcome } => tracing::error!(
            event = "audit soft_disk_limit_stopped",
            instance_id = %target.instance_id,
            protocol = %target.protocol,
            physical_bytes = snapshot.usage.physical_bytes,
            logical_bytes = snapshot.usage.logical_bytes,
            limit_bytes = snapshot.limit_bytes,
            stop_threshold_bytes = snapshot.stop_threshold_bytes,
            growth_bytes_per_second = snapshot.growth_bytes_per_second,
            peak_growth_bytes_per_second = snapshot.peak_growth_bytes_per_second,
            predicted_seconds_to_limit = snapshot.predicted_seconds_to_limit,
            stop_outcome = match outcome {
                StopOutcome::Graceful => "graceful",
                StopOutcome::Forced => "forced_after_deadline",
                StopOutcome::SkippedStale => unreachable!("handled above"),
            },
            "stopped an instance before soft disk-limit overshoot could consume the host"
        ),
    }
}
