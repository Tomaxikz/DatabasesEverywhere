use std::{
    collections::{HashMap, HashSet},
    panic::AssertUnwindSafe,
    sync::Arc,
    time::Instant,
};

use futures::FutureExt;

mod root_identity;
mod watch_operations;

use super::*;
use crate::{
    disk::soft::{
        HybridScanExecution, HybridScanRequest, PerformedScanKind, ScanOutcome,
        SoftDiskLimitExceeded, SoftDiskRuntime, SoftDiskTarget, StopOutcome,
        planner::{
            CompletionDisposition, HybridScanPlanner, PlannerConfig, ScanCandidate, ScanCompletion,
            ScanKind, TargetSpec,
        },
        watcher::{DirtyBatch, RegistrationStatus, SoftDiskWatcher},
    },
    instances::metadata::DesiredInstanceState,
};
use root_identity::{ObservationDisposition, RootIdentityTracker, watch_fingerprint};
use watch_operations::{DesiredWatch, WatchOperation, WatchOperationQueue};

pub(super) async fn monitor_soft_disk_limits(state: AppState) {
    let scanner = &state.config.disk.soft_scanner;
    let base_interval = state.soft_disk_limiter.scan_interval();
    let mut watcher = scanner
        .use_inotify
        .then(|| Arc::new(SoftDiskWatcher::new(scanner.max_dirty_paths_per_instance)));
    if let Some(watcher) = &watcher {
        tracing::info!(
            event = "soft_disk_watcher_initialized",
            backend_available = watcher.backend_available(),
            max_dirty_paths_per_instance = scanner.max_dirty_paths_per_instance,
            "soft disk inotify acceleration initialized; periodic full scans remain authoritative"
        );
    } else {
        tracing::info!(
            event = "soft_disk_watcher_disabled",
            "soft disk limiter will use periodic authoritative full scans"
        );
    }

    let monitor_started = Instant::now();
    let mut planner = HybridScanPlanner::new(PlannerConfig {
        scan_interval: base_interval,
        full_scan_interval: Duration::from_secs(scanner.full_scan_interval_seconds.max(1)),
        debounce: Duration::from_millis(scanner.inotify_debounce_milliseconds.max(1)),
        watcher_enabled: watcher.is_some(),
    });
    let mut shutdown = state.daemon_shutdown.subscribe();
    let mut ticker = tokio::time::interval(base_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The explicit reconcile below replaces Tokio's immediate first tick.
    ticker.tick().await;
    let mut targets = HashMap::<String, SoftDiskTarget>::new();
    let mut root_identities = RootIdentityTracker::default();
    let mut watch_queue = WatchOperationQueue::default();
    let mut watch_tasks = tokio::task::JoinSet::<CompletedWatchOperation>::new();
    let mut forced_watch_refresh = PendingWatchRefresh::default();
    let mut scans = tokio::task::JoinSet::<CompletedSoftDiskScan>::new();
    let mut observed_watcher_sequence = watcher
        .as_ref()
        .map_or(0, |watcher| watcher.current_change_sequence());

    reconcile_soft_disk_targets(
        &state,
        &watcher,
        &mut planner,
        &mut targets,
        &mut root_identities,
        &mut watch_queue,
        monitor_started.elapsed(),
    )
    .await;
    observed_watcher_sequence = refresh_watcher_work(
        &watcher,
        &mut planner,
        &targets,
        &watch_queue,
        &mut forced_watch_refresh,
        monitor_started.elapsed(),
        observed_watcher_sequence,
    );

    loop {
        while let Some(result) = scans.try_join_next() {
            complete_soft_disk_scan_task(
                result,
                &watcher,
                &targets,
                &mut root_identities,
                &mut watch_queue,
                &mut planner,
                monitor_started.elapsed(),
            );
        }
        while let Some(result) = watch_tasks.try_join_next() {
            forced_watch_refresh.include(complete_watch_operation(
                result,
                RootObservationContext {
                    watcher: &watcher,
                    planner: &mut planner,
                    targets: &targets,
                    root_identities: &mut root_identities,
                    watch_queue: &mut watch_queue,
                },
                monitor_started.elapsed(),
                base_interval,
            ));
        }
        observed_watcher_sequence = refresh_watcher_work(
            &watcher,
            &mut planner,
            &targets,
            &watch_queue,
            &mut forced_watch_refresh,
            monitor_started.elapsed(),
            observed_watcher_sequence,
        );
        dispatch_watch_operation(
            &watcher,
            &mut watch_queue,
            &mut watch_tasks,
            monitor_started.elapsed(),
        );
        dispatch_due_scans(
            &state,
            &watcher,
            &watch_queue,
            &targets,
            &mut planner,
            &mut scans,
            monitor_started.elapsed(),
        );
        let planner_delay = if scans.len() < state.soft_disk_limiter.max_concurrent_scans() {
            planner
                .next_wakeup(monitor_started.elapsed())
                .unwrap_or(base_interval)
                .min(base_interval)
        } else {
            base_interval
        };
        let mut reconcile = false;
        let mut completed = None;
        let mut watch_completed = None;

        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    planner.shutdown();
                    scans.abort_all();
                    watch_tasks.abort_all();
                    return;
                }
            }
            result = scans.join_next(), if !scans.is_empty() => completed = result,
            result = watch_tasks.join_next(), if !watch_tasks.is_empty() => watch_completed = result,
            _ = ticker.tick() => {
                reconcile = true;
            }
            sequence = wait_for_watcher_change(&watcher, observed_watcher_sequence), if watcher.is_some() => {
                observed_watcher_sequence = sequence;
            }
            _ = tokio::time::sleep(planner_delay) => {}
        }

        if let Some(result) = completed {
            complete_soft_disk_scan_task(
                result,
                &watcher,
                &targets,
                &mut root_identities,
                &mut watch_queue,
                &mut planner,
                monitor_started.elapsed(),
            );
        }
        if let Some(result) = watch_completed {
            forced_watch_refresh.include(complete_watch_operation(
                result,
                RootObservationContext {
                    watcher: &watcher,
                    planner: &mut planner,
                    targets: &targets,
                    root_identities: &mut root_identities,
                    watch_queue: &mut watch_queue,
                },
                monitor_started.elapsed(),
                base_interval,
            ));
        }
        if reconcile {
            reconcile_soft_disk_targets(
                &state,
                &watcher,
                &mut planner,
                &mut targets,
                &mut root_identities,
                &mut watch_queue,
                monitor_started.elapsed(),
            )
            .await;
        }
        observed_watcher_sequence = refresh_watcher_work(
            &watcher,
            &mut planner,
            &targets,
            &watch_queue,
            &mut forced_watch_refresh,
            monitor_started.elapsed(),
            observed_watcher_sequence,
        );
        if let Some(operation) = watch_queue.take_stalled(
            monitor_started.elapsed(),
            Duration::from_secs(scanner.scan_timeout_seconds.max(1)),
        ) {
            tracing::warn!(
                event = "soft_disk_watcher_operation_stalled",
                operation = operation.kind(),
                target_id = operation.target_id().unwrap_or("<all>"),
                "kernel watch operation exceeded its deadline; disabling inotify acceleration and retaining periodic full scans"
            );
            watch_tasks.abort_all();
            watch_queue.disable();
            watcher = None;
            for target_id in targets.keys() {
                planner.set_watcher_trusted(target_id, false, monitor_started.elapsed());
                state.soft_disk_limiter.evict_usage_cache(target_id).await;
            }
            observed_watcher_sequence = 0;
        }
    }
}

async fn reconcile_soft_disk_targets(
    state: &AppState,
    watcher: &Option<Arc<SoftDiskWatcher>>,
    planner: &mut HybridScanPlanner,
    targets: &mut HashMap<String, SoftDiskTarget>,
    root_identities: &mut RootIdentityTracker,
    watch_queue: &mut WatchOperationQueue,
    now: Duration,
) {
    let mut current = HashMap::new();
    for metadata in state.instances.list().await {
        if !matches!(
            metadata.status,
            InstanceStatus::Running | InstanceStatus::Booting
        ) || !(crate::disk::soft::SoftDiskLimiter::enforcement_required(
            state.config.disk.mode,
            metadata.protocol,
        ) || (metadata.protocol == Protocol::Qdrant
            && metadata.limits.disk_enforcement_method == "fuse_quota"))
        {
            continue;
        }
        let paths = match InstancePaths::new(&state.config.paths, &metadata.instance_id) {
            Ok(paths) => paths,
            Err(error) => {
                tracing::error!(
                    event = "audit soft_disk_scan_invalid_path",
                    instance_id = %metadata.instance_id,
                    %error,
                    "soft disk limiter could not construct the instance path"
                );
                continue;
            }
        };
        let target = SoftDiskTarget {
            instance_id: metadata.instance_id,
            created_at: metadata.created_at,
            protocol: metadata.protocol,
            data_path: paths.data,
            limit_bytes: metadata.limits.disk_mib.saturating_mul(1024 * 1024),
            durable_blocked: metadata.disk_limit_blocked,
        };
        let target_id = target.instance_id.clone();
        let scanner_fingerprint = target.scanner_fingerprint();
        current.insert(target_id.clone(), scanner_fingerprint.clone());
        let root_identity = root_identities.identity_for(&target_id, &scanner_fingerprint);
        let watch_fingerprint = watch_fingerprint(&scanner_fingerprint, root_identity);
        if watcher.is_some() && target.protocol != Protocol::Qdrant {
            watch_queue.upsert(
                target_id.clone(),
                DesiredWatch {
                    fingerprint: watch_fingerprint.clone(),
                    target_fingerprint: scanner_fingerprint.clone(),
                    root: target.data_path.clone(),
                },
            );
        } else if target.protocol == Protocol::Qdrant {
            let retired = watcher
                .as_ref()
                .and_then(|watcher| watcher.retire(&target_id));
            watch_queue.remove(&target_id, retired);
        }
        let watcher_trusted = target.protocol != Protocol::Qdrant
            && watcher.as_ref().is_some_and(|watcher| {
                watch_queue.is_confirmed(&target_id, &watch_fingerprint)
                    && watcher
                        .status(&target_id)
                        .is_some_and(|status| status.status == RegistrationStatus::Watching)
            });
        planner.upsert_target(
            now,
            TargetSpec {
                id: target_id.clone(),
                fingerprint: scanner_fingerprint,
                root_identity,
                enabled: true,
                watcher_trusted,
                force_periodic_full: target.protocol == Protocol::Qdrant,
            },
        );
        targets.insert(target_id, target);
    }

    let removed = targets
        .keys()
        .filter(|target_id| !current.contains_key(*target_id))
        .cloned()
        .collect::<Vec<_>>();
    for target_id in removed {
        targets.remove(&target_id);
        planner.remove_target(&target_id);
        let retired = watcher
            .as_ref()
            .and_then(|watcher| watcher.retire(&target_id));
        watch_queue.remove(&target_id, retired);
        // Preserve stop hysteresis while releasing the large usage tree.
        state.soft_disk_limiter.evict_usage_cache(&target_id).await;
    }

    root_identities.retain_targets(&current);

    if watcher.is_some() {
        watch_queue.request_retry();
    }
}

struct RootObservationContext<'a> {
    watcher: &'a Option<Arc<SoftDiskWatcher>>,
    planner: &'a mut HybridScanPlanner,
    targets: &'a HashMap<String, SoftDiskTarget>,
    root_identities: &'a mut RootIdentityTracker,
    watch_queue: &'a mut WatchOperationQueue,
}

fn observe_root_identity(
    context: &mut RootObservationContext<'_>,
    target_id: &str,
    completed_fingerprint: &str,
    identity: crate::disk::soft::planner::RootIdentity,
    now: Duration,
) -> ObservationDisposition {
    let Some(target) = context.targets.get(target_id) else {
        return ObservationDisposition::StaleTarget;
    };
    let current_fingerprint = target.scanner_fingerprint();
    let disposition = context.root_identities.observe(
        target_id,
        completed_fingerprint,
        &current_fingerprint,
        identity,
    );
    if !matches!(
        disposition,
        ObservationDisposition::Initialized | ObservationDisposition::Replaced
    ) {
        return disposition;
    }

    if context.watcher.is_some() && target.protocol != Protocol::Qdrant {
        context.watch_queue.upsert(
            target_id.to_string(),
            DesiredWatch {
                fingerprint: watch_fingerprint(&current_fingerprint, Some(identity)),
                target_fingerprint: current_fingerprint.clone(),
                root: target.data_path.clone(),
            },
        );
    }
    context.planner.upsert_target(
        now,
        TargetSpec {
            id: target_id.to_string(),
            fingerprint: current_fingerprint,
            root_identity: Some(identity),
            enabled: true,
            // A replaced root stays untrusted until its watch and baseline agree.
            watcher_trusted: false,
            force_periodic_full: target.protocol == Protocol::Qdrant,
        },
    );
    tracing::info!(
        event = "soft_disk_root_identity_changed",
        instance_id = target_id,
        replacement = disposition == ObservationDisposition::Replaced,
        "soft disk root identity changed; invalidated stale scans and requested a new watch-bound full baseline"
    );
    disposition
}

#[derive(Debug)]
enum WatchOperationResult {
    Registered {
        registration: crate::disk::soft::watcher::WatchRegistration,
        root_identity: crate::disk::soft::planner::RootIdentity,
    },
    Unregistered,
    Retried(crate::disk::soft::watcher::RetrySummary),
}

#[derive(Debug)]
struct CompletedWatchOperation {
    operation: WatchOperation,
    result: Result<WatchOperationResult, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WatchRefresh {
    None,
    Target(String),
    All,
}

#[derive(Default)]
struct PendingWatchRefresh {
    all: bool,
    targets: HashSet<String>,
}

impl PendingWatchRefresh {
    fn include(&mut self, refresh: WatchRefresh) {
        match refresh {
            WatchRefresh::None => {}
            WatchRefresh::Target(target_id) if !self.all => {
                self.targets.insert(target_id);
            }
            WatchRefresh::Target(_) => {}
            WatchRefresh::All => {
                self.all = true;
                self.targets.clear();
            }
        }
    }

    fn take_targets(&mut self, current: &HashMap<String, SoftDiskTarget>) -> HashSet<String> {
        if std::mem::take(&mut self.all) {
            self.targets.clear();
            current.keys().cloned().collect()
        } else {
            std::mem::take(&mut self.targets)
        }
    }
}

fn dispatch_watch_operation(
    watcher: &Option<Arc<SoftDiskWatcher>>,
    queue: &mut WatchOperationQueue,
    tasks: &mut tokio::task::JoinSet<CompletedWatchOperation>,
    now: Duration,
) {
    let Some(watcher) = watcher else {
        return;
    };
    let Some(operation) = queue.next(now) else {
        return;
    };
    let worker_operation = operation.clone();
    let watcher = Arc::clone(watcher);
    tasks.spawn(async move {
        let result = tokio::task::spawn_blocking(move || match &worker_operation {
            WatchOperation::Register { target_id, desired } => {
                let opened_identity =
                    crate::disk::soft::usage_tree::root_identity(&desired.root)
                        .map_err(|error| format!("failed to identify watch root: {error}"))?;
                let registration = watcher
                    .register(target_id, &desired.fingerprint, &desired.root)
                    .map_err(|error| error.to_string())?;
                let root_identity =
                    match crate::disk::soft::usage_tree::root_identity(&desired.root) {
                        Ok(identity) => identity,
                        Err(error) => {
                            if let Some(retired) = watcher.retire(target_id) {
                                watcher.unwatch_retired(&retired);
                            }
                            return Err(format!("failed to identify watched root: {error}"));
                        }
                    };
                if root_identity != opened_identity {
                    if let Some(retired) = watcher.retire(target_id) {
                        watcher.unwatch_retired(&retired);
                    }
                    return Err("watch root was replaced during registration".to_string());
                }
                Ok(WatchOperationResult::Registered {
                    registration,
                    root_identity,
                })
            }
            WatchOperation::Unregister { retired, .. } => {
                watcher.unwatch_retired(retired);
                Ok(WatchOperationResult::Unregistered)
            }
            WatchOperation::RetryDegraded => {
                Ok(WatchOperationResult::Retried(watcher.retry_degraded()))
            }
        })
        .await
        .map_err(|error| format!("watch operation worker failed: {error}"))
        .and_then(|result| result);
        CompletedWatchOperation { operation, result }
    });
}

fn complete_watch_operation(
    completed: Result<CompletedWatchOperation, tokio::task::JoinError>,
    mut context: RootObservationContext<'_>,
    now: Duration,
    retry_delay: Duration,
) -> WatchRefresh {
    let completed = match completed {
        Ok(completed) => completed,
        Err(error) => {
            let operation = context.watch_queue.fail_active(now, retry_delay);
            tracing::error!(
                event = "soft_disk_watcher_operation_task_failed",
                operation = operation.as_ref().map_or("<unknown>", WatchOperation::kind),
                target_id = operation
                    .as_ref()
                    .and_then(WatchOperation::target_id)
                    .unwrap_or("<all>"),
                %error,
                "watch operation task failed; periodic full scanning remains active"
            );
            return operation
                .and_then(|operation| operation.target_id().map(str::to_string))
                .map_or(WatchRefresh::All, WatchRefresh::Target);
        }
    };

    let refresh = match &completed.operation {
        WatchOperation::Register { target_id, .. } => WatchRefresh::Target(target_id.clone()),
        WatchOperation::Unregister { .. } => WatchRefresh::None,
        WatchOperation::RetryDegraded => WatchRefresh::All,
    };

    let retirement_target = match &completed.operation {
        WatchOperation::Register { target_id, .. }
            if context.watch_queue.retirement_pending(target_id) =>
        {
            Some(target_id.clone())
        }
        _ => None,
    };
    let succeeded = match (&completed.operation, &completed.result) {
        (
            WatchOperation::Register { target_id, desired },
            Ok(WatchOperationResult::Registered { registration, .. }),
        ) => {
            retirement_target.is_none()
                && registration.status == RegistrationStatus::Watching
                && context
                    .watcher
                    .as_ref()
                    .is_some_and(|watcher| watcher.is_watching(target_id, &desired.fingerprint))
        }
        (_, Ok(_)) => true,
        (_, Err(_)) => false,
    };
    let current_registration = context
        .watch_queue
        .is_current_registration(&completed.operation);
    if !context
        .watch_queue
        .complete(&completed.operation, succeeded, now, retry_delay)
    {
        tracing::warn!(
            event = "soft_disk_watcher_stale_operation_result",
            operation = completed.operation.kind(),
            target_id = completed.operation.target_id().unwrap_or("<all>"),
            "ignored a stale watch operation result"
        );
        return refresh;
    }
    if succeeded
        && current_registration
        && let (
            WatchOperation::Register { target_id, desired },
            Ok(WatchOperationResult::Registered { root_identity, .. }),
        ) = (&completed.operation, &completed.result)
    {
        observe_root_identity(
            &mut context,
            target_id,
            &desired.target_fingerprint,
            *root_identity,
            now,
        );
    }
    if let Some(target_id) = retirement_target {
        let retired = context
            .watcher
            .as_ref()
            .and_then(|watcher| watcher.retire(&target_id));
        context.watch_queue.resolve_retirement(&target_id, retired);
    }

    match completed.result {
        Ok(WatchOperationResult::Registered { registration, .. }) => {
            if registration.changed && registration.status == RegistrationStatus::Degraded {
                tracing::warn!(
                    event = "soft_disk_watcher_degraded",
                    target_id = completed.operation.target_id().unwrap_or("<all>"),
                    "inotify registration is unavailable; periodic full scanning is active"
                );
            }
        }
        Ok(WatchOperationResult::Unregistered) => {}
        Ok(WatchOperationResult::Retried(summary)) if summary.restored > 0 => tracing::info!(
            event = "soft_disk_watcher_recovered",
            restored_targets = summary.restored,
            still_degraded_targets = summary.still_degraded,
            "soft disk watcher registrations recovered; full baselines were requested"
        ),
        Ok(WatchOperationResult::Retried(summary)) if summary.attempted > 0 => tracing::warn!(
            event = "soft_disk_watcher_retry_failed",
            attempted_targets = summary.attempted,
            still_degraded_targets = summary.still_degraded,
            backend_available = summary.backend_available,
            "soft disk watcher remains degraded; periodic full scanning is active"
        ),
        Ok(WatchOperationResult::Retried(_)) => {}
        Err(error) => tracing::error!(
            event = "soft_disk_watcher_operation_failed",
            operation = completed.operation.kind(),
            target_id = completed.operation.target_id().unwrap_or("<all>"),
            %error,
            "watch operation failed; periodic full scanning remains active"
        ),
    }
    refresh
}

fn refresh_watcher_work(
    watcher: &Option<Arc<SoftDiskWatcher>>,
    planner: &mut HybridScanPlanner,
    targets: &HashMap<String, SoftDiskTarget>,
    watch_queue: &WatchOperationQueue,
    forced: &mut PendingWatchRefresh,
    now: Duration,
    previous_sequence: u64,
) -> u64 {
    let Some(watcher) = watcher else {
        forced.all = false;
        forced.targets.clear();
        return previous_sequence;
    };
    let changes = watcher.drain_changes();
    let mut changed_targets = forced.take_targets(targets);
    if changes.is_empty() && changed_targets.is_empty() {
        return changes.sequence;
    }
    if changes.global_reconcile {
        changed_targets.extend(targets.keys().cloned());
    } else {
        changed_targets.extend(changes.target_ids);
    }
    for target_id in changed_targets {
        if !targets.contains_key(&target_id) {
            continue;
        }
        let trusted = watch_queue.is_current_desire_confirmed(&target_id)
            && watcher
                .status(&target_id)
                .is_some_and(|status| status.status == RegistrationStatus::Watching);
        planner.set_watcher_trusted(&target_id, trusted, now);
        if !trusted {
            continue;
        }
        let Some(batch) = watcher.capture(&target_id) else {
            continue;
        };
        if batch.requires_full_reconcile() {
            planner.mark_overflow(&target_id, now, batch.generation());
        } else {
            planner.mark_dirty(&target_id, now, batch.generation());
        }
    }
    changes.sequence
}

fn dispatch_due_scans(
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
        let watcher_trusted = watcher.as_ref().is_some_and(|watcher| {
            watch_queue.is_current_desire_confirmed(&candidate.target_id)
                && watcher
                    .status(&candidate.target_id)
                    .is_some_and(|status| status.status == RegistrationStatus::Watching)
        });
        let batch = watcher_trusted
            .then(|| {
                watcher
                    .as_ref()
                    .and_then(|watcher| watcher.capture(&candidate.target_id))
            })
            .flatten();
        let request = if !watcher_trusted || target.protocol == Protocol::Qdrant {
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

struct CompletedSoftDiskScan {
    candidate: ScanCandidate,
    batch: Option<DirtyBatch>,
    target: SoftDiskTarget,
    elapsed: Duration,
    result: Result<HybridScanExecution, String>,
}

fn complete_soft_disk_scan_task(
    result: Result<CompletedSoftDiskScan, tokio::task::JoinError>,
    watcher: &Option<Arc<SoftDiskWatcher>>,
    targets: &HashMap<String, SoftDiskTarget>,
    root_identities: &mut RootIdentityTracker,
    watch_queue: &mut WatchOperationQueue,
    planner: &mut HybridScanPlanner,
    now: Duration,
) {
    match result {
        Ok(completed) => complete_soft_disk_scan(
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

fn complete_soft_disk_scan(
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
            event = if crate::disk::soft::SoftDiskLimiter::is_capacity_outage(&error) {
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

fn log_scan_outcome(target: &SoftDiskTarget, outcome: ScanOutcome) {
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

async fn wait_for_watcher_change(watcher: &Option<Arc<SoftDiskWatcher>>, observed: u64) -> u64 {
    match watcher {
        Some(watcher) => watcher.changed_after(observed).await,
        None => std::future::pending().await,
    }
}

#[derive(Clone)]
struct AppStateSoftDiskRuntime {
    state: AppState,
    lifecycle_lock_held: bool,
}

impl AppStateSoftDiskRuntime {
    fn target_is_current(
        &self,
        metadata: &crate::instances::metadata::InstanceMetadata,
        target: &SoftDiskTarget,
    ) -> bool {
        soft_disk_target_is_current(metadata, target, self.state.config.disk.mode)
    }
}

pub(super) fn soft_disk_target_is_current(
    metadata: &crate::instances::metadata::InstanceMetadata,
    target: &SoftDiskTarget,
    global_mode: crate::config::DiskLimitMode,
) -> bool {
    let monitoring_required =
        crate::disk::soft::SoftDiskLimiter::enforcement_required(global_mode, metadata.protocol)
            || (metadata.protocol == Protocol::Qdrant
                && metadata.limits.disk_enforcement_method == "fuse_quota");
    metadata.instance_id == target.instance_id
        && metadata.created_at == target.created_at
        && metadata.protocol == target.protocol
        && matches!(
            metadata.status,
            InstanceStatus::Running | InstanceStatus::Booting
        )
        && metadata.limits.disk_mib.saturating_mul(1024 * 1024) == target.limit_bytes
        && monitoring_required
}

impl SoftDiskRuntime for AppStateSoftDiskRuntime {
    fn mark_disk_blocked<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
        exceeded: &'a SoftDiskLimitExceeded,
    ) -> crate::disk::soft::RuntimeFuture<'a> {
        Box::pin(async move {
            let _operation = if self.lifecycle_lock_held {
                None
            } else {
                Some(self.state.instance_locks.lock(&target.instance_id).await)
            };
            let Some(mut metadata) = self.state.instances.get(&target.instance_id).await else {
                return Ok(());
            };
            if !self.target_is_current(&metadata, target) {
                return Ok(());
            }
            metadata.desired_state = DesiredInstanceState::Stopped;
            metadata.disk_limit_blocked = true;
            metadata.updated_at = now_rfc3339();
            self.state
                .manager
                .upsert(metadata)
                .await
                .map_err(|error| format!("failed to persist disk-limit stop intent: {error}"))?;
            tracing::warn!(
                event = "audit soft_disk_restart_blocked",
                instance_id = %target.instance_id,
                protocol = %target.protocol,
                physical_bytes = exceeded.snapshot.usage.physical_bytes,
                stop_threshold_bytes = exceeded.snapshot.stop_threshold_bytes,
                recovery_threshold_bytes = exceeded.snapshot.recovery_threshold_bytes,
                block_reason = exceeded.reason.as_str(),
                scan_error = exceeded.reason.scan_error(),
                "persisted an intentional stopped state until disk usage recovers"
            );
            Ok(())
        })
    }

    fn graceful_stop<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
        grace: Duration,
    ) -> crate::disk::soft::RuntimeFuture<'a> {
        Box::pin(async move {
            // Leave the exact stop deadline and SIGKILL fallback to the supervisor.
            match self
                .state
                .docker
                .stop_with_timeout(
                    target.protocol,
                    &target.instance_id,
                    grace.saturating_add(Duration::from_secs(5)),
                )
                .await
            {
                Ok(_) => Ok(()),
                Err(error) if error.is_not_found() || error.is_not_running() => Ok(()),
                Err(error) => Err(error.to_string()),
            }
        })
    }

    fn force_kill<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
    ) -> crate::disk::soft::RuntimeFuture<'a> {
        Box::pin(async move {
            match self
                .state
                .docker
                .kill(target.protocol, &target.instance_id)
                .await
            {
                Ok(_) => Ok(()),
                Err(error) if error.is_not_found() || error.is_not_running() => Ok(()),
                Err(error) => Err(error.to_string()),
            }
        })
    }

    fn clear_disk_blocked<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
    ) -> crate::disk::soft::RuntimeFuture<'a> {
        Box::pin(async move {
            let _operation = if self.lifecycle_lock_held {
                None
            } else {
                Some(self.state.instance_locks.lock(&target.instance_id).await)
            };
            let Some(mut metadata) = self.state.instances.get(&target.instance_id).await else {
                return Ok(());
            };
            if !self.target_is_current(&metadata, target) || !metadata.disk_limit_blocked {
                return Ok(());
            }
            metadata.disk_limit_blocked = false;
            metadata.updated_at = now_rfc3339();
            self.state
                .manager
                .upsert(metadata)
                .await
                .map_err(|error| format!("failed to clear durable disk-limit block: {error}"))
        })
    }

    fn enforce_disk_stop<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
        exceeded: &'a SoftDiskLimitExceeded,
        grace: Duration,
    ) -> crate::disk::soft::StopRuntimeFuture<'a> {
        Box::pin(async move {
            // Keep Start serialized through durable intent and runtime shutdown.
            let _operation = if self.lifecycle_lock_held {
                None
            } else {
                Some(self.state.instance_locks.lock(&target.instance_id).await)
            };
            let Some(mut metadata) = self.state.instances.get(&target.instance_id).await else {
                return Ok(StopOutcome::Graceful);
            };
            if !self.target_is_current(&metadata, target) {
                return Ok(StopOutcome::SkippedStale);
            }
            metadata.desired_state = DesiredInstanceState::Stopped;
            metadata.disk_limit_blocked = true;
            metadata.updated_at = now_rfc3339();
            self.state
                .manager
                .upsert(metadata)
                .await
                .map_err(|error| format!("failed to persist disk-limit stop intent: {error}"))?;
            tracing::warn!(
                event = "audit soft_disk_restart_blocked",
                instance_id = %target.instance_id,
                protocol = %target.protocol,
                physical_bytes = exceeded.snapshot.usage.physical_bytes,
                stop_threshold_bytes = exceeded.snapshot.stop_threshold_bytes,
                recovery_threshold_bytes = exceeded.snapshot.recovery_threshold_bytes,
                block_reason = exceeded.reason.as_str(),
                scan_error = exceeded.reason.scan_error(),
                "persisted an intentional stopped state until disk usage recovers"
            );
            crate::disk::soft::stop_with_kill_fallback(self, target, grace).await
        })
    }
}
