use std::{
    collections::{HashMap, HashSet},
    panic::AssertUnwindSafe,
    sync::Arc,
    time::Instant,
};

use futures::FutureExt;

mod root_identity;
mod runtime;
mod scanning;
mod targets;
mod watch_operations;
mod watching;

use super::*;
use crate::{
    instance::disk::soft::{
        HybridScanExecution, HybridScanRequest, PerformedScanKind, ScanOutcome,
        SoftDiskLimitExceeded, SoftDiskRuntime, SoftDiskTarget, StopOutcome,
        planner::{
            CompletionDisposition, HybridScanPlanner, PlannerConfig, ScanCandidate, ScanCompletion,
            ScanKind, TargetSpec,
        },
        watcher::{DirtyBatch, RegistrationStatus, SoftDiskWatcher},
    },
    instance::metadata::DesiredInstanceState,
};
use root_identity::{ObservationDisposition, RootIdentityTracker, watch_fingerprint};
use scanning::*;
use targets::*;
use watch_operations::{DesiredWatch, WatchOperation, WatchOperationQueue};
use watching::*;

pub(super) use runtime::*;

const GRACEFUL_STOP_TIMEOUT_PADDING: Duration = Duration::from_secs(5);

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

    sync_soft_disk_targets(
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
            finish_soft_disk_scan(
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
            forced_watch_refresh.include(finish_watch(
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
        dispatch_watch(
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
            finish_soft_disk_scan(
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
            forced_watch_refresh.include(finish_watch(
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
            sync_soft_disk_targets(
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

async fn wait_for_watcher_change(watcher: &Option<Arc<SoftDiskWatcher>>, observed: u64) -> u64 {
    match watcher {
        Some(watcher) => watcher.changed_after(observed).await,
        None => std::future::pending().await,
    }
}
