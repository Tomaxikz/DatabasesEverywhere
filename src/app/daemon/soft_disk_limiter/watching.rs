use crate::{
    daemon::soft_disk_limiter::{
        targets::{RootObservationContext, observe_root_identity},
        watch_operations::{WatchOperation, WatchOperationQueue},
    },
    server::disk::soft::{
        SoftDiskTarget,
        planner::HybridScanPlanner,
        watcher::{RegistrationStatus, SoftDiskWatcher},
    },
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

#[derive(Debug)]
pub(super) enum WatchOperationResult {
    Registered {
        registration: crate::server::disk::soft::watcher::WatchRegistration,
        root_identity: crate::server::disk::soft::planner::RootIdentity,
    },
    Unregistered,
    Retried(crate::server::disk::soft::watcher::RetrySummary),
}

#[derive(Debug)]
pub(super) struct CompletedWatchOperation {
    pub(super) operation: WatchOperation,
    pub(super) result: Result<WatchOperationResult, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WatchRefresh {
    None,
    Target(String),
    All,
}

#[derive(Default)]
pub(super) struct PendingWatchRefresh {
    all: bool,
    targets: HashSet<String>,
}

impl PendingWatchRefresh {
    pub(super) fn include(&mut self, refresh: WatchRefresh) {
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

pub(super) fn dispatch_watch(
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
                    crate::server::disk::soft::usage_tree::root_identity(&desired.root)
                        .map_err(|error| format!("failed to identify watch root: {error}"))?;
                let registration = watcher
                    .register(target_id, &desired.fingerprint, &desired.root)
                    .map_err(|error| error.to_string())?;
                let root_identity =
                    match crate::server::disk::soft::usage_tree::root_identity(&desired.root) {
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

pub(super) fn finish_watch(
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

pub(super) fn refresh_watcher_work(
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
        let trusted = watcher_is_trusted(watcher, watch_queue, &target_id);
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

pub(super) fn watcher_is_trusted(
    watcher: &SoftDiskWatcher,
    watch_queue: &WatchOperationQueue,
    target_id: &str,
) -> bool {
    watch_queue.is_current_desire_confirmed(target_id) && is_watching(watcher, target_id)
}

pub(super) fn is_watching(watcher: &SoftDiskWatcher, target_id: &str) -> bool {
    watcher
        .status(target_id)
        .is_some_and(|status| status.status == RegistrationStatus::Watching)
}
