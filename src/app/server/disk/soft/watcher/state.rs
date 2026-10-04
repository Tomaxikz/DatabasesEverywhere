use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(test)]
use std::sync::Barrier;

use notify::{Event, EventKind, RecommendedWatcher};
use tokio::sync::Notify;

use super::helpers::{
    is_strict_descendant, lock_recover, nearest_recorded_ancestor, next_nonzero,
    root_watch_may_be_lost, route_path, safe_relative_parent,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WatchHealth {
    Watching,
    Degraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecursiveWatchInstall {
    Installed,
    FailedCleanly,
    BackendContaminated,
}

pub(super) struct TargetState {
    pub(super) fingerprint: String,
    pub(super) root: PathBuf,
    pub(super) registration_generation: u64,
    pub(super) target_generation: u64,
    pub(super) full_generation: Option<u64>,
    pub(super) dirty_paths: BTreeMap<PathBuf, u64>,
    pub(super) acknowledged_global_generation: u64,
    pub(super) health: WatchHealth,
    pub(super) health_generation: u64,
    pub(super) retry_attempts: u32,
    pub(super) retry_at: Instant,
}

impl TargetState {
    fn next_generation(&mut self) -> u64 {
        self.target_generation = next_nonzero(self.target_generation);
        self.target_generation
    }

    pub(super) fn mark_full(&mut self) {
        let generation = self.next_generation();
        self.full_generation = Some(generation);
        self.dirty_paths.clear();
    }

    pub(super) fn mark_dirty(&mut self, relative_directory: PathBuf, maximum_paths: usize) {
        let generation = self.next_generation();
        if self.full_generation.is_some() {
            self.full_generation = Some(generation);
            return;
        }

        if let Some(ancestor) = nearest_recorded_ancestor(&self.dirty_paths, &relative_directory) {
            self.dirty_paths.insert(ancestor, generation);
            return;
        }

        self.dirty_paths
            .retain(|path, _| !is_strict_descendant(path, &relative_directory));
        self.dirty_paths.insert(relative_directory, generation);
        if self.dirty_paths.len() > maximum_paths {
            self.dirty_paths.clear();
            self.full_generation = Some(generation);
        }
    }

    pub(super) fn degrade(&mut self, now: Instant, retry_policy: RetryPolicy) {
        self.health = WatchHealth::Degraded;
        self.health_generation = next_nonzero(self.health_generation);
        self.retry_at = now + retry_policy.delay(self.retry_attempts);
        self.retry_attempts = self.retry_attempts.saturating_add(1);
    }

    pub(super) fn needs_full_reconcile(&self, global_generation: u64) -> bool {
        self.full_generation.is_some() || self.acknowledged_global_generation != global_generation
    }

    pub(super) fn pending(&self, global_generation: u64) -> bool {
        self.full_generation.is_some()
            || !self.dirty_paths.is_empty()
            || global_generation != self.acknowledged_global_generation
    }
}

#[derive(Default)]
pub(super) struct WatchState {
    pub(super) targets: HashMap<String, TargetState>,
    pub(super) roots: HashMap<PathBuf, String>,
    pub(super) changed_targets: HashSet<String>,
    pub(super) global_change_pending: bool,
    pub(super) next_registration_generation: u64,
}

#[derive(Clone, Copy)]
pub(super) struct RetryPolicy {
    pub(super) initial: Duration,
    pub(super) maximum: Duration,
}

impl RetryPolicy {
    pub(super) fn delay(self, attempts: u32) -> Duration {
        let multiplier = 1_u32.checked_shl(attempts.min(16)).unwrap_or(u32::MAX);
        self.initial.saturating_mul(multiplier).min(self.maximum)
    }
}

pub(super) struct Shared {
    pub(super) state: Mutex<WatchState>,
    pub(super) maximum_dirty_paths: usize,
    pub(super) maximum_pending_targets: usize,
    pub(super) retry_policy: RetryPolicy,
    pub(super) global_generation: AtomicU64,
    pub(super) backend_rebuild_requested: AtomicBool,
    pub(super) change_sequence: AtomicU64,
    pub(super) changed: Notify,
}

impl Shared {
    pub(super) fn signal_change(&self) {
        self.change_sequence.fetch_add(1, Ordering::Release);
        self.changed.notify_waiters();
    }

    pub(super) fn force_full_all(&self) {
        let mut state = lock_recover(&self.state);
        self.enqueue_global_change(&mut state);
        drop(state);
        self.signal_change();
    }

    pub(super) fn degrade_all(&self) {
        let now = Instant::now();
        self.backend_rebuild_requested
            .store(true, Ordering::Release);
        let mut state = lock_recover(&self.state);
        for target in state.targets.values_mut() {
            target.degrade(now, self.retry_policy);
        }
        self.enqueue_global_change(&mut state);
        drop(state);
        self.signal_change();
    }

    pub(super) fn enqueue_target_change(&self, state: &mut WatchState, target_id: &str) {
        if state.global_change_pending {
            return;
        }
        state.changed_targets.insert(target_id.to_string());
        if state.changed_targets.len() > self.maximum_pending_targets {
            self.enqueue_global_change(state);
        }
    }

    fn enqueue_global_change(&self, state: &mut WatchState) {
        state.global_change_pending = true;
        state.changed_targets.clear();
        self.global_generation.fetch_add(1, Ordering::AcqRel);
        for target in state.targets.values_mut() {
            target.mark_full();
        }
    }

    pub(super) fn handle_callback(&self, result: notify::Result<Event>) {
        let event = match result {
            Ok(event) => event,
            Err(_) => {
                // Backend errors invalidate every watch until re-registration.
                self.degrade_all();
                return;
            }
        };

        // This check must precede kind filtering: Linux queue-overflow events
        // are commonly reported as EventKind::Other.
        if event.need_rescan() {
            self.force_full_all();
            return;
        }
        if matches!(event.kind, EventKind::Access(_) | EventKind::Other) {
            return;
        }
        if event.paths.is_empty() {
            self.force_full_all();
            return;
        }

        let now = Instant::now();
        let mut state = lock_recover(&self.state);
        let mut changed_targets = HashSet::new();
        for event_path in &event.paths {
            let Some((target_id, root)) = route_path(&state.roots, event_path) else {
                continue;
            };
            let Some(target) = state.targets.get_mut(&target_id) else {
                continue;
            };

            if event_path == &root {
                target.mark_full();
                if root_watch_may_be_lost(event.kind) {
                    target.degrade(now, self.retry_policy);
                }
                changed_targets.insert(target_id);
                continue;
            }

            let Some(relative_directory) = safe_relative_parent(&root, event_path) else {
                target.mark_full();
                changed_targets.insert(target_id);
                continue;
            };
            target.mark_dirty(relative_directory, self.maximum_dirty_paths);
            changed_targets.insert(target_id);
        }
        for target_id in &changed_targets {
            self.enqueue_target_change(&mut state, target_id);
        }
        drop(state);
        if !changed_targets.is_empty() {
            self.signal_change();
        }
    }
}

pub(super) struct RetryCandidate {
    pub(super) target_id: String,
    pub(super) fingerprint: String,
    pub(super) registration_generation: u64,
    pub(super) health_generation: u64,
    pub(super) root: PathBuf,
}

pub(super) struct BackendState {
    pub(super) watcher: Option<RecommendedWatcher>,
    pub(super) retry_attempts: u32,
    pub(super) retry_at: Instant,
}

#[cfg(test)]
pub(super) struct RegistrationPause {
    pub(super) installed: Barrier,
    pub(super) resume: Barrier,
}
