use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    path::{Component, Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::Notify;

#[cfg(test)]
use std::sync::Barrier;

const DEFAULT_RETRY_INITIAL: Duration = Duration::from_secs(5);
const DEFAULT_RETRY_MAX: Duration = Duration::from_secs(5 * 60);
const DEFAULT_MAXIMUM_PENDING_TARGETS: usize = 4_096;

/// Root-relative filesystem activity accumulated for one target.
#[derive(Clone)]
pub(crate) struct DirtyBatch {
    target_id: String,
    fingerprint: String,
    registration_generation: u64,
    target_generation: u64,
    global_generation: u64,
    relative_paths: Vec<PathBuf>,
    full_reconcile: bool,
    watcher_active: bool,
}

impl DirtyBatch {
    #[cfg(test)]
    pub(crate) fn target_id(&self) -> &str {
        &self.target_id
    }

    #[cfg(test)]
    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub(crate) fn generation(&self) -> u64 {
        self.target_generation
    }

    pub(crate) fn relative_paths(&self) -> &[PathBuf] {
        &self.relative_paths
    }

    pub(crate) fn requires_full_reconcile(&self) -> bool {
        self.full_reconcile
    }

    #[cfg(test)]
    pub(crate) fn watcher_active(&self) -> bool {
        self.watcher_active
    }
}

// Keep target identities and paths out of logs.
impl fmt::Debug for DirtyBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirtyBatch")
            .field("registration_generation", &self.registration_generation)
            .field("target_generation", &self.target_generation)
            .field("global_generation", &self.global_generation)
            .field("dirty_directory_count", &self.relative_paths.len())
            .field("full_reconcile", &self.full_reconcile)
            .field("watcher_active", &self.watcher_active)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegistrationStatus {
    Watching,
    Degraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WatchRegistration {
    pub(crate) status: RegistrationStatus,
    pub(crate) changed: bool,
    pub(crate) full_reconcile_pending: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TargetWatchStatus {
    pub(crate) status: RegistrationStatus,
    pub(crate) registration_generation: u64,
    pub(crate) pending_change: bool,
    pub(crate) full_reconcile_pending: bool,
    pub(crate) dirty_directory_count: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RetrySummary {
    pub(crate) attempted: usize,
    pub(crate) restored: usize,
    pub(crate) still_degraded: usize,
    pub(crate) backend_available: bool,
}

/// Coalesced watcher work and the sequence for the next wait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WatcherChanges {
    pub(crate) sequence: u64,
    pub(crate) global_reconcile: bool,
    pub(crate) target_ids: Vec<String>,
}

impl WatcherChanges {
    pub(crate) fn is_empty(&self) -> bool {
        !self.global_reconcile && self.target_ids.is_empty()
    }
}

/// Opaque token for deferred kernel-watch cleanup.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RetiredWatch {
    root: PathBuf,
}

impl RetiredWatch {
    #[cfg(test)]
    pub(crate) fn for_test(root: PathBuf) -> Self {
        Self { root }
    }
}

impl fmt::Debug for RetiredWatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetiredWatch { root: <redacted> }")
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum WatchRegistrationError {
    #[error("soft disk watcher target identity is invalid")]
    InvalidIdentity,
    #[error("soft disk watcher root must be a normalized absolute path")]
    InvalidRoot,
    #[error("soft disk watcher root is already owned by another target")]
    RootCollision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchHealth {
    Watching,
    Degraded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecursiveWatchInstall {
    Installed,
    FailedCleanly,
    BackendContaminated,
}

struct TargetState {
    fingerprint: String,
    root: PathBuf,
    registration_generation: u64,
    target_generation: u64,
    full_generation: Option<u64>,
    dirty_paths: BTreeMap<PathBuf, u64>,
    acknowledged_global_generation: u64,
    health: WatchHealth,
    health_generation: u64,
    retry_attempts: u32,
    retry_at: Instant,
}

impl TargetState {
    fn next_generation(&mut self) -> u64 {
        self.target_generation = next_nonzero(self.target_generation);
        self.target_generation
    }

    fn mark_full(&mut self) {
        let generation = self.next_generation();
        self.full_generation = Some(generation);
        self.dirty_paths.clear();
    }

    fn mark_dirty(&mut self, relative_directory: PathBuf, maximum_paths: usize) {
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

    fn degrade(&mut self, now: Instant, retry_policy: RetryPolicy) {
        self.health = WatchHealth::Degraded;
        self.health_generation = next_nonzero(self.health_generation);
        self.retry_at = now + retry_policy.delay(self.retry_attempts);
        self.retry_attempts = self.retry_attempts.saturating_add(1);
    }

    fn pending(&self, global_generation: u64) -> bool {
        self.full_generation.is_some()
            || !self.dirty_paths.is_empty()
            || global_generation != self.acknowledged_global_generation
    }
}

#[derive(Default)]
struct WatchState {
    targets: HashMap<String, TargetState>,
    roots: HashMap<PathBuf, String>,
    changed_targets: HashSet<String>,
    global_change_pending: bool,
    next_registration_generation: u64,
}

#[derive(Clone, Copy)]
struct RetryPolicy {
    initial: Duration,
    maximum: Duration,
}

impl RetryPolicy {
    fn delay(self, attempts: u32) -> Duration {
        let multiplier = 1_u32.checked_shl(attempts.min(16)).unwrap_or(u32::MAX);
        self.initial.saturating_mul(multiplier).min(self.maximum)
    }
}

struct Shared {
    state: Mutex<WatchState>,
    maximum_dirty_paths: usize,
    maximum_pending_targets: usize,
    retry_policy: RetryPolicy,
    global_generation: AtomicU64,
    backend_rebuild_requested: AtomicBool,
    change_sequence: AtomicU64,
    changed: Notify,
}

impl Shared {
    fn signal_change(&self) {
        self.change_sequence.fetch_add(1, Ordering::Release);
        self.changed.notify_waiters();
    }

    fn force_full_all(&self) {
        let mut state = lock_recover(&self.state);
        self.enqueue_global_change(&mut state);
        drop(state);
        self.signal_change();
    }

    fn degrade_all(&self) {
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

    fn enqueue_target_change(&self, state: &mut WatchState, target_id: &str) {
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

    fn handle_callback(&self, result: notify::Result<Event>) {
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

struct BackendState {
    watcher: Option<RecommendedWatcher>,
    retry_attempts: u32,
    retry_at: Instant,
}

#[cfg(test)]
struct RegistrationPause {
    installed: Barrier,
    resume: Barrier,
}

/// Process-wide recursive watcher with serialized registration.
pub(crate) struct SoftDiskWatcher {
    shared: Arc<Shared>,
    backend: Mutex<BackendState>,
    registration_gate: Mutex<()>,
    #[cfg(test)]
    registration_pause: Mutex<Option<Arc<RegistrationPause>>>,
    #[cfg(test)]
    stale_cleanup_attempts: AtomicU64,
}

impl SoftDiskWatcher {
    pub(crate) fn new(maximum_dirty_paths: usize) -> Self {
        Self::new_with_retry_policy(
            maximum_dirty_paths,
            DEFAULT_RETRY_INITIAL,
            DEFAULT_RETRY_MAX,
        )
    }

    pub(crate) fn new_with_retry_policy(
        maximum_dirty_paths: usize,
        retry_initial: Duration,
        retry_maximum: Duration,
    ) -> Self {
        Self::new_with_limits(
            maximum_dirty_paths,
            DEFAULT_MAXIMUM_PENDING_TARGETS,
            retry_initial,
            retry_maximum,
        )
    }

    fn new_with_limits(
        maximum_dirty_paths: usize,
        maximum_pending_targets: usize,
        retry_initial: Duration,
        retry_maximum: Duration,
    ) -> Self {
        let retry_policy = RetryPolicy {
            initial: retry_initial,
            maximum: retry_maximum.max(retry_initial),
        };
        let shared = Arc::new(Shared {
            state: Mutex::new(WatchState::default()),
            maximum_dirty_paths: maximum_dirty_paths.max(1),
            maximum_pending_targets: maximum_pending_targets.max(1),
            retry_policy,
            global_generation: AtomicU64::new(0),
            backend_rebuild_requested: AtomicBool::new(false),
            change_sequence: AtomicU64::new(0),
            changed: Notify::new(),
        });
        let now = Instant::now();
        let (watcher, retry_attempts, retry_at) = match create_backend(Arc::clone(&shared)) {
            Ok(watcher) => (Some(watcher), 0, now),
            Err(_) => (None, 1, now + retry_policy.delay(0)),
        };
        Self {
            shared,
            backend: Mutex::new(BackendState {
                watcher,
                retry_attempts,
                retry_at,
            }),
            registration_gate: Mutex::new(()),
            #[cfg(test)]
            registration_pause: Mutex::new(None),
            #[cfg(test)]
            stale_cleanup_attempts: AtomicU64::new(0),
        }
    }

    pub(crate) fn register(
        &self,
        target_id: &str,
        fingerprint: &str,
        root: &Path,
    ) -> Result<WatchRegistration, WatchRegistrationError> {
        validate_registration(target_id, fingerprint, root)?;
        let _gate = lock_recover(&self.registration_gate);

        {
            let state = lock_recover(&self.shared.state);
            if let Some(existing) = state.targets.get(target_id)
                && existing.fingerprint == fingerprint
                && existing.root == root
            {
                return Ok(registration_result(existing, false));
            }
            if state
                .roots
                .get(root)
                .is_some_and(|owner| owner != target_id)
            {
                return Err(WatchRegistrationError::RootCollision);
            }
        }

        let (old_root, registration_generation) = {
            let mut state = lock_recover(&self.shared.state);
            let old_root = state.targets.remove(target_id).map(|target| target.root);
            if let Some(old_root) = &old_root {
                state.roots.remove(old_root);
            }
            state.changed_targets.remove(target_id);
            state.next_registration_generation = next_nonzero(state.next_registration_generation);
            let registration_generation = state.next_registration_generation;
            let global_generation = self.shared.global_generation.load(Ordering::Acquire);
            let mut target = TargetState {
                fingerprint: fingerprint.to_string(),
                root: root.to_path_buf(),
                registration_generation,
                target_generation: 0,
                full_generation: None,
                dirty_paths: BTreeMap::new(),
                acknowledged_global_generation: global_generation,
                health: WatchHealth::Degraded,
                health_generation: 0,
                retry_attempts: 0,
                retry_at: Instant::now(),
            };
            target.mark_full();
            state
                .roots
                .insert(root.to_path_buf(), target_id.to_string());
            state.targets.insert(target_id.to_string(), target);
            self.shared.enqueue_target_change(&mut state, target_id);
            (old_root, registration_generation)
        };
        self.shared.signal_change();

        let now = Instant::now();
        let watch_succeeded = {
            let mut backend = lock_recover(&self.backend);
            let outcome = if self
                .shared
                .backend_rebuild_requested
                .load(Ordering::Acquire)
            {
                // Do not register new roots on a backend awaiting replacement.
                RecursiveWatchInstall::FailedCleanly
            } else {
                let stale_cleanup_failed = match (backend.watcher.as_mut(), old_root.as_ref()) {
                    (Some(watcher), Some(old_root)) => watcher.unwatch(old_root).is_err(),
                    _ => false,
                };
                if stale_cleanup_failed {
                    RecursiveWatchInstall::BackendContaminated
                } else {
                    ensure_backend(&self.shared, &mut backend, now);
                    backend
                        .watcher
                        .as_mut()
                        .map_or(RecursiveWatchInstall::FailedCleanly, |watcher| {
                            install_recursive_watch(watcher, root)
                        })
                }
            };
            if outcome == RecursiveWatchInstall::BackendContaminated {
                abandon_backend(&self.shared, &mut backend, now);
            }
            outcome == RecursiveWatchInstall::Installed
        };

        #[cfg(test)]
        if watch_succeeded && let Some(pause) = lock_recover(&self.registration_pause).take() {
            pause.installed.wait();
            pause.resume.wait();
        }

        let (result, stale_watch_installed) = {
            let mut state = lock_recover(&self.shared.state);
            let (result, stale_watch_installed) = match state.targets.get_mut(target_id) {
                Some(target)
                    if target.registration_generation == registration_generation
                        && target.fingerprint == fingerprint
                        && target.root == root =>
                {
                    if watch_succeeded {
                        target.health = WatchHealth::Watching;
                        target.retry_attempts = 0;
                    } else {
                        target.degrade(now, self.shared.retry_policy);
                    }
                    (registration_result(target, true), false)
                }
                _ => (
                    WatchRegistration {
                        status: RegistrationStatus::Degraded,
                        changed: false,
                        full_reconcile_pending: false,
                    },
                    watch_succeeded,
                ),
            };
            self.shared.enqueue_target_change(&mut state, target_id);
            (result, stale_watch_installed)
        };
        if stale_watch_installed {
            #[cfg(test)]
            self.stale_cleanup_attempts.fetch_add(1, Ordering::Relaxed);
            let mut backend = lock_recover(&self.backend);
            if backend
                .watcher
                .as_mut()
                .is_some_and(|watcher| watcher.unwatch(root).is_err())
            {
                abandon_backend(&self.shared, &mut backend, now);
            }
        }
        self.shared.signal_change();
        Ok(result)
    }

    /// Retire callback routing immediately and defer kernel cleanup.
    pub(crate) fn retire(&self, target_id: &str) -> Option<RetiredWatch> {
        let retired = {
            let mut state = lock_recover(&self.shared.state);
            let target = state.targets.remove(target_id)?;
            state.roots.remove(&target.root);
            state.changed_targets.remove(target_id);
            self.shared.enqueue_target_change(&mut state, target_id);
            RetiredWatch { root: target.root }
        };
        self.shared.signal_change();
        Some(retired)
    }

    /// Clean up a retired watch without unwatching a reused root.
    pub(crate) fn unwatch_retired(&self, retired: &RetiredWatch) {
        let _gate = lock_recover(&self.registration_gate);
        if lock_recover(&self.shared.state)
            .roots
            .contains_key(&retired.root)
        {
            return;
        }
        let now = Instant::now();
        let mut backend = lock_recover(&self.backend);
        if backend
            .watcher
            .as_mut()
            .is_some_and(|watcher| watcher.unwatch(&retired.root).is_err())
        {
            abandon_backend(&self.shared, &mut backend, now);
        }
    }

    #[cfg(test)]
    pub(crate) fn unregister(&self, target_id: &str) -> bool {
        let Some(retired) = self.retire(target_id) else {
            return false;
        };
        self.unwatch_retired(&retired);
        true
    }

    pub(crate) fn capture(&self, target_id: &str) -> Option<DirtyBatch> {
        let global_generation = self.shared.global_generation.load(Ordering::Acquire);
        let state = lock_recover(&self.shared.state);
        let target = state.targets.get(target_id)?;
        if !target.pending(global_generation) {
            return None;
        }
        let full_reconcile = target.full_generation.is_some()
            || target.acknowledged_global_generation != global_generation;
        Some(DirtyBatch {
            target_id: target_id.to_string(),
            fingerprint: target.fingerprint.clone(),
            registration_generation: target.registration_generation,
            target_generation: target.target_generation,
            global_generation,
            relative_paths: if full_reconcile {
                Vec::new()
            } else {
                target.dirty_paths.keys().cloned().collect()
            },
            full_reconcile,
            watcher_active: target.health == WatchHealth::Watching,
        })
    }

    /// Acknowledge only the captured registration and generation.
    pub(crate) fn acknowledge(&self, batch: &DirtyBatch) -> bool {
        let mut state = lock_recover(&self.shared.state);
        let Some(target) = state.targets.get_mut(&batch.target_id) else {
            return false;
        };
        if target.fingerprint != batch.fingerprint
            || target.registration_generation != batch.registration_generation
        {
            return false;
        }
        target
            .dirty_paths
            .retain(|_, generation| *generation > batch.target_generation);
        if target
            .full_generation
            .is_some_and(|generation| generation <= batch.target_generation)
        {
            target.full_generation = None;
        }
        target.acknowledged_global_generation = target
            .acknowledged_global_generation
            .max(batch.global_generation);
        true
    }

    #[cfg(test)]
    pub(crate) fn force_full(&self, target_id: &str) -> bool {
        {
            let mut state = lock_recover(&self.shared.state);
            let Some(target) = state.targets.get_mut(target_id) else {
                return false;
            };
            target.mark_full();
            self.shared.enqueue_target_change(&mut state, target_id);
        }
        self.shared.signal_change();
        true
    }

    #[cfg(test)]
    pub(crate) fn force_full_all(&self) {
        self.shared.force_full_all();
    }

    pub(crate) fn status(&self, target_id: &str) -> Option<TargetWatchStatus> {
        let global_generation = self.shared.global_generation.load(Ordering::Acquire);
        let state = lock_recover(&self.shared.state);
        let target = state.targets.get(target_id)?;
        Some(TargetWatchStatus {
            status: health_status(target.health),
            registration_generation: target.registration_generation,
            pending_change: target.pending(global_generation),
            full_reconcile_pending: target.full_generation.is_some()
                || target.acknowledged_global_generation != global_generation,
            dirty_directory_count: target.dirty_paths.len(),
        })
    }

    pub(crate) fn is_watching(&self, target_id: &str, fingerprint: &str) -> bool {
        lock_recover(&self.shared.state)
            .targets
            .get(target_id)
            .is_some_and(|target| {
                target.fingerprint == fingerprint && target.health == WatchHealth::Watching
            })
    }

    pub(crate) fn backend_available(&self) -> bool {
        lock_recover(&self.backend).watcher.is_some()
    }

    pub(crate) fn current_change_sequence(&self) -> u64 {
        self.shared.change_sequence.load(Ordering::Acquire)
    }

    /// Drain coalesced work and sample its sequence under one lock.
    pub(crate) fn drain_changes(&self) -> WatcherChanges {
        let mut state = lock_recover(&self.shared.state);
        let global_reconcile = std::mem::take(&mut state.global_change_pending);
        let target_ids = if global_reconcile {
            state.changed_targets.clear();
            Vec::new()
        } else {
            state.changed_targets.drain().collect()
        };
        let sequence = self.current_change_sequence();
        WatcherChanges {
            sequence,
            global_reconcile,
            target_ids,
        }
    }

    /// Wait for a sequence change without losing wakeups.
    pub(crate) async fn changed_after(&self, observed: u64) -> u64 {
        loop {
            let notified = self.shared.changed.notified();
            tokio::pin!(notified);
            // Register before checking because `notify_waiters` retains no permit.
            notified.as_mut().enable();
            let current = self.current_change_sequence();
            if current != observed {
                return current;
            }
            notified.await;
        }
    }

    pub(crate) fn retry_degraded(&self) -> RetrySummary {
        let _gate = lock_recover(&self.registration_gate);
        let now = Instant::now();
        let retry_targets = {
            let state = lock_recover(&self.shared.state);
            state
                .targets
                .iter()
                .filter(|(_, target)| {
                    target.health == WatchHealth::Degraded && target.retry_at <= now
                })
                .map(|(target_id, target)| {
                    (
                        target_id.clone(),
                        target.fingerprint.clone(),
                        target.registration_generation,
                        target.health_generation,
                        target.root.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let mut summary = RetrySummary::default();

        let mut backend = lock_recover(&self.backend);
        if self
            .shared
            .backend_rebuild_requested
            .swap(false, Ordering::AcqRel)
        {
            backend.watcher = None;
            backend.retry_at = now;
        }
        ensure_backend(&self.shared, &mut backend, now);
        for (target_id, fingerprint, registration_generation, health_generation, root) in
            retry_targets
        {
            summary.attempted += 1;
            let outcome = backend
                .watcher
                .as_mut()
                .map_or(RecursiveWatchInstall::FailedCleanly, |watcher| {
                    install_recursive_watch(watcher, &root)
                });
            if outcome == RecursiveWatchInstall::BackendContaminated {
                abandon_backend(&self.shared, &mut backend, now);
                summary.restored = 0;
                break;
            }
            let succeeded = outcome == RecursiveWatchInstall::Installed;
            let mut state = lock_recover(&self.shared.state);
            let Some(target) = state.targets.get_mut(&target_id) else {
                continue;
            };
            if target.fingerprint != fingerprint
                || target.registration_generation != registration_generation
                || target.health_generation != health_generation
            {
                continue;
            }
            if succeeded {
                target.health = WatchHealth::Watching;
                target.retry_attempts = 0;
                target.mark_full();
                summary.restored += 1;
            } else {
                target.degrade(now, self.shared.retry_policy);
            }
            self.shared.enqueue_target_change(&mut state, &target_id);
        }
        summary.backend_available = backend.watcher.is_some();
        drop(backend);

        summary.still_degraded = lock_recover(&self.shared.state)
            .targets
            .values()
            .filter(|target| target.health == WatchHealth::Degraded)
            .count();
        if summary.attempted > 0 {
            self.shared.signal_change();
        }
        summary
    }

    #[cfg(test)]
    fn handle_callback_for_test(&self, result: notify::Result<Event>) {
        self.shared.handle_callback(result);
    }

    #[cfg(test)]
    fn pause_next_registration_after_install(&self) -> Arc<RegistrationPause> {
        let pause = Arc::new(RegistrationPause {
            installed: Barrier::new(2),
            resume: Barrier::new(2),
        });
        *lock_recover(&self.registration_pause) = Some(Arc::clone(&pause));
        pause
    }
}

fn create_backend(shared: Arc<Shared>) -> notify::Result<RecommendedWatcher> {
    RecommendedWatcher::new(
        move |event| shared.handle_callback(event),
        Config::default().with_follow_symlinks(false),
    )
}

/// Unwind partial recursive registrations reported by `notify`.
fn install_recursive_watch<W: Watcher>(watcher: &mut W, root: &Path) -> RecursiveWatchInstall {
    let watch_error = match watcher.watch(root, RecursiveMode::Recursive) {
        Ok(()) => return RecursiveWatchInstall::Installed,
        Err(error) => error,
    };
    match watcher.unwatch(root) {
        Ok(()) => RecursiveWatchInstall::FailedCleanly,
        Err(cleanup_error)
            if matches!(watch_error.kind, notify::ErrorKind::PathNotFound)
                && matches!(cleanup_error.kind, notify::ErrorKind::WatchNotFound) =>
        {
            // A missing root with no watch does not contaminate the backend.
            RecursiveWatchInstall::FailedCleanly
        }
        Err(_) => RecursiveWatchInstall::BackendContaminated,
    }
}

fn abandon_backend(shared: &Arc<Shared>, backend: &mut BackendState, now: Instant) {
    // Closing the descriptor is the only reliable partial-rollback cleanup.
    backend.watcher = None;
    backend.retry_attempts = 0;
    backend.retry_at = now;
    shared.degrade_all();
}

fn ensure_backend(shared: &Arc<Shared>, backend: &mut BackendState, now: Instant) {
    if backend.watcher.is_some() || backend.retry_at > now {
        return;
    }
    match create_backend(Arc::clone(shared)) {
        Ok(watcher) => {
            backend.watcher = Some(watcher);
            backend.retry_attempts = 0;
            backend.retry_at = now;
        }
        Err(_) => {
            backend.retry_at = now + shared.retry_policy.delay(backend.retry_attempts);
            backend.retry_attempts = backend.retry_attempts.saturating_add(1);
        }
    }
}

fn registration_result(target: &TargetState, changed: bool) -> WatchRegistration {
    WatchRegistration {
        status: health_status(target.health),
        changed,
        full_reconcile_pending: target.full_generation.is_some(),
    }
}

fn health_status(health: WatchHealth) -> RegistrationStatus {
    match health {
        WatchHealth::Watching => RegistrationStatus::Watching,
        WatchHealth::Degraded => RegistrationStatus::Degraded,
    }
}

fn validate_registration(
    target_id: &str,
    fingerprint: &str,
    root: &Path,
) -> Result<(), WatchRegistrationError> {
    if target_id.is_empty() || fingerprint.is_empty() {
        return Err(WatchRegistrationError::InvalidIdentity);
    }
    if !root.is_absolute()
        || root.components().any(|component| {
            !matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
    {
        return Err(WatchRegistrationError::InvalidRoot);
    }
    Ok(())
}

fn route_path(roots: &HashMap<PathBuf, String>, event_path: &Path) -> Option<(String, PathBuf)> {
    if !event_path.is_absolute() {
        return None;
    }
    let mut candidate = Some(event_path);
    while let Some(path) = candidate {
        if let Some(target_id) = roots.get(path) {
            return Some((target_id.clone(), path.to_path_buf()));
        }
        candidate = path.parent();
    }
    None
}

fn safe_relative_parent(root: &Path, event_path: &Path) -> Option<PathBuf> {
    let relative = event_path.strip_prefix(root).ok()?;
    if relative.as_os_str().is_empty() {
        return None;
    }
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    if parent
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        Some(parent.to_path_buf())
    } else {
        None
    }
}

fn root_watch_may_be_lost(kind: EventKind) -> bool {
    matches!(
        kind,
        EventKind::Remove(_) | EventKind::Modify(notify::event::ModifyKind::Name(_))
    )
}

fn nearest_recorded_ancestor(paths: &BTreeMap<PathBuf, u64>, path: &Path) -> Option<PathBuf> {
    let mut candidate = Some(path);
    while let Some(current) = candidate {
        if paths.contains_key(current) {
            return Some(current.to_path_buf());
        }
        candidate = current.parent();
    }
    None
}

fn is_strict_descendant(path: &Path, ancestor: &Path) -> bool {
    path != ancestor && path.starts_with(ancestor)
}

fn next_nonzero(value: u64) -> u64 {
    let next = value.wrapping_add(1);
    if next == 0 { 1 } else { next }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests;
