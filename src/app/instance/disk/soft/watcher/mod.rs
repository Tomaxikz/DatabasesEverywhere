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

mod changes;
mod helpers;
mod registration;
mod retry;
mod state;
mod types;

use self::helpers::*;
use self::state::*;
pub(crate) use self::types::*;

const DEFAULT_RETRY_INITIAL: Duration = Duration::from_secs(5);
const DEFAULT_RETRY_MAX: Duration = Duration::from_secs(5 * 60);
const DEFAULT_MAXIMUM_PENDING_TARGETS: usize = 4_096;

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

#[cfg(test)]
mod tests;
