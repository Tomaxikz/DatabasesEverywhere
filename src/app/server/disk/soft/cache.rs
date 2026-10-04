use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use super::{
    types::{SoftDiskSnapshot, SoftDiskTarget},
    usage_tree,
};
use crate::databases::protocol::Protocol;

#[derive(Debug, Clone, Copy)]
pub(super) struct UsageCacheLimits {
    pub(super) per_target_directories: usize,
    pub(super) global_directories: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TargetFingerprint {
    pub(super) created_at: String,
    pub(super) protocol: Protocol,
    pub(super) data_path: PathBuf,
    pub(super) limit_bytes: u64,
}

#[derive(Debug, Clone)]
pub(super) struct UsageTreeState {
    pub(super) target: TargetFingerprint,
    pub(super) slot: Arc<UsageTreeSlot>,
}

#[derive(Debug)]
pub(super) struct UsageTreeSlot {
    pub(super) state: std::sync::Mutex<UsageTreeSlotState>,
    pub(super) cached_directories: Arc<AtomicUsize>,
    global_directory_limit: usize,
}

#[derive(Debug, Default)]
pub(super) struct UsageTreeSlotState {
    pub(super) cache: Option<usage_tree::UsageTreeCache>,
    pub(super) cached_directory_count: usize,
    pub(super) streaming_only: bool,
}

impl UsageTreeSlot {
    pub(super) fn new(cached_directories: Arc<AtomicUsize>, global_directory_limit: usize) -> Self {
        Self {
            state: std::sync::Mutex::new(UsageTreeSlotState::default()),
            cached_directories,
            global_directory_limit,
        }
    }

    pub(super) fn install_cache(
        &self,
        state: &mut UsageTreeSlotState,
        cache: usage_tree::UsageTreeCache,
    ) -> bool {
        if state.streaming_only {
            return false;
        }
        if !self.resize_directory_accounting(state, cache.directory_count()) {
            return false;
        }
        state.cache = Some(cache);
        true
    }

    /// Reserve the reconciled cache size before publishing it.
    pub(super) fn account_reconciled_cache(&self, state: &mut UsageTreeSlotState) -> bool {
        let Some(new_count) = state
            .cache
            .as_ref()
            .map(usage_tree::UsageTreeCache::directory_count)
        else {
            return false;
        };
        self.resize_directory_accounting(state, new_count)
    }

    fn resize_directory_accounting(
        &self,
        state: &mut UsageTreeSlotState,
        new_count: usize,
    ) -> bool {
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

    pub(super) fn switch_to_streaming(&self, state: &mut UsageTreeSlotState) {
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
    let _ = counter.try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
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
pub(super) struct TrackerState {
    pub(super) target: TargetFingerprint,
    pub(super) snapshot: SoftDiskSnapshot,
    pub(super) warned: bool,
}

#[derive(Debug, Clone)]
pub(super) struct TargetScanFailures {
    pub(super) target: TargetFingerprint,
    pub(super) consecutive: u8,
}
