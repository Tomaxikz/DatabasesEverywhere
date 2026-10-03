use super::*;

impl SoftDiskWatcher {
    pub(crate) fn capture(&self, target_id: &str) -> Option<DirtyBatch> {
        let global_generation = self.shared.global_generation.load(Ordering::Acquire);
        let state = lock_recover(&self.shared.state);
        let target = state.targets.get(target_id)?;
        if !target.pending(global_generation) {
            return None;
        }
        let full_reconcile = target.needs_full_reconcile(global_generation);
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
            full_reconcile_pending: target.needs_full_reconcile(global_generation),
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
}
