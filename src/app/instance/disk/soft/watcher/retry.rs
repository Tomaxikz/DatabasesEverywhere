use super::*;

impl SoftDiskWatcher {
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
                .map(|(target_id, target)| RetryCandidate {
                    target_id: target_id.clone(),
                    fingerprint: target.fingerprint.clone(),
                    registration_generation: target.registration_generation,
                    health_generation: target.health_generation,
                    root: target.root.clone(),
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
        for candidate in retry_targets {
            summary.attempted += 1;
            let outcome = backend
                .watcher
                .as_mut()
                .map_or(RecursiveWatchInstall::FailedCleanly, |watcher| {
                    install_recursive_watch(watcher, &candidate.root)
                });
            if outcome == RecursiveWatchInstall::BackendContaminated {
                abandon_backend(&self.shared, &mut backend, now);
                summary.restored = 0;
                break;
            }
            let succeeded = outcome == RecursiveWatchInstall::Installed;
            let target_id = candidate.target_id;
            let mut state = lock_recover(&self.shared.state);
            let Some(target) = state.targets.get_mut(&target_id) else {
                continue;
            };
            if target.fingerprint != candidate.fingerprint
                || target.registration_generation != candidate.registration_generation
                || target.health_generation != candidate.health_generation
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
}
