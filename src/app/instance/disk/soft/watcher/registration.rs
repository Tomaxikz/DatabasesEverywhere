use super::*;

impl SoftDiskWatcher {
    pub(crate) fn register(
        &self,
        target_id: &str,
        fingerprint: &str,
        root: &Path,
    ) -> Result<WatchRegistration, WatchRegistrationError> {
        validate_registration(target_id, fingerprint, root)?;
        let _gate = lock_recover(&self.registration_gate);

        if let Some(unchanged) = self.unchanged_registration(target_id, fingerprint, root)? {
            return Ok(unchanged);
        }

        let (old_root, registration_generation) =
            self.replace_target_state(target_id, fingerprint, root);
        self.shared.signal_change();

        let now = Instant::now();
        let watch_succeeded = self.install_registration_watch(root, old_root.as_deref(), now);

        #[cfg(test)]
        if watch_succeeded && let Some(pause) = lock_recover(&self.registration_pause).take() {
            pause.installed.wait();
            pause.resume.wait();
        }

        let (result, stale_watch_installed) = self.finish_registration(
            target_id,
            fingerprint,
            root,
            registration_generation,
            watch_succeeded,
            now,
        );
        if stale_watch_installed {
            #[cfg(test)]
            self.stale_cleanup_attempts.fetch_add(1, Ordering::Relaxed);
            self.unwatch_or_abandon_backend(root, now);
        }
        self.shared.signal_change();
        Ok(result)
    }

    fn unchanged_registration(
        &self,
        target_id: &str,
        fingerprint: &str,
        root: &Path,
    ) -> Result<Option<WatchRegistration>, WatchRegistrationError> {
        let state = lock_recover(&self.shared.state);
        if let Some(existing) = state.targets.get(target_id)
            && existing.fingerprint == fingerprint
            && existing.root == root
        {
            return Ok(Some(registration_result(existing, false)));
        }
        if state
            .roots
            .get(root)
            .is_some_and(|owner| owner != target_id)
        {
            return Err(WatchRegistrationError::RootCollision);
        }
        Ok(None)
    }

    fn replace_target_state(
        &self,
        target_id: &str,
        fingerprint: &str,
        root: &Path,
    ) -> (Option<PathBuf>, u64) {
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
    }

    fn install_registration_watch(
        &self,
        root: &Path,
        old_root: Option<&Path>,
        now: Instant,
    ) -> bool {
        let mut backend = lock_recover(&self.backend);
        let outcome = if self
            .shared
            .backend_rebuild_requested
            .load(Ordering::Acquire)
        {
            // Do not register new roots on a backend awaiting replacement.
            RecursiveWatchInstall::FailedCleanly
        } else {
            let stale_cleanup_failed = match (backend.watcher.as_mut(), old_root) {
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
    }

    fn finish_registration(
        &self,
        target_id: &str,
        fingerprint: &str,
        root: &Path,
        registration_generation: u64,
        watch_succeeded: bool,
        now: Instant,
    ) -> (WatchRegistration, bool) {
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
    }

    fn unwatch_or_abandon_backend(&self, root: &Path, now: Instant) {
        let mut backend = lock_recover(&self.backend);
        if backend
            .watcher
            .as_mut()
            .is_some_and(|watcher| watcher.unwatch(root).is_err())
        {
            abandon_backend(&self.shared, &mut backend, now);
        }
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
        self.unwatch_or_abandon_backend(&retired.root, now);
    }

    #[cfg(test)]
    pub(crate) fn unregister(&self, target_id: &str) -> bool {
        let Some(retired) = self.retire(target_id) else {
            return false;
        };
        self.unwatch_retired(&retired);
        true
    }
}
