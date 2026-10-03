use super::*;

pub(super) fn create_backend(shared: Arc<Shared>) -> notify::Result<RecommendedWatcher> {
    RecommendedWatcher::new(
        move |event| shared.handle_callback(event),
        Config::default().with_follow_symlinks(false),
    )
}

/// Unwind partial recursive registrations reported by `notify`.
pub(super) fn install_recursive_watch<W: Watcher>(
    watcher: &mut W,
    root: &Path,
) -> RecursiveWatchInstall {
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

pub(super) fn abandon_backend(shared: &Arc<Shared>, backend: &mut BackendState, now: Instant) {
    // Closing the descriptor is the only reliable partial-rollback cleanup.
    backend.watcher = None;
    backend.retry_attempts = 0;
    backend.retry_at = now;
    shared.degrade_all();
}

pub(super) fn ensure_backend(shared: &Arc<Shared>, backend: &mut BackendState, now: Instant) {
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

pub(super) fn registration_result(target: &TargetState, changed: bool) -> WatchRegistration {
    WatchRegistration {
        status: health_status(target.health),
        changed,
        full_reconcile_pending: target.full_generation.is_some(),
    }
}

pub(super) fn health_status(health: WatchHealth) -> RegistrationStatus {
    match health {
        WatchHealth::Watching => RegistrationStatus::Watching,
        WatchHealth::Degraded => RegistrationStatus::Degraded,
    }
}

pub(super) fn validate_registration(
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

pub(super) fn route_path(
    roots: &HashMap<PathBuf, String>,
    event_path: &Path,
) -> Option<(String, PathBuf)> {
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

pub(super) fn safe_relative_parent(root: &Path, event_path: &Path) -> Option<PathBuf> {
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

pub(super) fn root_watch_may_be_lost(kind: EventKind) -> bool {
    matches!(
        kind,
        EventKind::Remove(_) | EventKind::Modify(notify::event::ModifyKind::Name(_))
    )
}

pub(super) fn nearest_recorded_ancestor(
    paths: &BTreeMap<PathBuf, u64>,
    path: &Path,
) -> Option<PathBuf> {
    let mut candidate = Some(path);
    while let Some(current) = candidate {
        if paths.contains_key(current) {
            return Some(current.to_path_buf());
        }
        candidate = current.parent();
    }
    None
}

pub(super) fn is_strict_descendant(path: &Path, ancestor: &Path) -> bool {
    path != ancestor && path.starts_with(ancestor)
}

pub(super) fn next_nonzero(value: u64) -> u64 {
    let next = value.wrapping_add(1);
    if next == 0 { 1 } else { next }
}

pub(super) fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
