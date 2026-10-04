use std::{fmt, path::PathBuf};

/// Root-relative filesystem activity accumulated for one target.
#[derive(Clone)]
pub(crate) struct DirtyBatch {
    pub(super) target_id: String,
    pub(super) fingerprint: String,
    pub(super) registration_generation: u64,
    pub(super) target_generation: u64,
    pub(super) global_generation: u64,
    pub(super) relative_paths: Vec<PathBuf>,
    pub(super) full_reconcile: bool,
    pub(super) watcher_active: bool,
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
    pub(super) root: PathBuf,
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
