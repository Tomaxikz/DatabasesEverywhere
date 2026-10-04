use sha2::Digest;
use std::os::unix::ffi::OsStrExt;
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use super::{RuntimeFuture, StopRuntimeFuture, enforcement::stop_with_kill_fallback, usage_tree};
use crate::{databases::protocol::Protocol, server::disk::usage::DirectoryUsage};

#[derive(Debug, Clone)]
pub struct SoftDiskTarget {
    pub instance_id: String,
    pub created_at: String,
    pub protocol: Protocol,
    pub data_path: PathBuf,
    pub limit_bytes: u64,
    /// Durable restart hysteresis owned by the disk limiter.
    pub durable_blocked: bool,
}

impl SoftDiskTarget {
    /// Process-local fingerprint of the instance generation and disk policy.
    pub(crate) fn scanner_fingerprint(&self) -> String {
        let mut digest = sha2::Sha256::new();
        for component in [
            self.created_at.as_bytes(),
            self.protocol.as_str().as_bytes(),
            self.data_path.as_os_str().as_bytes(),
            &self.limit_bytes.to_le_bytes(),
        ] {
            digest.update(component.len().to_le_bytes());
            digest.update(component);
        }
        crate::utils::hex::encode_lower(&digest.finalize())
    }
}

#[derive(Debug, Clone)]
pub struct SoftDiskSnapshot {
    pub usage: DirectoryUsage,
    pub limit_bytes: u64,
    pub stop_threshold_bytes: u64,
    pub recovery_threshold_bytes: u64,
    pub growth_bytes_per_second: f64,
    pub peak_growth_bytes_per_second: f64,
    pub predicted_seconds_to_limit: Option<u64>,
    pub blocked: bool,
    pub sampled_at: Instant,
}

#[derive(Debug, Clone)]
pub struct SoftDiskLimitExceeded {
    pub snapshot: SoftDiskSnapshot,
    pub reason: SoftDiskBlockReason,
}

#[derive(Debug, Clone)]
pub enum SoftDiskBlockReason {
    UsageThreshold,
    Unmeasurable {
        consecutive_failures: u8,
        error: String,
    },
    ScannerCapacityOutage {
        consecutive_failures: u8,
        error: String,
    },
}

impl SoftDiskBlockReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UsageThreshold => "usage_threshold",
            Self::Unmeasurable { .. } => "scan_unmeasurable",
            Self::ScannerCapacityOutage { .. } => "scanner_capacity_outage",
        }
    }

    pub fn scan_error(&self) -> Option<&str> {
        match self {
            Self::UsageThreshold => None,
            Self::Unmeasurable { error, .. } | Self::ScannerCapacityOutage { error, .. } => {
                Some(error)
            }
        }
    }
}

pub trait SoftDiskRuntime: Send + Sync {
    /// Persist stopped intent before touching the runtime.
    fn mark_disk_blocked<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
        exceeded: &'a SoftDiskLimitExceeded,
    ) -> RuntimeFuture<'a>;

    fn graceful_stop<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
        grace: Duration,
    ) -> RuntimeFuture<'a>;

    fn force_kill<'a>(&'a self, target: &'a SoftDiskTarget) -> RuntimeFuture<'a>;

    /// Clear only the limiter-owned block after crossing recovery hysteresis.
    fn clear_disk_blocked<'a>(&'a self, _target: &'a SoftDiskTarget) -> RuntimeFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    /// Persist and enforce stop intent; production wraps this in a lifecycle lock.
    fn enforce_disk_stop<'a>(
        &'a self,
        target: &'a SoftDiskTarget,
        exceeded: &'a SoftDiskLimitExceeded,
        grace: Duration,
    ) -> StopRuntimeFuture<'a> {
        Box::pin(async move {
            self.mark_disk_blocked(target, exceeded).await?;
            stop_with_kill_fallback(self, target, grace).await
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopOutcome {
    Graceful,
    Forced,
    SkippedStale,
}

#[derive(Debug, Clone)]
pub enum ScanOutcome {
    Healthy(SoftDiskSnapshot),
    Warning(SoftDiskSnapshot),
    Recovered(SoftDiskSnapshot),
    AlreadyBlocked(SoftDiskSnapshot),
    Stopped {
        snapshot: SoftDiskSnapshot,
        outcome: StopOutcome,
    },
}

#[derive(Debug, Clone)]
pub(crate) enum HybridScanRequest {
    /// Authoritative O(depth) scan that does not retain incremental state.
    StreamingFull,
    Full,
    Partial {
        relative_directories: Vec<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PerformedScanKind {
    Full,
    Partial,
}

#[derive(Debug, Clone)]
pub(crate) struct HybridScanExecution {
    pub(crate) outcome: ScanOutcome,
    pub(crate) performed: PerformedScanKind,
    /// False when fail-closed enforcement used an older trustworthy sample.
    pub(crate) measurement_succeeded: bool,
    pub(crate) root_identity: Option<usage_tree::RootIdentity>,
}

impl HybridScanExecution {
    pub(super) fn unmeasured(outcome: ScanOutcome) -> Self {
        Self {
            outcome,
            performed: PerformedScanKind::Full,
            measurement_succeeded: false,
            root_identity: None,
        }
    }
}

impl ScanOutcome {
    pub fn snapshot(&self) -> &SoftDiskSnapshot {
        match self {
            Self::Healthy(snapshot)
            | Self::Warning(snapshot)
            | Self::Recovered(snapshot)
            | Self::AlreadyBlocked(snapshot)
            | Self::Stopped { snapshot, .. } => snapshot,
        }
    }
}
