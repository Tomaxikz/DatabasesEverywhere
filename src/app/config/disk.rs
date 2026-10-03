use super::*;

#[derive(Debug, Clone, Serialize)]
pub struct DiskConfig {
    #[serde(skip)]
    pub mode: DiskLimitMode,
    /// Operator selection. `auto` prefers native filesystem quotas and falls
    /// back to FuseQuota; Qdrant is always resolved to the soft scanner when
    /// that fallback would otherwise be FUSE-backed.
    #[serde(rename = "mode")]
    pub selection: DiskLimitSelection,
    pub project_id_base: u32,
    pub fuse_quota_binary: String,
    pub fuse_quota_binary_sha256: String,
    pub fuse_quota_rescan_interval_seconds: u64,
    pub soft_scanner: SoftDiskScannerConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DiskFileConfig {
    mode: DiskLimitSelection,
    project_id_base: u32,
    fuse_quota_binary: String,
    fuse_quota_binary_sha256: String,
    fuse_quota_rescan_interval_seconds: u64,
    soft_scanner: SoftDiskScannerConfig,
}

impl Default for DiskFileConfig {
    fn default() -> Self {
        let defaults = DiskConfig::default();
        Self {
            mode: defaults.selection,
            project_id_base: defaults.project_id_base,
            fuse_quota_binary: defaults.fuse_quota_binary,
            fuse_quota_binary_sha256: defaults.fuse_quota_binary_sha256,
            fuse_quota_rescan_interval_seconds: defaults.fuse_quota_rescan_interval_seconds,
            soft_scanner: defaults.soft_scanner,
        }
    }
}

impl<'de> Deserialize<'de> for DiskConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let file = DiskFileConfig::deserialize(deserializer)?;
        Ok(Self {
            mode: DiskLimitMode::default(),
            selection: file.mode,
            project_id_base: file.project_id_base,
            fuse_quota_binary: file.fuse_quota_binary,
            fuse_quota_binary_sha256: file.fuse_quota_binary_sha256,
            fuse_quota_rescan_interval_seconds: file.fuse_quota_rescan_interval_seconds,
            soft_scanner: file.soft_scanner,
        })
    }
}

impl DiskConfig {
    pub fn fuse_quota_binary(&self) -> &str {
        let binary = self.fuse_quota_binary.trim();
        if binary.is_empty() {
            "embedded"
        } else {
            binary
        }
    }
}

impl Default for DiskConfig {
    fn default() -> Self {
        Self {
            mode: DiskLimitMode::FuseQuota,
            selection: DiskLimitSelection::Auto,
            project_id_base: 200_000,
            fuse_quota_binary: "embedded".to_string(),
            fuse_quota_binary_sha256: String::new(),
            fuse_quota_rescan_interval_seconds: 150,
            soft_scanner: SoftDiskScannerConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskLimitSelection {
    /// Prefer native quotas; fall back to FuseQuota for compatible databases.
    #[default]
    Auto,
    /// Force the FuseQuota fallback for compatible databases.
    FuseQuota,
    /// Scanner-enforced soft limits. `none` is accepted as a compatibility
    /// alias, but API metadata deliberately calls the active mechanism a
    /// soft scanner rather than implying that limits are disabled.
    #[serde(alias = "none")]
    SoftScanner,
    /// Require a supported native filesystem quota implementation.
    ProjectQuota,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SoftDiskScannerConfig {
    /// Base scheduler interval. It is also the authoritative full-scan
    /// interval for protocols such as Qdrant whose mmap writes may not emit
    /// filesystem notifications.
    pub scan_interval_seconds: u64,
    /// Use one process-wide recursive inotify watcher to prioritize changed
    /// instances and perform bounded incremental subtree reconciliation.
    /// Periodic full scans remain authoritative when this is disabled or the
    /// host watcher is unavailable.
    pub use_inotify: bool,
    /// Maximum time between authoritative full scans while incremental
    /// inotify-driven scans are healthy.
    pub full_scan_interval_seconds: u64,
    /// Coalesce event bursts for this long before scanning dirty subtrees.
    pub inotify_debounce_milliseconds: u64,
    /// Maximum independent dirty subtrees retained for one instance. Hitting
    /// the bound discards the hints and forces a full reconciliation.
    pub max_dirty_paths_per_instance: usize,
    /// Concurrent directory walks across all instances.
    pub max_concurrent_scans: usize,
    /// Cached directory records across all instances; overflow uses full scans.
    pub max_cached_directories_global: usize,
    /// Per-instance entry bound for a single walk.
    pub max_entries_per_scan: usize,
    /// Per-instance wall-clock budget for a single walk.
    pub scan_timeout_seconds: u64,
    /// Stop an active instance after this many consecutive scans cannot
    /// produce a trustworthy measurement. This prevents scanner bounds or
    /// filesystem errors from becoming a fail-open bypass.
    pub max_consecutive_scan_failures: u8,
    /// Minimum reserve used to absorb writes during detection and shutdown.
    pub safety_reserve_mib: u64,
    /// Clear a restart block only below this percentage of the configured
    /// limit. This hysteresis prevents stop/start oscillation.
    pub recovery_percent: u8,
    /// Graceful shutdown deadline before SIGKILL fallback.
    pub shutdown_grace_seconds: u64,
}

impl Default for SoftDiskScannerConfig {
    fn default() -> Self {
        Self {
            scan_interval_seconds: 15,
            use_inotify: true,
            full_scan_interval_seconds: 90,
            inotify_debounce_milliseconds: 500,
            max_dirty_paths_per_instance: 512,
            max_concurrent_scans: 2,
            max_cached_directories_global: 32_768,
            max_entries_per_scan: 1_000_000,
            scan_timeout_seconds: 30,
            max_consecutive_scan_failures: 3,
            safety_reserve_mib: 64,
            recovery_percent: 85,
            shutdown_grace_seconds: 30,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DiskLimitMode {
    #[default]
    FuseQuota,
    ProjectQuota,
    SoftScanner,
}

impl DiskLimitMode {
    /// This legacy API bit means a hard write-time filesystem limit. The soft
    /// scanner remains active enforcement, but is intentionally reported as
    /// non-hard so callers do not mistake it for quota isolation.
    pub fn enforced(self) -> bool {
        self != Self::SoftScanner
    }

    pub fn method(self) -> &'static str {
        match self {
            Self::FuseQuota => "fuse_quota",
            Self::ProjectQuota => "host_filesystem_quota",
            Self::SoftScanner => "soft_scanner",
        }
    }

    pub fn from_persisted_method(method: &str) -> Option<Self> {
        match method {
            "fuse_quota" => Some(Self::FuseQuota),
            "soft_scanner" => Some(Self::SoftScanner),
            "host_filesystem_quota"
            | "host_xfs_project_quota"
            | "host_linux_project_quota"
            | "host_btrfs_qgroup"
            | "host_zfs_refquota" => Some(Self::ProjectQuota),
            _ => None,
        }
    }
}
