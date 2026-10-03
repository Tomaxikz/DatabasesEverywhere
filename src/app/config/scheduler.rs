use super::*;

/// Bounds durable data-operation admission separately from active execution.
/// Dynamic mode accounts for estimated CPU, memory, and I/O work. Operators
/// can disable it and use `manual_max_active_jobs` as a fixed ceiling. Dynamic
/// work may remain queued when live memory cannot safely fit one estimated
/// job; CPU and I/O are concurrency weights that still allow one isolated,
/// memory-safe job.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImportExportSchedulerConfig {
    pub dynamic_limiter_enabled: bool,
    pub max_queued_jobs: usize,
    pub max_queued_jobs_per_instance: usize,
    pub manual_max_active_jobs: usize,
    pub dynamic_max_active_jobs: usize,
    /// Zero periodically derives a conservative budget from effective
    /// host-or-cgroup available memory.
    pub dynamic_memory_budget_mib: u64,
    /// Zero derives an in-flight work budget that covers configured uploads
    /// and one maximum physical restore.
    pub dynamic_io_budget_mib: u64,
    /// Zero periodically derives CPU tokens from the effective host-or-cgroup
    /// CPU quota.
    pub dynamic_cpu_units: usize,
    /// Maximum time an estimate that cannot fit the current dynamic capacity
    /// may wait for live auto-detected headroom to recover.
    pub starvation_timeout_seconds: u64,
    pub max_bypass: usize,
}

impl Default for ImportExportSchedulerConfig {
    fn default() -> Self {
        Self {
            dynamic_limiter_enabled: true,
            max_queued_jobs: 1_024,
            max_queued_jobs_per_instance: 32,
            manual_max_active_jobs: 16,
            dynamic_max_active_jobs: 256,
            dynamic_memory_budget_mib: 0,
            dynamic_io_budget_mib: 0,
            dynamic_cpu_units: 0,
            starvation_timeout_seconds: 30,
            max_bypass: 8,
        }
    }
}
