use crate::server::placement::DeploymentMode;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ResourceReport {
    pub instance_id: String,
    pub runtime_id: String,
    pub deployment_mode: DeploymentMode,
    pub scope: ResourceScope,
    pub protocol: String,
    pub status: String,
    pub cpu: CpuReport,
    pub memory: MemoryReport,
    pub disk: DiskReport,
    pub network: NetworkReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool: Option<PoolUsageReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResourceView {
    Tenant,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceScope {
    DedicatedInstance,
    SharedTenant,
}

#[derive(Debug, Serialize)]
pub struct PoolUsageReport {
    pub runtime_id: String,
    /// Cgroup CPU capacity configured for the complete shared engine.
    pub cpu_limit_cores: f64,
    pub cpu_usage_percent: Option<f64>,
    /// Cgroup memory capacity configured for the complete shared engine.
    pub memory_limit_bytes: u64,
    pub memory_usage_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct CpuReport {
    pub configured_cores: f64,
    pub usage_percent: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct MemoryReport {
    pub configured_mib: u64,
    pub usage_bytes: Option<u64>,
    pub limit_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct DiskReport {
    pub configured_mib: u64,
    pub limit_bytes: u64,
    /// Null means no current measurement; it never means an empty database.
    pub used_bytes: Option<u64>,
    pub enforced: bool,
    pub enforcement_method: String,
    /// `hard` means writes are rejected by a filesystem quota; `soft` means
    /// bounded predictive scanning with stop/kill enforcement.
    pub enforcement_strength: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_logical_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_physical_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_growth_bytes_per_second: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_peak_growth_bytes_per_second: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_predicted_seconds_to_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_stop_threshold_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_recovery_threshold_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_restart_blocked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanner_sample_age_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct NetworkReport {
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct NodeResourceSummary {
    pub node_uuid: String,
    pub sampled_at: String,
    pub cpu: NodeCpuSummary,
    pub memory: NodeMemorySummary,
    pub disk: NodeDiskSummary,
    pub instances: NodeInstanceSummary,
}

#[derive(Debug, Serialize)]
pub struct NodeCpuSummary {
    pub total_cores: u64,
    pub allocated_cores: f64,
    pub host_usage_percent: f64,
    pub managed_usage_cores: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct NodeMemorySummary {
    pub total_bytes: u64,
    pub allocation_limit_bytes: u64,
    pub reserved_bytes: u64,
    pub allocated_bytes: u64,
    pub host_used_bytes: u64,
    pub managed_used_bytes: Option<u64>,
    pub available_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct NodeDiskSummary {
    pub total_bytes: u64,
    pub allocation_limit_bytes: u64,
    pub reserved_bytes: u64,
    pub allocated_bytes: u64,
    pub host_used_bytes: u64,
    pub managed_used_bytes: Option<u64>,
    pub available_bytes: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct NodeInstanceSummary {
    pub total: u64,
    pub creating: u64,
    pub booting: u64,
    pub running: u64,
    pub stopped: u64,
    pub failed: u64,
    pub quarantined: u64,
    pub deleting: u64,
}
