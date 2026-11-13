use crate::server::placement::DeploymentMode;
use serde::Serialize;

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ResourceReport {
    pub instance_id: String,
    pub runtime_id: String,
    pub deployment_mode: DeploymentMode,
    #[schema(inline)]
    pub scope: ResourceScope,
    #[schema(value_type = crate::databases::protocol::Protocol)]
    pub protocol: String,
    pub status: String,
    #[schema(inline)]
    pub cpu: CpuReport,
    #[schema(inline)]
    pub memory: MemoryReport,
    #[schema(inline)]
    pub disk: DiskReport,
    #[schema(inline)]
    pub network: NetworkReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(inline, nullable = false)]
    pub pool: Option<PoolUsageReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResourceView {
    Tenant,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceScope {
    DedicatedInstance,
    SharedTenant,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PoolUsageReport {
    pub runtime_id: String,
    pub cpu_limit_cores: f64,
    #[schema(required)]
    pub cpu_usage_percent: Option<f64>,
    pub memory_limit_bytes: u64,
    #[schema(required)]
    pub memory_usage_bytes: Option<u64>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CpuReport {
    pub configured_cores: f64,
    #[schema(required)]
    pub usage_percent: Option<f64>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MemoryReport {
    pub configured_mib: u64,
    #[schema(required)]
    pub usage_bytes: Option<u64>,
    #[schema(required)]
    pub limit_bytes: Option<u64>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DiskReport {
    pub configured_mib: u64,
    pub limit_bytes: u64,
    /// it never means an empty database.
    #[schema(required)]
    pub used_bytes: Option<u64>,
    pub enforced: bool,
    pub enforcement_method: String,
    #[schema(schema_with = crate::routes::openapi::literals::enforcement_strength)]
    pub enforcement_strength: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub scanner_logical_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub scanner_physical_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub scanner_growth_bytes_per_second: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub scanner_peak_growth_bytes_per_second: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub scanner_predicted_seconds_to_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub scanner_stop_threshold_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub scanner_recovery_threshold_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub scanner_restart_blocked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub scanner_sample_age_seconds: Option<u64>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct NetworkReport {
    #[schema(required)]
    pub rx_bytes: Option<u64>,
    #[schema(required)]
    pub tx_bytes: Option<u64>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct NodeResourceSummary {
    pub node_uuid: String,
    #[schema(format = DateTime)]
    pub sampled_at: String,
    #[schema(inline)]
    pub cpu: NodeCpuSummary,
    #[schema(inline)]
    pub memory: NodeMemorySummary,
    #[schema(inline)]
    pub disk: NodeDiskSummary,
    #[schema(inline)]
    pub instances: NodeInstanceSummary,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct NodeCpuSummary {
    #[schema(minimum = 1)]
    pub total_cores: u64,
    #[schema(minimum = 0)]
    pub allocated_cores: f64,
    #[schema(minimum = 0, maximum = 100)]
    pub host_usage_percent: f64,
    #[schema(required, minimum = 0)]
    pub managed_usage_cores: Option<f64>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct NodeMemorySummary {
    pub total_bytes: u64,
    pub allocation_limit_bytes: u64,
    pub reserved_bytes: u64,
    pub allocated_bytes: u64,
    pub host_used_bytes: u64,
    #[schema(required)]
    pub managed_used_bytes: Option<u64>,
    pub available_bytes: u64,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct NodeDiskSummary {
    pub total_bytes: u64,
    pub allocation_limit_bytes: u64,
    pub reserved_bytes: u64,
    pub allocated_bytes: u64,
    pub host_used_bytes: u64,
    #[schema(required)]
    pub managed_used_bytes: Option<u64>,
    pub available_bytes: u64,
}

#[derive(Debug, Default, Serialize, utoipa::ToSchema)]
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
