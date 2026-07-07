use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceLimits {
    pub cpu_cores: f64,
    pub memory_mib: u64,
    pub disk_mib: u64,
    pub disk_enforced: bool,
    pub disk_enforcement_method: String,
}

impl Default for InstanceLimits {
    fn default() -> Self {
        Self {
            cpu_cores: 1.0,
            memory_mib: 1024,
            disk_mib: 10240,
            disk_enforced: false,
            disk_enforcement_method: "not_supported".to_string(),
        }
    }
}
