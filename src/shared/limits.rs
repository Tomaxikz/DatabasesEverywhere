use serde::{Deserialize, Serialize};

pub const MIN_CPU_CORES: f64 = 0.01;
pub const MAX_CPU_CORES: f64 = 1024.0;
pub const MAX_MEMORY_MIB: u64 = 1024 * 1024;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ResourceLimitError {
    #[error("cpu_cores must be finite and at least {MIN_CPU_CORES}")]
    InvalidCpuCores,
    #[error("cpu_cores must not exceed {MAX_CPU_CORES}")]
    CpuCoresTooHigh,
    #[error("memory_mib must be greater than zero")]
    InvalidMemory,
    #[error("memory_mib must not exceed {MAX_MEMORY_MIB}")]
    MemoryTooHigh,
}

pub fn validate_runtime_limits(cpu_cores: f64, memory_mib: u64) -> Result<(), ResourceLimitError> {
    if !cpu_cores.is_finite() || cpu_cores < MIN_CPU_CORES {
        return Err(ResourceLimitError::InvalidCpuCores);
    }
    if cpu_cores > MAX_CPU_CORES {
        return Err(ResourceLimitError::CpuCoresTooHigh);
    }
    if memory_mib == 0 {
        return Err(ResourceLimitError::InvalidMemory);
    }
    if memory_mib > MAX_MEMORY_MIB {
        return Err(ResourceLimitError::MemoryTooHigh);
    }
    Ok(())
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_production_limit_boundaries() {
        validate_runtime_limits(MIN_CPU_CORES, 1).unwrap();
        validate_runtime_limits(MAX_CPU_CORES, MAX_MEMORY_MIB).unwrap();
    }

    #[test]
    fn rejects_non_finite_cpu_limits() {
        for cpu_cores in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(
                validate_runtime_limits(cpu_cores, 1024),
                Err(ResourceLimitError::InvalidCpuCores)
            );
        }
    }

    #[test]
    fn rejects_limits_above_production_caps() {
        assert_eq!(
            validate_runtime_limits(MAX_CPU_CORES + 0.1, 1024),
            Err(ResourceLimitError::CpuCoresTooHigh)
        );
        assert_eq!(
            validate_runtime_limits(1.0, MAX_MEMORY_MIB + 1),
            Err(ResourceLimitError::MemoryTooHigh)
        );
        assert_eq!(
            validate_runtime_limits(1.0, 1_u64 << 44),
            Err(ResourceLimitError::MemoryTooHigh)
        );
    }

    #[test]
    fn rejects_cpu_values_below_docker_minimum() {
        assert_eq!(
            validate_runtime_limits(MIN_CPU_CORES / 2.0, 1024),
            Err(ResourceLimitError::InvalidCpuCores)
        );
    }
}
