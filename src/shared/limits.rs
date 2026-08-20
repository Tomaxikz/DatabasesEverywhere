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
    fn validates_all_production_limit_boundaries() {
        let cases = [
            (MIN_CPU_CORES, 1, Ok(())),
            (MAX_CPU_CORES, MAX_MEMORY_MIB, Ok(())),
            (f64::NAN, 1024, Err(ResourceLimitError::InvalidCpuCores)),
            (
                f64::INFINITY,
                1024,
                Err(ResourceLimitError::InvalidCpuCores),
            ),
            (
                f64::NEG_INFINITY,
                1024,
                Err(ResourceLimitError::InvalidCpuCores),
            ),
            (
                MAX_CPU_CORES + 0.1,
                1024,
                Err(ResourceLimitError::CpuCoresTooHigh),
            ),
            (
                1.0,
                MAX_MEMORY_MIB + 1,
                Err(ResourceLimitError::MemoryTooHigh),
            ),
            (1.0, 1_u64 << 44, Err(ResourceLimitError::MemoryTooHigh)),
            (
                MIN_CPU_CORES / 2.0,
                1024,
                Err(ResourceLimitError::InvalidCpuCores),
            ),
        ];
        for (cpu_cores, memory_mib, expected) in cases {
            assert_eq!(
                validate_runtime_limits(cpu_cores, memory_mib),
                expected,
                "cpu={cpu_cores:?}, memory_mib={memory_mib}"
            );
        }
    }
}
