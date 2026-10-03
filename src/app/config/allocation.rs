use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AllocationConfig {
    /// Reject CPU-limit reservations that would allocate more cores than the
    /// daemon host exposes. Disable only when deliberate CPU overcommit is
    /// acceptable.
    pub prevent_cpu_overallocation: bool,
    /// Reject memory-limit reservations that exceed the configured safe pool
    /// or consume the host memory reserve.
    pub prevent_memory_overallocation: bool,
    /// Reject disk-limit reservations that exceed the configured safe pool or
    /// consume the host disk reserve.
    pub prevent_disk_overallocation: bool,
    /// Optional hard reservation ceiling. When omitted, physical memory minus
    /// `reserved_memory_mib` is used.
    pub max_memory_mib: Option<u64>,
    /// Optional hard reservation ceiling. When omitted, the capacity of the
    /// filesystem backing `paths.volumes` minus `reserved_disk_mib` is used.
    pub max_disk_mib: Option<u64>,
    /// Memory kept outside the database allocation pool for the OS and other
    /// services. This reserve is also required to remain currently available
    /// before an allocation increase is admitted.
    pub reserved_memory_mib: u64,
    /// Disk kept outside the database allocation pool. This reserve is also
    /// required to remain currently available before an allocation increase.
    pub reserved_disk_mib: u64,
}

impl Default for AllocationConfig {
    fn default() -> Self {
        Self {
            prevent_cpu_overallocation: true,
            prevent_memory_overallocation: true,
            prevent_disk_overallocation: true,
            max_memory_mib: None,
            max_disk_mib: None,
            reserved_memory_mib: 512,
            reserved_disk_mib: 2048,
        }
    }
}

impl AllocationConfig {
    pub fn memory_allocation_cap_bytes(&self, physical_total_bytes: u64) -> u64 {
        allocation_cap_bytes(
            physical_total_bytes,
            self.max_memory_mib,
            self.reserved_memory_mib,
        )
    }

    pub fn disk_allocation_cap_bytes(&self, physical_total_bytes: u64) -> u64 {
        allocation_cap_bytes(
            physical_total_bytes,
            self.max_disk_mib,
            self.reserved_disk_mib,
        )
    }

    pub fn reserved_memory_bytes(&self) -> u64 {
        mib_to_bytes(self.reserved_memory_mib)
    }

    pub fn reserved_disk_bytes(&self) -> u64 {
        mib_to_bytes(self.reserved_disk_mib)
    }
}

fn allocation_cap_bytes(
    physical_total_bytes: u64,
    configured_max_mib: Option<u64>,
    reserved_mib: u64,
) -> u64 {
    let after_reserve = physical_total_bytes.saturating_sub(mib_to_bytes(reserved_mib));
    configured_max_mib
        .map(mib_to_bytes)
        .unwrap_or(after_reserve)
        .min(after_reserve)
}
