use serde::Serialize;

use super::MIB;
use crate::{databases::protocol::Protocol, utils::limits::bytes_to_mib_ceil};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct JobResourceCost {
    pub input_size_bytes: u64,
    pub memory_mib: u64,
    pub io_mib: u64,
    pub cpu_units: usize,
}

impl JobResourceCost {
    pub fn estimate(input: JobEstimateInput) -> Self {
        let source_mib = bytes_to_mib_ceil(input.input_size_bytes).max(1);
        let cost = input.protocol.engine().job_cost();
        let base_memory_mib = cost.base_memory_mib;
        let io_multiplier = cost.io_multiplier;
        let base_cpu_units = cost.base_cpu_units;
        let stream_memory =
            (source_mib / cost.stream_memory_divisor).min(cost.stream_memory_cap_mib);
        let compression_memory = u64::from(input.compressed) * 64;
        let logical_wipe = input.wipe && input.rollback_size_bytes > 0;
        let rollback_memory = u64::from(logical_wipe) * 64;
        let memory_mib = base_memory_mib
            .saturating_add(stream_memory)
            .saturating_add(compression_memory)
            .saturating_add(rollback_memory);

        let io_mib = if input.export {
            source_mib.saturating_mul(2)
        } else {
            let rollback_io = if logical_wipe {
                bytes_to_mib_ceil(input.rollback_size_bytes).saturating_mul(2)
            } else {
                0
            };
            source_mib
                .saturating_mul(io_multiplier)
                .saturating_add(rollback_io)
        };
        let cpu_units = base_cpu_units + usize::from(input.compressed) + usize::from(logical_wipe);
        Self {
            input_size_bytes: input.input_size_bytes,
            memory_mib: memory_mib.max(1),
            io_mib: io_mib.max(1),
            cpu_units: cpu_units.max(1),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct JobEstimateInput {
    pub protocol: Protocol,
    pub input_size_bytes: u64,
    pub rollback_size_bytes: u64,
    pub wipe: bool,
    pub compressed: bool,
    pub export: bool,
}

pub fn protocol_uses_native_compression(protocol: Protocol) -> bool {
    protocol.engine().native_export_compression()
}

pub fn protocol_uses_logical_dumps(protocol: Protocol) -> bool {
    !protocol.engine().is_physical()
}

pub fn conservative_import_input_bytes(
    protocol: Protocol,
    source_bytes: u64,
    prepared_ceiling_bytes: u64,
    target_disk_mib: u64,
    compressed: bool,
) -> u64 {
    if compressed && !protocol_uses_logical_dumps(protocol) {
        target_disk_mib
            .saturating_mul(MIB)
            .clamp(1, super::super::MAX_DATA_ARCHIVE_BYTES)
    } else if compressed {
        prepared_ceiling_bytes.max(1)
    } else {
        source_bytes.max(1)
    }
}
