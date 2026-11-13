use std::collections::{HashMap, HashSet};

use serde::{Serialize, Serializer};

use super::{InstallProgress, ResourceReport, TenantActivity};
use crate::{
    server::monitoring::OperationCounts,
    subsystems::monitoring::{
        activity::ActivitySources,
        resources::{CpuReport, DiskReport, MemoryReport},
    },
};

#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MonitoringResources<'a> {
    #[schema(inline)]
    cpu: &'a CpuReport,
    #[schema(inline)]
    memory: &'a MemoryReport,
    #[schema(inline)]
    disk: &'a DiskReport,
}

#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct MonitoringActivity<'a> {
    stats_epoch: &'a str,
    sampled_at_unix: i64,
    accepted: OperationCounts,
    rejected: OperationCounts,
    active_connections: u64,
    opened_connections: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    #[schema(required)]
    cpu_time_micros: Option<u64>,
    #[schema(required)]
    peak_query_memory_bytes: Option<u64>,
    #[schema(inline)]
    sources: &'a ActivitySources,
}

pub(crate) fn resources<S: Serializer>(
    report: &Option<ResourceReport>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    report
        .as_ref()
        .map(|report| MonitoringResources {
            cpu: &report.cpu,
            memory: &report.memory,
            disk: &report.disk,
        })
        .serialize(serializer)
}

pub(crate) fn activity<S: Serializer>(
    activity: &TenantActivity,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let current = &activity.current;
    MonitoringActivity {
        stats_epoch: &current.stats_epoch,
        sampled_at_unix: current.sampled_at_unix,
        accepted: current.accepted,
        rejected: current.rejected,
        active_connections: current.active_connections,
        opened_connections: current.opened_connections,
        rx_bytes: current.rx_bytes,
        tx_bytes: current.tx_bytes,
        cpu_time_micros: current.cpu_time_micros,
        peak_query_memory_bytes: current.peak_query_memory_bytes,
        sources: &activity.sources,
    }
    .serialize(serializer)
}

#[derive(Default)]
pub(crate) struct ProgressCursor {
    initialized: bool,
    seen: HashMap<String, u64>,
}

pub(crate) struct ProgressDelta<'a> {
    pub reset: bool,
    pub updates: Vec<&'a InstallProgress>,
    pub removed: Vec<String>,
}

impl ProgressCursor {
    pub(crate) fn select<'a>(&mut self, entries: &[&'a InstallProgress]) -> ProgressDelta<'a> {
        let reset = !self.initialized;
        self.initialized = true;
        let current = entries
            .iter()
            .map(|entry| entry.instance_id.as_str())
            .collect::<HashSet<_>>();
        let mut removed = self
            .seen
            .keys()
            .filter(|id| !current.contains(id.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        removed.sort_unstable();
        self.seen.retain(|id, _| current.contains(id.as_str()));
        let mut updates = Vec::new();
        for &entry in entries {
            if self.seen.get(&entry.instance_id) != Some(&entry.revision) {
                updates.push(entry);
                self.seen.insert(entry.instance_id.clone(), entry.revision);
            }
        }
        ProgressDelta {
            reset,
            updates,
            removed,
        }
    }
}
