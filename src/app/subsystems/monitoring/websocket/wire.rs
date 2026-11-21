use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    ops::Deref,
};

use serde::{Serialize, Serializer};
use serde_json::value::RawValue;

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

/// A row of a monitoring snapshot together with its compact JSON encoding.
///
/// Rows are encoded once when the snapshot is built and every viewer of that snapshot reuses the
/// same bytes: serializing an `EncodedRow` copies the stored JSON verbatim, so batch payloads are
/// byte-identical to serializing the value itself. The value stays read-only (no `DerefMut`) so
/// it cannot drift from its encoding.
#[derive(Debug)]
pub(crate) struct EncodedRow<T> {
    value: T,
    json: Box<RawValue>,
}

impl<T: Serialize> EncodedRow<T> {
    pub(crate) fn new(value: T) -> Result<Self, serde_json::Error> {
        let json = serde_json::value::to_raw_value(&value)?;
        Ok(Self { value, json })
    }
}

impl<T> EncodedRow<T> {
    pub(crate) fn encoded_len(&self) -> usize {
        self.json.get().len()
    }
}

impl<T> Deref for EncodedRow<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl Borrow<InstallProgress> for EncodedRow<InstallProgress> {
    fn borrow(&self) -> &InstallProgress {
        &self.value
    }
}

impl<T> Serialize for EncodedRow<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.json.serialize(serializer)
    }
}

#[derive(Default)]
pub(crate) struct ProgressCursor {
    initialized: bool,
    seen: HashMap<String, u64>,
}

pub(crate) struct ProgressDelta<'a, P = InstallProgress> {
    pub reset: bool,
    pub updates: Vec<&'a P>,
    pub removed: Vec<String>,
}

impl ProgressCursor {
    pub(crate) fn select<'a, P: Borrow<InstallProgress>>(
        &mut self,
        entries: &[&'a P],
    ) -> ProgressDelta<'a, P> {
        let reset = !self.initialized;
        self.initialized = true;
        let current = entries
            .iter()
            .map(|entry| (*entry).borrow().instance_id.as_str())
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
            let progress = entry.borrow();
            if self.seen.get(&progress.instance_id) != Some(&progress.revision) {
                updates.push(entry);
                self.seen
                    .insert(progress.instance_id.clone(), progress.revision);
            }
        }
        ProgressDelta {
            reset,
            updates,
            removed,
        }
    }
}
