use std::collections::{HashMap, HashSet};

use serde::{Serializer, ser::SerializeStruct};

use super::{InstallProgress, ResourceReport, TenantActivity};

// REST reports stay self-contained. Inside a stats item its identity and
// activity network counters already have one authoritative location.
pub(crate) fn resources<S: Serializer>(
    report: &Option<ResourceReport>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let Some(report) = report else {
        return serializer.serialize_none();
    };
    let mut fields = serializer.serialize_struct("MonitoringResources", 3)?;
    fields.serialize_field("cpu", &report.cpu)?;
    fields.serialize_field("memory", &report.memory)?;
    fields.serialize_field("disk", &report.disk)?;
    fields.end()
}

pub(crate) fn activity<S: Serializer>(
    activity: &TenantActivity,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let current = &activity.current;
    let mut fields = serializer.serialize_struct("MonitoringActivity", 11)?;
    fields.serialize_field("stats_epoch", &current.stats_epoch)?;
    fields.serialize_field("sampled_at_unix", &current.sampled_at_unix)?;
    fields.serialize_field("accepted", &current.accepted)?;
    fields.serialize_field("rejected", &current.rejected)?;
    fields.serialize_field("active_connections", &current.active_connections)?;
    fields.serialize_field("opened_connections", &current.opened_connections)?;
    fields.serialize_field("rx_bytes", &current.rx_bytes)?;
    fields.serialize_field("tx_bytes", &current.tx_bytes)?;
    fields.serialize_field("cpu_time_micros", &current.cpu_time_micros)?;
    fields.serialize_field("peak_query_memory_bytes", &current.peak_query_memory_bytes)?;
    fields.serialize_field("sources", &activity.sources)?;
    fields.end()
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
    /// Called only on the authorized snapshot. A new connection has no cursor
    /// and receives all retained results, including completed/failed jobs.
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
