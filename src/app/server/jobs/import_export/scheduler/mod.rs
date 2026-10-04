use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::Serialize;
use tokio::sync::oneshot;

use crate::config::ImportExportSchedulerConfig;

use super::lock_unpoisoned;

#[cfg(test)]
use crate::databases::protocol::Protocol;

const MIB: u64 = 1024 * 1024;
const FALLBACK_AVAILABLE_MEMORY_MIB: u64 = 4096;
const CAPACITY_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const MIN_REFRESH_WAKEUP_INTERVAL: Duration = Duration::from_millis(10);

mod resources;
use resources::HostResourceProvider;
#[cfg(test)]
use resources::{
    cgroup_candidate_bases, cgroup_memory_sample_complete, cgroup_path,
    cgroup_v2_cpu_sample_complete, control_value_unchanged, minimum_present,
    parse_cgroup_memory_available_mib, parse_cgroup_v1_cpu_units, parse_cgroup_v2_cpu_units,
    parse_host_available_memory_mib, read_cgroup_memory, read_cgroup_v2_cpu_units,
    safe_cgroup_relative_path, test_resource_sample_from_cgroups,
};

#[cfg(test)]
mod resource_tests;

mod capacity;
mod cost;
mod dispatch;
#[cfg(test)]
mod tests;

pub use self::capacity::SchedulerCapacity;
use self::capacity::SchedulerResourceProvider;
#[cfg(test)]
use self::capacity::SchedulerResourceSample;
pub use self::cost::{
    JobEstimateInput, JobResourceCost, conservative_import_input_bytes,
    protocol_uses_logical_dumps, protocol_uses_native_compression,
};
use self::dispatch::{dispatch, release};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerMode {
    Dynamic,
    Manual,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct SchedulerSnapshot {
    pub capacity: SchedulerCapacity,
    pub active_jobs: usize,
    pub waiting_jobs: usize,
    pub active_memory_mib: u64,
    pub active_io_mib: u64,
    pub active_cpu_units: usize,
    pub accepting: bool,
}

#[derive(Debug, Clone)]
pub struct ImportExportScheduler {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    starvation_timeout: Duration,
    max_bypass: usize,
    auto_memory_budget: bool,
    auto_cpu_units: bool,
    capacity_refresh_interval: Duration,
    resource_provider: Arc<dyn SchedulerResourceProvider>,
    state: Mutex<SchedulerState>,
}

impl Shared {
    fn refreshes_capacity(&self) -> bool {
        self.auto_memory_budget || self.auto_cpu_units
    }
}

#[derive(Debug)]
struct SchedulerState {
    capacity: SchedulerCapacity,
    pending_memory_increase_mib: Option<u64>,
    pending_cpu_increase: Option<usize>,
    refresh_wakeup_scheduled: bool,
    accepting: bool,
    next_sequence: u64,
    active_jobs: usize,
    active_memory_mib: u64,
    active_io_mib: u64,
    active_cpu_units: usize,
    waiting: VecDeque<WaitingJob>,
}

#[derive(Debug)]
struct WaitingJob {
    sequence: u64,
    queued_at: Instant,
    bypasses: usize,
    cost: JobResourceCost,
    ready: oneshot::Sender<Result<ExecutionPermit, SchedulerAcquireError>>,
}

#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum SchedulerAcquireError {
    #[error("the import/export scheduler is shutting down")]
    Closed,
    #[error("the estimated job exceeds a fixed dynamic scheduler budget")]
    InsufficientCapacity,
}

#[derive(Debug)]
pub struct ExecutionPermit {
    shared: Arc<Shared>,
    cost: Option<JobResourceCost>,
}

struct WaitingRegistration {
    shared: Arc<Shared>,
    sequence: u64,
    armed: bool,
}

impl ImportExportScheduler {
    pub fn new(capacity: SchedulerCapacity, config: &ImportExportSchedulerConfig) -> Self {
        Self::new_with_provider_and_refresh(
            capacity,
            config,
            Arc::new(HostResourceProvider),
            CAPACITY_REFRESH_INTERVAL,
        )
    }

    fn new_with_provider_and_refresh(
        capacity: SchedulerCapacity,
        config: &ImportExportSchedulerConfig,
        resource_provider: Arc<dyn SchedulerResourceProvider>,
        capacity_refresh_interval: Duration,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                starvation_timeout: Duration::from_secs(config.starvation_timeout_seconds),
                max_bypass: config.max_bypass,
                auto_memory_budget: config.dynamic_memory_budget_mib == 0,
                auto_cpu_units: config.dynamic_cpu_units == 0,
                capacity_refresh_interval,
                resource_provider,
                state: Mutex::new(SchedulerState {
                    capacity,
                    pending_memory_increase_mib: None,
                    pending_cpu_increase: None,
                    refresh_wakeup_scheduled: false,
                    accepting: true,
                    next_sequence: 0,
                    active_jobs: 0,
                    active_memory_mib: 0,
                    active_io_mib: 0,
                    active_cpu_units: 0,
                    waiting: VecDeque::new(),
                }),
            }),
        }
    }

    pub async fn acquire(
        &self,
        cost: JobResourceCost,
    ) -> Result<ExecutionPermit, SchedulerAcquireError> {
        let (ready, receiver) = oneshot::channel();
        let sequence;
        {
            let mut state = lock_unpoisoned(&self.shared.state);
            if !state.accepting {
                return Err(SchedulerAcquireError::Closed);
            }
            if structurally_exceeds_fixed_budget(&self.shared, &state, cost) {
                return Err(SchedulerAcquireError::InsufficientCapacity);
            }
            sequence = state.next_sequence;
            state.next_sequence = state.next_sequence.wrapping_add(1);
            state.waiting.push_back(WaitingJob {
                sequence,
                queued_at: Instant::now(),
                bypasses: 0,
                cost,
                ready,
            });
            dispatch(&self.shared, &mut state);
        }
        let mut registration = WaitingRegistration {
            shared: Arc::clone(&self.shared),
            sequence,
            armed: true,
        };
        let result = receiver.await.unwrap_or(Err(SchedulerAcquireError::Closed));
        registration.armed = false;
        result
    }

    pub fn close(&self) {
        let mut state = lock_unpoisoned(&self.shared.state);
        state.accepting = false;
        for waiting in state.waiting.drain(..) {
            let _ = waiting.ready.send(Err(SchedulerAcquireError::Closed));
        }
    }

    pub fn snapshot(&self) -> SchedulerSnapshot {
        let mut state = lock_unpoisoned(&self.shared.state);
        dispatch(&self.shared, &mut state);
        SchedulerSnapshot {
            capacity: state.capacity,
            active_jobs: state.active_jobs,
            waiting_jobs: state.waiting.len(),
            active_memory_mib: state.active_memory_mib,
            active_io_mib: state.active_io_mib,
            active_cpu_units: state.active_cpu_units,
            accepting: state.accepting,
        }
    }
}

fn structurally_exceeds_fixed_budget(
    shared: &Shared,
    state: &SchedulerState,
    cost: JobResourceCost,
) -> bool {
    state.capacity.mode == SchedulerMode::Dynamic
        && !shared.auto_memory_budget
        && cost.memory_mib > state.capacity.memory_budget_mib
}

impl Drop for ExecutionPermit {
    fn drop(&mut self) {
        let Some(cost) = self.cost.take() else {
            return;
        };
        let mut state = lock_unpoisoned(&self.shared.state);
        release(&mut state, cost);
        dispatch(&self.shared, &mut state);
    }
}

impl Drop for WaitingRegistration {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut state = lock_unpoisoned(&self.shared.state);
        if let Some(index) = state
            .waiting
            .iter()
            .position(|waiting| waiting.sequence == self.sequence)
        {
            state.waiting.remove(index);
            dispatch(&self.shared, &mut state);
        }
    }
}
