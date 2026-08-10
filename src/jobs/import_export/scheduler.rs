use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use serde::Serialize;
use tokio::sync::oneshot;

use crate::{config::ImportExportSchedulerConfig, shared::protocol::Protocol};

const MIB: u64 = 1024 * 1024;
const FALLBACK_AVAILABLE_MEMORY_MIB: u64 = 4096;
const CAPACITY_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const MIN_REFRESH_WAKEUP_INTERVAL: Duration = Duration::from_millis(10);

#[path = "scheduler/resources.rs"]
mod resources;
use resources::HostResourceProvider;
#[cfg(test)]
use resources::{
    cgroup_candidate_bases, cgroup_memory_sample_complete, cgroup_path,
    cgroup_v2_cpu_sample_complete, control_value_unchanged, minimum_present,
    parse_cgroup_memory_available_mib, parse_cgroup_v1_cpu_units, parse_cgroup_v2_cpu_units,
    parse_host_available_memory_mib, read_cgroup_memory, read_cgroup_v2_cpu_units,
    safe_cgroup_relative_path,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerMode {
    Dynamic,
    Manual,
}

trait SchedulerResourceProvider: std::fmt::Debug + Send + Sync {
    fn sample(&self) -> SchedulerResourceSample;
}

#[derive(Debug, Clone, Copy)]
struct SchedulerResourceSample {
    available_memory_mib: Option<u64>,
    cpu_units: Option<usize>,
    memory_valid: bool,
    cpu_valid: bool,
}

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
        let (base_memory_mib, io_multiplier, base_cpu_units) = match input.protocol {
            Protocol::Postgres | Protocol::Mariadb | Protocol::Mysql => (96_u64, 4_u64, 1),
            Protocol::Mongodb => (256, 4, 2),
            Protocol::Clickhouse => (192, 3, 2),
            Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => (128, 2, 1),
        };
        let stream_memory = match input.protocol {
            Protocol::Mongodb => (source_mib / 16).min(512),
            _ => (source_mib / 32).min(256),
        };
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
    matches!(
        protocol,
        Protocol::Mongodb | Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
    )
}

pub fn protocol_uses_logical_dumps(protocol: Protocol) -> bool {
    !matches!(
        protocol,
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
    )
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
            .clamp(1, super::MAX_DATA_ARCHIVE_BYTES)
    } else if compressed {
        prepared_ceiling_bytes.max(1)
    } else {
        source_bytes.max(1)
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct SchedulerCapacity {
    pub mode: SchedulerMode,
    pub max_active_jobs: usize,
    pub memory_budget_mib: u64,
    pub io_budget_mib: u64,
    pub cpu_units: usize,
}

impl SchedulerCapacity {
    pub fn detect(
        config: &ImportExportSchedulerConfig,
        max_upload_bytes: u64,
        max_total_upload_bytes: u64,
    ) -> Self {
        Self::detect_with_provider(
            config,
            max_upload_bytes,
            max_total_upload_bytes,
            &HostResourceProvider,
        )
    }

    fn detect_with_provider(
        config: &ImportExportSchedulerConfig,
        max_upload_bytes: u64,
        max_total_upload_bytes: u64,
        provider: &dyn SchedulerResourceProvider,
    ) -> Self {
        let sample = provider.sample();
        let mode = if config.dynamic_limiter_enabled {
            SchedulerMode::Dynamic
        } else {
            SchedulerMode::Manual
        };
        let memory_budget_mib = if config.dynamic_memory_budget_mib == 0 {
            let available = if sample.memory_valid {
                sample
                    .available_memory_mib
                    .unwrap_or(FALLBACK_AVAILABLE_MEMORY_MIB)
            } else {
                1
            };
            available.saturating_mul(3).saturating_div(5).max(1)
        } else {
            config.dynamic_memory_budget_mib
        };
        let io_budget_mib = if config.dynamic_io_budget_mib == 0 {
            let one_maximum_physical_restore = super::MAX_DATA_ARCHIVE_BYTES.saturating_mul(2);
            bytes_to_mib_ceil(
                max_total_upload_bytes
                    .max(max_upload_bytes.saturating_mul(6))
                    .max(one_maximum_physical_restore),
            )
            .max(256)
        } else {
            config.dynamic_io_budget_mib
        };
        let cpu_units = if config.dynamic_cpu_units == 0 {
            sample
                .cpu_valid
                .then_some(sample.cpu_units)
                .flatten()
                .unwrap_or(1)
        } else {
            config.dynamic_cpu_units
        };
        let max_active_jobs = match mode {
            SchedulerMode::Dynamic => config.dynamic_max_active_jobs,
            SchedulerMode::Manual => config.manual_max_active_jobs,
        };
        Self {
            mode,
            max_active_jobs,
            memory_budget_mib,
            io_budget_mib,
            cpu_units: cpu_units.max(1),
        }
    }

    pub fn recommended_active_jobs(self, cost: JobResourceCost) -> usize {
        if self.mode == SchedulerMode::Manual {
            return self.max_active_jobs;
        }
        self.model_recommended_active_jobs(cost, self.max_active_jobs)
    }

    pub fn model_recommended_active_jobs(self, cost: JobResourceCost, maximum: usize) -> usize {
        let by_memory = ratio(self.memory_budget_mib, cost.memory_mib);
        if by_memory == 0 {
            return 0;
        }
        let by_io = ratio(self.io_budget_mib, cost.io_mib).max(1);
        let by_cpu = (self.cpu_units / cost.cpu_units.max(1)).max(1);
        maximum.min(by_memory).min(by_io).min(by_cpu)
    }
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
        state.active_jobs = state.active_jobs.saturating_sub(1);
        state.active_memory_mib = state.active_memory_mib.saturating_sub(cost.memory_mib);
        state.active_io_mib = state.active_io_mib.saturating_sub(cost.io_mib);
        state.active_cpu_units = state.active_cpu_units.saturating_sub(cost.cpu_units);
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

fn refresh_capacity(shared: &Shared, state: &mut SchedulerState) {
    if !shared.auto_memory_budget && !shared.auto_cpu_units {
        return;
    }
    let sample = shared.resource_provider.sample();
    if shared.auto_memory_budget {
        if sample.memory_valid {
            let candidate = sample
                .available_memory_mib
                .unwrap_or(FALLBACK_AVAILABLE_MEMORY_MIB)
                .saturating_mul(3)
                .saturating_div(5)
                .max(1);
            apply_capacity_sample(
                &mut state.capacity.memory_budget_mib,
                &mut state.pending_memory_increase_mib,
                candidate,
            );
        } else {
            state.pending_memory_increase_mib = None;
            state.capacity.memory_budget_mib = 1;
        }
    }
    if shared.auto_cpu_units {
        if sample.cpu_valid {
            apply_capacity_sample(
                &mut state.capacity.cpu_units,
                &mut state.pending_cpu_increase,
                sample.cpu_units.unwrap_or(1).max(1),
            );
        } else {
            state.pending_cpu_increase = None;
            state.capacity.cpu_units = 1;
        }
    }
}

fn apply_capacity_sample<T: Ord + Copy>(current: &mut T, pending: &mut Option<T>, candidate: T) {
    if candidate <= *current {
        *current = candidate;
        *pending = None;
        return;
    }
    if let Some(previous) = pending.take() {
        *current = previous.min(candidate);
    } else {
        *pending = Some(candidate);
    }
}

fn dispatch(shared: &Arc<Shared>, state: &mut SchedulerState) {
    refresh_capacity(shared, state);
    reject_expired_unfit_jobs(shared, state);
    while state.accepting && state.active_jobs < state.capacity.max_active_jobs {
        let Some(index) = runnable_index(shared, state) else {
            break;
        };
        if index > 0
            && let Some(head) = state.waiting.front_mut()
        {
            head.bypasses = head.bypasses.saturating_add(1);
        }
        let Some(waiting) = state.waiting.remove(index) else {
            break;
        };
        reserve(state, waiting.cost);
        let permit = ExecutionPermit {
            shared: Arc::clone(shared),
            cost: Some(waiting.cost),
        };
        if let Err(returned) = waiting.ready.send(Ok(permit)) {
            if let Ok(mut permit) = returned {
                permit.cost = None;
            }
            release(state, waiting.cost);
        }
    }
    if state.accepting && !state.waiting.is_empty() {
        schedule_capacity_refresh(shared, state);
    }
}

fn reject_expired_unfit_jobs(shared: &Shared, state: &mut SchedulerState) {
    if state.capacity.mode != SchedulerMode::Dynamic {
        return;
    }
    let mut index = 0;
    while index < state.waiting.len() {
        let expired = state.waiting[index].queued_at.elapsed() >= shared.starvation_timeout;
        let unfit = !fits_hard_memory(state.capacity, state.waiting[index].cost);
        if expired && unfit {
            if let Some(waiting) = state.waiting.remove(index) {
                let _ = waiting
                    .ready
                    .send(Err(SchedulerAcquireError::InsufficientCapacity));
            }
        } else {
            index += 1;
        }
    }
}

fn schedule_capacity_refresh(shared: &Arc<Shared>, state: &mut SchedulerState) {
    if state.refresh_wakeup_scheduled || (!shared.auto_memory_budget && !shared.auto_cpu_units) {
        return;
    }
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return;
    };
    state.refresh_wakeup_scheduled = true;
    let shared = Arc::downgrade(shared);
    let delay = shared
        .upgrade()
        .map(|shared| {
            shared
                .capacity_refresh_interval
                .max(MIN_REFRESH_WAKEUP_INTERVAL)
        })
        .unwrap_or(MIN_REFRESH_WAKEUP_INTERVAL);
    runtime.spawn(async move {
        tokio::time::sleep(delay).await;
        if let Some(shared) = shared.upgrade() {
            let mut state = lock_unpoisoned(&shared.state);
            state.refresh_wakeup_scheduled = false;
            dispatch(&shared, &mut state);
        }
    });
}

fn runnable_index(shared: &Shared, state: &SchedulerState) -> Option<usize> {
    let head = state.waiting.front()?;
    if fits(state.capacity, state, head.cost)
        || (state.active_jobs == 0 && fits_hard_memory(state.capacity, head.cost))
    {
        return Some(0);
    }
    let waiting_for_live_capacity = state.capacity.mode == SchedulerMode::Dynamic
        && !fits_hard_memory(state.capacity, head.cost);
    if !waiting_for_live_capacity
        && (head.bypasses >= shared.max_bypass
            || head.queued_at.elapsed() >= shared.starvation_timeout)
    {
        return None;
    }
    state
        .waiting
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, waiting)| waiting.sequence > head.sequence)
        .find_map(|(index, waiting)| fits(state.capacity, state, waiting.cost).then_some(index))
}

fn fits_hard_memory(capacity: SchedulerCapacity, cost: JobResourceCost) -> bool {
    capacity.mode == SchedulerMode::Manual || cost.memory_mib <= capacity.memory_budget_mib
}

fn fits(capacity: SchedulerCapacity, state: &SchedulerState, cost: JobResourceCost) -> bool {
    if capacity.mode == SchedulerMode::Manual {
        return state.active_jobs < capacity.max_active_jobs;
    }
    state.active_memory_mib.saturating_add(cost.memory_mib) <= capacity.memory_budget_mib
        && state.active_io_mib.saturating_add(cost.io_mib) <= capacity.io_budget_mib
        && state.active_cpu_units.saturating_add(cost.cpu_units) <= capacity.cpu_units
}

fn reserve(state: &mut SchedulerState, cost: JobResourceCost) {
    state.active_jobs = state.active_jobs.saturating_add(1);
    state.active_memory_mib = state.active_memory_mib.saturating_add(cost.memory_mib);
    state.active_io_mib = state.active_io_mib.saturating_add(cost.io_mib);
    state.active_cpu_units = state.active_cpu_units.saturating_add(cost.cpu_units);
}

fn release(state: &mut SchedulerState, cost: JobResourceCost) {
    state.active_jobs = state.active_jobs.saturating_sub(1);
    state.active_memory_mib = state.active_memory_mib.saturating_sub(cost.memory_mib);
    state.active_io_mib = state.active_io_mib.saturating_sub(cost.io_mib);
    state.active_cpu_units = state.active_cpu_units.saturating_sub(cost.cpu_units);
}

fn ratio(total: u64, each: u64) -> usize {
    usize::try_from(total / each.max(1)).unwrap_or(usize::MAX)
}

fn bytes_to_mib_ceil(bytes: u64) -> u64 {
    bytes.saturating_add(MIB - 1) / MIB
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[derive(Debug)]
    struct MutableResourceProvider {
        memory_mib: std::sync::atomic::AtomicU64,
        cpu_units: std::sync::atomic::AtomicUsize,
        valid: std::sync::atomic::AtomicBool,
    }

    impl SchedulerResourceProvider for MutableResourceProvider {
        fn sample(&self) -> SchedulerResourceSample {
            let valid = self.valid.load(std::sync::atomic::Ordering::Acquire);
            SchedulerResourceSample {
                available_memory_mib: Some(
                    self.memory_mib.load(std::sync::atomic::Ordering::Acquire),
                ),
                cpu_units: Some(self.cpu_units.load(std::sync::atomic::Ordering::Acquire)),
                memory_valid: valid,
                cpu_valid: valid,
            }
        }
    }

    fn dynamic_capacity(max: usize, memory: u64, io: u64, cpu: usize) -> SchedulerCapacity {
        SchedulerCapacity {
            mode: SchedulerMode::Dynamic,
            max_active_jobs: max,
            memory_budget_mib: memory,
            io_budget_mib: io,
            cpu_units: cpu,
        }
    }

    fn config() -> ImportExportSchedulerConfig {
        ImportExportSchedulerConfig {
            starvation_timeout_seconds: 60,
            max_bypass: 2,
            ..ImportExportSchedulerConfig::default()
        }
    }

    fn cost(memory: u64, io: u64, cpu: usize) -> JobResourceCost {
        JobResourceCost {
            input_size_bytes: 1,
            memory_mib: memory,
            io_mib: io,
            cpu_units: cpu,
        }
    }

    fn fixed_dynamic_scheduler(capacity: SchedulerCapacity) -> ImportExportScheduler {
        let mut configuration = config();
        configuration.dynamic_memory_budget_mib = capacity.memory_budget_mib;
        configuration.dynamic_io_budget_mib = capacity.io_budget_mib;
        configuration.dynamic_cpu_units = capacity.cpu_units;
        ImportExportScheduler::new(capacity, &configuration)
    }

    #[tokio::test]
    async fn dynamic_budget_blocks_until_resources_are_released() {
        let scheduler = fixed_dynamic_scheduler(dynamic_capacity(8, 100, 100, 4));
        let first = scheduler.acquire(cost(80, 80, 3)).await.unwrap();
        let waiting = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.acquire(cost(30, 30, 2)).await })
        };
        tokio::task::yield_now().await;
        assert_eq!(scheduler.snapshot().waiting_jobs, 1);
        drop(first);
        assert!(waiting.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn auto_capacity_refreshes_and_falling_headroom_blocks_new_dispatches() {
        let provider = Arc::new(MutableResourceProvider {
            memory_mib: std::sync::atomic::AtomicU64::new(1000),
            cpu_units: std::sync::atomic::AtomicUsize::new(4),
            valid: std::sync::atomic::AtomicBool::new(true),
        });
        let provider_dyn: Arc<dyn SchedulerResourceProvider> = provider.clone();
        let scheduler = ImportExportScheduler::new_with_provider_and_refresh(
            dynamic_capacity(8, 600, 1000, 4),
            &config(),
            provider_dyn,
            Duration::ZERO,
        );
        let first = scheduler.acquire(cost(400, 10, 3)).await.unwrap();
        provider
            .memory_mib
            .store(300, std::sync::atomic::Ordering::Release);
        provider
            .cpu_units
            .store(1, std::sync::atomic::Ordering::Release);
        let snapshot = scheduler.snapshot();
        assert_eq!(snapshot.capacity.memory_budget_mib, 180);
        assert_eq!(snapshot.capacity.cpu_units, 1);

        let waiting = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.acquire(cost(100, 10, 1)).await })
        };
        tokio::task::yield_now().await;
        assert_eq!(scheduler.snapshot().waiting_jobs, 1);
        drop(first);
        let second = waiting.await.unwrap().unwrap();
        assert_eq!(scheduler.snapshot().active_jobs, 1);
        drop(second);

        let mut explicit = config();
        explicit.dynamic_memory_budget_mib = 700;
        explicit.dynamic_cpu_units = 7;
        let fixed = ImportExportScheduler::new_with_provider_and_refresh(
            dynamic_capacity(8, 700, 1000, 7),
            &explicit,
            provider,
            Duration::ZERO,
        );
        let snapshot = fixed.snapshot();
        assert_eq!(snapshot.capacity.memory_budget_mib, 700);
        assert_eq!(snapshot.capacity.cpu_units, 7);
    }

    #[test]
    fn unreadable_live_sample_fails_closed_and_requires_confirmed_recovery() {
        let provider = Arc::new(MutableResourceProvider {
            memory_mib: std::sync::atomic::AtomicU64::new(300),
            cpu_units: std::sync::atomic::AtomicUsize::new(1),
            valid: std::sync::atomic::AtomicBool::new(true),
        });
        let scheduler = ImportExportScheduler::new_with_provider_and_refresh(
            dynamic_capacity(8, 180, 1000, 1),
            &config(),
            provider.clone(),
            Duration::ZERO,
        );

        provider
            .memory_mib
            .store(16_000, std::sync::atomic::Ordering::Release);
        provider
            .cpu_units
            .store(64, std::sync::atomic::Ordering::Release);
        provider
            .valid
            .store(false, std::sync::atomic::Ordering::Release);
        let unreadable = scheduler.snapshot();
        assert_eq!(unreadable.capacity.memory_budget_mib, 1);
        assert_eq!(unreadable.capacity.cpu_units, 1);

        provider
            .memory_mib
            .store(300, std::sync::atomic::Ordering::Release);
        provider
            .cpu_units
            .store(1, std::sync::atomic::Ordering::Release);
        provider
            .valid
            .store(true, std::sync::atomic::Ordering::Release);
        let first_constrained_sample = scheduler.snapshot();
        assert_eq!(first_constrained_sample.capacity.memory_budget_mib, 1);
        assert_eq!(first_constrained_sample.capacity.cpu_units, 1);
        let constrained_again = scheduler.snapshot();
        assert_eq!(constrained_again.capacity.memory_budget_mib, 180);
        assert_eq!(constrained_again.capacity.cpu_units, 1);

        provider
            .memory_mib
            .store(1000, std::sync::atomic::Ordering::Release);
        provider
            .cpu_units
            .store(4, std::sync::atomic::Ordering::Release);
        let first_increase = scheduler.snapshot();
        assert_eq!(first_increase.capacity.memory_budget_mib, 180);
        assert_eq!(first_increase.capacity.cpu_units, 1);
        let confirmed_increase = scheduler.snapshot();
        assert_eq!(confirmed_increase.capacity.memory_budget_mib, 600);
        assert_eq!(confirmed_increase.capacity.cpu_units, 4);
    }

    #[tokio::test]
    async fn manual_mode_uses_only_the_fixed_active_ceiling() {
        let scheduler = ImportExportScheduler::new(
            SchedulerCapacity {
                mode: SchedulerMode::Manual,
                max_active_jobs: 2,
                memory_budget_mib: 1,
                io_budget_mib: 1,
                cpu_units: 1,
            },
            &config(),
        );
        let first = scheduler.acquire(cost(100, 100, 10)).await.unwrap();
        let second = scheduler.acquire(cost(100, 100, 10)).await.unwrap();
        let third = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.acquire(cost(1, 1, 1)).await })
        };
        tokio::task::yield_now().await;
        assert_eq!(scheduler.snapshot().active_jobs, 2);
        assert_eq!(scheduler.snapshot().waiting_jobs, 1);
        drop(first);
        assert!(third.await.unwrap().is_ok());
        drop(second);
    }

    #[tokio::test]
    async fn small_jobs_may_bypass_a_large_head_only_to_the_configured_limit() {
        let scheduler = fixed_dynamic_scheduler(dynamic_capacity(4, 100, 100, 4));
        let held = scheduler.acquire(cost(60, 60, 2)).await.unwrap();
        let large = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.acquire(cost(80, 80, 3)).await })
        };
        tokio::task::yield_now().await;
        let small_one = scheduler.acquire(cost(20, 20, 1)).await.unwrap();
        let small_two = scheduler.acquire(cost(20, 20, 1)).await.unwrap();
        let third = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.acquire(cost(10, 10, 1)).await })
        };
        tokio::task::yield_now().await;
        assert!(!large.is_finished());
        assert!(!third.is_finished());
        drop(small_one);
        drop(small_two);
        drop(held);
        assert!(large.await.unwrap().is_ok());
        assert!(third.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn close_rejects_and_wakes_waiting_jobs_without_revoking_active_work() {
        let scheduler = fixed_dynamic_scheduler(dynamic_capacity(1, 100, 100, 1));
        let active = scheduler.acquire(cost(10, 10, 1)).await.unwrap();
        let waiting = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.acquire(cost(10, 10, 1)).await })
        };
        tokio::task::yield_now().await;
        scheduler.close();
        assert_eq!(
            waiting.await.unwrap().unwrap_err(),
            SchedulerAcquireError::Closed
        );
        assert_eq!(
            scheduler.acquire(cost(1, 1, 1)).await.unwrap_err(),
            SchedulerAcquireError::Closed
        );
        assert_eq!(scheduler.snapshot().active_jobs, 1);
        drop(active);
        assert_eq!(scheduler.snapshot().active_jobs, 0);
    }

    #[tokio::test]
    async fn cancelling_a_queued_acquire_removes_its_waiter() {
        let scheduler = fixed_dynamic_scheduler(dynamic_capacity(1, 100, 100, 1));
        let active = scheduler.acquire(cost(10, 10, 1)).await.unwrap();
        let waiting = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.acquire(cost(10, 10, 1)).await })
        };
        tokio::task::yield_now().await;
        assert_eq!(scheduler.snapshot().waiting_jobs, 1);
        waiting.abort();
        let _ = waiting.await;
        assert_eq!(scheduler.snapshot().waiting_jobs, 0);
        drop(active);
        assert_eq!(scheduler.snapshot().active_jobs, 0);
    }

    #[test]
    fn dropping_receiver_after_dispatch_releases_sent_permit() {
        let scheduler = fixed_dynamic_scheduler(dynamic_capacity(1, 100, 100, 1));
        let (ready, receiver) = oneshot::channel();
        {
            let mut state = lock_unpoisoned(&scheduler.shared.state);
            state.waiting.push_back(WaitingJob {
                sequence: 0,
                queued_at: Instant::now(),
                bypasses: 0,
                cost: cost(10, 10, 1),
                ready,
            });
            dispatch(&scheduler.shared, &mut state);
            assert_eq!(state.active_jobs, 1);
        }
        drop(receiver);
        assert_eq!(scheduler.snapshot().active_jobs, 0);
        assert_eq!(scheduler.snapshot().active_memory_mib, 0);
        assert_eq!(scheduler.snapshot().active_io_mib, 0);
        assert_eq!(scheduler.snapshot().active_cpu_units, 0);
    }

    #[tokio::test]
    async fn explicit_dynamic_memory_budget_never_admits_oversized_jobs() {
        let capacity = dynamic_capacity(8, 128, 1000, 1);
        let mut fixed = config();
        fixed.dynamic_memory_budget_mib = 128;
        fixed.dynamic_io_budget_mib = 1000;
        fixed.dynamic_cpu_units = 1;
        let scheduler = ImportExportScheduler::new(capacity, &fixed);
        assert_eq!(
            scheduler.acquire(cost(320, 10, 3)).await.unwrap_err(),
            SchedulerAcquireError::InsufficientCapacity
        );
        let fitting = scheduler.acquire(cost(1, 1, 1)).await.unwrap();
        assert_eq!(scheduler.snapshot().active_jobs, 1);
        assert_eq!(scheduler.snapshot().waiting_jobs, 0);
        drop(fitting);
    }

    #[tokio::test]
    async fn cpu_and_io_weights_allow_one_memory_safe_job_in_isolation() {
        let capacity = dynamic_capacity(8, 1000, 10, 1);
        let mut fixed = config();
        fixed.dynamic_memory_budget_mib = 1000;
        fixed.dynamic_io_budget_mib = 10;
        fixed.dynamic_cpu_units = 1;
        let scheduler = ImportExportScheduler::new(capacity, &fixed);
        let weighted = scheduler.acquire(cost(100, 20, 3)).await.unwrap();
        let follower = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.acquire(cost(1, 1, 1)).await })
        };
        tokio::task::yield_now().await;
        assert!(!follower.is_finished());
        drop(weighted);
        drop(follower.await.unwrap().unwrap());
    }

    #[tokio::test]
    async fn automatic_dynamic_budget_times_out_instead_of_retaining_admission_forever() {
        let provider = Arc::new(MutableResourceProvider {
            memory_mib: std::sync::atomic::AtomicU64::new(500),
            cpu_units: std::sync::atomic::AtomicUsize::new(4),
            valid: std::sync::atomic::AtomicBool::new(true),
        });
        let scheduler = ImportExportScheduler::new_with_provider_and_refresh(
            dynamic_capacity(8, 300, 1000, 4),
            &config(),
            provider,
            Duration::ZERO,
        );
        let oversized = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.acquire(cost(800, 10, 1)).await })
        };
        tokio::task::yield_now().await;
        let fitting = scheduler.acquire(cost(100, 10, 1)).await.unwrap();
        assert!(!oversized.is_finished());
        drop(fitting);
        {
            let mut state = lock_unpoisoned(&scheduler.shared.state);
            state.waiting.front_mut().unwrap().queued_at =
                Instant::now().checked_sub(Duration::from_secs(61)).unwrap();
        }
        let _ = scheduler.snapshot();
        assert_eq!(
            oversized.await.unwrap().unwrap_err(),
            SchedulerAcquireError::InsufficientCapacity
        );
    }

    #[tokio::test]
    async fn live_low_headroom_blocks_oversized_escape_and_wakes_after_recovery() {
        let provider = Arc::new(MutableResourceProvider {
            memory_mib: std::sync::atomic::AtomicU64::new(1000),
            cpu_units: std::sync::atomic::AtomicUsize::new(4),
            valid: std::sync::atomic::AtomicBool::new(true),
        });
        let scheduler = ImportExportScheduler::new_with_provider_and_refresh(
            dynamic_capacity(8, 600, 1000, 4),
            &config(),
            provider.clone(),
            Duration::ZERO,
        );
        provider
            .memory_mib
            .store(1, std::sync::atomic::Ordering::Release);
        assert_eq!(scheduler.snapshot().capacity.memory_budget_mib, 1);

        let waiting = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.acquire(cost(100, 10, 1)).await })
        };
        tokio::task::yield_now().await;
        assert_eq!(scheduler.snapshot().waiting_jobs, 1);
        assert!(!waiting.is_finished());

        provider
            .memory_mib
            .store(1000, std::sync::atomic::Ordering::Release);
        let permit = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        drop(permit);
    }

    #[tokio::test]
    async fn live_blocked_head_does_not_deadlock_fitting_followers() {
        let provider = Arc::new(MutableResourceProvider {
            memory_mib: std::sync::atomic::AtomicU64::new(1),
            cpu_units: std::sync::atomic::AtomicUsize::new(4),
            valid: std::sync::atomic::AtomicBool::new(true),
        });
        let scheduler = ImportExportScheduler::new_with_provider_and_refresh(
            dynamic_capacity(8, 1, 1000, 4),
            &config(),
            provider.clone(),
            Duration::ZERO,
        );
        let blocked = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.acquire(cost(100, 10, 1)).await })
        };
        tokio::task::yield_now().await;

        for _ in 0..4 {
            let follower = scheduler.acquire(cost(1, 1, 1)).await.unwrap();
            assert!(!blocked.is_finished());
            drop(follower);
        }
        assert_eq!(scheduler.snapshot().waiting_jobs, 1);

        provider
            .memory_mib
            .store(1000, std::sync::atomic::Ordering::Release);
        let permit = tokio::time::timeout(Duration::from_secs(1), blocked)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        drop(permit);
    }

    #[test]
    fn recommendation_is_bounded_by_the_scarcest_resource() {
        let capacity = dynamic_capacity(256, 16_384, 32_768, 64);
        assert_eq!(capacity.recommended_active_jobs(cost(512, 4096, 2)), 8);
    }

    #[test]
    fn recommendation_reports_zero_when_live_capacity_cannot_run_the_model() {
        let capacity = dynamic_capacity(256, 1, 65_536, 128);
        assert_eq!(capacity.recommended_active_jobs(cost(96, 1, 1)), 0);
    }

    #[tokio::test]
    async fn default_auto_budgets_fit_one_maximum_wipe_and_physical_restore() {
        let provider = Arc::new(MutableResourceProvider {
            memory_mib: std::sync::atomic::AtomicU64::new(32 * 1024),
            cpu_units: std::sync::atomic::AtomicUsize::new(1),
            valid: std::sync::atomic::AtomicBool::new(true),
        });
        let configuration = ImportExportSchedulerConfig::default();
        let upload_bytes = 8 * 1024 * 1024 * 1024;
        let capacity = SchedulerCapacity::detect_with_provider(
            &configuration,
            upload_bytes,
            4 * upload_bytes,
            provider.as_ref(),
        );
        let wipe = JobResourceCost::estimate(JobEstimateInput {
            protocol: Protocol::Mongodb,
            input_size_bytes: upload_bytes,
            rollback_size_bytes: upload_bytes,
            wipe: true,
            compressed: true,
            export: false,
        });
        let physical_restore = JobResourceCost::estimate(JobEstimateInput {
            protocol: Protocol::Redis,
            input_size_bytes: crate::jobs::import_export::MAX_DATA_ARCHIVE_BYTES,
            rollback_size_bytes: 0,
            wipe: true,
            compressed: true,
            export: false,
        });
        assert!(capacity.recommended_active_jobs(wipe) >= 1);
        assert!(capacity.recommended_active_jobs(physical_restore) >= 1);
        assert_eq!(capacity.cpu_units, 1);

        let scheduler = ImportExportScheduler::new_with_provider_and_refresh(
            capacity,
            &configuration,
            provider,
            Duration::ZERO,
        );
        drop(scheduler.acquire(wipe).await.unwrap());
        drop(scheduler.acquire(physical_restore).await.unwrap());
    }

    #[test]
    fn model_recommendation_is_independent_of_manual_execution_ceiling() {
        let capacity = SchedulerCapacity {
            mode: SchedulerMode::Manual,
            max_active_jobs: 3,
            memory_budget_mib: 16_384,
            io_budget_mib: 32_768,
            cpu_units: 64,
        };
        assert_eq!(capacity.recommended_active_jobs(cost(512, 4096, 2)), 3);
        assert_eq!(
            capacity.model_recommended_active_jobs(cost(512, 4096, 2), 256),
            8
        );
    }

    #[test]
    fn four_gibibyte_mongodb_wipe_is_charged_for_rollback_and_stream_memory() {
        let estimate = JobResourceCost::estimate(JobEstimateInput {
            protocol: Protocol::Mongodb,
            input_size_bytes: 4 * 1024 * 1024 * 1024,
            rollback_size_bytes: 4 * 1024 * 1024 * 1024,
            wipe: true,
            compressed: true,
            export: false,
        });
        assert_eq!(estimate.memory_mib, 640);
        assert_eq!(estimate.io_mib, 24 * 1024);
        assert_eq!(estimate.cpu_units, 4);
    }

    #[test]
    fn native_archives_are_always_charged_as_compressed() {
        for protocol in [
            Protocol::Mongodb,
            Protocol::Redis,
            Protocol::Valkey,
            Protocol::Qdrant,
        ] {
            assert!(protocol_uses_native_compression(protocol));
        }
        for protocol in [
            Protocol::Postgres,
            Protocol::Mariadb,
            Protocol::Mysql,
            Protocol::Clickhouse,
        ] {
            assert!(!protocol_uses_native_compression(protocol));
        }
    }

    #[test]
    fn small_plain_imports_receive_more_concurrency_than_large_imports() {
        let capacity = dynamic_capacity(256, 32_768, 65_536, 128);
        let small = JobResourceCost::estimate(JobEstimateInput {
            protocol: Protocol::Postgres,
            input_size_bytes: 100 * MIB,
            rollback_size_bytes: 0,
            wipe: false,
            compressed: false,
            export: false,
        });
        let large = JobResourceCost::estimate(JobEstimateInput {
            protocol: Protocol::Postgres,
            input_size_bytes: 8 * 1024 * MIB,
            rollback_size_bytes: 0,
            wipe: false,
            compressed: false,
            export: false,
        });
        assert!(capacity.recommended_active_jobs(small) > capacity.recommended_active_jobs(large));
    }

    #[test]
    fn small_logical_wipe_charges_the_full_large_target_rollback() {
        let estimate = JobResourceCost::estimate(JobEstimateInput {
            protocol: Protocol::Postgres,
            input_size_bytes: MIB,
            rollback_size_bytes: 8 * 1024 * MIB,
            wipe: true,
            compressed: false,
            export: false,
        });
        assert_eq!(estimate.io_mib, 16_388);
        assert_eq!(estimate.cpu_units, 2);
    }

    #[test]
    fn host_and_cgroup_memory_parsers_use_current_available_capacity() {
        assert_eq!(
            parse_host_available_memory_mib("MemTotal: 8388608 kB\nMemAvailable: 3145728 kB\n"),
            Some(3072)
        );
        assert_eq!(
            parse_cgroup_memory_available_mib(
                &(4 * 1024 * MIB).to_string(),
                &(1536 * MIB).to_string(),
                false,
            ),
            Some(2560)
        );
        assert_eq!(parse_cgroup_memory_available_mib("max", "0", false), None);
        assert_eq!(
            parse_cgroup_memory_available_mib(&(1_u64 << 60).to_string(), "0", true),
            None
        );
        assert_eq!(minimum_present(Some(8192), Some(2560)), Some(2560));
    }

    #[test]
    fn cgroup_cpu_parsers_round_fractional_quotas_down_conservatively() {
        assert_eq!(parse_cgroup_v2_cpu_units("200000 100000"), Some(2));
        assert_eq!(parse_cgroup_v2_cpu_units("150000 100000"), Some(1));
        assert_eq!(parse_cgroup_v2_cpu_units("50000 100000"), Some(1));
        assert_eq!(parse_cgroup_v2_cpu_units("max 100000"), None);
        assert_eq!(parse_cgroup_v1_cpu_units("300000", "100000"), Some(3));
        assert_eq!(parse_cgroup_v1_cpu_units("-1", "100000"), None);
        assert_eq!(parse_cgroup_v1_cpu_units("100000", "0"), None);
        assert!(control_value_unchanged("2048\n", " 2048 "));
        assert!(!control_value_unchanged("2048", "1024"));
        assert!(control_value_unchanged("max 100000\n", "max 100000"));
        assert!(!control_value_unchanged("max 100000", "50000 100000"));
        assert!(control_value_unchanged("-1", "-1\n"));
        assert!(!control_value_unchanged("-1", "100000"));
    }

    #[test]
    fn cgroup_paths_are_controller_specific_and_cannot_escape_the_mount() {
        let contents = "0::/docker/service\n5:memory:/legacy/memory\n4:cpu,cpuacct:/legacy/cpu\n";
        assert_eq!(
            cgroup_path(contents, None).as_deref(),
            Some("/docker/service")
        );
        assert_eq!(
            cgroup_path(contents, Some("memory")).as_deref(),
            Some("/legacy/memory")
        );
        assert_eq!(
            cgroup_path(contents, Some("cpu")).as_deref(),
            Some("/legacy/cpu")
        );
        assert_eq!(
            safe_cgroup_relative_path("/docker/service"),
            Some(PathBuf::from("docker/service"))
        );
        assert_eq!(safe_cgroup_relative_path("../../escape"), None);
    }

    #[test]
    fn inherited_cgroup_limits_are_found_when_the_leaf_is_unlimited() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let parent = root.join("pod");
        let leaf = parent.join("service");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(root.join("memory.max"), "max\n").unwrap();
        std::fs::write(root.join("cpu.max"), "max 100000\n").unwrap();
        std::fs::write(leaf.join("memory.max"), "max\n").unwrap();
        std::fs::write(leaf.join("memory.current"), "0\n").unwrap();
        std::fs::write(parent.join("memory.max"), (2048 * MIB).to_string()).unwrap();
        std::fs::write(parent.join("memory.current"), (512 * MIB).to_string()).unwrap();
        std::fs::write(leaf.join("cpu.max"), "max 100000\n").unwrap();
        std::fs::write(parent.join("cpu.max"), "150000 100000\n").unwrap();

        assert_eq!(
            cgroup_candidate_bases(&[root], Some("/pod/service")),
            vec![leaf, parent, root.to_path_buf()]
        );
        assert_eq!(
            read_cgroup_memory(
                &[root],
                Some("/pod/service"),
                "memory.max",
                "memory.current",
                false,
            ),
            Some(1536)
        );
        assert_eq!(
            read_cgroup_v2_cpu_units(&[root], Some("/pod/service")),
            Some(1)
        );
        assert!(cgroup_memory_sample_complete(
            &[root],
            Some("/pod/service"),
            "memory.max",
            "memory.current",
            false,
        ));
        assert!(cgroup_v2_cpu_sample_complete(&[root], Some("/pod/service")));

        std::fs::remove_file(root.join("pod/memory.current")).unwrap();
        assert!(!cgroup_memory_sample_complete(
            &[root],
            Some("/pod/service"),
            "memory.max",
            "memory.current",
            false,
        ));
    }
}
