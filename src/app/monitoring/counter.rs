use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use super::{GatewayActivity, OperationCounts, OperationKind};

const MAX_COUNTER: u64 = i64::MAX as u64;
const NO_MEMORY_OBSERVATION: u64 = u64::MAX;

#[derive(Debug, Clone, Copy)]
pub(crate) struct EngineObservation {
    pub cpu_time_micros: Option<u64>,
    pub peak_query_memory_bytes: Option<u64>,
    pub operations: Option<OperationCounts>,
    pub cpu_available: bool,
    pub memory_available: bool,
    pub operations_available: Option<bool>,
    pub discontinuity: bool,
}

#[derive(Debug)]
pub struct ActivityCounter {
    accepted: [AtomicU64; 4],
    sample_lock: Mutex<()>,
    operations_measured: AtomicBool,
    engine_operations_initialized: AtomicBool,
    rejected: [AtomicU64; 4],
    active_connections: AtomicU64,
    opened_connections: AtomicU64,
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    cpu_time_micros: AtomicU64,
    cpu_measured: AtomicBool,
    cpu_initialized: AtomicBool,
    peak_query_memory_bytes: AtomicU64,
    bucket_peak_memory_bytes: AtomicU64,
    memory_measured: AtomicBool,
    memory_initialized: AtomicBool,
    continuity: AtomicU64,
}

impl Default for ActivityCounter {
    fn default() -> Self {
        Self {
            accepted: Default::default(),
            sample_lock: Mutex::new(()),
            operations_measured: AtomicBool::new(false),
            engine_operations_initialized: AtomicBool::new(false),
            rejected: Default::default(),
            active_connections: AtomicU64::new(0),
            opened_connections: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            cpu_time_micros: AtomicU64::new(0),
            cpu_measured: AtomicBool::new(false),
            cpu_initialized: AtomicBool::new(false),
            peak_query_memory_bytes: AtomicU64::new(0),
            bucket_peak_memory_bytes: AtomicU64::new(NO_MEMORY_OBSERVATION),
            memory_measured: AtomicBool::new(false),
            memory_initialized: AtomicBool::new(false),
            continuity: AtomicU64::new(0),
        }
    }
}

impl ActivityCounter {
    /// Records one accepted operation. This is the hot-path alias used by the
    /// protocol gateways.
    pub fn record(&self, kind: OperationKind) {
        self.accept(kind);
    }

    pub fn accept(&self, kind: OperationKind) {
        self.accept_many(kind, 1);
    }

    pub fn accept_many(&self, kind: OperationKind, count: u64) {
        add(&self.accepted[kind.index()], count);
        // Publish availability only after the corresponding count is visible.
        // Readers use an acquire load, so they cannot observe a measured zero
        // while this sample is still being applied.
        self.operations_measured.store(true, Ordering::Release);
    }

    /// Marks a gateway parser as available before it observes its first
    /// operation. This lets an idle interval report a measured zero instead
    /// of looking indistinguishable from an unsupported protocol.
    pub(crate) fn mark_gateway_ops_available(&self) {
        self.operations_measured.store(true, Ordering::Release);
    }

    /// Adds one aggregate engine observation without looping per query. A
    /// successful all-zero interval still marks operations as available.
    #[cfg(test)]
    pub(crate) fn observe_operations(&self, counts: OperationCounts) {
        // One engine sample contains four categories that belong to the same
        // observation window. Serialize it with snapshots so a minute bucket
        // cannot split one aggregate across two samples.
        let _observation = self.lock_sample();
        if availability_changed(
            &self.operations_measured,
            &self.engine_operations_initialized,
            true,
        ) {
            self.break_continuity_locked();
        }
        self.observe_operations_locked(counts);
    }

    /// Records a rejection that could not be classified more precisely.
    pub fn reject(&self) {
        self.reject_kind(OperationKind::Other);
    }

    pub fn reject_kind(&self, kind: OperationKind) {
        self.reject_many(kind, 1);
    }

    pub fn reject_many(&self, kind: OperationKind, count: u64) {
        add(&self.rejected[kind.index()], count);
    }

    #[cfg(test)]
    pub(crate) fn operations_measured(&self) -> bool {
        self.operations_measured.load(Ordering::Acquire)
    }

    /// Updates optional engine-source availability without discarding any
    /// cumulative values already observed. `operations` is `None` for engines
    /// whose operation counter comes from the gateway instead.
    pub(crate) fn set_engine_availability(
        &self,
        cpu: bool,
        memory: bool,
        operations: Option<bool>,
    ) {
        let _sample = self.lock_sample();
        self.set_engine_availability_locked(cpu, memory, operations);
    }

    pub fn connection_opened(&self) {
        add(&self.opened_connections, 1);
        add(&self.active_connections, 1);
    }

    pub fn connection_closed(&self) {
        let _ =
            self.active_connections
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_sub(1))
                });
    }

    /// Reconciles cumulative byte counters from the canonical gateway network
    /// meter without changing authenticated connection accounting.
    pub fn observe_network(&self, rx_bytes: u64, tx_bytes: u64) {
        let _sample = self.lock_sample();
        self.rx_bytes
            .store(rx_bytes.min(MAX_COUNTER), Ordering::Relaxed);
        self.tx_bytes
            .store(tx_bytes.min(MAX_COUNTER), Ordering::Relaxed);
    }

    /// Adds engine-observed query cost. Missing values stay unavailable;
    /// explicitly observing zero makes the corresponding field `Some(0)`.
    pub fn observe(&self, cpu_time_micros: Option<u64>, peak_query_memory_bytes: Option<u64>) {
        let _sample = self.lock_sample();
        let mut changed = cpu_time_micros.is_some()
            && availability_changed(&self.cpu_measured, &self.cpu_initialized, true);
        changed |= peak_query_memory_bytes.is_some()
            && availability_changed(&self.memory_measured, &self.memory_initialized, true);
        if changed {
            self.break_continuity_locked();
        }
        self.observe_locked(cpu_time_micros, peak_query_memory_bytes);
    }

    /// Publishes one complete engine interval. Values, aggregate operations,
    /// source availability, and a possible counter discontinuity become
    /// visible under one lock so a history boundary cannot split the sample.
    pub(crate) fn observe_engine_sample(&self, observation: EngineObservation) {
        let _sample = self.lock_sample();
        if observation.discontinuity {
            self.break_continuity_locked();
        }
        self.set_engine_availability_locked(
            observation.cpu_available,
            observation.memory_available,
            observation.operations_available,
        );
        self.observe_locked(
            observation.cpu_time_micros,
            observation.peak_query_memory_bytes,
        );
        if let Some(operations) = observation.operations {
            self.observe_operations_locked(operations);
        }
    }

    fn observe_locked(&self, cpu_time_micros: Option<u64>, peak_query_memory_bytes: Option<u64>) {
        if let Some(cpu_time_micros) = cpu_time_micros {
            add(&self.cpu_time_micros, cpu_time_micros);
        }
        if let Some(peak_query_memory_bytes) = peak_query_memory_bytes {
            let peak_query_memory_bytes = peak_query_memory_bytes.min(MAX_COUNTER);
            self.peak_query_memory_bytes
                .fetch_max(peak_query_memory_bytes, Ordering::Relaxed);
            let _ = self.bucket_peak_memory_bytes.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |current| {
                    Some(if current == NO_MEMORY_OBSERVATION {
                        peak_query_memory_bytes
                    } else {
                        current.max(peak_query_memory_bytes)
                    })
                },
            );
        }
    }

    /// Starts fresh cumulative counters. The store detects the decrease and
    /// rotates the series epoch instead of emitting a wraparound spike.
    pub fn reset(&self) {
        let _sample = self.lock_sample();
        for counter in self.accepted.iter().chain(self.rejected.iter()) {
            counter.store(0, Ordering::Relaxed);
        }
        self.operations_measured.store(false, Ordering::Release);
        self.engine_operations_initialized
            .store(false, Ordering::Relaxed);
        self.active_connections.store(0, Ordering::Relaxed);
        self.opened_connections.store(0, Ordering::Relaxed);
        self.rx_bytes.store(0, Ordering::Relaxed);
        self.tx_bytes.store(0, Ordering::Relaxed);
        self.cpu_time_micros.store(0, Ordering::Relaxed);
        self.peak_query_memory_bytes.store(0, Ordering::Relaxed);
        self.bucket_peak_memory_bytes
            .store(NO_MEMORY_OBSERVATION, Ordering::Relaxed);
        self.cpu_measured.store(false, Ordering::Release);
        self.cpu_initialized.store(false, Ordering::Relaxed);
        self.memory_measured.store(false, Ordering::Release);
        self.memory_initialized.store(false, Ordering::Relaxed);
        self.break_continuity_locked();
    }

    pub(crate) fn snapshot(&self) -> CounterSnapshot {
        let _sample = self.lock_sample();
        self.snapshot_locked()
    }

    pub(crate) fn snapshot_and_take_bucket_peak(&self) -> (CounterSnapshot, Option<u64>) {
        let _sample = self.lock_sample();
        let snapshot = self.snapshot_locked();
        let peak = self.take_bucket_peak_locked();
        (snapshot, peak)
    }

    fn snapshot_locked(&self) -> CounterSnapshot {
        // Availability is published with Release only after numeric values.
        // Acquire it first, then read the values it makes visible.
        let cpu_available = self.cpu_measured.load(Ordering::Acquire);
        let memory_available = self.memory_measured.load(Ordering::Acquire);
        let operations_available = self.operations_measured.load(Ordering::Acquire);
        CounterSnapshot {
            accepted: counts(&self.accepted),
            operations_available,
            rejected: counts(&self.rejected),
            gateway: GatewayActivity {
                active_connections: self.active_connections.load(Ordering::Relaxed),
                opened_connections: self.opened_connections.load(Ordering::Relaxed),
                rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
                tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            },
            cpu_time_micros: self.cpu_time_micros.load(Ordering::Relaxed),
            cpu_available,
            peak_query_memory_bytes: self.peak_query_memory_bytes.load(Ordering::Relaxed),
            memory_available,
            continuity: self.continuity.load(Ordering::Acquire),
        }
    }

    fn take_bucket_peak_locked(&self) -> Option<u64> {
        match self
            .bucket_peak_memory_bytes
            .swap(NO_MEMORY_OBSERVATION, Ordering::AcqRel)
        {
            NO_MEMORY_OBSERVATION => None,
            peak => Some(peak),
        }
    }

    fn observe_operations_locked(&self, counts: OperationCounts) {
        add(&self.accepted[OperationKind::Read.index()], counts.read);
        add(&self.accepted[OperationKind::Write.index()], counts.write);
        add(&self.accepted[OperationKind::Ddl.index()], counts.ddl);
        add(&self.accepted[OperationKind::Other.index()], counts.other);
        self.operations_measured.store(true, Ordering::Release);
    }

    fn set_engine_availability_locked(&self, cpu: bool, memory: bool, operations: Option<bool>) {
        let mut changed = availability_changed(&self.cpu_measured, &self.cpu_initialized, cpu);
        changed |= availability_changed(&self.memory_measured, &self.memory_initialized, memory);
        if let Some(operations) = operations {
            changed |= availability_changed(
                &self.operations_measured,
                &self.engine_operations_initialized,
                operations,
            );
        }
        if changed {
            self.break_continuity_locked();
        }
    }

    fn break_continuity_locked(&self) {
        add(&self.continuity, 1);
    }

    fn lock_sample(&self) -> std::sync::MutexGuard<'_, ()> {
        self.sample_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CounterSnapshot {
    pub accepted: OperationCounts,
    pub operations_available: bool,
    pub rejected: OperationCounts,
    pub gateway: GatewayActivity,
    pub cpu_time_micros: u64,
    pub cpu_available: bool,
    pub peak_query_memory_bytes: u64,
    pub memory_available: bool,
    pub continuity: u64,
}

impl CounterSnapshot {
    pub(crate) fn current_cpu_time(self) -> Option<u64> {
        self.cpu_available.then_some(self.cpu_time_micros)
    }

    pub(crate) fn current_peak_memory(self) -> Option<u64> {
        self.memory_available
            .then_some(self.peak_query_memory_bytes)
    }

    pub(crate) fn reset_since(self, earlier: Self) -> bool {
        self.accepted.checked_delta(earlier.accepted).is_none()
            || self.rejected.checked_delta(earlier.rejected).is_none()
            || self.gateway.opened_connections < earlier.gateway.opened_connections
            || self.gateway.rx_bytes < earlier.gateway.rx_bytes
            || self.gateway.tx_bytes < earlier.gateway.tx_bytes
            || self.cpu_time_micros < earlier.cpu_time_micros
            || self.peak_query_memory_bytes < earlier.peak_query_memory_bytes
            || self.continuity != earlier.continuity
    }
}

fn availability_changed(flag: &AtomicBool, initialized: &AtomicBool, available: bool) -> bool {
    let previous = flag.swap(available, Ordering::Relaxed);
    if initialized.swap(true, Ordering::Relaxed) {
        previous != available
    } else {
        // A first available sample can arrive after a history baseline was
        // taken. Mark that boundary; a first unavailable state has no values
        // that could contaminate the bucket.
        available
    }
}

fn counts(counters: &[AtomicU64; 4]) -> OperationCounts {
    OperationCounts::from_values(std::array::from_fn(|index| {
        counters[index].load(Ordering::Relaxed)
    }))
}

fn add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value).min(MAX_COUNTER))
    });
}
