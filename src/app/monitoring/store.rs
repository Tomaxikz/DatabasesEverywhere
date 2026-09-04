use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, MutexGuard},
};

use uuid::Uuid;

use super::{ActivityBucket, ActivityCounter, ActivityCurrent, counter::CounterSnapshot};

pub const BUCKET_SECONDS: i64 = 60;

#[derive(Debug, Clone, Default)]
pub struct ActivityStore {
    inner: Arc<Mutex<StoreState>>,
}

impl ActivityStore {
    pub fn counter(
        &self,
        instance_id: impl Into<String>,
        instance_generation: impl Into<String>,
    ) -> Arc<ActivityCounter> {
        let instance_id = instance_id.into();
        let instance_generation = instance_generation.into();
        let mut state = lock(&self.inner);
        state
            .entries
            .entry((instance_id, instance_generation))
            .or_insert_with(Entry::new)
            .counter
            .clone()
    }

    pub fn current(
        &self,
        instance_id: &str,
        instance_generation: &str,
        sampled_at_unix: i64,
    ) -> Option<ActivityCurrent> {
        let mut state = lock(&self.inner);
        let entry = state
            .entries
            .get_mut(&(instance_id.to_string(), instance_generation.to_string()))?;
        let snapshot = entry.counter.snapshot();
        entry.sync_epoch(snapshot);
        Some(ActivityCurrent {
            instance_id: instance_id.to_string(),
            stats_epoch: entry.epoch.clone(),
            sampled_at_unix,
            accepted: snapshot.accepted,
            operations_measured: snapshot.operations_available,
            rejected: snapshot.rejected,
            active_connections: snapshot.gateway.active_connections,
            opened_connections: snapshot.gateway.opened_connections,
            rx_bytes: snapshot.gateway.rx_bytes,
            tx_bytes: snapshot.gateway.tx_bytes,
            cpu_time_micros: snapshot.current_cpu_time(),
            peak_query_memory_bytes: snapshot.current_peak_memory(),
        })
    }

    pub fn current_with_network(
        &self,
        instance_id: &str,
        instance_generation: &str,
        sampled_at_unix: i64,
        rx_bytes: u64,
        tx_bytes: u64,
    ) -> ActivityCurrent {
        let mut state = lock(&self.inner);
        let entry = state
            .entries
            .entry((instance_id.to_string(), instance_generation.to_string()))
            .or_insert_with(Entry::new);
        entry.counter.observe_network(rx_bytes, tx_bytes);
        let snapshot = entry.counter.snapshot();
        entry.sync_epoch(snapshot);
        ActivityCurrent {
            instance_id: instance_id.to_string(),
            stats_epoch: entry.epoch.clone(),
            sampled_at_unix,
            accepted: snapshot.accepted,
            operations_measured: snapshot.operations_available,
            rejected: snapshot.rejected,
            active_connections: snapshot.gateway.active_connections,
            opened_connections: snapshot.gateway.opened_connections,
            rx_bytes: snapshot.gateway.rx_bytes,
            tx_bytes: snapshot.gateway.tx_bytes,
            cpu_time_micros: snapshot.current_cpu_time(),
            peak_query_memory_bytes: snapshot.current_peak_memory(),
        }
    }

    /// Takes all due rolling samples. Callers may invoke this more frequently
    /// than once per minute; no bucket is emitted until 60 seconds elapsed.
    pub fn sample(&self, sampled_at_unix: i64) -> Vec<ActivityBucket> {
        let mut state = lock(&self.inner);
        let mut buckets = Vec::new();

        for ((instance_id, instance_generation), entry) in &mut state.entries {
            let Some(baseline) = entry.baseline else {
                let (current, _) = entry.counter.snapshot_and_take_bucket_peak();
                entry.sync_epoch(current);
                entry.baseline = Some(Baseline {
                    sampled_at_unix,
                    snapshot: current,
                });
                continue;
            };
            let elapsed = sampled_at_unix.saturating_sub(baseline.sampled_at_unix);
            if elapsed < BUCKET_SECONDS {
                continue;
            }

            // Capture the counters and roll over the interval peak under the
            // same lock. An engine sample therefore belongs wholly to either
            // this bucket or the next one.
            let (current, bucket_peak) = entry.counter.snapshot_and_take_bucket_peak();
            let duration_seconds = elapsed.clamp(BUCKET_SECONDS, i64::from(u32::MAX)) as u32;
            let continuity_changed = entry.sync_epoch(current);
            if current.reset_since(baseline.snapshot) {
                if !continuity_changed && current.continuity == baseline.snapshot.continuity {
                    entry.epoch = Uuid::new_v4().to_string();
                }
                buckets.push(ActivityBucket::gap(
                    instance_id.clone(),
                    instance_generation.clone(),
                    baseline.sampled_at_unix,
                    duration_seconds,
                    entry.epoch.clone(),
                    current.gateway.active_connections,
                ));
            } else {
                let accepted = current
                    .accepted
                    .checked_delta(baseline.snapshot.accepted)
                    .unwrap_or_default();
                let rejected = current
                    .rejected
                    .checked_delta(baseline.snapshot.rejected)
                    .unwrap_or_default();
                let cpu_time_micros = current.cpu_available.then(|| {
                    current
                        .cpu_time_micros
                        .saturating_sub(baseline.snapshot.cpu_time_micros)
                });
                buckets.push(ActivityBucket {
                    instance_id: instance_id.clone(),
                    instance_generation: instance_generation.clone(),
                    bucket_start_unix: baseline.sampled_at_unix,
                    duration_seconds,
                    stats_epoch: entry.epoch.clone(),
                    gap: false,
                    operations_observed: current.operations_available,
                    accepted,
                    rejected,
                    active_connections: current.gateway.active_connections,
                    opened_connections: current
                        .gateway
                        .opened_connections
                        .saturating_sub(baseline.snapshot.gateway.opened_connections),
                    rx_bytes: current
                        .gateway
                        .rx_bytes
                        .saturating_sub(baseline.snapshot.gateway.rx_bytes),
                    tx_bytes: current
                        .gateway
                        .tx_bytes
                        .saturating_sub(baseline.snapshot.gateway.tx_bytes),
                    cpu_time_micros,
                    peak_query_memory_bytes: bucket_peak,
                });
            }
            entry.baseline = Some(Baseline {
                sampled_at_unix,
                snapshot: current,
            });
        }

        buckets
    }

    pub fn remove(&self, instance_id: &str) -> bool {
        let mut state = lock(&self.inner);
        let old_len = state.entries.len();
        state.entries.retain(|(id, _), _| id != instance_id);
        state.entries.len() != old_len
    }

    /// Drops counters for deleted/recreated generations. Stale gateway handles
    /// may still hold their `Arc`, but can no longer occupy sampler memory or
    /// produce durable rows after the next reconciliation tick.
    pub fn retain_generations(&self, generations: &[(String, String)]) {
        let generations = generations.iter().cloned().collect::<HashSet<_>>();
        lock(&self.inner)
            .entries
            .retain(|key, _| generations.contains(key));
    }
}

#[derive(Debug, Default)]
struct StoreState {
    entries: HashMap<(String, String), Entry>,
}

#[derive(Debug)]
struct Entry {
    counter: Arc<ActivityCounter>,
    epoch: String,
    continuity: u64,
    baseline: Option<Baseline>,
}

impl Entry {
    fn new() -> Self {
        Self {
            counter: Arc::new(ActivityCounter::default()),
            epoch: Uuid::new_v4().to_string(),
            continuity: 0,
            baseline: None,
        }
    }

    fn sync_epoch(&mut self, snapshot: CounterSnapshot) -> bool {
        if self.continuity == snapshot.continuity {
            return false;
        }
        self.continuity = snapshot.continuity;
        self.epoch = Uuid::new_v4().to_string();
        true
    }
}

#[derive(Debug, Clone, Copy)]
struct Baseline {
    sampled_at_unix: i64,
    snapshot: CounterSnapshot,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
