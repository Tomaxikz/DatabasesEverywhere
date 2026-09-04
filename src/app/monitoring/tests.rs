use serde_json::json;

use super::counter::EngineObservation;
use super::*;

#[test]
fn first_sample_only_sets_the_baseline() {
    let store = ActivityStore::default();
    let counter = store.counter("tenant-a", "generation-a");
    counter.record(OperationKind::Read);

    assert!(store.sample(1_000).is_empty());
    assert!(store.sample(1_059).is_empty());

    counter.record(OperationKind::Write);
    let buckets = store.sample(1_060);
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].accepted.read, 0);
    assert_eq!(buckets[0].accepted.write, 1);
    assert!(buckets[0].operations_observed);
    assert!(!buckets[0].gap);
}

#[test]
fn samples_gateway_and_optional_engine_metrics() {
    let store = ActivityStore::default();
    let counter = store.counter("tenant-a", "generation-a");
    for _ in 0..2 {
        counter.connection_opened();
    }
    counter.observe_network(1_000, 2_000);
    counter.observe(Some(0), Some(0));
    store.sample(100);

    counter.record(OperationKind::Read);
    counter.reject_kind(OperationKind::Write);
    counter.connection_opened();
    counter.connection_opened();
    counter.connection_closed();
    counter.observe_network(1_100, 2_250);
    counter.observe(Some(25), Some(4_096));

    let bucket = store.sample(160).pop().unwrap();
    assert_eq!(bucket.active_connections, 3);
    assert_eq!(bucket.opened_connections, 2);
    assert_eq!(bucket.rx_bytes, 100);
    assert_eq!(bucket.tx_bytes, 250);
    assert_eq!(bucket.accepted.read, 1);
    assert_eq!(bucket.rejected.write, 1);
    assert_eq!(bucket.cpu_time_micros, Some(25));
    assert_eq!(bucket.peak_query_memory_bytes, Some(4_096));
}

#[test]
fn reset_rotates_epoch_and_emits_a_gap_without_spikes() {
    let store = ActivityStore::default();
    let counter = store.counter("tenant-a", "generation-a");
    counter.record(OperationKind::Read);
    for _ in 0..5 {
        counter.connection_opened();
    }
    counter.observe_network(500, 0);
    counter.observe(Some(100), Some(128));
    store.sample(0);
    let old_epoch = store
        .current("tenant-a", "generation-a", 0)
        .unwrap()
        .stats_epoch;

    counter.reset();
    counter.record(OperationKind::Write);
    let bucket = store.sample(60).pop().unwrap();
    assert!(bucket.gap);
    assert!(!bucket.operations_observed);
    assert_eq!(bucket.accepted.total(), 0);
    assert_eq!(bucket.opened_connections, 0);
    assert_eq!(bucket.rx_bytes, 0);
    assert_eq!(bucket.cpu_time_micros, None);
    assert_ne!(bucket.stats_epoch, old_epoch);

    counter.record(OperationKind::Ddl);
    let next = store.sample(120).pop().unwrap();
    assert!(!next.gap);
    assert_eq!(next.accepted.ddl, 1);
}

#[test]
fn unavailable_and_measured_zero_serialize_differently() {
    let store = ActivityStore::default();
    store.counter("unavailable", "generation-a");
    store
        .counter("measured", "generation-a")
        .observe(Some(0), Some(0));

    let unavailable =
        serde_json::to_value(store.current("unavailable", "generation-a", 1).unwrap()).unwrap();
    let measured =
        serde_json::to_value(store.current("measured", "generation-a", 1).unwrap()).unwrap();
    assert_eq!(unavailable["cpu_time_micros"], json!(null));
    assert_eq!(unavailable["peak_query_memory_bytes"], json!(null));
    assert_eq!(measured["cpu_time_micros"], json!(0));
    assert_eq!(measured["peak_query_memory_bytes"], json!(0));
}

#[test]
fn counter_hot_path_is_shared_without_store_locking() {
    let store = ActivityStore::default();
    let first = store.counter("tenant-a", "generation-a");
    let second = store.counter("tenant-a", "generation-a");
    first.connection_opened();
    second.record(OperationKind::Other);
    second.reject();

    let current = store.current("tenant-a", "generation-a", 10).unwrap();
    assert_eq!(current.opened_connections, 1);
    assert_eq!(current.active_connections, 1);
    assert_eq!(current.accepted.other, 1);
    assert_eq!(current.rejected.other, 1);
    assert!(std::sync::Arc::ptr_eq(&first, &second));
}

#[test]
fn recreated_instance_gets_a_fresh_counter_generation() {
    let store = ActivityStore::default();
    let deleted = store.counter("tenant-a", "generation-a");
    deleted.connection_opened();

    let recreated = store.counter("tenant-a", "generation-b");
    recreated.record(OperationKind::Write);
    assert!(!std::sync::Arc::ptr_eq(&deleted, &recreated));
    let replacement = store.current("tenant-a", "generation-b", 10).unwrap();
    let replacement_epoch = replacement.stats_epoch.clone();
    assert_eq!(replacement.active_connections, 0);
    assert_eq!(replacement.accepted.write, 1);

    // A resolver from generation A resumes after B exists. It can only reach
    // A's own entry; it cannot replace or reset B before failing route recheck.
    let late = store.counter("tenant-a", "generation-a");
    assert!(std::sync::Arc::ptr_eq(&deleted, &late));
    late.record(OperationKind::Read);
    deleted.connection_closed();
    let replacement = store.current("tenant-a", "generation-b", 11).unwrap();
    assert_eq!(replacement.stats_epoch, replacement_epoch);
    assert_eq!(replacement.active_connections, 0);
    assert_eq!(replacement.accepted.write, 1);
    assert_eq!(replacement.accepted.read, 0);

    store.retain_generations(&[("tenant-a".to_string(), "generation-b".to_string())]);
    assert!(store.current("tenant-a", "generation-a", 12).is_none());
}

#[test]
fn aggregate_collectors_add_counts_without_per_query_loops() {
    let store = ActivityStore::default();
    let counter = store.counter("tenant-a", "generation-a");
    counter.accept_many(OperationKind::Read, 50_000);
    counter.reject_many(OperationKind::Ddl, 3);

    let current = store.current("tenant-a", "generation-a", 10).unwrap();
    assert_eq!(current.accepted.read, 50_000);
    assert_eq!(current.rejected.ddl, 3);
}

#[test]
fn complete_engine_samples_are_published_atomically() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    let counter = Arc::new(ActivityCounter::default());
    let done = Arc::new(AtomicBool::new(false));
    let writer_counter = Arc::clone(&counter);
    let writer_done = Arc::clone(&done);
    let writer = std::thread::spawn(move || {
        for _ in 0..10_000 {
            writer_counter.observe_engine_sample(EngineObservation {
                cpu_time_micros: Some(5),
                peak_query_memory_bytes: Some(4096),
                operations: Some(OperationCounts {
                    read: 1,
                    write: 2,
                    ddl: 3,
                    other: 4,
                }),
                cpu_available: true,
                memory_available: true,
                operations_available: Some(true),
                discontinuity: false,
            });
        }
        writer_done.store(true, Ordering::Release);
    });

    while !done.load(Ordering::Acquire) {
        let measured = counter.operations_measured();
        let snapshot = counter.snapshot();
        assert_eq!(snapshot.accepted.write, snapshot.accepted.read * 2);
        assert_eq!(snapshot.accepted.ddl, snapshot.accepted.read * 3);
        assert_eq!(snapshot.accepted.other, snapshot.accepted.read * 4);
        assert_eq!(snapshot.cpu_time_micros, snapshot.accepted.read * 5);
        if measured {
            assert!(snapshot.accepted.read > 0);
        }
    }
    writer.join().unwrap();
}

#[test]
fn successful_zero_operation_sample_is_distinct_from_unavailable() {
    let store = ActivityStore::default();
    let counter = store.counter("tenant-a", "generation-a");
    assert!(
        !store
            .current("tenant-a", "generation-a", 0)
            .unwrap()
            .operations_measured
    );

    counter.accept_many(OperationKind::Read, 0);
    assert!(
        store
            .current("tenant-a", "generation-a", 1)
            .unwrap()
            .operations_measured
    );

    counter.reset();
    assert!(
        !store
            .current("tenant-a", "generation-a", 2)
            .unwrap()
            .operations_measured
    );
}

#[test]
fn idle_gateway_minutes_are_measured_zeroes() {
    let store = ActivityStore::default();
    let counter = store.counter("tenant-a", "generation-a");
    counter.mark_gateway_ops_available();
    store.sample(0);

    let bucket = store.sample(60).pop().unwrap();
    assert!(bucket.operations_observed);
    assert_eq!(bucket.accepted.total(), 0);
    assert_eq!(bucket.rejected.total(), 0);
}

#[test]
fn temporary_engine_unavailability_hides_but_keeps_totals() {
    let store = ActivityStore::default();
    let counter = store.counter("tenant-a", "generation-a");
    counter.observe(Some(25), Some(4096));
    counter.observe_operations(OperationCounts {
        read: 2,
        ..OperationCounts::default()
    });

    counter.set_engine_availability(false, false, Some(false));
    let unavailable = store.current("tenant-a", "generation-a", 1).unwrap();
    assert_eq!(unavailable.cpu_time_micros, None);
    assert_eq!(unavailable.peak_query_memory_bytes, None);
    assert!(
        !store
            .current("tenant-a", "generation-a", 1)
            .unwrap()
            .operations_measured
    );

    counter.set_engine_availability(true, true, Some(true));
    let restored = store.current("tenant-a", "generation-a", 2).unwrap();
    assert_eq!(restored.cpu_time_micros, Some(25));
    assert_eq!(restored.peak_query_memory_bytes, Some(4096));
    assert_eq!(restored.accepted.read, 2);
    assert!(
        store
            .current("tenant-a", "generation-a", 2)
            .unwrap()
            .operations_measured
    );
}

#[test]
fn availability_transitions_emit_gaps_without_replaying_cpu_totals() {
    let store = ActivityStore::default();
    let counter = store.counter("tenant-a", "generation-a");
    counter.observe(Some(25), Some(4096));
    store.sample(0);
    let epoch = store
        .current("tenant-a", "generation-a", 0)
        .unwrap()
        .stats_epoch;

    counter.set_engine_availability(false, false, None);
    let unavailable = store.sample(60).pop().unwrap();
    assert!(unavailable.gap);
    assert_ne!(unavailable.stats_epoch, epoch);
    assert_eq!(unavailable.cpu_time_micros, None);

    counter.observe_engine_sample(EngineObservation {
        cpu_time_micros: Some(5),
        peak_query_memory_bytes: Some(1024),
        operations: None,
        cpu_available: true,
        memory_available: true,
        operations_available: None,
        discontinuity: false,
    });
    let recovered = store.sample(120).pop().unwrap();
    assert!(recovered.gap);
    assert_ne!(recovered.stats_epoch, unavailable.stats_epoch);

    counter.observe_engine_sample(EngineObservation {
        cpu_time_micros: Some(5),
        peak_query_memory_bytes: Some(1024),
        operations: None,
        cpu_available: true,
        memory_available: true,
        operations_available: None,
        discontinuity: false,
    });
    let stable = store.sample(180).pop().unwrap();
    assert!(!stable.gap);
    assert_eq!(stable.stats_epoch, recovered.stats_epoch);
    assert_eq!(stable.cpu_time_micros, Some(5));
    assert_eq!(stable.peak_query_memory_bytes, Some(1024));
}

#[test]
fn live_epoch_rotates_as_soon_as_continuity_changes() {
    let store = ActivityStore::default();
    let counter = store.counter("tenant-a", "generation-a");
    counter.observe(Some(25), Some(4096));
    store.sample(0);
    let old_epoch = store
        .current("tenant-a", "generation-a", 0)
        .unwrap()
        .stats_epoch;

    counter.set_engine_availability(false, false, None);
    let live_epoch = store
        .current("tenant-a", "generation-a", 30)
        .unwrap()
        .stats_epoch;
    assert_ne!(live_epoch, old_epoch);

    let gap = store.sample(60).pop().unwrap();
    assert!(gap.gap);
    assert_eq!(gap.stats_epoch, live_epoch);
}

#[test]
fn memory_peak_is_none_in_buckets_without_an_observation() {
    let store = ActivityStore::default();
    let counter = store.counter("tenant-a", "generation-a");
    counter.observe(Some(0), Some(4096));
    store.sample(0);

    assert_eq!(
        store.sample(60).pop().unwrap().peak_query_memory_bytes,
        None
    );
    counter.observe(None, Some(1024));
    assert_eq!(
        store.sample(120).pop().unwrap().peak_query_memory_bytes,
        Some(1024)
    );
    assert_eq!(
        store.sample(180).pop().unwrap().peak_query_memory_bytes,
        None
    );
}
