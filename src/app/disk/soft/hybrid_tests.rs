use std::{
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
};

use super::*;

#[derive(Clone, Default)]
struct NoopRuntime;

impl SoftDiskRuntime for NoopRuntime {
    fn mark_disk_blocked<'a>(
        &'a self,
        _target: &'a SoftDiskTarget,
        _exceeded: &'a SoftDiskLimitExceeded,
    ) -> RuntimeFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn graceful_stop<'a>(
        &'a self,
        _target: &'a SoftDiskTarget,
        _grace: Duration,
    ) -> RuntimeFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn force_kill<'a>(&'a self, _target: &'a SoftDiskTarget) -> RuntimeFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

fn hybrid_config() -> SoftDiskScannerConfig {
    SoftDiskScannerConfig {
        scan_interval_seconds: 1,
        use_inotify: true,
        full_scan_interval_seconds: 4,
        inotify_debounce_milliseconds: 1,
        max_dirty_paths_per_instance: 32,
        max_concurrent_scans: 2,
        max_entries_per_scan: 1_000,
        scan_timeout_seconds: 5,
        max_consecutive_scan_failures: 3,
        safety_reserve_mib: 0,
        recovery_percent: 80,
        shutdown_grace_seconds: 1,
    }
}

fn target(path: PathBuf) -> SoftDiskTarget {
    SoftDiskTarget {
        instance_id: "inst_hybrid".to_string(),
        created_at: "2026-08-10T00:00:00Z".to_string(),
        protocol: Protocol::Postgres,
        data_path: path,
        limit_bytes: 64 * 1024 * 1024,
        durable_blocked: false,
    }
}

async fn cache_state(limiter: &SoftDiskLimiter, instance_id: &str) -> Option<(usize, bool)> {
    let slot = limiter
        .usage_trees
        .lock()
        .await
        .get(instance_id)
        .map(|state| Arc::clone(&state.slot));
    slot.map(|slot| {
        let state = slot
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (state.cached_directory_count, state.streaming_only)
    })
}

#[tokio::test]
async fn full_baseline_then_partial_subtree_reconciliation_updates_usage() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    std::fs::create_dir_all(root.join("nested")).unwrap();
    std::fs::write(root.join("nested/value.bin"), b"one").unwrap();
    let limiter = SoftDiskLimiter::new(hybrid_config());
    let target = target(root.clone());

    let full = limiter
        .scan_hybrid_and_enforce(&NoopRuntime, &target, HybridScanRequest::Full)
        .await
        .unwrap();
    assert_eq!(full.performed, PerformedScanKind::Full);

    std::fs::write(root.join("nested/value.bin"), vec![7_u8; 2 * 1024 * 1024]).unwrap();
    let partial = limiter
        .scan_hybrid_and_enforce(
            &NoopRuntime,
            &target,
            HybridScanRequest::Partial {
                relative_directories: vec![PathBuf::from("nested")],
            },
        )
        .await
        .unwrap();

    assert_eq!(partial.performed, PerformedScanKind::Partial);
    assert_eq!(
        partial.outcome.snapshot().usage.logical_bytes,
        2 * 1024 * 1024
    );
}

#[tokio::test]
async fn root_level_dirty_hint_safely_promotes_to_a_full_scan() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    std::fs::create_dir(&root).unwrap();
    let limiter = SoftDiskLimiter::new(hybrid_config());
    let target = target(root.clone());
    limiter
        .scan_hybrid_and_enforce(&NoopRuntime, &target, HybridScanRequest::Full)
        .await
        .unwrap();
    std::fs::write(root.join("root.bin"), vec![1_u8; 1024 * 1024]).unwrap();

    let execution = limiter
        .scan_hybrid_and_enforce(
            &NoopRuntime,
            &target,
            HybridScanRequest::Partial {
                relative_directories: vec![PathBuf::new()],
            },
        )
        .await
        .unwrap();

    assert_eq!(execution.performed, PerformedScanKind::Full);
    assert_eq!(
        execution.outcome.snapshot().usage.logical_bytes,
        1024 * 1024
    );
}

#[tokio::test]
async fn same_path_root_replacement_invalidates_the_incremental_cache() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    std::fs::create_dir_all(root.join("nested")).unwrap();
    std::fs::write(root.join("nested/old.bin"), b"old").unwrap();
    let limiter = SoftDiskLimiter::new(hybrid_config());
    let target = target(root.clone());
    limiter
        .scan_hybrid_and_enforce(&NoopRuntime, &target, HybridScanRequest::Full)
        .await
        .unwrap();

    std::fs::rename(&root, temporary.path().join("old-data")).unwrap();
    std::fs::create_dir_all(root.join("nested")).unwrap();
    std::fs::write(root.join("nested/new.bin"), vec![2_u8; 512 * 1024]).unwrap();
    let execution = limiter
        .scan_hybrid_and_enforce(
            &NoopRuntime,
            &target,
            HybridScanRequest::Partial {
                relative_directories: vec![PathBuf::from("nested")],
            },
        )
        .await
        .unwrap();

    assert_eq!(execution.performed, PerformedScanKind::Full);
    assert_eq!(execution.outcome.snapshot().usage.logical_bytes, 512 * 1024);
}

#[tokio::test]
async fn start_preflight_ignores_cached_usage_and_always_scans_fresh() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("value.bin"), b"one").unwrap();
    let limiter = SoftDiskLimiter::new(hybrid_config());
    let target = target(root.clone());
    limiter
        .scan_hybrid_and_enforce(&NoopRuntime, &target, HybridScanRequest::Full)
        .await
        .unwrap();

    std::fs::write(root.join("value.bin"), vec![3_u8; 768 * 1024]).unwrap();
    let snapshot = limiter.ensure_start_allowed(&target).await.unwrap();

    assert_eq!(snapshot.usage.logical_bytes, 768 * 1024);
    assert!(cache_state(&limiter, &target.instance_id).await.is_none());
    assert_eq!(limiter.cached_directories.load(Ordering::Acquire), 0);
}

#[test]
fn scanner_fingerprint_changes_with_generation_path_protocol_and_limit() {
    let mut target = target(PathBuf::from("/var/lib/dbev/volumes/one/data"));
    let original = target.scanner_fingerprint();
    target.limit_bytes += 1;
    assert_ne!(original, target.scanner_fingerprint());
    target.limit_bytes -= 1;
    target.protocol = Protocol::Redis;
    assert_ne!(original, target.scanner_fingerprint());
    target.protocol = Protocol::Postgres;
    target.created_at.push('1');
    assert_ne!(original, target.scanner_fingerprint());
    target.created_at.pop();
    target.data_path = PathBuf::from("/var/lib/dbev/volumes/two/data");
    assert_ne!(original, target.scanner_fingerprint());
}

#[tokio::test]
async fn watcher_disabled_uses_streaming_scans_without_retaining_a_tree() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    std::fs::create_dir_all(root.join("nested")).unwrap();
    std::fs::write(root.join("nested/value.bin"), b"streamed").unwrap();
    let mut config = hybrid_config();
    config.use_inotify = false;
    let limiter = SoftDiskLimiter::new(config);
    let target = target(root);

    let execution = limiter
        .scan_hybrid_and_enforce(&NoopRuntime, &target, HybridScanRequest::Full)
        .await
        .unwrap();

    assert_eq!(execution.performed, PerformedScanKind::Full);
    assert_eq!(execution.outcome.snapshot().usage.logical_bytes, 8);
    assert!(cache_state(&limiter, &target.instance_id).await.is_none());
    assert_eq!(limiter.cached_directories.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn forced_streaming_full_evicts_an_existing_tree_and_measures_fresh_usage() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    std::fs::create_dir_all(root.join("nested")).unwrap();
    std::fs::write(root.join("nested/value.bin"), b"cached").unwrap();
    let limiter = SoftDiskLimiter::new(hybrid_config());
    let target = target(root.clone());
    limiter
        .scan_hybrid_and_enforce(&NoopRuntime, &target, HybridScanRequest::Full)
        .await
        .unwrap();
    assert!(limiter.cached_directories.load(Ordering::Acquire) > 0);

    std::fs::write(root.join("nested/value.bin"), b"fresh-streamed-value").unwrap();
    let execution = limiter
        .scan_hybrid_and_enforce(&NoopRuntime, &target, HybridScanRequest::StreamingFull)
        .await
        .unwrap();

    assert_eq!(execution.performed, PerformedScanKind::Full);
    assert_eq!(execution.outcome.snapshot().usage.logical_bytes, 20);
    assert!(cache_state(&limiter, &target.instance_id).await.is_none());
    assert_eq!(limiter.cached_directories.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn qdrant_uses_streaming_scans_even_when_inotify_is_enabled() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    std::fs::create_dir_all(root.join("collections/one")).unwrap();
    std::fs::write(root.join("collections/one/segment.bin"), b"qdrant").unwrap();
    let limiter = SoftDiskLimiter::new(hybrid_config());
    let mut target = target(root);
    target.protocol = Protocol::Qdrant;

    let execution = limiter
        .scan_hybrid_and_enforce(
            &NoopRuntime,
            &target,
            HybridScanRequest::Partial {
                relative_directories: vec![PathBuf::from("collections")],
            },
        )
        .await
        .unwrap();

    assert_eq!(execution.performed, PerformedScanKind::Full);
    assert_eq!(execution.outcome.snapshot().usage.logical_bytes, 6);
    assert!(cache_state(&limiter, &target.instance_id).await.is_none());
    assert_eq!(limiter.cached_directories.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn per_target_cache_bound_falls_back_to_periodic_streaming_scans() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    std::fs::create_dir_all(root.join("one")).unwrap();
    std::fs::create_dir_all(root.join("two")).unwrap();
    std::fs::write(root.join("two/value.bin"), b"bounded").unwrap();
    let limiter = SoftDiskLimiter::with_usage_cache_limits(
        hybrid_config(),
        UsageCacheLimits {
            per_target_directories: 2,
            global_directories: 100,
        },
    );
    let target = target(root.clone());

    let full = limiter
        .scan_hybrid_and_enforce(&NoopRuntime, &target, HybridScanRequest::Full)
        .await
        .unwrap();
    assert_eq!(full.outcome.snapshot().usage.logical_bytes, 7);
    assert_eq!(
        cache_state(&limiter, &target.instance_id).await,
        Some((0, true))
    );
    assert_eq!(limiter.cached_directories.load(Ordering::Acquire), 0);

    std::fs::write(root.join("two/value.bin"), b"streaming-fallback").unwrap();
    let next = limiter
        .scan_hybrid_and_enforce(
            &NoopRuntime,
            &target,
            HybridScanRequest::Partial {
                relative_directories: vec![PathBuf::from("two")],
            },
        )
        .await
        .unwrap();
    assert_eq!(next.performed, PerformedScanKind::Full);
    assert_eq!(next.outcome.snapshot().usage.logical_bytes, 18);
    assert_eq!(
        cache_state(&limiter, &target.instance_id).await,
        Some((0, true))
    );
}

#[tokio::test]
async fn default_cache_cap_bounds_a_tenant_tree_above_4096_directories() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    std::fs::create_dir(&root).unwrap();
    for index in 0..DEFAULT_MAX_CACHED_DIRECTORIES_PER_TARGET {
        std::fs::create_dir(root.join(format!("directory-{index}"))).unwrap();
    }
    let mut config = hybrid_config();
    config.max_entries_per_scan = DEFAULT_MAX_CACHED_DIRECTORIES_PER_TARGET + 16;
    config.scan_timeout_seconds = 10;
    let limiter = SoftDiskLimiter::new(config);
    let target = target(root);

    let baseline = limiter
        .scan_hybrid_and_enforce(&NoopRuntime, &target, HybridScanRequest::Full)
        .await
        .unwrap();
    assert_eq!(
        baseline.outcome.snapshot().usage.entries,
        DEFAULT_MAX_CACHED_DIRECTORIES_PER_TARGET as u64
    );
    assert_eq!(
        cache_state(&limiter, &target.instance_id).await,
        Some((0, true))
    );
    assert_eq!(limiter.cached_directories.load(Ordering::Acquire), 0);

    let dirty_storm = limiter
        .scan_hybrid_and_enforce(
            &NoopRuntime,
            &target,
            HybridScanRequest::Partial {
                relative_directories: (0..32)
                    .map(|index| PathBuf::from(format!("directory-{index}")))
                    .collect(),
            },
        )
        .await
        .unwrap();
    assert_eq!(dirty_storm.performed, PerformedScanKind::Full);
    assert_eq!(
        cache_state(&limiter, &target.instance_id).await,
        Some((0, true))
    );
}

#[tokio::test]
async fn global_cache_bound_is_released_when_a_target_leaves_monitoring() {
    let temporary = tempfile::tempdir().unwrap();
    let first_root = temporary.path().join("first");
    let second_root = temporary.path().join("second");
    std::fs::create_dir_all(first_root.join("nested")).unwrap();
    std::fs::create_dir_all(second_root.join("nested")).unwrap();
    std::fs::write(first_root.join("nested/value"), b"first").unwrap();
    std::fs::write(second_root.join("nested/value"), b"second").unwrap();
    let limiter = SoftDiskLimiter::with_usage_cache_limits(
        hybrid_config(),
        UsageCacheLimits {
            per_target_directories: 4,
            global_directories: 2,
        },
    );
    let first = target(first_root);
    let mut second = target(second_root);
    second.instance_id = "inst_hybrid_second".to_string();

    limiter
        .scan_hybrid_and_enforce(&NoopRuntime, &first, HybridScanRequest::Full)
        .await
        .unwrap();
    assert_eq!(
        cache_state(&limiter, &first.instance_id).await,
        Some((2, false))
    );
    assert_eq!(limiter.cached_directories.load(Ordering::Acquire), 2);

    limiter
        .scan_hybrid_and_enforce(&NoopRuntime, &second, HybridScanRequest::Full)
        .await
        .unwrap();
    assert_eq!(
        cache_state(&limiter, &second.instance_id).await,
        Some((0, true))
    );
    assert_eq!(limiter.cached_directories.load(Ordering::Acquire), 2);

    limiter.remove(&first.instance_id).await;
    assert!(cache_state(&limiter, &first.instance_id).await.is_none());
    assert_eq!(limiter.cached_directories.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn monitor_cache_eviction_preserves_growth_and_hysteresis_snapshot() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    std::fs::create_dir_all(root.join("nested")).unwrap();
    std::fs::write(root.join("nested/value"), b"sample").unwrap();
    let limiter = SoftDiskLimiter::new(hybrid_config());
    let target = target(root);
    limiter
        .scan_hybrid_and_enforce(&NoopRuntime, &target, HybridScanRequest::Full)
        .await
        .unwrap();
    assert!(limiter.snapshot(&target).await.is_some());
    assert!(limiter.cached_directories.load(Ordering::Acquire) > 0);

    limiter.evict_usage_cache(&target.instance_id).await;

    assert!(cache_state(&limiter, &target.instance_id).await.is_none());
    assert_eq!(limiter.cached_directories.load(Ordering::Acquire), 0);
    assert_eq!(
        limiter.snapshot(&target).await.unwrap().usage.logical_bytes,
        6
    );
}

#[tokio::test]
async fn incremental_cache_growth_over_global_bound_keeps_usage_then_switches_to_streaming() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    std::fs::create_dir_all(root.join("nested")).unwrap();
    std::fs::write(root.join("nested/old.bin"), b"old").unwrap();
    let limiter = SoftDiskLimiter::with_usage_cache_limits(
        hybrid_config(),
        UsageCacheLimits {
            per_target_directories: 8,
            global_directories: 2,
        },
    );
    let target = target(root.clone());
    limiter
        .scan_hybrid_and_enforce(&NoopRuntime, &target, HybridScanRequest::Full)
        .await
        .unwrap();
    assert_eq!(limiter.cached_directories.load(Ordering::Acquire), 2);

    std::fs::create_dir(root.join("nested/new")).unwrap();
    std::fs::write(root.join("nested/new/value.bin"), b"new-value").unwrap();
    let execution = limiter
        .scan_hybrid_and_enforce(
            &NoopRuntime,
            &target,
            HybridScanRequest::Partial {
                relative_directories: vec![PathBuf::from("nested")],
            },
        )
        .await
        .unwrap();

    assert_eq!(execution.performed, PerformedScanKind::Partial);
    assert_eq!(execution.outcome.snapshot().usage.logical_bytes, 12);
    assert_eq!(
        cache_state(&limiter, &target.instance_id).await,
        Some((0, true))
    );
    assert_eq!(limiter.cached_directories.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn incremental_growth_past_per_target_cap_falls_back_without_partial_commit() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("data");
    std::fs::create_dir_all(root.join("nested")).unwrap();
    std::fs::write(root.join("nested/old.bin"), b"old").unwrap();
    let limiter = SoftDiskLimiter::with_usage_cache_limits(
        hybrid_config(),
        UsageCacheLimits {
            per_target_directories: 2,
            global_directories: 100,
        },
    );
    let target = target(root.clone());
    limiter
        .scan_hybrid_and_enforce(&NoopRuntime, &target, HybridScanRequest::Full)
        .await
        .unwrap();
    assert_eq!(
        cache_state(&limiter, &target.instance_id).await,
        Some((2, false))
    );

    std::fs::create_dir(root.join("nested/new")).unwrap();
    std::fs::write(root.join("nested/new/value.bin"), b"new-value").unwrap();
    let execution = limiter
        .scan_hybrid_and_enforce(
            &NoopRuntime,
            &target,
            HybridScanRequest::Partial {
                relative_directories: vec![PathBuf::from("nested")],
            },
        )
        .await
        .unwrap();

    assert_eq!(execution.performed, PerformedScanKind::Full);
    assert_eq!(execution.outcome.snapshot().usage.logical_bytes, 12);
    assert_eq!(
        cache_state(&limiter, &target.instance_id).await,
        Some((0, true))
    );
    assert_eq!(limiter.cached_directories.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn incremental_cache_shrink_releases_global_capacity_for_another_target() {
    let temporary = tempfile::tempdir().unwrap();
    let first_root = temporary.path().join("first");
    let second_root = temporary.path().join("second");
    std::fs::create_dir_all(first_root.join("nested/removed")).unwrap();
    std::fs::create_dir_all(second_root.join("nested")).unwrap();
    let limiter = SoftDiskLimiter::with_usage_cache_limits(
        hybrid_config(),
        UsageCacheLimits {
            per_target_directories: 8,
            global_directories: 4,
        },
    );
    let first = target(first_root.clone());
    let mut second = target(second_root);
    second.instance_id = "inst_hybrid_after_shrink".to_string();

    limiter
        .scan_hybrid_and_enforce(&NoopRuntime, &first, HybridScanRequest::Full)
        .await
        .unwrap();
    assert_eq!(limiter.cached_directories.load(Ordering::Acquire), 3);

    std::fs::remove_dir(first_root.join("nested/removed")).unwrap();
    limiter
        .scan_hybrid_and_enforce(
            &NoopRuntime,
            &first,
            HybridScanRequest::Partial {
                relative_directories: vec![PathBuf::from("nested")],
            },
        )
        .await
        .unwrap();
    assert_eq!(
        cache_state(&limiter, &first.instance_id).await,
        Some((2, false))
    );
    assert_eq!(limiter.cached_directories.load(Ordering::Acquire), 2);

    limiter
        .scan_hybrid_and_enforce(&NoopRuntime, &second, HybridScanRequest::Full)
        .await
        .unwrap();
    assert_eq!(
        cache_state(&limiter, &second.instance_id).await,
        Some((2, false))
    );
    assert_eq!(limiter.cached_directories.load(Ordering::Acquire), 4);
}

fn growth_tracker(sampled_at: Instant, growth: f64) -> TrackerState {
    TrackerState {
        target: TargetFingerprint {
            created_at: "generation".to_string(),
            protocol: Protocol::Postgres,
            data_path: PathBuf::from("/data"),
            limit_bytes: 1_000_000,
        },
        snapshot: SoftDiskSnapshot {
            usage: DirectoryUsage::default(),
            limit_bytes: 1_000_000,
            stop_threshold_bytes: 1_000_000,
            recovery_threshold_bytes: 800_000,
            growth_bytes_per_second: growth,
            peak_growth_bytes_per_second: growth,
            predicted_seconds_to_limit: None,
            blocked: false,
            sampled_at,
        },
        warned: false,
    }
}

#[test]
fn growth_decay_depends_on_wall_time_not_hybrid_sample_count() {
    let started = Instant::now();
    let base_interval = Duration::from_secs(10);
    let coarse = growth_tracker(started, 1_000.0);
    let coarse_rate = growth::growth_rate(Some(&coarse), 0, started + base_interval, base_interval);

    let mut fine = growth_tracker(started, 1_000.0);
    for elapsed_seconds in [2_u64, 4, 6, 8, 10] {
        let sampled_at = started + Duration::from_secs(elapsed_seconds);
        let rate = growth::growth_rate(Some(&fine), 0, sampled_at, base_interval);
        fine = growth_tracker(sampled_at, rate);
    }

    assert!((coarse_rate - 600.0).abs() < 1e-9);
    assert!((fine.snapshot.growth_bytes_per_second - coarse_rate).abs() < 1e-9);
    let config = hybrid_config();
    let coarse_thresholds = thresholds(&config, Protocol::Postgres, 1_000_000, coarse_rate);
    let fine_thresholds = thresholds(
        &config,
        Protocol::Postgres,
        1_000_000,
        fine.snapshot.growth_bytes_per_second,
    );
    assert!(coarse_thresholds.0.abs_diff(fine_thresholds.0) <= 1);
    assert_eq!(coarse_thresholds.1, fine_thresholds.1);
}
