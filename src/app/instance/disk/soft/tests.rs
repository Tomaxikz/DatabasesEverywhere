use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use super::*;

#[derive(Clone, Default)]
struct HangingRuntime {
    blocked: Arc<AtomicUsize>,
    graceful: Arc<AtomicUsize>,
    killed: Arc<AtomicUsize>,
}

#[derive(Clone, Default)]
struct RetryRuntime {
    blocked: Arc<AtomicUsize>,
    killed: Arc<AtomicUsize>,
}

impl SoftDiskRuntime for RetryRuntime {
    fn mark_disk_blocked<'a>(
        &'a self,
        _target: &'a SoftDiskTarget,
        _exceeded: &'a SoftDiskLimitExceeded,
    ) -> RuntimeFuture<'a> {
        Box::pin(async move {
            self.blocked.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }

    fn graceful_stop<'a>(
        &'a self,
        _target: &'a SoftDiskTarget,
        _grace: Duration,
    ) -> RuntimeFuture<'a> {
        Box::pin(async { Err("simulated graceful stop failure".to_string()) })
    }

    fn force_kill<'a>(&'a self, _target: &'a SoftDiskTarget) -> RuntimeFuture<'a> {
        Box::pin(async move {
            let attempt = self.killed.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                Err("simulated first kill failure".to_string())
            } else {
                Ok(())
            }
        })
    }
}

impl SoftDiskRuntime for HangingRuntime {
    fn mark_disk_blocked<'a>(
        &'a self,
        _target: &'a SoftDiskTarget,
        _exceeded: &'a SoftDiskLimitExceeded,
    ) -> RuntimeFuture<'a> {
        Box::pin(async move {
            self.blocked.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }

    fn graceful_stop<'a>(
        &'a self,
        _target: &'a SoftDiskTarget,
        _grace: Duration,
    ) -> RuntimeFuture<'a> {
        Box::pin(async move {
            self.graceful.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<()>().await;
            Ok(())
        })
    }

    fn force_kill<'a>(&'a self, _target: &'a SoftDiskTarget) -> RuntimeFuture<'a> {
        Box::pin(async move {
            self.killed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

fn test_config() -> SoftDiskScannerConfig {
    SoftDiskScannerConfig {
        scan_interval_seconds: 1,
        use_inotify: false,
        full_scan_interval_seconds: 4,
        inotify_debounce_milliseconds: 1,
        max_dirty_paths_per_instance: 32,
        max_concurrent_scans: 1,
        max_cached_directories_global: 32_768,
        max_entries_per_scan: 100,
        scan_timeout_seconds: 2,
        max_consecutive_scan_failures: 3,
        safety_reserve_mib: 0,
        recovery_percent: 80,
        shutdown_grace_seconds: 1,
    }
}

#[tokio::test]
async fn over_limit_write_is_blocked_and_a_hung_stop_is_force_killed() {
    let temporary = tempfile::tempdir().unwrap();
    let data = temporary.path().join("data");
    std::fs::create_dir(&data).unwrap();
    std::fs::write(data.join("growth.bin"), vec![7_u8; 2 * 1024 * 1024]).unwrap();
    let runtime = HangingRuntime::default();
    let limiter = SoftDiskLimiter::new(test_config());
    let target = SoftDiskTarget {
        instance_id: "inst_over_limit".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        protocol: Protocol::Qdrant,
        data_path: data,
        limit_bytes: 1024 * 1024,
        durable_blocked: false,
    };

    // Exercise the production timeout/kill path with a short test deadline.
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        limiter.scan_and_enforce(&runtime, &target),
    )
    .await
    .unwrap()
    .unwrap();

    assert!(matches!(
        outcome,
        ScanOutcome::Stopped {
            outcome: StopOutcome::Forced,
            ..
        }
    ));
    assert_eq!(runtime.blocked.load(Ordering::SeqCst), 1);
    assert_eq!(runtime.graceful.load(Ordering::SeqCst), 1);
    assert_eq!(runtime.killed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn restart_block_clears_only_below_hysteresis() {
    let temporary = tempfile::tempdir().unwrap();
    let data = temporary.path().join("data");
    std::fs::create_dir(&data).unwrap();
    let file = data.join("growth.bin");
    std::fs::write(&file, vec![1_u8; 2 * 1024 * 1024]).unwrap();
    let runtime = HangingRuntime::default();
    let mut config = test_config();
    config.shutdown_grace_seconds = 1;
    let limiter = SoftDiskLimiter::new(config);
    let target = SoftDiskTarget {
        instance_id: "inst_hysteresis".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        protocol: Protocol::Qdrant,
        data_path: data,
        limit_bytes: 1024 * 1024,
        durable_blocked: false,
    };

    limiter.scan_and_enforce(&runtime, &target).await.unwrap();
    assert!(limiter.ensure_start_allowed(&target).await.is_err());
    std::fs::remove_file(file).unwrap();
    assert!(limiter.ensure_start_allowed(&target).await.is_ok());
}

#[tokio::test]
async fn active_blocked_instance_retries_enforcement_after_a_failed_kill() {
    let temporary = tempfile::tempdir().unwrap();
    let data = temporary.path().join("data");
    std::fs::create_dir(&data).unwrap();
    std::fs::write(data.join("growth.bin"), vec![9_u8; 2 * 1024 * 1024]).unwrap();
    let runtime = RetryRuntime::default();
    let limiter = SoftDiskLimiter::new(test_config());
    let target = SoftDiskTarget {
        instance_id: "inst_retry".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        protocol: Protocol::Qdrant,
        data_path: data,
        limit_bytes: 1024 * 1024,
        durable_blocked: false,
    };

    assert!(limiter.scan_and_enforce(&runtime, &target).await.is_err());
    let retry = limiter.scan_and_enforce(&runtime, &target).await.unwrap();

    assert!(matches!(
        retry,
        ScanOutcome::Stopped {
            outcome: StopOutcome::Forced,
            ..
        }
    ));
    assert_eq!(runtime.blocked.load(Ordering::SeqCst), 2);
    assert_eq!(runtime.killed.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn recovery_threshold_stays_below_predictive_stop_threshold() {
    let mut config = test_config();
    config.safety_reserve_mib = 64;
    config.recovery_percent = 85;
    let limiter = SoftDiskLimiter::new(config);
    let target = SoftDiskTarget {
        instance_id: "inst_small_limit".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        protocol: Protocol::Qdrant,
        data_path: PathBuf::from("/var/lib/dbev/volumes/inst_small_limit"),
        limit_bytes: 1024 * 1024,
        durable_blocked: false,
    };
    let decision = limiter
        .record_sample(&target, DirectoryUsage::default())
        .await;

    assert!(decision.snapshot.recovery_threshold_bytes < decision.snapshot.stop_threshold_bytes);
}

#[tokio::test]
async fn recreated_target_does_not_inherit_blocked_hysteresis_or_growth() {
    let limiter = SoftDiskLimiter::new(test_config());
    let old_target = SoftDiskTarget {
        instance_id: "inst_reused".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        protocol: Protocol::Qdrant,
        data_path: PathBuf::from("/var/lib/dbev/volumes/inst_reused-old"),
        limit_bytes: 1_000,
        durable_blocked: false,
    };
    let blocked = limiter
        .record_sample(
            &old_target,
            DirectoryUsage {
                logical_bytes: 1_000,
                physical_bytes: 1_000,
                entries: 1,
            },
        )
        .await;
    assert!(blocked.snapshot.blocked);
    assert!(blocked.must_stop);

    let new_target = SoftDiskTarget {
        created_at: "2026-02-01T00:00:00Z".to_string(),
        data_path: PathBuf::from("/var/lib/dbev/volumes/inst_reused-new"),
        limit_bytes: 2_000,
        ..old_target.clone()
    };
    // 1,700 is between this target's recovery and stop thresholds.
    let current = limiter
        .record_sample(
            &new_target,
            DirectoryUsage {
                logical_bytes: 1_700,
                physical_bytes: 1_700,
                entries: 1,
            },
        )
        .await;

    assert!(!current.snapshot.blocked);
    assert!(!current.must_stop);
    assert!(!current.already_blocked);
    assert_eq!(current.snapshot.growth_bytes_per_second, 0.0);
    assert!(limiter.snapshot(&old_target).await.is_none());
    assert_eq!(
        limiter
            .snapshot(&new_target)
            .await
            .unwrap()
            .usage
            .physical_bytes,
        1_700
    );
}

#[tokio::test]
async fn durable_restart_block_survives_a_fresh_limiter_until_recovery() {
    let temporary = tempfile::tempdir().unwrap();
    let data = temporary.path().join("data");
    std::fs::create_dir(&data).unwrap();
    let file = data.join("between-thresholds.bin");
    std::fs::write(&file, vec![3_u8; 3_600_000]).unwrap();
    let limiter = SoftDiskLimiter::new(test_config());
    let target = SoftDiskTarget {
        instance_id: "inst_durable_hysteresis".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        protocol: Protocol::Qdrant,
        data_path: data,
        limit_bytes: 4 * 1024 * 1024,
        durable_blocked: true,
    };

    assert!(limiter.ensure_start_allowed(&target).await.is_err());
    std::fs::remove_file(file).unwrap();
    assert!(limiter.ensure_start_allowed(&target).await.is_ok());
}

#[tokio::test]
async fn repeated_unmeasurable_scans_fail_closed() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::write(temporary.path().join("one"), b"1").unwrap();
    std::fs::write(temporary.path().join("two"), b"2").unwrap();
    let runtime = HangingRuntime::default();
    let mut config = test_config();
    config.max_entries_per_scan = 1;
    config.max_consecutive_scan_failures = 2;
    let limiter = SoftDiskLimiter::new(config);
    let target = SoftDiskTarget {
        instance_id: "inst_unmeasurable".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        protocol: Protocol::Qdrant,
        data_path: temporary.path().to_path_buf(),
        limit_bytes: 128 * 1024 * 1024,
        durable_blocked: false,
    };

    assert!(limiter.scan_and_enforce(&runtime, &target).await.is_err());
    let second = limiter.scan_and_enforce(&runtime, &target).await.unwrap();
    assert!(matches!(
        second,
        ScanOutcome::Stopped {
            outcome: StopOutcome::Forced,
            ..
        }
    ));
    assert_eq!(runtime.blocked.load(Ordering::SeqCst), 1);
    assert_eq!(runtime.killed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn global_scanner_capacity_outage_stops_targets_after_bounded_failures() {
    let temporary = tempfile::tempdir().unwrap();
    let runtime = HangingRuntime::default();
    let mut config = test_config();
    config.max_consecutive_scan_failures = 2;
    let limiter = SoftDiskLimiter::new(config);
    let target = SoftDiskTarget {
        instance_id: "inst_capacity_outage".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        protocol: Protocol::Qdrant,
        data_path: temporary.path().to_path_buf(),
        limit_bytes: 128 * 1024 * 1024,
        durable_blocked: false,
    };

    assert!(
        limiter
            .enforce_capacity_outage(&runtime, &target, "all workers wedged".to_string())
            .await
            .is_err()
    );
    let second = limiter
        .enforce_capacity_outage(&runtime, &target, "all workers wedged".to_string())
        .await
        .unwrap();
    assert!(matches!(
        second,
        ScanOutcome::Stopped {
            outcome: StopOutcome::Forced,
            ..
        }
    ));
    assert_eq!(runtime.blocked.load(Ordering::SeqCst), 1);
    assert_eq!(runtime.killed.load(Ordering::SeqCst), 1);
}

#[test]
fn qdrant_is_scanned_when_the_node_uses_fuse_quota() {
    assert!(SoftDiskLimiter::enforcement_required(
        DiskLimitMode::FuseQuota,
        Protocol::Qdrant
    ));
    assert!(!SoftDiskLimiter::enforcement_required(
        DiskLimitMode::FuseQuota,
        Protocol::Postgres
    ));
}

#[test]
fn reserve_covers_the_authoritative_full_scan_window_and_qdrant_base_window() {
    let mut config = test_config();
    config.scan_interval_seconds = 10;
    config.use_inotify = true;
    config.full_scan_interval_seconds = 100;
    config.scan_timeout_seconds = 20;
    config.shutdown_grace_seconds = 30;
    let limit = 10 * 1024 * 1024;

    assert_eq!(
        safety_reserve_bytes(&config, Protocol::Postgres, limit, 1_000.0),
        151_000
    );
    assert_eq!(
        safety_reserve_bytes(&config, Protocol::Qdrant, limit, 1_000.0),
        61_000
    );
}
