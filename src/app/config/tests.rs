use super::*;

#[test]
fn runtime_config_rejects_invalid_limits_before_constructing_resources() {
    let mut settings = Config::default();
    for mib in [
        0,
        u64::MAX,
        (tokio::sync::Semaphore::MAX_PERMITS / (1024 * 1024)) as u64 + 1,
    ] {
        settings.daemon.sql_buffer_global_mib = mib;
        assert!(matches!(
            RuntimeConfig::new(settings.clone()),
            Err(validate::ConfigValidationError::InvalidDaemonLimit {
                field: "sql_buffer_global_mib",
                ..
            })
        ));
    }
    assert_eq!(
        RuntimeConfig::default()
            .sql_buffer_budget
            .available_permits(),
        1024 * 1024 * 1024
    );
}

#[test]
fn snapshots_contain_only_settings_and_do_not_replace_live_budgets() {
    let settings: Config = yaml_serde::from_str("daemon:\n  sql_buffer_global_mib: 1\n").unwrap();
    let running = Arc::new(RuntimeConfig::new(settings).unwrap());
    let consumer = Arc::clone(&running);
    let reservation = running
        .sql_buffer_budget
        .try_acquire_many(1024 * 1024)
        .unwrap();
    assert!(consumer.sql_buffer_budget.try_acquire().is_err());
    let snapshot = running.snapshot();
    let yaml = yaml_serde::to_string(snapshot.as_ref()).unwrap();
    assert!(yaml.contains("sql_buffer_global_mib: 1"));
    assert!(!yaml.contains("sql_buffer_budget:"));
    let mut updated = (*snapshot).clone();
    updated.daemon.sql_buffer_global_mib = 2;
    let next_run = RuntimeConfig::new(updated).unwrap();
    assert_eq!(
        next_run.sql_buffer_budget.available_permits(),
        2 * 1024 * 1024
    );
    assert_eq!(running.daemon.sql_buffer_global_mib, 1);
    assert_eq!(consumer.sql_buffer_budget.available_permits(), 0);
    drop(reservation);
    assert_eq!(consumer.sql_buffer_budget.available_permits(), 1024 * 1024);
}

#[test]
fn overallocation_prevention_defaults_to_enabled_for_new_and_legacy_configs() {
    let allocation = AllocationConfig::default();

    assert!(allocation.prevent_cpu_overallocation);
    assert!(allocation.prevent_memory_overallocation);
    assert!(allocation.prevent_disk_overallocation);

    let allocation: AllocationConfig = yaml_serde::from_str(
        r#"
max_memory_mib: null
max_disk_mib: null
reserved_memory_mib: 512
reserved_disk_mib: 2048
"#,
    )
    .unwrap();

    assert!(allocation.prevent_cpu_overallocation);
    assert!(allocation.prevent_memory_overallocation);
    assert!(allocation.prevent_disk_overallocation);
}

#[test]
fn automatic_pool_keeps_the_reserve_outside_allocations() {
    let allocation = AllocationConfig {
        reserved_memory_mib: 512,
        ..AllocationConfig::default()
    };

    assert_eq!(
        allocation.memory_allocation_cap_bytes(8 * 1024 * 1024 * 1024),
        7_680 * 1024 * 1024
    );
}

#[test]
fn explicit_pool_can_only_reduce_the_safe_physical_pool() {
    let allocation = AllocationConfig {
        max_disk_mib: Some(20_000),
        reserved_disk_mib: 2_048,
        ..AllocationConfig::default()
    };

    assert_eq!(
        allocation.disk_allocation_cap_bytes(16_000 * 1024 * 1024),
        13_952 * 1024 * 1024
    );
}

#[test]
fn runtime_disk_mode_is_not_serialized_as_configuration() {
    let disk = DiskConfig {
        mode: DiskLimitMode::ProjectQuota,
        ..DiskConfig::default()
    };

    let yaml = yaml_serde::to_string(&disk).unwrap();

    assert!(yaml.contains("mode: auto"));
    assert!(!yaml.contains("host_filesystem_quota"));
    assert!(yaml.contains("project_id_base:"));
}

#[test]
fn legacy_soft_scanner_config_receives_safe_hybrid_defaults() {
    let scanner: SoftDiskScannerConfig = yaml_serde::from_str(
        r#"
scan_interval_seconds: 20
max_concurrent_scans: 3
"#,
    )
    .unwrap();

    assert!(scanner.use_inotify);
    assert_eq!(scanner.full_scan_interval_seconds, 90);
    assert_eq!(scanner.inotify_debounce_milliseconds, 500);
    assert_eq!(scanner.max_dirty_paths_per_instance, 512);
    assert_eq!(scanner.scan_interval_seconds, 20);
    assert_eq!(scanner.max_concurrent_scans, 3);
}
