use super::*;
use crate::{
    instances::metadata::{
        DatabaseIdentity, PublicEndpoint, RuntimeKind, RuntimeMetadata, SCHEMA_VERSION,
    },
    shared::{backend::BackendEndpoint, limits::InstanceLimits},
};
use bollard::models::{
    ContainerCpuStats, ContainerCpuUsage, ContainerMemoryStats, ContainerStatsResponse,
};

#[test]
fn parses_host_cpu_and_calculates_non_idle_percentage() {
    let previous =
        parse_host_cpu("cpu  100 0 50 850 0 0 0 0 0 0\ncpu0 50 0 25 425\ncpu1 50 0 25 425\n")
            .unwrap();
    let current =
        parse_host_cpu("cpu  150 0 100 950 0 0 0 0 0 0\ncpu0 75 0 50 475\ncpu1 75 0 50 475\n")
            .unwrap();

    assert_eq!(current.cores, 2);
    assert_eq!(host_cpu_percent_between(previous, current), Some(50.0));
}

#[test]
fn container_cpu_counter_resets_do_not_emit_bogus_usage() {
    let previous = CpuStatsSample {
        total_usage: 1_000,
        system_cpu_usage: 10_000,
        online_cpus: 4,
    };
    let reset = CpuStatsSample {
        total_usage: 10,
        system_cpu_usage: 100,
        online_cpus: 4,
    };

    assert_eq!(cpu_percent_between(previous, reset), None);
}

#[test]
fn container_cpu_matches_docker_percentage_points() {
    let previous = CpuStatsSample {
        total_usage: 1_000,
        system_cpu_usage: 10_000,
        online_cpus: 4,
    };
    let current = CpuStatsSample {
        total_usage: 1_110,
        system_cpu_usage: 14_000,
        online_cpus: 4,
    };

    assert_eq!(cpu_percent_between(previous, current), Some(11.0));
}

#[test]
fn primed_docker_cpu_sample_wins_over_cross_request_fallback() {
    assert_eq!(preferred_cpu_percent(Some(11.0), Some(0.01)), Some(11.0));
    assert_eq!(preferred_cpu_percent(None, Some(0.01)), Some(0.01));
}

#[test]
fn container_cpu_uses_per_cpu_count_when_online_cpus_is_missing() {
    let stats = ContainerCpuStats {
        cpu_usage: Some(ContainerCpuUsage {
            total_usage: Some(1_000),
            percpu_usage: Some(vec![0; 8]),
            ..ContainerCpuUsage::default()
        }),
        system_cpu_usage: Some(10_000),
        online_cpus: None,
        ..ContainerCpuStats::default()
    };

    assert_eq!(
        cpu_sample_from_container_stats(Some(&stats))
            .unwrap()
            .online_cpus,
        8
    );
}

#[test]
fn memory_usage_matches_docker_cli_working_set_on_cgroup_v1_and_v2() {
    for inactive_key in ["total_inactive_file", "inactive_file"] {
        let stats = ContainerStatsResponse {
            os_type: Some("linux".to_string()),
            memory_stats: Some(ContainerMemoryStats {
                usage: Some(512),
                stats: Some(HashMap::from([(inactive_key.to_string(), 128)])),
                ..ContainerMemoryStats::default()
            }),
            ..ContainerStatsResponse::default()
        };

        assert_eq!(docker_compatible_memory_usage(&stats), Some(384));
    }
}

#[tokio::test]
async fn docker_refresh_errors_cannot_keep_old_runtime_stats_alive() {
    let cache = ResourceCache::default();
    let fresh_sampled_at = Instant::now() - STATS_REFRESH_INTERVAL;
    {
        let mut inner = cache.inner.lock().await;
        inner.stats.insert(
            "inst_stats".to_string(),
            CachedRuntimeStats {
                cpu_usage_percent: Some(11.0),
                memory_usage_bytes: Some(384),
                sampled_at: fresh_sampled_at,
            },
        );
    }

    let transient = cache.stats_after_refresh_error("inst_stats").await.unwrap();
    assert_eq!(transient.sampled_at, fresh_sampled_at);

    {
        let mut inner = cache.inner.lock().await;
        inner.stats.get_mut("inst_stats").unwrap().sampled_at = Instant::now() - STATS_STALE_GRACE;
        inner.cpu_samples.insert(
            "inst_stats".to_string(),
            CpuStatsSample {
                total_usage: 1,
                system_cpu_usage: 2,
                online_cpus: 1,
            },
        );
    }

    assert!(
        cache
            .stats_after_refresh_error("inst_stats")
            .await
            .is_none()
    );
    let inner = cache.inner.lock().await;
    assert!(!inner.stats.contains_key("inst_stats"));
    assert!(!inner.cpu_samples.contains_key("inst_stats"));
}

#[tokio::test]
async fn gateway_network_counters_are_shared_and_removed_with_the_instance() {
    let cache = ResourceCache::default();
    let first = cache.network_counter("inst_network").await;
    let second = cache.network_counter("inst_network").await;

    first.add_rx(11);
    second.add_tx(17);
    assert_eq!(cache.network_usage("inst_network").await, (11, 17));

    cache.remove("inst_network").await;
    assert_eq!(cache.network_usage("inst_network").await, (0, 0));
}

#[tokio::test]
async fn scanner_snapshot_bypasses_the_fallback_disk_traversal() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    let snapshot = crate::disk::soft::SoftDiskSnapshot {
        usage: crate::disk::usage::DirectoryUsage {
            logical_bytes: 321,
            physical_bytes: 654,
            entries: 1,
        },
        limit_bytes: 1_000,
        stop_threshold_bytes: 1_000,
        recovery_threshold_bytes: 800,
        growth_bytes_per_second: 0.0,
        peak_growth_bytes_per_second: 0.0,
        predicted_seconds_to_limit: None,
        blocked: false,
        sampled_at: std::time::Instant::now(),
    };
    let fallback_called = Arc::new(AtomicBool::new(false));
    let fallback_flag = Arc::clone(&fallback_called);

    let used = reported_disk_used_bytes(Some(&snapshot), move || async move {
        fallback_flag.store(true, Ordering::SeqCst);
        Err::<u64, String>("fallback traversal must not run".to_string())
    })
    .await
    .unwrap();

    assert_eq!(used, 654);
    assert!(!fallback_called.load(Ordering::SeqCst));
}

#[test]
fn parses_mem_available_as_scheduler_safe_host_memory() {
    let sample = parse_host_memory(
        "MemTotal:       1000 kB\nMemFree:         100 kB\nMemAvailable:    400 kB\n",
    )
    .unwrap();

    assert_eq!(sample.total_bytes, 1_024_000);
    assert_eq!(sample.available_bytes, 409_600);
    assert_eq!(sample.used_bytes, 614_400);
}

#[tokio::test]
async fn host_disk_sample_uses_the_target_filesystem() {
    let directory = tempfile::tempdir().unwrap();
    let sample = read_host_disk(directory.path().to_str().unwrap())
        .await
        .unwrap();

    assert!(sample.total_bytes > 0);
    assert!(sample.used_bytes <= sample.total_bytes);
    assert!(sample.available_bytes <= sample.total_bytes);
}

#[tokio::test]
async fn capacity_measurement_ignores_a_stale_dashboard_disk_sample() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("data.bin");
    tokio::fs::write(&data, vec![0_u8; 7 * 1024 * 1024])
        .await
        .unwrap();
    let cache = ResourceCache::default();
    cache
        .store_disk_usage(
            "inst_fresh_capacity".to_string(),
            CachedDiskUsage {
                used_bytes: 8 * 1024 * 1024 * 1024,
                sampled_at: Instant::now(),
            },
        )
        .await;

    let measured = cache
        .fresh_disk_usage(
            &Config::default(),
            "inst_fresh_capacity",
            directory.path().to_path_buf(),
        )
        .await
        .unwrap();

    assert!(measured.used_bytes >= 7 * 1024 * 1024);
    assert!(measured.used_bytes < 8 * 1024 * 1024);
}

#[test]
fn allocations_include_running_and_stopped_instances() {
    let running = metadata_with_limits(
        "inst_running",
        InstanceStatus::Running,
        InstanceLimits {
            cpu_cores: 1.5,
            memory_mib: 512,
            disk_mib: 1024,
            ..InstanceLimits::default()
        },
    );
    let stopped = metadata_with_limits(
        "inst_stopped",
        InstanceStatus::Stopped,
        InstanceLimits {
            cpu_cores: 0.5,
            memory_mib: 256,
            disk_mib: 2048,
            ..InstanceLimits::default()
        },
    );

    let summary = aggregate_allocations_and_statuses(&[running, stopped]);

    assert_eq!(summary.allocated_cpu_cores, 2.0);
    assert_eq!(summary.allocated_memory_bytes, mib_to_bytes(768));
    assert_eq!(summary.allocated_disk_bytes, mib_to_bytes(3072));
    assert_eq!(summary.instances.total, 2);
    assert_eq!(summary.instances.running, 1);
    assert_eq!(summary.instances.stopped, 1);
}

#[test]
fn managed_usage_is_null_when_a_running_instance_lacks_a_sample() {
    let reports = vec![Ok(ResourceReport {
        instance_id: "inst_running".to_string(),
        protocol: "mysql".to_string(),
        status: "running".to_string(),
        cpu: CpuReport {
            configured_cores: 1.0,
            usage_percent: None,
        },
        memory: MemoryReport {
            configured_mib: 512,
            usage_bytes: None,
            limit_bytes: Some(mib_to_bytes(512)),
        },
        disk: DiskReport {
            configured_mib: 1024,
            limit_bytes: mib_to_bytes(1024),
            used_bytes: 123,
            enforced: true,
            enforcement_method: "fuse_quota".to_string(),
            enforcement_strength: "hard",
            scanner_logical_bytes: None,
            scanner_physical_bytes: None,
            scanner_growth_bytes_per_second: None,
            scanner_peak_growth_bytes_per_second: None,
            scanner_predicted_seconds_to_limit: None,
            scanner_stop_threshold_bytes: None,
            scanner_recovery_threshold_bytes: None,
            scanner_restart_blocked: None,
            scanner_sample_age_seconds: None,
        },
        network: NetworkReport {
            rx_bytes: None,
            tx_bytes: None,
        },
    })];

    let usage = aggregate_managed_usage(&reports);

    assert_eq!(usage.cpu_usage_cores, None);
    assert_eq!(usage.memory_used_bytes, None);
    assert_eq!(usage.disk_used_bytes, Some(123));
}

fn metadata_with_limits(
    instance_id: &str,
    status: InstanceStatus,
    limits: InstanceLimits,
) -> InstanceMetadata {
    InstanceMetadata {
        schema_version: SCHEMA_VERSION,
        instance_id: instance_id.to_string(),
        protocol: Protocol::Mysql,
        status,
        desired_state: crate::instances::metadata::DesiredInstanceState::Running,
        disk_limit_blocked: false,
        public: PublicEndpoint {
            host: "127.0.0.1".to_string(),
            port: 3308,
        },
        backend: BackendEndpoint::UnixSocket {
            socket_path: format!("/run/dbev/sockets/{instance_id}/mysqld.sock"),
        },
        runtime: RuntimeMetadata {
            kind: RuntimeKind::Docker,
            container_name: format!("dbe-mysql-{instance_id}"),
            network_mode: "none".to_string(),
        },
        database: DatabaseIdentity {
            name: format!("db_{instance_id}"),
            username: format!("user_{instance_id}"),
        },
        route_key_sha256: None,
        mariadb_native_password_sha1_stage2: None,
        mariadb_root_password: None,
        mysql_native_password_sha1_stage2: None,
        mysql_root_password: None,
        mongodb_root_password: None,
        postgres_admin_password: None,
        tenant_password: None,
        limits,
        image: None,
        database_version: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    }
}
