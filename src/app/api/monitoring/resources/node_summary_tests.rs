use super::*;
use super::{
    pools::{PoolCapacity, runtime_report_usage},
    sampler::{host_cpu_percent_between, parse_host_cpu, parse_host_memory},
    shared_disk::reported_disk_used_bytes,
};
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
fn disk_enforcement_strength_prefers_the_persisted_hard_quota() {
    assert_eq!(disk_enforcement_strength(true, false), "hard");
    assert_eq!(disk_enforcement_strength(true, true), "hard");
    assert_eq!(disk_enforcement_strength(false, true), "soft");
    assert_eq!(disk_enforcement_strength(false, false), "none");
}

#[test]
fn generic_disk_sampler_excludes_shared_pool_roots() {
    let limits = InstanceLimits::default();
    let dedicated = metadata_with_limits("dedicated", InstanceStatus::Running, limits.clone());
    let mut shared = metadata_with_limits("tenant", InstanceStatus::Running, limits.clone());
    shared.deployment_mode = crate::placement::DeploymentMode::Shared;
    shared.runtime_id = "pool-a".to_string();
    let stopped = metadata_with_limits("stopped", InstanceStatus::Stopped, limits);

    let selected = disk_sample_instance_ids(vec![dedicated, shared, stopped]);

    assert_eq!(selected.len(), 1);
    assert!(selected.contains("dedicated"));
    assert!(!selected.contains("pool-a"));
    assert!(!selected.contains("tenant"));
}

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
    assert_eq!(
        cpu_percent_over_wall_time(1_000, 10, Duration::from_secs(1)),
        0.0
    );
}

#[test]
fn container_cpu_matches_wings_rs_wall_clock_percentage() {
    assert_eq!(
        cpu_percent_over_wall_time(1_000, 110_001_000, Duration::from_secs(1)),
        11.0
    );
    assert_eq!(
        cpu_percent_over_wall_time(1_000, 2_500_001_000, Duration::from_secs(1)),
        250.0
    );
}

#[test]
fn container_cpu_reads_the_cgroup_total_counter() {
    let stats = ContainerStatsResponse {
        cpu_stats: Some(ContainerCpuStats {
            cpu_usage: Some(ContainerCpuUsage {
                total_usage: Some(123_456),
                ..ContainerCpuUsage::default()
            }),
            ..ContainerCpuStats::default()
        }),
        ..ContainerStatsResponse::default()
    };

    assert_eq!(container_cpu_total(&stats), Some(123_456));
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
async fn polling_stats_workers_ignore_superseded_samples() {
    let cache = ResourceCache::default();
    let first_worker = cache.begin_runtime_stats_worker("inst_stats").await;
    let second_worker = cache.begin_runtime_stats_worker("inst_stats").await;
    let stats = ContainerStatsResponse {
        cpu_stats: Some(ContainerCpuStats {
            cpu_usage: Some(ContainerCpuUsage {
                total_usage: Some(1_110),
                percpu_usage: Some(vec![0; 4]),
                ..ContainerCpuUsage::default()
            }),
            system_cpu_usage: Some(14_000),
            online_cpus: Some(4),
            ..ContainerCpuStats::default()
        }),
        memory_stats: Some(ContainerMemoryStats {
            usage: Some(512),
            ..ContainerMemoryStats::default()
        }),
        ..ContainerStatsResponse::default()
    };

    assert!(
        !cache
            .store_runtime_stats("inst_stats", first_worker, Some(99.0), &stats)
            .await
    );
    assert!(
        cache
            .store_runtime_stats("inst_stats", second_worker, Some(11.0), &stats)
            .await
    );
    let sample = cache.runtime_stats("inst_stats").await.unwrap();
    assert_eq!(sample.cpu_usage_percent, Some(11.0));
    assert_eq!(sample.memory_usage_bytes, Some(512));
}

#[tokio::test]
async fn stale_runtime_stats_are_hidden_but_retained_for_diagnostics() {
    let cache = ResourceCache::default();
    let worker = cache.begin_runtime_stats_worker("inst_stats").await;
    {
        let mut inner = cache.inner.lock().await;
        inner.stats.insert(
            "inst_stats".to_string(),
            CachedRuntimeStats {
                cpu_usage_percent: Some(11.0),
                memory_usage_bytes: Some(384),
                sampled_at: Instant::now() - RUNTIME_STATS_STALE_AFTER,
            },
        );
    }

    assert!(cache.runtime_stats("inst_stats").await.is_none());
    let snapshot = cache.runtime_stats_snapshot("inst_stats").await;
    assert!(snapshot.sample().is_some());
    assert!(snapshot.worker_active());
    let inner = cache.inner.lock().await;
    assert!(inner.stats.contains_key("inst_stats"));
    assert_eq!(inner.runtime_stats_workers.get("inst_stats"), Some(&worker));
    drop(inner);

    cache.clear_runtime_stats("inst_stats").await;
    let inner = cache.inner.lock().await;
    assert!(!inner.runtime_stats_workers.contains_key("inst_stats"));
}

#[tokio::test]
async fn runtime_invalidation_preserves_network_until_tenant_removal() {
    let cache = ResourceCache::default();
    let first = cache.network_counter("inst_network").await;
    let second = cache.network_counter("inst_network").await;
    let activity = cache.activity_counter("inst_network", "generation-a").await;

    first.add_rx(11);
    second.add_tx(17);
    activity.connection_opened();
    assert_eq!(cache.network_usage("inst_network").await, (11, 17));

    cache.invalidate_runtime("inst_network").await;
    assert_eq!(cache.network_usage("inst_network").await, (11, 17));
    assert!(Arc::ptr_eq(
        &activity,
        &cache.activity_counter("inst_network", "generation-a").await
    ));
    assert_eq!(
        cache
            .current_activity("inst_network", "generation-a", 1)
            .await
            .active_connections,
        1
    );

    cache.remove_tenant("inst_network").await;
    assert_eq!(cache.network_usage("inst_network").await, (0, 0));
    assert!(!Arc::ptr_eq(
        &activity,
        &cache.activity_counter("inst_network", "generation-b").await
    ));
}

#[tokio::test]
async fn disk_invalidation_preserves_live_runtime_and_network_metrics() {
    let cache = ResourceCache::default();
    let worker = cache.begin_runtime_stats_worker("pool-a").await;
    let network = cache.network_counter("pool-a").await;
    network.add_rx(11);
    network.add_tx(17);
    let stale_generation = cache.disk_refresh_lock("pool-a").await;
    assert!(
        cache
            .store_disk_usage_if_current_lock(
                "pool-a",
                &stale_generation,
                CachedDiskUsage {
                    used_bytes: 99,
                    sampled_at: Instant::now(),
                },
            )
            .await
    );

    cache.invalidate_disk("pool-a").await;

    assert_eq!(cache.network_usage("pool-a").await, (11, 17));
    assert!(cache.cached_disk_usage("pool-a").await.is_none());
    assert_eq!(
        cache.inner.lock().await.runtime_stats_workers.get("pool-a"),
        Some(&worker)
    );
    assert!(
        !cache
            .store_disk_usage_if_current_lock(
                "pool-a",
                &stale_generation,
                CachedDiskUsage {
                    used_bytes: 100,
                    sampled_at: Instant::now(),
                },
            )
            .await
    );
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

    let runtimes = [
        crate::placement::EngineRuntime::legacy_dedicated(
            &running,
            crate::placement::EngineRuntimeStatus::Running,
            "mysql:8.4".to_string(),
        ),
        crate::placement::EngineRuntime::legacy_dedicated(
            &stopped,
            crate::placement::EngineRuntimeStatus::Stopped,
            "mysql:8.4".to_string(),
        ),
    ];
    let summary = summarize_allocations(&[running, stopped], &runtimes);

    assert_eq!(summary.allocated_cpu_cores, 2.0);
    assert_eq!(summary.allocated_memory_bytes, mib_to_bytes(768));
    assert_eq!(summary.allocated_disk_bytes, mib_to_bytes(3072));
    assert_eq!(summary.instances.total, 2);
    assert_eq!(summary.instances.running, 1);
    assert_eq!(summary.instances.stopped, 1);
}

#[test]
fn allocations_include_an_unrouted_migration_target() {
    let mut runtime = shared_runtime("migration_target", Protocol::Mysql);
    runtime.limits = InstanceLimits {
        cpu_cores: 2.25,
        memory_mib: 2432,
        disk_mib: 8704,
        ..InstanceLimits::default()
    };

    let summary = summarize_allocations(&[], &[runtime]);

    assert_eq!(summary.allocated_cpu_cores, 2.25);
    assert_eq!(summary.allocated_memory_bytes, mib_to_bytes(2432));
    assert_eq!(summary.allocated_disk_bytes, mib_to_bytes(8704));
    assert_eq!(summary.instances.total, 0);
}

#[test]
fn managed_usage_is_null_when_a_running_instance_lacks_a_sample() {
    let reports = vec![(
        crate::placement::DeploymentMode::Dedicated,
        Ok(ResourceReport {
            instance_id: "inst_running".to_string(),
            runtime_id: "inst_running".to_string(),
            deployment_mode: crate::placement::DeploymentMode::Dedicated,
            scope: ResourceScope::DedicatedInstance,
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
            pool: None,
        }),
    )];

    let usage = aggregate_managed_usage(&reports, &[]);

    assert_eq!(usage.cpu_usage_cores, None);
    assert_eq!(usage.memory_used_bytes, None);
    assert_eq!(usage.disk_used_bytes, Some(123));
}

#[test]
fn shared_tenants_use_one_runtime_sample_target() {
    let mut first = metadata_with_limits(
        "tenant_one",
        InstanceStatus::Running,
        InstanceLimits::default(),
    );
    first.deployment_mode = crate::placement::DeploymentMode::Shared;
    first.runtime_id = "mysql_pool_one".to_string();
    let mut second = metadata_with_limits(
        "tenant_two",
        InstanceStatus::Running,
        InstanceLimits::default(),
    );
    second.deployment_mode = crate::placement::DeploymentMode::Shared;
    second.runtime_id = "mysql_pool_one".to_string();

    let targets = sampler::runtime_targets(&[first, second], &[]);

    assert_eq!(targets.len(), 1);
    assert_eq!(
        targets.get("mysql_pool_one"),
        Some(&sampler::RuntimeSampleTarget {
            protocol: Protocol::Mysql,
        })
    );
}

#[test]
fn dedicated_instances_keep_independent_sample_targets() {
    let first = metadata_with_limits(
        "dedicated_one",
        InstanceStatus::Running,
        InstanceLimits::default(),
    );
    let second = metadata_with_limits(
        "dedicated_two",
        InstanceStatus::Running,
        InstanceLimits::default(),
    );

    let targets = sampler::runtime_targets(&[first, second], &[]);

    assert_eq!(targets.len(), 2);
    assert!(targets.contains_key("dedicated_one"));
    assert!(targets.contains_key("dedicated_two"));
}

#[test]
fn running_shared_pool_is_sampled_when_all_tenants_are_stopped() {
    let mut tenant = metadata_with_limits(
        "tenant_stopped",
        InstanceStatus::Stopped,
        InstanceLimits::default(),
    );
    tenant.deployment_mode = crate::placement::DeploymentMode::Shared;
    tenant.runtime_id = "mysql_pool_idle".to_string();
    let runtime = shared_runtime("mysql_pool_idle", Protocol::Mysql);

    let targets = sampler::runtime_targets(&[tenant], &[runtime]);

    assert_eq!(
        targets.get("mysql_pool_idle"),
        Some(&sampler::RuntimeSampleTarget {
            protocol: Protocol::Mysql,
        })
    );
}

fn shared_runtime(runtime_id: &str, protocol: Protocol) -> crate::placement::EngineRuntime {
    use crate::placement::{
        DeploymentMode, ENGINE_RUNTIME_SCHEMA_VERSION, EngineRuntime, EngineRuntimeStatus,
        RuntimeReservation,
    };

    EngineRuntime {
        schema_version: ENGINE_RUNTIME_SCHEMA_VERSION,
        runtime_id: runtime_id.to_string(),
        protocol,
        deployment_mode: DeploymentMode::Shared,
        status: EngineRuntimeStatus::Running,
        backend: BackendEndpoint::UnixSocket {
            socket_path: format!("/run/{runtime_id}.sock"),
        },
        runtime: RuntimeMetadata {
            kind: RuntimeKind::Docker,
            container_name: runtime_id.to_string(),
            network_mode: "none".to_string(),
        },
        limits: InstanceLimits::default(),
        image: "test:latest".to_string(),
        database_version: None,
        compatibility: None,
        compatibility_key: "test".to_string(),
        max_tenants: 10,
        reserved: RuntimeReservation::default(),
        admin_secret: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    }
}

#[test]
fn admin_shared_reports_separate_tenant_and_pool_usage() {
    let stats = CachedRuntimeStats {
        cpu_usage_percent: Some(25.0),
        memory_usage_bytes: Some(1_024),
        sampled_at: Instant::now(),
    };

    let usage = runtime_report_usage(
        crate::placement::DeploymentMode::Shared,
        "mysql_pool_one",
        512,
        Some(&stats),
        Some(PoolCapacity {
            cpu_limit_cores: 8.0,
            memory_limit_bytes: mib_to_bytes(16_384),
        }),
        ResourceView::Admin,
    )
    .unwrap();

    assert_eq!(usage.cpu_usage_percent, None);
    assert_eq!(usage.memory_usage_bytes, None);
    assert_eq!(usage.memory_limit_bytes, None);
    let pool = usage.pool.unwrap();
    assert_eq!(pool.runtime_id, "mysql_pool_one");
    assert_eq!(pool.cpu_limit_cores, 8.0);
    assert_eq!(pool.cpu_usage_percent, Some(25.0));
    assert_eq!(pool.memory_limit_bytes, mib_to_bytes(16_384));
    assert_eq!(pool.memory_usage_bytes, Some(1_024));
}

#[test]
fn dedicated_reports_keep_the_existing_runtime_usage_fields() {
    let stats = CachedRuntimeStats {
        cpu_usage_percent: Some(11.0),
        memory_usage_bytes: Some(384),
        sampled_at: Instant::now(),
    };

    let usage = runtime_report_usage(
        crate::placement::DeploymentMode::Dedicated,
        "dedicated_one",
        512,
        Some(&stats),
        None,
        ResourceView::Tenant,
    )
    .unwrap();

    assert_eq!(usage.cpu_usage_percent, Some(11.0));
    assert_eq!(usage.memory_usage_bytes, Some(384));
    assert_eq!(usage.memory_limit_bytes, Some(mib_to_bytes(512)));
    assert!(usage.pool.is_none());
}

#[test]
fn shared_report_missing_pool_capacity_returns_an_error() {
    let error = runtime_report_usage(
        crate::placement::DeploymentMode::Shared,
        "missing_pool",
        512,
        None,
        None,
        ResourceView::Admin,
    )
    .err()
    .expect("shared usage without pool capacity must fail closed");

    assert!(
        error
            .to_string()
            .contains("capacity is temporarily unavailable")
    );
}

#[test]
fn tenant_shared_reports_omit_physical_pool_usage() {
    let stats = CachedRuntimeStats {
        cpu_usage_percent: Some(25.0),
        memory_usage_bytes: Some(1_024),
        sampled_at: Instant::now(),
    };

    let usage = runtime_report_usage(
        crate::placement::DeploymentMode::Shared,
        "mysql_pool_one",
        512,
        Some(&stats),
        None,
        ResourceView::Tenant,
    )
    .unwrap();

    assert_eq!(usage.cpu_usage_percent, None);
    assert_eq!(usage.memory_usage_bytes, None);
    assert_eq!(usage.memory_limit_bytes, None);
    assert!(usage.pool.is_none());
}

#[test]
fn managed_usage_counts_one_shared_runtime_once() {
    let reports = ["tenant_one", "tenant_two"]
        .into_iter()
        .map(|instance_id| {
            (
                crate::placement::DeploymentMode::Shared,
                Ok(shared_resource_report(
                    instance_id,
                    "mysql_pool_one",
                    25.0,
                    1_024,
                    100,
                )),
            )
        })
        .collect::<Vec<_>>();
    let physical = [SharedRuntimeUsage {
        runtime_id: "mysql_pool_one".to_string(),
        expects_live_sample: true,
        cpu_usage_percent: Some(25.0),
        memory_usage_bytes: Some(1_024),
        runtime_stats: sampler::RuntimeStatsSnapshot::default(),
        disk_usage: Ok(sampler::SharedDiskUsage {
            bytes: 350,
            sampled_at: Instant::now(),
            source: sampler::SharedDiskUsageSource::FilesystemQuota,
        }),
    }];

    let usage = aggregate_managed_usage(&reports, &physical);

    assert_eq!(usage.cpu_usage_cores, Some(0.25));
    assert_eq!(usage.memory_used_bytes, Some(1_024));
    assert_eq!(usage.disk_used_bytes, Some(350));
}

fn shared_resource_report(
    instance_id: &str,
    runtime_id: &str,
    cpu_usage_percent: f64,
    memory_usage_bytes: u64,
    disk_used_bytes: u64,
) -> ResourceReport {
    ResourceReport {
        instance_id: instance_id.to_string(),
        runtime_id: runtime_id.to_string(),
        deployment_mode: crate::placement::DeploymentMode::Shared,
        scope: ResourceScope::SharedTenant,
        protocol: "mysql".to_string(),
        status: "running".to_string(),
        cpu: CpuReport {
            configured_cores: 1.0,
            usage_percent: None,
        },
        memory: MemoryReport {
            configured_mib: 512,
            usage_bytes: None,
            limit_bytes: None,
        },
        disk: DiskReport {
            configured_mib: 1_024,
            limit_bytes: mib_to_bytes(1_024),
            used_bytes: disk_used_bytes,
            enforced: true,
            enforcement_method: "tenant_quota".to_string(),
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
            rx_bytes: Some(1),
            tx_bytes: Some(2),
        },
        pool: Some(PoolUsageReport {
            runtime_id: runtime_id.to_string(),
            cpu_limit_cores: 8.0,
            cpu_usage_percent: Some(cpu_usage_percent),
            memory_limit_bytes: mib_to_bytes(16_384),
            memory_usage_bytes: Some(memory_usage_bytes),
        }),
    }
}

fn metadata_with_limits(
    instance_id: &str,
    status: InstanceStatus,
    limits: InstanceLimits,
) -> InstanceMetadata {
    InstanceMetadata {
        schema_version: SCHEMA_VERSION,
        instance_id: instance_id.to_string(),
        deployment_mode: crate::placement::DeploymentMode::Dedicated,
        runtime_id: String::new(),
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
