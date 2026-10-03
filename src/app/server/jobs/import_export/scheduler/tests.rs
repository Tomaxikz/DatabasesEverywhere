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
            available_memory_mib: Some(self.memory_mib.load(std::sync::atomic::Ordering::Acquire)),
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
fn recommendation_respects_scarce_and_unavailable_resources() {
    for (capacity, job, expected) in [
        (
            dynamic_capacity(256, 16_384, 32_768, 64),
            cost(512, 4096, 2),
            8,
        ),
        (dynamic_capacity(256, 1, 65_536, 128), cost(96, 1, 1), 0),
    ] {
        assert_eq!(capacity.recommended_active_jobs(job), expected);
    }
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
        input_size_bytes: crate::server::jobs::import_export::MAX_DATA_ARCHIVE_BYTES,
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
fn unlimited_systemd_cgroup_uses_host_capacity() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let slice = root.join("system.slice");
    let service = slice.join("databases-everywhere.service");
    std::fs::create_dir_all(&service).unwrap();
    std::fs::write(root.join("cgroup.controllers"), "cpu memory\n").unwrap();

    for base in [root, slice.as_path(), service.as_path()] {
        std::fs::write(base.join("memory.max"), "max\n").unwrap();
        std::fs::write(base.join("cpu.max"), "max 100000\n").unwrap();
    }
    std::fs::write(service.join("memory.current"), (937 * MIB).to_string()).unwrap();

    assert!(cgroup_memory_sample_complete(
        &[root],
        Some("/system.slice/databases-everywhere.service"),
        "memory.max",
        "memory.current",
        false,
    ));
    assert_eq!(
        read_cgroup_memory(
            &[root],
            Some("/system.slice/databases-everywhere.service"),
            "memory.max",
            "memory.current",
            false,
        ),
        None
    );
    assert!(cgroup_v2_cpu_sample_complete(
        &[root],
        Some("/system.slice/databases-everywhere.service"),
    ));
    assert_eq!(
        read_cgroup_v2_cpu_units(&[root], Some("/system.slice/databases-everywhere.service"),),
        None
    );
    assert_eq!(minimum_present(Some(11_451), None), Some(11_451));

    let provider = MutableResourceProvider {
        memory_mib: std::sync::atomic::AtomicU64::new(11_451),
        cpu_units: std::sync::atomic::AtomicUsize::new(8),
        valid: std::sync::atomic::AtomicBool::new(true),
    };
    let capacity = SchedulerCapacity::detect_with_provider(
        &ImportExportSchedulerConfig::default(),
        8 * 1024 * MIB,
        32 * 1024 * MIB,
        &provider,
    );
    assert_eq!(capacity.memory_budget_mib, 6_870);
    assert_eq!(capacity.cpu_units, 8);
}

#[test]
fn verified_unavailable_v2_controller_is_unlimited_but_malformed_limits_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let service = root.join("system.slice/databases-everywhere.service");
    std::fs::create_dir_all(&service).unwrap();
    std::fs::write(root.join("cgroup.controllers"), "io\n").unwrap();

    assert!(cgroup_memory_sample_complete(
        &[root],
        Some("/system.slice/databases-everywhere.service"),
        "memory.max",
        "memory.current",
        false,
    ));
    assert!(cgroup_v2_cpu_sample_complete(
        &[root],
        Some("/system.slice/databases-everywhere.service"),
    ));

    std::fs::write(service.join("memory.max"), "not-a-limit\n").unwrap();
    std::fs::write(service.join("memory.current"), "0\n").unwrap();
    std::fs::write(service.join("cpu.max"), "max not-a-period\n").unwrap();

    assert!(!cgroup_memory_sample_complete(
        &[root],
        Some("/system.slice/databases-everywhere.service"),
        "memory.max",
        "memory.current",
        false,
    ));
    assert!(!cgroup_v2_cpu_sample_complete(
        &[root],
        Some("/system.slice/databases-everywhere.service"),
    ));
}
