use super::*;

use std::path::Path;

fn write_v2_evidence(root: &Path, controllers: &str) {
    std::fs::write(root.join("cgroup.controllers"), controllers).unwrap();
}

fn write_v1_memory(base: &Path, limit: u64, usage: u64) {
    std::fs::write(base.join("memory.limit_in_bytes"), limit.to_string()).unwrap();
    std::fs::write(base.join("memory.usage_in_bytes"), usage.to_string()).unwrap();
}

fn write_v1_cpu(base: &Path, quota: i64, period: u64) {
    std::fs::write(base.join("cpu.cfs_quota_us"), quota.to_string()).unwrap();
    std::fs::write(base.join("cpu.cfs_period_us"), period.to_string()).unwrap();
}

#[test]
fn inherited_cgroup_limits_are_found_when_the_leaf_is_unlimited() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let parent = root.join("pod");
    let leaf = parent.join("service");
    std::fs::create_dir_all(&leaf).unwrap();
    write_v2_evidence(root, "cpu memory\n");
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
        vec![leaf, parent.clone(), root.to_path_buf()]
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

    std::fs::remove_file(parent.join("memory.current")).unwrap();
    assert!(!cgroup_memory_sample_complete(
        &[root],
        Some("/pod/service"),
        "memory.max",
        "memory.current",
        false,
    ));
}

#[test]
fn verified_systemd_v2_allows_missing_root_controller_interface() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let slice = root.join("system.slice");
    let service = slice.join("databases-everywhere.service");
    std::fs::create_dir_all(&service).unwrap();
    write_v2_evidence(root, "cpu memory io\n");
    for base in [slice.as_path(), service.as_path()] {
        std::fs::write(base.join("memory.max"), "max\n").unwrap();
        std::fs::write(base.join("cpu.max"), "max 100000\n").unwrap();
    }

    let sample = test_resource_sample_from_cgroups(
        Some(11_451),
        Some(8),
        "0::/system.slice/databases-everywhere.service\n",
        &[root],
        &[],
        &[],
    );
    assert!(sample.memory_valid);
    assert!(sample.cpu_valid);
    assert_eq!(sample.available_memory_mib, Some(11_451));
    assert_eq!(sample.cpu_units, Some(8));
}

#[test]
fn empty_ordinary_directory_is_not_accepted_as_cgroup_v2() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    std::fs::create_dir_all(root.join("service")).unwrap();

    let sample =
        test_resource_sample_from_cgroups(Some(8192), Some(8), "0::/service\n", &[root], &[], &[]);
    assert!(!sample.memory_valid);
    assert!(!sample.cpu_valid);
}

#[test]
fn hybrid_finite_v1_memory_wins_when_v2_memory_controller_is_absent() {
    let v2_directory = tempfile::tempdir().unwrap();
    let v2_root = v2_directory.path();
    let v2_slice = v2_root.join("system.slice");
    let v2_leaf = v2_slice.join("databases-everywhere.service");
    std::fs::create_dir_all(&v2_leaf).unwrap();
    write_v2_evidence(v2_root, "cpu io\n");
    std::fs::write(v2_leaf.join("cpu.max"), "max 100000\n").unwrap();
    std::fs::write(v2_slice.join("cpu.max"), "max 100000\n").unwrap();

    let v1_directory = tempfile::tempdir().unwrap();
    let v1_root = v1_directory.path();
    let v1_parent = v1_root.join("legacy");
    let v1_leaf = v1_parent.join("service");
    std::fs::create_dir_all(&v1_leaf).unwrap();
    write_v1_memory(v1_root, 1_u64 << 60, 0);
    write_v1_memory(&v1_parent, 1_u64 << 60, 0);
    write_v1_memory(&v1_leaf, 2048 * MIB, 512 * MIB);

    let sample = test_resource_sample_from_cgroups(
        Some(8192),
        Some(8),
        "0::/system.slice/databases-everywhere.service\n5:memory:/legacy/service\n",
        &[v2_root],
        &[v1_root],
        &[],
    );
    assert!(sample.memory_valid);
    assert_eq!(sample.available_memory_mib, Some(1536));
    assert!(sample.cpu_valid);
    assert_eq!(sample.cpu_units, Some(8));
}

#[test]
fn hybrid_finite_v1_cpu_wins_when_v2_cpu_controller_is_absent() {
    let v2_directory = tempfile::tempdir().unwrap();
    let v2_root = v2_directory.path();
    let v2_slice = v2_root.join("system.slice");
    let v2_leaf = v2_slice.join("databases-everywhere.service");
    std::fs::create_dir_all(&v2_leaf).unwrap();
    write_v2_evidence(v2_root, "memory io\n");
    std::fs::write(v2_leaf.join("memory.max"), "max\n").unwrap();
    std::fs::write(v2_slice.join("memory.max"), "max\n").unwrap();

    let v1_directory = tempfile::tempdir().unwrap();
    let v1_root = v1_directory.path();
    let v1_parent = v1_root.join("legacy");
    let v1_leaf = v1_parent.join("service");
    std::fs::create_dir_all(&v1_leaf).unwrap();
    write_v1_cpu(v1_root, -1, 100_000);
    write_v1_cpu(&v1_parent, -1, 100_000);
    write_v1_cpu(&v1_leaf, 200_000, 100_000);

    let sample = test_resource_sample_from_cgroups(
        Some(8192),
        Some(8),
        "0::/system.slice/databases-everywhere.service\n4:cpu,cpuacct:/legacy/service\n",
        &[v2_root],
        &[],
        &[v1_root],
    );
    assert!(sample.memory_valid);
    assert_eq!(sample.available_memory_mib, Some(8192));
    assert!(sample.cpu_valid);
    assert_eq!(sample.cpu_units, Some(2));
}

#[test]
fn advertised_v2_controller_without_leaf_interface_is_invalid() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    std::fs::create_dir_all(root.join("system.slice/service")).unwrap();
    write_v2_evidence(root, "cpu memory\n");

    let sample = test_resource_sample_from_cgroups(
        Some(8192),
        Some(8),
        "0::/system.slice/service\n",
        &[root],
        &[],
        &[],
    );
    assert!(!sample.memory_valid);
    assert!(!sample.cpu_valid);
}

#[test]
fn v1_leaf_missing_or_unreadable_never_falls_back_to_unlimited_ancestor() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let parent = root.join("legacy");
    let leaf = parent.join("service");
    std::fs::create_dir_all(&leaf).unwrap();
    write_v1_memory(root, 1_u64 << 60, 0);
    write_v1_memory(&parent, 1_u64 << 60, 0);
    write_v1_cpu(root, -1, 100_000);
    write_v1_cpu(&parent, -1, 100_000);
    let memberships = "5:memory:/legacy/service\n4:cpu,cpuacct:/legacy/service\n";

    let missing =
        test_resource_sample_from_cgroups(Some(8192), Some(8), memberships, &[], &[root], &[root]);
    assert!(!missing.memory_valid);
    assert!(!missing.cpu_valid);

    std::fs::create_dir(leaf.join("memory.limit_in_bytes")).unwrap();
    std::fs::create_dir(leaf.join("cpu.cfs_quota_us")).unwrap();
    let unreadable =
        test_resource_sample_from_cgroups(Some(8192), Some(8), memberships, &[], &[root], &[root]);
    assert!(!unreadable.memory_valid);
    assert!(!unreadable.cpu_valid);
}

#[test]
fn verified_v2_controller_absence_uses_host_but_malformed_values_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let service = root.join("system.slice/service");
    std::fs::create_dir_all(&service).unwrap();
    write_v2_evidence(root, "io\n");
    let memberships = "0::/system.slice/service\n";

    let absent =
        test_resource_sample_from_cgroups(Some(8192), Some(8), memberships, &[root], &[], &[]);
    assert!(absent.memory_valid);
    assert!(absent.cpu_valid);
    assert_eq!(absent.available_memory_mib, Some(8192));
    assert_eq!(absent.cpu_units, Some(8));

    std::fs::write(service.join("memory.max"), "not-a-limit\n").unwrap();
    std::fs::write(service.join("memory.current"), "0\n").unwrap();
    std::fs::write(service.join("cpu.max"), "max not-a-period\n").unwrap();
    let malformed =
        test_resource_sample_from_cgroups(Some(8192), Some(8), memberships, &[root], &[], &[]);
    assert!(!malformed.memory_valid);
    assert!(!malformed.cpu_valid);
}

#[test]
fn systemd_host_capacity_resolves_to_sixty_percent_in_dynamic_mode() {
    #[derive(Debug)]
    struct Provider;
    impl SchedulerResourceProvider for Provider {
        fn sample(&self) -> SchedulerResourceSample {
            SchedulerResourceSample {
                available_memory_mib: Some(11_451),
                cpu_units: Some(8),
                memory_valid: true,
                cpu_valid: true,
            }
        }
    }

    let capacity = SchedulerCapacity::detect_with_provider(
        &ImportExportSchedulerConfig::default(),
        8 * 1024 * MIB,
        32 * 1024 * MIB,
        &Provider,
    );
    assert_eq!(capacity.memory_budget_mib, 6_870);
    assert_eq!(capacity.cpu_units, 8);
}
