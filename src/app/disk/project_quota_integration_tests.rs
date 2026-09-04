use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use super::{DiskLimitError, DiskLimiter, project_id};
use crate::config::{DiskConfig, DiskLimitMode};

const MIB: usize = 1024 * 1024;
const INITIAL_LIMIT_MIB: u64 = 12;
const RESIZED_LIMIT_MIB: u64 = 24;
const PROJECT_ID_BASE: u32 = 3_000_000;

/// This test mutates real kernel quota state and is therefore run only by the
/// dedicated privileged loopback workflow. Keeping it ignored prevents an
/// ordinary `cargo test` from depending on root, mount, or host quota tools.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root and a loopback XFS/ext4/F2FS project-quota mount"]
async fn real_project_quota_enforces_tenant_boundary() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "the project-quota smoke test must run as root"
    );

    let filesystem = required_env("DBE_PROJECT_QUOTA_TEST_FS");
    let expected_method = match filesystem.as_str() {
        "xfs" => "host_xfs_project_quota",
        "ext4" | "f2fs" => "host_linux_project_quota",
        other => panic!("unsupported project-quota smoke-test filesystem: {other}"),
    };
    let root = canonical_test_root(&required_env("DBE_PROJECT_QUOTA_TEST_ROOT"));
    let registry_root = root.join("registry");
    let tenant_a = root.join("tenant-a");
    let tenant_b = root.join("tenant-b");
    for path in [&registry_root, &tenant_a, &tenant_b] {
        fs::create_dir(path)
            .unwrap_or_else(|error| panic!("failed to create {}: {error}", path.display()));
    }

    // Prove adoption accounts files that existed before the project was set.
    append_exact(&tenant_a.join("preexisting.bin"), MIB);

    let config = DiskConfig {
        mode: DiskLimitMode::ProjectQuota,
        project_id_base: PROJECT_ID_BASE,
        ..DiskConfig::default()
    };
    let limiter = DiskLimiter::new(config);

    let a = limiter
        .apply_path_quota(
            "quota-smoke-tenant-a",
            &tenant_a,
            &registry_root,
            INITIAL_LIMIT_MIB,
        )
        .await
        .expect("apply tenant A project quota");
    let b = limiter
        .apply_path_quota(
            "quota-smoke-tenant-b",
            &tenant_b,
            &registry_root,
            INITIAL_LIMIT_MIB,
        )
        .await
        .expect("apply tenant B project quota");
    assert!(a.enforced && b.enforced);
    assert_eq!(a.method, expected_method);
    assert_eq!(b.method, expected_method);
    let tenant_a_project =
        project_id::find_active_in("quota-smoke-tenant-a", &registry_root, PROJECT_ID_BASE)
            .await
            .expect("read tenant A project claim")
            .expect("tenant A project claim must be active");
    let tenant_b_project =
        project_id::find_active_in("quota-smoke-tenant-b", &registry_root, PROJECT_ID_BASE)
            .await
            .expect("read tenant B project claim")
            .expect("tenant B project claim must be active");
    assert_ne!(tenant_a_project, tenant_b_project);

    let a_data = tenant_a.join("quota-fill.bin");
    append_until_edquot(&a_data, 2 * RESIZED_LIMIT_MIB as usize);
    let a_usage_before_resize = limiter
        .path_quota_usage_bytes("quota-smoke-tenant-a", &tenant_a, &registry_root)
        .await
        .expect("read tenant A kernel-accounted usage");
    assert!(
        a_usage_before_resize >= INITIAL_LIMIT_MIB.saturating_sub(2) * MIB as u64,
        "tenant A hit EDQUOT but reported only {a_usage_before_resize} bytes"
    );

    // Exhausting A must not consume B's independent budget.
    append_exact(&tenant_b.join("independent.bin"), 2 * MIB);
    let b_usage_before_clear = limiter
        .path_quota_usage_bytes("quota-smoke-tenant-b", &tenant_b, &registry_root)
        .await
        .expect("read tenant B kernel-accounted usage");
    assert!(b_usage_before_clear >= 2 * MIB as u64);

    limiter
        .update_path_quota(
            "quota-smoke-tenant-a",
            &tenant_a,
            &registry_root,
            RESIZED_LIMIT_MIB,
        )
        .await
        .expect("grow tenant A project quota");
    append_exact(&a_data, 4 * MIB);
    let a_usage_after_resize = limiter
        .path_quota_usage_bytes("quota-smoke-tenant-a", &tenant_a, &registry_root)
        .await
        .expect("read resized tenant A usage");
    assert!(
        a_usage_after_resize > a_usage_before_resize,
        "growing tenant A did not permit additional accounted writes"
    );

    limiter
        .remove_path_quota("quota-smoke-tenant-a", &tenant_a, &registry_root)
        .await
        .expect("clear tenant A project quota");
    assert_missing_claim(
        limiter
            .path_quota_usage_bytes("quota-smoke-tenant-a", &tenant_a, &registry_root)
            .await,
    );
    assert_tombstoned(&registry_root, "quota-smoke-tenant-a");

    // Clearing A removes its write boundary without disturbing B's label,
    // limit, accounting, or project-ID claim.
    append_exact(&a_data, MIB);
    append_exact(&tenant_b.join("survives-a-clear.bin"), MIB);
    let b_usage_after_clear = limiter
        .path_quota_usage_bytes("quota-smoke-tenant-b", &tenant_b, &registry_root)
        .await
        .expect("tenant B must survive tenant A cleanup");
    assert!(b_usage_after_clear > b_usage_before_clear);
    assert_eq!(
        project_id::find_active_in("quota-smoke-tenant-b", &registry_root, PROJECT_ID_BASE,)
            .await
            .expect("read surviving tenant B project claim"),
        Some(tenant_b_project)
    );

    limiter
        .remove_path_quota("quota-smoke-tenant-b", &tenant_b, &registry_root)
        .await
        .expect("clear tenant B project quota");
    assert_missing_claim(
        limiter
            .path_quota_usage_bytes("quota-smoke-tenant-b", &tenant_b, &registry_root)
            .await,
    );
    assert_tombstoned(&registry_root, "quota-smoke-tenant-b");
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} must be set by the quota smoke runner"))
}

fn canonical_test_root(raw: &str) -> PathBuf {
    let root = PathBuf::from(raw)
        .canonicalize()
        .unwrap_or_else(|error| panic!("invalid quota test root {raw}: {error}"));
    assert_ne!(root, Path::new("/"), "refusing to use / as the test root");
    assert!(
        root.parent().is_some(),
        "quota test root must not be a root path"
    );
    assert!(
        fs::read_dir(&root)
            .unwrap_or_else(|error| panic!("cannot inspect {}: {error}", root.display()))
            .next()
            .is_none(),
        "quota test root must be an empty disposable mount: {}",
        root.display()
    );
    root
}

fn append_until_edquot(path: &Path, maximum_mib: usize) {
    let mut file = open_append(path);
    let chunk = vec![0xA5; MIB];
    for _ in 0..maximum_mib {
        if let Err(error) = file.write_all(&chunk) {
            assert_edquot(error, path);
            return;
        }
        if let Err(error) = file.sync_data() {
            assert_edquot(error, path);
            return;
        }
    }
    panic!(
        "{} accepted {maximum_mib} MiB without returning EDQUOT",
        path.display()
    );
}

fn append_exact(path: &Path, bytes: usize) {
    let mut file = open_append(path);
    let chunk = vec![0x5A; MIB];
    let mut remaining = bytes;
    while remaining > 0 {
        let length = remaining.min(chunk.len());
        file.write_all(&chunk[..length])
            .unwrap_or_else(|error| panic!("write to {} failed: {error}", path.display()));
        remaining -= length;
    }
    file.sync_data()
        .unwrap_or_else(|error| panic!("sync of {} failed: {error}", path.display()));
}

fn open_append(path: &Path) -> fs::File {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap_or_else(|error| panic!("open {} failed: {error}", path.display()))
}

fn assert_edquot(error: io::Error, path: &Path) {
    assert_eq!(
        error.raw_os_error(),
        Some(libc::EDQUOT),
        "{} failed with {error}, not EDQUOT",
        path.display()
    );
}

fn assert_missing_claim(result: Result<u64, DiskLimitError>) {
    assert!(
        matches!(&result, Err(DiskLimitError::ProjectIdNotFound { .. })),
        "released tenant still returned quota usage: {result:?}"
    );
}

fn assert_tombstoned(registry_root: &Path, owner: &str) {
    let registry = registry_root.join(".dbe-project-quota-ids");
    let found = fs::read_dir(&registry)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", registry.display()))
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|suffix| suffix == "released")
        })
        .any(|entry| fs::read_to_string(entry.path()).is_ok_and(|value| value.trim() == owner));
    assert!(found, "no released project-ID tombstone records {owner}");
}
