use std::{fs, os::unix::fs::symlink, time::Duration};

use super::ResourceCache;

#[tokio::test]
async fn background_refresh_skips_only_a_matching_scanner_measurement() {
    use crate::{
        config::{Config, DiskLimitMode},
        databases::protocol::Protocol,
        server::{paths::InstancePaths, test_support::metadata},
    };

    let volumes = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.paths.volumes = volumes.path().display().to_string();
    config.disk.mode = DiskLimitMode::SoftScanner;
    let (state, _db) = crate::subsystems::test_support::database(config).await;
    let mut instance = metadata("inst_monitor", Protocol::Qdrant);
    instance.limits.disk_enforcement_method = "fuse_quota".to_owned();
    instance.limits.disk_mib = 128;
    let data = InstancePaths::new(&state.config.paths, &instance.instance_id)
        .unwrap()
        .data;
    fs::create_dir_all(&data).unwrap();
    fs::write(data.join("data.bin"), b"1234567").unwrap();
    let target = super::disk::scanner_target(&instance, data);
    state
        .soft_disk_limiter
        .ensure_start_allowed(&target)
        .await
        .unwrap();
    let cache = &state.resource_cache;

    // Both legacy Qdrant and explicitly scanner-backed reports use physical usage.
    for method in ["fuse_quota", "soft_scanner"] {
        instance.limits.disk_enforcement_method = method.to_owned();
        state.instances.upsert(instance.clone()).await;
        cache.refresh_all_disk_usage(&state).await;
        assert!(
            cache
                .cached_disk_usage(&instance.instance_id)
                .await
                .is_none()
        );
    }

    // The same ID with a new generation must take the logical-byte fallback.
    instance.created_at = "2026-02-01T00:00:00Z".to_owned();
    state.instances.upsert(instance.clone()).await;
    cache.refresh_all_disk_usage(&state).await;
    assert_eq!(
        cache
            .cached_disk_usage(&instance.instance_id)
            .await
            .unwrap()
            .used_bytes,
        7
    );
}

#[tokio::test]
async fn disk_scan_counts_regular_files_without_following_symlinks() {
    let temporary = tempfile::tempdir().unwrap();
    let data = temporary.path().join("data");
    let outside = temporary.path().join("outside");
    fs::create_dir_all(data.join("nested")).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(data.join("root.bin"), [0_u8; 7]).unwrap();
    fs::write(data.join("nested/child.bin"), [0_u8; 11]).unwrap();
    fs::write(outside.join("secret.bin"), [0_u8; 101]).unwrap();
    symlink(&outside, data.join("outside-link")).unwrap();

    assert_eq!(
        ResourceCache::default()
            .scan_directory(data, Duration::from_secs(1))
            .await
            .unwrap(),
        18
    );
}

#[tokio::test]
async fn disk_scan_rejects_a_symlink_root() {
    let temporary = tempfile::tempdir().unwrap();
    let data = temporary.path().join("data");
    let linked = temporary.path().join("linked");
    fs::create_dir(&data).unwrap();
    symlink(&data, &linked).unwrap();

    assert!(
        ResourceCache::default()
            .scan_directory(linked, Duration::from_secs(1))
            .await
            .is_err()
    );
}

#[test]
fn wide_scan_fits_a_small_descriptor_budget() {
    use std::{io, os::unix::process::CommandExt, process::Command};
    const CHILD_ROOT: &str = "DBEV_WIDE_SCAN_TEST_ROOT";
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let used = runtime
            .block_on(ResourceCache::default().scan_directory(root.into(), Duration::from_secs(5)))
            .unwrap();
        assert_eq!(used, 512);
        return;
    }

    let temporary = tempfile::tempdir().unwrap();
    for index in 0..512 {
        let child = temporary.path().join(format!("child-{index}"));
        fs::create_dir(&child).unwrap();
        fs::write(child.join("data"), b"x").unwrap();
    }
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .args([
            "--exact",
            "subsystems::monitoring::resources::disk_scan_tests::wide_scan_fits_a_small_descriptor_budget",
            "--nocapture",
        ])
        .env(CHILD_ROOT, temporary.path());
    // Limit only this isolated test process, never the parallel test runner.
    unsafe {
        child.pre_exec(|| {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                return Err(io::Error::last_os_error());
            }
            limit.rlim_cur = limit.rlim_max.min(64);
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = child.output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}
