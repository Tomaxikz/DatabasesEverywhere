use std::{fs, os::unix::fs::symlink, time::Duration};

use super::ResourceCache;

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
            "api::monitoring::resources::disk_scan_tests::wide_scan_fits_a_small_descriptor_budget",
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
