use std::os::unix::{fs::PermissionsExt, net::UnixListener};

use super::*;

#[test]
fn fuse_quota_uses_database_safe_mount_args() {
    let args = mount_args();

    assert!(args.contains(&"--nopassthrough"));
    assert!(args.contains(&"--nosplice"));
    assert!(args.contains(&"--clone-fd"));
    assert!(args.windows(2).any(|pair| pair == ["--num-threads", "2"]));
    assert!(!args.contains(&"--single"));
    assert!(args.contains(&"--nocache"));
    for (cmdline, expected) in [
        (b"fusequota\0--nocache\0/data\0/mount\0".as_slice(), true),
        (b"fusequota\0/data/--nocache\0/mount\0".as_slice(), false),
        (b"fusequota\0--nocache=false\0".as_slice(), false),
        (b"fusequota\0--nocache".as_slice(), false),
        (b"fusequota\0--\0--nocache\0".as_slice(), false),
        (b"".as_slice(), false),
    ] {
        assert_eq!(has_nocache_arg(cmdline), expected);
    }
}

#[test]
fn external_helper_metadata_must_be_root_owned_and_immutable_to_unprivileged_users() {
    assert!(check_external_binary(true, 0, 1, 0o100755).is_ok());
    assert!(check_external_binary(true, 1000, 1, 0o100755).is_err());
    assert!(check_external_binary(true, 0, 2, 0o100755).is_err());
    assert!(check_external_binary(true, 0, 1, 0o100775).is_err());
    assert!(check_external_binary(true, 0, 1, 0o100644).is_err());
    assert!(check_external_binary(false, 0, 1, 0o100755).is_err());
}

#[tokio::test]
#[ignore = "requires root, /dev/fuse and fusermount3 on a disposable Linux host"]
async fn mounted_helper_enforces_quota_and_reuses_process() {
    assert!(rustix::process::geteuid().is_root(), "run as root");
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    let root = temp.path().join("fuse");
    let result = timeout(Duration::from_secs(30), async {
        // Model a cached helper left by an older daemon. A live quota
        // change must reject it without remounting or changing its quota.
        let paths = fuse_paths_with_root(&data, Some(&root))?;
        prepare_fuse_dirs(&root)?;
        tokio::fs::create_dir_all(&data).await?;
        tokio::fs::create_dir_all(&paths.mount_path).await?;
        let binary = resolve_binary("embedded", "", Some(&root)).await?;
        let mut legacy = Command::new(binary)
            .args([
                "--foreground",
                "--quota",
                "67108864",
                "--uid",
                "0",
                "--gid",
                "0",
            ])
            .arg("--communication-socket-path")
            .arg(&paths.socket_path)
            .args(mount_args().into_iter().filter(|arg| *arg != "--nocache"))
            .arg(&data)
            .arg(&paths.mount_path)
            .kill_on_drop(true)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        wait_for_socket(&paths.socket_path).await?;
        let old_pid = send_command_detailed(&paths.socket_path, "get quota_used", None)
            .await?
            .peer_pid;
        anyhow::ensure!(!runtime_is_healthy(&data, Some(&root)).await?);
        let mut held = tokio::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(paths.mount_path.join("held-open"))
            .await?;
        held.write_all(b"before").await?;
        held.sync_all().await?;
        anyhow::ensure!(matches!(
            apply_with_root(&data, Some(&root), 1, "embedded", "", 150).await,
            Err(DiskLimitError::FuseRequiresRestart(_))
        ));
        held.write_all(b" after").await?;
        held.sync_all().await?;
        anyhow::ensure!(
            send_command_detailed(&paths.socket_path, "get quota_used", None)
                .await?
                .peer_pid
                == old_pid
        );
        let stats = rustix::fs::statvfs(&paths.mount_path)?;
        anyhow::ensure!(
            stats.f_blocks * stats.f_frsize == mib_to_bytes(64),
            "rejected update changed quota"
        );
        drop(held); // lifecycle must close database files before detaching
        destroy_with_root(&data, Some(&root)).await?;
        legacy.wait().await?;
        let mount = apply_with_root(&data, Some(&root), 64, "embedded", "", 150).await?;
        let peer = send_command_detailed(&paths.socket_path, "get quota_used", None)
            .await?
            .peer_pid;
        let command = tokio::fs::read(format!("/proc/{peer}/cmdline")).await?;
        anyhow::ensure!(has_nocache_arg(&command));
        anyhow::ensure!(runtime_is_healthy(&data, Some(&root)).await?);
        anyhow::ensure!(tokio::fs::read(mount.join("held-open")).await? == b"before after");
        anyhow::ensure!(
            command
                .windows(b"--num-threads\x002\0".len())
                .any(|w| w == b"--num-threads\x002\0")
        );

        // Redis AOF pattern: a newly created O_WRONLY append handle,
        // partial pages, sync, cache eviction, then another append.
        use std::os::fd::AsRawFd;
        let mut aof = tokio::fs::OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(mount.join("appendonly.aof"))
            .await?;
        let mut expected = vec![b'x'; 8192 + 123];
        aof.write_all(&expected).await?;
        aof.sync_all().await?;
        for _ in 0..8 {
            let error =
                unsafe { libc::posix_fadvise(aof.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
            anyhow::ensure!(error == 0, "cache eviction failed: {error}");
            aof.write_all(b"append\n").await?;
            aof.sync_data().await?;
            expected.extend_from_slice(b"append\n");
        }
        anyhow::ensure!(tokio::fs::read(mount.join("appendonly.aof")).await? == expected);

        let writes = (0..8).map(|index| {
            let path = mount.join(format!("data-{index}"));
            async move {
                let block = vec![index as u8; 1024 * 1024];
                let mut file = tokio::fs::File::create(&path).await?;
                for _ in 0..4 {
                    file.write_all(&block).await?;
                }
                file.sync_all().await?;
                drop(file);
                anyhow::ensure!(
                    tokio::fs::read(&path).await? == block.repeat(4),
                    "data changed"
                );
                Ok::<_, anyhow::Error>(())
            }
        });
        for write in futures::future::join_all(writes).await {
            write?;
        }
        let response = send_command_detailed(&paths.socket_path, "get quota_used", None).await?;
        anyhow::ensure!(parse_quota_usage(&response.lines)? >= mib_to_bytes(32));
        let reused = apply_with_root(&data, Some(&root), 48, "embedded", "", 150).await?;
        anyhow::ensure!(reused == mount);
        anyhow::ensure!(
            send_command_detailed(&paths.socket_path, "get quota_used", None)
                .await?
                .peer_pid
                == peer,
            "healthy helper was restarted"
        );
        aof.write_all(b"after quota update\n").await?;
        aof.sync_all().await?;
        expected.extend_from_slice(b"after quota update\n");
        drop(aof);
        anyhow::ensure!(tokio::fs::read(mount.join("appendonly.aof")).await? == expected);
        let mut file = tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .custom_flags(libc::O_SYNC)
            .open(mount.join("overflow"))
            .await?;
        // Tokio may acknowledge its write buffer before the underlying
        // syscall completes. Fill remaining quota (including the helper's
        // already-reserved headroom) and observe completed writes/fsync.
        let overflow = async {
            let block = vec![9; 1024 * 1024];
            for _ in 0..32 {
                file.write_all(&block).await?;
                file.sync_all().await?;
            }
            Ok::<_, std::io::Error>(())
        }
        .await;
        anyhow::ensure!(
            matches!(
                overflow.as_ref().err().map(std::io::Error::kind),
                Some(ErrorKind::StorageFull | ErrorKind::QuotaExceeded)
            ),
            "over-quota write was not rejected: {overflow:?}"
        );
        drop(file);
        anyhow::ensure!(
            tokio::fs::read(mount.join("data-1")).await? == vec![1; 4 * 1024 * 1024],
            "quota exhaustion damaged existing data"
        );
        for index in 0..8 {
            tokio::fs::remove_file(mount.join(format!("data-{index}"))).await?;
        }
        tokio::fs::remove_file(mount.join("overflow")).await?;
        let mut file = tokio::fs::File::create(mount.join("after-delete")).await?;
        file.write_all(b"quota capacity recovered").await?;
        file.sync_all().await?;
        drop(file);
        anyhow::ensure!(
            tokio::fs::read(mount.join("after-delete")).await? == b"quota capacity recovered"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await;
    // Never recursively remove a temporary directory while it is mounted.
    if let Err(error) = destroy_with_root(&data, Some(&root)).await {
        panic!(
            "test mount cleanup failed; preserved {}: {error}",
            temp.keep().display()
        );
    }
    result.unwrap().unwrap();
    assert_eq!(
        tokio::fs::read(data.join("after-delete")).await.unwrap(),
        b"quota capacity recovered"
    );
}

#[test]
fn parses_quota_used_response() {
    let lines = vec!["quota_used = 12345".to_string(), "OK".to_string()];
    assert_eq!(parse_quota_usage(&lines).unwrap(), 12345);
}

#[test]
fn parses_numeric_and_unlimited_open_file_limits() {
    let numeric = "Limit                     Soft Limit           Hard Limit           Units\n\
                       Max open files            1024                 524288               files\n";
    assert_eq!(
        parse_nofile_limits(numeric).unwrap(),
        NofileLimits {
            current: Some(1024),
            maximum: Some(524_288),
        }
    );

    let unlimited = "Max open files            unlimited            unlimited            files\n";
    assert_eq!(
        parse_nofile_limits(unlimited).unwrap(),
        NofileLimits {
            current: None,
            maximum: None,
        }
    );
}

#[test]
fn helper_open_file_target_uses_the_safe_available_ceiling() {
    assert_eq!(desired_nofile_current(Some(524_288)).unwrap(), 524_288);
    assert_eq!(
        desired_nofile_current(Some(2_000_000)).unwrap(),
        TARGET_FUSEQUOTA_NOFILE
    );
    assert_eq!(
        desired_nofile_current(None).unwrap(),
        TARGET_FUSEQUOTA_NOFILE
    );
    assert!(desired_nofile_current(Some(1024)).is_err());
}

#[test]
fn fuse_paths_keep_socket_path_short_for_long_instance_ids() {
    let data_path = Path::new(
        "/var/lib/dbev/volumes/dbe_upgrade_tmp_9689dc77d5ce499c80e4ae5beaec4217_inst_node_db_agent_1_1_mongodb_s1_testt",
    );
    let fuse_root = Path::new("/var/lib/dbev/fuse");

    let paths = fuse_paths_with_root(data_path, Some(fuse_root)).unwrap();

    assert!(paths.socket_path.to_string_lossy().len() < 100);
    assert!(
        paths
            .socket_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("dbe_upgrade_tmp_9689dc77")
    );
}

#[test]
fn fuse_runtime_directories_enforce_private_traversal() {
    for (initial_mode, expected_mode) in [(0o755, 0o700), (0o710, 0o710)] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("fuse");
        for path in [root.clone(), root.join("instances"), root.join("mounts")] {
            fs::create_dir_all(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(initial_mode)).unwrap();
        }

        prepare_fuse_dirs(&root).unwrap();

        for path in [root.clone(), root.join("instances"), root.join("mounts")] {
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                expected_mode,
                "unexpected mode for {} after starting at {initial_mode:o}",
                path.display()
            );
        }
    }
}

#[test]
fn control_socket_must_not_be_group_writable() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("control.sock");
    let _listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o620)).unwrap();

    let error = validate_control_socket(&socket).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("not writable by group or others")
    );
}

#[tokio::test]
async fn control_response_is_size_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("control.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut command = Vec::new();
        stream.read_to_end(&mut command).await.unwrap();
        stream
            .write_all(&vec![b'x'; MAX_CONTROL_RESPONSE_BYTES + 1])
            .await
            .unwrap();
    });

    let error = send_command(&socket, "get quota_used").await.unwrap_err();
    server.await.unwrap();

    assert!(error.to_string().contains("response exceeded"));
}

#[tokio::test]
async fn quota_mutation_rejects_a_replacement_peer_before_sending_data() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("control.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut command = Vec::new();
        stream.read_to_end(&mut command).await.unwrap();
        command
    });
    let error = send_command_detailed(&socket, "set quota = 123", Some(-1))
        .await
        .unwrap_err();
    assert!(matches!(error, DiskLimitError::FuseRequiresRestart(_)));
    assert!(server.await.unwrap().is_empty());
}

#[tokio::test]
async fn teardown_removes_only_confirmed_unmounted_runtime_paths() {
    let temp = tempfile::tempdir().unwrap();
    let fuse_root = temp.path().join("fuse");
    let data_path = temp.path().join("volumes").join("instance-one");
    let paths = fuse_paths_with_root(&data_path, Some(&fuse_root)).unwrap();
    fs::create_dir_all(&paths.mount_path).unwrap();
    fs::create_dir_all(paths.socket_path.parent().unwrap()).unwrap();

    destroy_with_root(&data_path, Some(&fuse_root))
        .await
        .unwrap();

    assert!(!paths.mount_path.exists());
    assert!(!paths.socket_path.exists());
}

#[tokio::test]
async fn teardown_preserves_invalid_control_path() {
    let temp = tempfile::tempdir().unwrap();
    let fuse_root = temp.path().join("fuse");
    let data_path = temp.path().join("volumes").join("instance-one");
    let paths = fuse_paths_with_root(&data_path, Some(&fuse_root)).unwrap();
    fs::create_dir_all(&paths.mount_path).unwrap();
    fs::create_dir_all(paths.socket_path.parent().unwrap()).unwrap();
    fs::write(&paths.socket_path, b"not a socket").unwrap();

    assert!(
        destroy_with_root(&data_path, Some(&fuse_root))
            .await
            .is_err()
    );
    assert!(paths.mount_path.exists());
    assert!(paths.socket_path.exists());
}
