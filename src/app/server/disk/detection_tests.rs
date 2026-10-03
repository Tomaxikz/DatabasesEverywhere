use super::*;
use crate::config::DiskLimitSelection;

#[test]
fn auto_selects_the_available_quota_backend() {
    for (fstype, options, expected) in [
        ("ext4", vec!["rw"], DiskLimitMode::FuseQuota),
        ("btrfs", vec!["rw"], DiskLimitMode::ProjectQuota),
        ("zfs", vec!["rw"], DiskLimitMode::ProjectQuota),
    ] {
        assert_eq!(
            select_disk_mode(
                fstype,
                &options.into_iter().map(String::from).collect::<Vec<_>>(),
                DiskLimitSelection::Auto
            )
            .0,
            expected
        );
    }
    for fstype in ["xfs", "ext4", "f2fs"] {
        for option in ["prjquota", "pquota"] {
            let options = ["rw".to_string(), option.to_string()];
            assert_eq!(
                select_disk_mode(fstype, &options, DiskLimitSelection::Auto).0,
                DiskLimitMode::ProjectQuota
            );
        }
    }
}

#[test]
fn shared_native_quota_detection_requires_supported_filesystem_and_mount_option() {
    for (fs, options, expected) in [
        (
            "xfs",
            vec!["rw", "prjquota"],
            Some(NativeProjectQuotaFs::Xfs),
        ),
        ("ext4", vec!["pquota"], Some(NativeProjectQuotaFs::Ext4)),
        ("xfs", vec!["rw"], None),
        ("btrfs", vec!["prjquota"], None),
    ] {
        let options = options.into_iter().map(String::from).collect::<Vec<_>>();
        assert_eq!(native_project_quota_fs(fs, &options), expected);
    }
}

#[tokio::test]
async fn non_project_modes_fall_back_before_touching_the_tenant_path() {
    let limiter = DiskLimiter::new(DiskConfig::default());
    let enforcement = limiter
        .apply_path_quota(
            "tenant",
            Path::new("/definitely/missing/tenant"),
            Path::new("/definitely/missing/registry"),
            1024,
        )
        .await
        .unwrap();

    assert!(!enforcement.enforced);
    assert_eq!(enforcement.method, DiskLimitMode::SoftScanner.method());
}

#[tokio::test]
async fn path_usage_accepts_only_the_exact_active_owner_claim() {
    let temporary = tempfile::tempdir().unwrap();
    let registry_root = temporary.path();
    let data_path = registry_root.join("tenant-data");
    std::fs::create_dir(&data_path).unwrap();
    let config = DiskConfig {
        mode: DiskLimitMode::ProjectQuota,
        ..DiskConfig::default()
    };
    let project_id_base = config.project_id_base;
    let limiter = DiskLimiter::new(config);

    let project_id = project_id::allocate_in("tenant-a", registry_root, project_id_base)
        .await
        .unwrap();
    let pending = limiter
        .path_quota_usage_bytes("tenant-a", &data_path, registry_root)
        .await
        .unwrap_err();
    assert!(matches!(
        pending,
        DiskLimitError::ProjectIdNotFound { owner_id, .. } if owner_id == "tenant-a"
    ));

    project_id::activate_in("tenant-a", registry_root, project_id)
        .await
        .unwrap();
    let wrong_owner = limiter
        .path_quota_usage_bytes("tenant-b", &data_path, registry_root)
        .await
        .unwrap_err();
    assert!(matches!(
        wrong_owner,
        DiskLimitError::ProjectIdNotFound { owner_id, .. } if owner_id == "tenant-b"
    ));

    project_id::release_in("tenant-a", registry_root, project_id_base)
        .await
        .unwrap();
    let released = limiter
        .path_quota_usage_bytes("tenant-a", &data_path, registry_root)
        .await
        .unwrap_err();
    assert!(matches!(
        released,
        DiskLimitError::ProjectIdNotFound { owner_id, .. } if owner_id == "tenant-a"
    ));
}

#[test]
fn explicit_soft_scanner_overrides_a_native_quota_filesystem() {
    assert_eq!(
        select_disk_mode(
            "xfs",
            &["rw".to_string(), "prjquota".to_string()],
            DiskLimitSelection::SoftScanner,
        )
        .0,
        DiskLimitMode::SoftScanner
    );
}

#[test]
fn qdrant_never_resolves_to_fuse_quota() {
    let limiter = DiskLimiter::new(DiskConfig::default());
    assert_eq!(
        limiter.mode_for_protocol(Protocol::Qdrant),
        DiskLimitMode::SoftScanner
    );
    assert_eq!(
        limiter.mode_for_protocol(Protocol::Postgres),
        DiskLimitMode::FuseQuota
    );
}

#[test]
fn native_project_quota_cannot_be_silently_relabelled_soft() {
    let config = DiskConfig {
        mode: DiskLimitMode::SoftScanner,
        ..DiskConfig::default()
    };
    let limiter = DiskLimiter::new(config);

    for method in [
        "host_filesystem_quota",
        "host_xfs_project_quota",
        "host_linux_project_quota",
        "host_btrfs_qgroup",
        "host_zfs_refquota",
    ] {
        assert!(
            limiter.check_method_change(method).is_err(),
            "{method} must remain a native project-quota mode"
        );
        assert_eq!(
            limiter.for_persisted_method(method).mode(),
            DiskLimitMode::ProjectQuota
        );
    }
    assert!(limiter.check_method_change("soft_scanner").is_ok());
}

#[test]
fn physical_replacement_accepts_recursive_project_quota_backends() {
    let data = Path::new("/srv/dbev/volumes/inst_1");

    for fstype in ["xfs", "ext4", "f2fs"] {
        assert!(check_project_quota_restore(data, fstype).is_ok());
    }
    for fstype in ["btrfs", "zfs"] {
        let error = check_project_quota_restore(data, fstype).unwrap_err();
        assert!(matches!(
            error,
            DiskLimitError::UnsupportedPhysicalDataReplacement {
                path,
                fstype: rejected,
            } if path == data && rejected == fstype
        ));
    }
}

#[test]
fn every_native_quota_backend_requires_a_transactional_major_upgrade_cutover() {
    let data = Path::new("/var/lib/dbev/volumes/instance-one");
    let limiter = DiskLimiter::new(DiskConfig {
        mode: DiskLimitMode::ProjectQuota,
        ..DiskConfig::default()
    });

    let error = limiter.check_upgrade_cutover(data).unwrap_err();
    assert!(error.to_string().contains("transactional native-quota"));
}

#[tokio::test]
async fn project_quota_runtime_teardown_preserves_staged_data() {
    let temporary = tempfile::tempdir().unwrap();
    let marker = temporary.path().join("imported-data");
    std::fs::write(&marker, b"preserve me").unwrap();
    let limiter = DiskLimiter::new(DiskConfig {
        mode: DiskLimitMode::ProjectQuota,
        ..DiskConfig::default()
    });

    limiter
        .teardown_instance_mount(temporary.path())
        .await
        .unwrap();

    assert_eq!(std::fs::read(marker).unwrap(), b"preserve me");
}

#[tokio::test]
async fn instance_release_fails_closed_with_an_unremovable_pending_claim() {
    let temporary = tempfile::tempdir_in("/dev/shm").unwrap();
    let data_path = temporary.path().join("instance-data");
    std::fs::create_dir(&data_path).unwrap();
    let config = DiskConfig {
        mode: DiskLimitMode::ProjectQuota,
        ..DiskConfig::default()
    };
    let project_id_base = config.project_id_base;
    let limiter = DiskLimiter::new(config);
    project_id::allocate_in("instance-one", temporary.path(), project_id_base)
        .await
        .unwrap();

    let error = limiter
        .release_instance_storage("instance-one", &data_path)
        .await
        .expect_err("a live project claim must not be skipped");

    assert!(matches!(
        error,
        DiskLimitError::NativeProjectQuotaUnavailable { path } if path == data_path
    ));
    let claim = project_id::find_claim_in("instance-one", temporary.path(), project_id_base)
        .await
        .unwrap()
        .expect("failed cleanup must retain the claim");
    assert_eq!(claim.state, project_id::ProjectIdState::Pending);
}

#[tokio::test]
async fn missing_instance_path_still_checks_its_project_claim() {
    let temporary = tempfile::tempdir_in("/dev/shm").unwrap();
    let data_path = temporary.path().join("missing-instance-data");
    let config = DiskConfig {
        mode: DiskLimitMode::ProjectQuota,
        ..DiskConfig::default()
    };
    let project_id_base = config.project_id_base;
    let limiter = DiskLimiter::new(config);
    project_id::allocate_in("instance-two", temporary.path(), project_id_base)
        .await
        .unwrap();

    let error = limiter
        .release_instance_storage("instance-two", &data_path)
        .await
        .expect_err(
            "a missing data path must not turn a pending quota claim into a successful purge",
        );
    assert!(matches!(
        error,
        DiskLimitError::NativeProjectQuotaUnavailable { path } if path == data_path
    ));
    let claim = project_id::find_claim_in("instance-two", temporary.path(), project_id_base)
        .await
        .unwrap()
        .expect("failed cleanup must retain the pending claim");
    assert_eq!(claim.state, project_id::ProjectIdState::Pending);
}
