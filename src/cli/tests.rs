use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    process::Command,
};

use super::*;
use crate::{
    instances::metadata::{
        DatabaseIdentity, InstanceMetadata, PublicEndpoint, RuntimeKind, RuntimeMetadata,
        SCHEMA_VERSION,
    },
    jobs::import_export::{ImportExportAction, ImportExportJob, ImportExportStatus},
    shared::{backend::BackendEndpoint, limits::InstanceLimits},
};

#[test]
fn api_connection_admission_is_per_ip_and_releases_capacity() {
    let limiter = Arc::new(ApiConnectionLimiter::new(3, 2));
    let first_ip: IpAddr = "192.0.2.10".parse().unwrap();
    let second_ip: IpAddr = "192.0.2.11".parse().unwrap();

    let first = limiter.try_acquire(first_ip).unwrap();
    let second = limiter.try_acquire(first_ip).unwrap();
    assert!(limiter.try_acquire(first_ip).is_none());
    let other_peer = limiter.try_acquire(second_ip).unwrap();

    drop(first);
    assert!(limiter.try_acquire(first_ip).is_some());
    drop(second);
    drop(other_peer);
}

#[test]
fn api_connection_admission_normalizes_ipv4_mapped_addresses() {
    let limiter = Arc::new(ApiConnectionLimiter::new(2, 1));
    let ipv4: IpAddr = "192.0.2.10".parse().unwrap();
    let mapped: IpAddr = "::ffff:192.0.2.10".parse().unwrap();

    let _permit = limiter.try_acquire(ipv4).unwrap();

    assert!(limiter.try_acquire(mapped).is_none());
}

#[test]
fn api_connection_admission_groups_ipv6_peers_by_64_bit_prefix() {
    let limiter = Arc::new(ApiConnectionLimiter::new(3, 1));
    let first: IpAddr = "2001:db8:1234:5678::1".parse().unwrap();
    let same_prefix: IpAddr = "2001:db8:1234:5678:ffff::2".parse().unwrap();
    let other_prefix: IpAddr = "2001:db8:1234:5679::1".parse().unwrap();

    let _first = limiter.try_acquire(first).unwrap();

    assert!(limiter.try_acquire(same_prefix).is_none());
    assert!(limiter.try_acquire(other_prefix).is_some());
}

#[test]
fn api_connection_admission_enforces_and_releases_global_capacity() {
    let limiter = Arc::new(ApiConnectionLimiter::new(2, 2));
    let first = limiter.try_acquire("192.0.2.10".parse().unwrap()).unwrap();
    let _second = limiter.try_acquire("192.0.2.11".parse().unwrap()).unwrap();

    assert!(limiter.try_acquire("192.0.2.12".parse().unwrap()).is_none());
    drop(first);
    assert!(limiter.try_acquire("192.0.2.12".parse().unwrap()).is_some());
}

#[test]
fn cli_parses_offline_protected_secret_repair() {
    let cli = Cli::try_parse_from([
        "dbev",
        "repair-protected-secret",
        "--instance-id",
        "inst_recovery",
        "--field",
        "tenant-password",
        "--confirm-legacy-plaintext",
    ])
    .unwrap();

    assert!(matches!(
        cli.command,
        Some(super::Command::RepairProtectedSecret {
            instance_id,
            field: ProtectedSecretField::TenantPassword,
            confirm_legacy_plaintext: true,
        }) if instance_id == "inst_recovery"
    ));
}

#[tokio::test]
async fn retained_manifest_quarantines_target_even_when_job_is_already_terminal() {
    let temp = tempfile::tempdir().unwrap();
    let metadata_root = temp.path().join("metadata");
    let pool = sqlite::connect(&metadata_root).await.unwrap();
    let repository = InstanceRepository::new(pool.clone());
    let manager = InstanceManager::new(InstanceStore::default(), repository.clone());
    manager.upsert(recovery_test_metadata()).await.unwrap();

    let jobs = ImportExportJobRepository::new(pool);
    jobs.insert(&ImportExportJob {
        job_id: "job-terminal".to_string(),
        instance_id: "inst_recovery".to_string(),
        action: ImportExportAction::Import,
        status: ImportExportStatus::Failed,
        artifact_path: None,
        replay_options: None,
        error: Some("rollback failed".to_string()),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:01Z".to_string(),
    })
    .await
    .unwrap();
    assert!(jobs.running_import_instance_ids().await.unwrap().is_empty());

    let tmp_root = temp.path().join("tmp");
    let recovery_root = tmp_root.join("import-export");
    tokio::fs::create_dir_all(&recovery_root).await.unwrap();
    tokio::fs::write(
        recovery_root.join(".dbe-import-recovery-00000000-0000-4000-8000-000000000001.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "recovery_kind": "logical_remote_import",
            "instance_id": "inst_recovery",
            "protocol": "postgres",
            "import_mode": "wipe",
            "rollback_file": "rollback.postgres.sql",
            "created_at": "2026-01-01T00:00:00Z"
        }))
        .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(
        quarantine_retained_import_recovery_manifests(&manager, &tmp_root)
            .await
            .unwrap(),
        1
    );

    let reloaded = InstanceManager::new(InstanceStore::default(), repository);
    reloaded.load_from_storage().await.unwrap();
    assert_eq!(
        reloaded.store().get("inst_recovery").await.unwrap().status,
        InstanceStatus::Quarantined
    );
}

#[tokio::test]
async fn retained_physical_restore_workspace_quarantines_target() {
    let temp = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(&temp.path().join("metadata"))
        .await
        .unwrap();
    let repository = InstanceRepository::new(pool);
    let manager = InstanceManager::new(InstanceStore::default(), repository.clone());
    manager.upsert(recovery_test_metadata()).await.unwrap();

    let volumes = temp.path().join("volumes");
    tokio::fs::create_dir_all(
        volumes
            .join(".dbe-restore-inst_recovery-00000000-0000-4000-8000-000000000001/previous-data"),
    )
    .await
    .unwrap();

    assert_eq!(
        quarantine_retained_physical_restore_workspaces(&manager, &volumes)
            .await
            .unwrap(),
        1
    );
    let reloaded = InstanceManager::new(InstanceStore::default(), repository);
    reloaded.load_from_storage().await.unwrap();
    let metadata = reloaded.store().get("inst_recovery").await.unwrap();
    assert_eq!(metadata.status, InstanceStatus::Quarantined);
    assert_eq!(
        metadata.desired_state,
        crate::instances::metadata::DesiredInstanceState::Stopped
    );
}

#[tokio::test]
async fn physical_restore_recovery_scan_does_not_follow_workspace_symlinks() {
    let temp = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(&temp.path().join("metadata"))
        .await
        .unwrap();
    let repository = InstanceRepository::new(pool);
    let manager = InstanceManager::new(InstanceStore::default(), repository);
    manager.upsert(recovery_test_metadata()).await.unwrap();

    let volumes = temp.path().join("volumes");
    let elsewhere = temp.path().join("elsewhere");
    fs::create_dir_all(&volumes).unwrap();
    fs::create_dir_all(&elsewhere).unwrap();
    symlink(
        &elsewhere,
        volumes.join(".dbe-restore-inst_recovery-00000000-0000-4000-8000-000000000001"),
    )
    .unwrap();

    assert_eq!(
        quarantine_retained_physical_restore_workspaces(&manager, &volumes)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        manager.store().get("inst_recovery").await.unwrap().status,
        InstanceStatus::Running
    );
}

fn recovery_test_metadata() -> InstanceMetadata {
    InstanceMetadata {
        schema_version: SCHEMA_VERSION,
        instance_id: "inst_recovery".to_string(),
        protocol: Protocol::Postgres,
        status: InstanceStatus::Running,
        desired_state: crate::instances::metadata::DesiredInstanceState::Running,
        disk_limit_blocked: false,
        public: PublicEndpoint {
            host: "db.example.com".to_string(),
            port: 5433,
        },
        backend: BackendEndpoint::UnixSocket {
            socket_path: "/run/dbev/sockets/inst_recovery/.s.PGSQL.5432".to_string(),
        },
        runtime: RuntimeMetadata {
            kind: RuntimeKind::Docker,
            container_name: "dbe-postgres-inst-recovery".to_string(),
            network_mode: "none".to_string(),
        },
        database: DatabaseIdentity {
            name: "app_db".to_string(),
            username: "app".to_string(),
        },
        route_key_sha256: None,
        mariadb_native_password_sha1_stage2: None,
        mariadb_root_password: None,
        mysql_native_password_sha1_stage2: None,
        mysql_root_password: None,
        mongodb_root_password: None,
        postgres_admin_password: None,
        tenant_password: None,
        limits: InstanceLimits::default(),
        image: None,
        database_version: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    }
}

#[tokio::test]
async fn desired_stopped_instances_are_never_published_to_gateways() {
    let store = InstanceStore::default();
    let mut metadata = recovery_test_metadata();
    metadata.desired_state = crate::instances::metadata::DesiredInstanceState::Stopped;
    store.upsert(metadata.clone()).await;
    assert!(store.resolve_postgres("app", "app_db").await.is_none());

    metadata.desired_state = crate::instances::metadata::DesiredInstanceState::Running;
    store.upsert(metadata).await;
    assert!(store.resolve_postgres("app", "app_db").await.is_some());
}

#[test]
fn recovery_scan_accepts_only_canonical_generated_names() {
    assert!(is_generated_logical_recovery_manifest_name(
        std::ffi::OsStr::new(".dbe-import-recovery-00000000-0000-4000-8000-000000000001.json")
    ));
    assert!(!is_generated_logical_recovery_manifest_name(
        std::ffi::OsStr::new(".dbe-import-recovery-manual.json")
    ));
    assert!(is_canonical_uuid_file_name(std::ffi::OsStr::new(
        "00000000-0000-4000-8000-000000000001"
    )));
    assert!(!is_canonical_uuid_file_name(std::ffi::OsStr::new(
        "00000000000040008000000000000001"
    )));
    assert_eq!(
        physical_restore_workspace_instance_id(std::ffi::OsStr::new(
            ".dbe-restore-inst_recovery-00000000-0000-4000-8000-000000000001"
        ))
        .as_deref(),
        Some("inst_recovery")
    );
    assert!(
        physical_restore_workspace_instance_id(std::ffi::OsStr::new(
            ".dbe-restore-inst_recovery-not-a-uuid"
        ))
        .is_none()
    );
}

#[test]
fn retained_valkey_recovery_manifests_are_protocol_bound() {
    assert!(recovery_kind_matches_protocol(
        "valkey_remote_import",
        Protocol::Valkey
    ));
    assert!(!recovery_kind_matches_protocol(
        "valkey_remote_import",
        Protocol::Redis
    ));
    assert!(!recovery_kind_matches_protocol(
        "redis_remote_import",
        Protocol::Valkey
    ));
}

#[test]
fn daemon_boot_preserves_running_containers() {
    use crate::instances::metadata::DesiredInstanceState;

    assert_eq!(
        managed_boot_action(InstanceStatus::Running, DesiredInstanceState::Running),
        None
    );
    assert_eq!(
        managed_boot_action(InstanceStatus::Failed, DesiredInstanceState::Running),
        Some(ManagedBootAction::Restart)
    );
    assert_eq!(
        managed_boot_action(InstanceStatus::Stopped, DesiredInstanceState::Running),
        Some(ManagedBootAction::Start)
    );
    assert_eq!(
        managed_boot_action(InstanceStatus::Stopped, DesiredInstanceState::Stopped),
        None
    );
    assert_eq!(
        managed_boot_action(InstanceStatus::Failed, DesiredInstanceState::Stopped),
        None
    );
    assert_eq!(
        managed_boot_action(InstanceStatus::Booting, DesiredInstanceState::Running),
        None
    );
    assert_eq!(
        managed_boot_action(
            reconcile::classify_container_status(DockerContainerStatus::Created),
            DesiredInstanceState::Running,
        ),
        Some(ManagedBootAction::Start),
        "a crash after create-before-start must be recovered on the next boot"
    );
}

#[test]
fn startup_resolves_qdrant_away_from_the_fuse_fallback() {
    let limiter = DiskLimiter::new(crate::config::DiskConfig::default());

    assert_eq!(
        limiter.mode_for_protocol(Protocol::Qdrant),
        crate::config::DiskLimitMode::SoftScanner
    );
    assert_eq!(
        limiter.mode_for_protocol(Protocol::Postgres),
        crate::config::DiskLimitMode::FuseQuota
    );
}

#[test]
fn stale_qdrant_fuse_mount_does_not_trigger_container_recreation() {
    let legacy = Path::new("/var/lib/dbev/fuse/instances/qdrant");

    assert!(legacy_qdrant_container_uses_fuse(Some(legacy), legacy));
    assert!(!legacy_qdrant_container_uses_fuse(
        Some(Path::new("/var/lib/dbev/volumes/qdrant")),
        legacy,
    ));
    assert!(!legacy_qdrant_container_uses_fuse(None, legacy));
}

#[test]
fn qdrant_fuse_migration_follows_durable_power_intent() {
    use crate::instances::metadata::DesiredInstanceState;

    assert_eq!(
        qdrant_migration_runtime_actions(
            DockerContainerStatus::Stopped,
            DesiredInstanceState::Running,
        ),
        (false, true),
        "a desired-running instance must start its replacement even when the old container was stopped"
    );
    assert_eq!(
        qdrant_migration_runtime_actions(
            DockerContainerStatus::Running,
            DesiredInstanceState::Stopped,
        ),
        (true, false),
        "a desired-stopped instance must stop an unexpectedly live old container without starting its replacement"
    );
}

#[test]
fn qdrant_fuse_migration_defers_native_quota_adoption_before_runtime_mutation() {
    assert!(!qdrant_fuse_migration_target_is_safe(
        crate::config::DiskLimitMode::ProjectQuota
    ));
    assert!(qdrant_fuse_migration_target_is_safe(
        crate::config::DiskLimitMode::SoftScanner
    ));
}

#[test]
fn retained_qdrant_fuse_uses_truthful_mode_even_when_soft_is_selected() {
    let disk = crate::config::DiskConfig {
        mode: crate::config::DiskLimitMode::SoftScanner,
        ..crate::config::DiskConfig::default()
    };
    let limiter = DiskLimiter::new(disk);

    assert_eq!(
        limiter.legacy_fuse_limiter().mode(),
        crate::config::DiskLimitMode::FuseQuota
    );
    assert_eq!(limiter.legacy_fuse_limiter().mode().method(), "fuse_quota");
    assert!(limiter.legacy_fuse_limiter().mode().enforced());
}

#[test]
fn disk_mode_transition_failure_is_durably_stopped() {
    let mut metadata = recovery_test_metadata();
    metadata.desired_state = crate::instances::metadata::DesiredInstanceState::Running;

    isolate_disk_reconciliation_failure(&mut metadata, false);

    assert_eq!(
        metadata.desired_state,
        crate::instances::metadata::DesiredInstanceState::Stopped
    );
    assert_eq!(metadata.status, InstanceStatus::Failed);
}

#[test]
fn disk_reconciliation_never_downgrades_an_existing_quarantine() {
    let mut metadata = recovery_test_metadata();
    metadata.status = InstanceStatus::Quarantined;

    isolate_disk_reconciliation_failure(&mut metadata, false);

    assert_eq!(metadata.status, InstanceStatus::Quarantined);
    assert_eq!(
        metadata.desired_state,
        crate::instances::metadata::DesiredInstanceState::Stopped
    );
}

#[test]
fn qdrant_fuse_migration_preserves_container_project_grouping() {
    let config = Config::default();
    let mut metadata = recovery_test_metadata();
    metadata.protocol = Protocol::Qdrant;
    let paths = InstancePaths::new(&config.paths, &metadata.instance_id).unwrap();

    let spec = qdrant_migration_spec(
        &config,
        &metadata,
        &paths,
        QdrantMigrationContainer {
            data_path: paths.data.clone(),
            image: "sha256:0123456789abcdef",
            api_key: "tenant-key",
            container_user: "1000:1000",
            project_id: Some("panel-project".to_string()),
        },
    );

    assert_eq!(spec.project_id.as_deref(), Some("panel-project"));
}

#[test]
fn queued_soft_disk_decision_is_stale_after_a_limit_increase() {
    let mut metadata = recovery_test_metadata();
    metadata.protocol = Protocol::Qdrant;
    metadata.limits.disk_mib = 100;
    metadata.limits.disk_enforcement_method = "soft_scanner".to_string();
    let target = crate::disk::soft::SoftDiskTarget {
        instance_id: metadata.instance_id.clone(),
        created_at: metadata.created_at.clone(),
        protocol: metadata.protocol,
        data_path: PathBuf::from("/var/lib/dbev/volumes/inst_recovery"),
        limit_bytes: 100 * 1024 * 1024,
        durable_blocked: false,
    };
    assert!(soft_disk_target_is_current(
        &metadata,
        &target,
        crate::config::DiskLimitMode::SoftScanner,
    ));

    metadata.limits.disk_mib = 200;
    assert!(!soft_disk_target_is_current(
        &metadata,
        &target,
        crate::config::DiskLimitMode::SoftScanner,
    ));
}

#[test]
fn hardens_existing_runtime_directory_permissions() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = temp.path().join("runtime");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o777)).unwrap();

    harden_runtime_directory(&runtime).unwrap();

    let mode = fs::metadata(runtime).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn rejects_symlinked_runtime_directory() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    let runtime = temp.path().join("runtime");
    fs::create_dir(&target).unwrap();
    symlink(&target, &runtime).unwrap();

    let error = harden_runtime_directory(&runtime).unwrap_err();

    assert!(error.to_string().contains("not a symlink"));
}

#[test]
fn rejects_symlinked_runtime_path_ancestor() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    let linked_parent = temp.path().join("linked-parent");
    fs::create_dir(&target).unwrap();
    symlink(&target, &linked_parent).unwrap();

    let error = validate_runtime_path_ancestors(&linked_parent.join("runtime"), false).unwrap_err();

    assert!(error.to_string().contains("must be a real directory"));
}

#[test]
fn securely_creates_nested_runtime_directories() {
    let temp = tempfile::tempdir().unwrap();
    let runtime = temp.path().join("nested").join("runtime");

    create_runtime_directory_tree(&runtime).unwrap();

    assert!(runtime.is_dir());
    assert_eq!(
        fs::metadata(&runtime).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn secure_runtime_creation_rejects_symlinked_component() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    let linked_parent = temp.path().join("linked-parent");
    fs::create_dir(&target).unwrap();
    symlink(&target, &linked_parent).unwrap();

    let error = create_runtime_directory_tree(&linked_parent.join("runtime")).unwrap_err();

    assert!(error.to_string().contains("not a symlink"));
    assert!(!target.join("runtime").exists());
}

#[test]
fn rejects_runtime_path_ancestor_writable_by_other_users() {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("unsafe-parent");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();

    let error = validate_runtime_path_ancestors(&parent.join("runtime"), false).unwrap_err();

    assert!(error.to_string().contains("writable by group or others"));
}

#[test]
fn rejects_runtime_directory_owned_by_another_uid() {
    let error = require_runtime_directory_owner(Path::new("/runtime"), 1001, 1000).unwrap_err();

    assert!(error.to_string().contains("owned by uid 1001"));
}

#[test]
fn setup_moves_legacy_logs_below_the_private_data_root_when_its_parent_is_unsafe() {
    let temp = tempfile::tempdir().unwrap();
    let unsafe_parent = temp.path().join("group-writable-logs");
    fs::create_dir(&unsafe_parent).unwrap();
    fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o775)).unwrap();
    let legacy_logs = unsafe_parent.join("dbev");
    let data = temp.path().join("private").join("dbev");
    let mut config = Config {
        uuid: "node-uuid".to_string(),
        token_id: "token-id".to_string(),
        token: "test-api-token-0123456789abcdef-01".to_string(),
        jwt_signing_key: "test-jwt-signing-key-0123456789abcdef-02".to_string(),
        remote: "https://panel.example.com".to_string(),
        ..Default::default()
    };
    config.images.mongodb = "mongo:7.0.37".to_string();
    config.paths.data = data.display().to_string();
    config.paths.logs = legacy_logs.display().to_string();

    let (migrated, replacement, error) = build_legacy_logs_migration(&config, &legacy_logs)
        .unwrap()
        .unwrap();

    assert_eq!(replacement, data.join("logs").display().to_string());
    assert_eq!(migrated.paths.logs, replacement);
    assert!(error.contains("writable by group or others"));
}

#[test]
fn default_logs_live_below_the_private_data_root() {
    let paths = crate::config::PathConfig::default();

    assert_eq!(paths.logs, format!("{}/logs", paths.data));
}

#[test]
fn setup_config_path_rejects_unit_file_metacharacters() {
    assert!(validate_setup_config_path(Path::new("/etc/dbev/config.yml")).is_ok());
    assert!(validate_setup_config_path(Path::new("relative.yml")).is_err());
    assert!(validate_setup_config_path(Path::new("/etc/dbev/../config.yml")).is_err());
    assert!(validate_setup_config_path(Path::new("/etc/dbev/config\nExecStart=evil")).is_err());
}

#[test]
fn managed_memory_sysctl_enables_overcommit_persistently() {
    assert_eq!(
        memory_overcommit_sysctl_contents(),
        "# Managed by DatabasesEverywhere --setup.\nvm.overcommit_memory = 1\n"
    );
}

#[test]
fn generated_systemd_service_runs_as_root_without_service_account_sandboxing() {
    let daemon = crate::config::DaemonConfig::default();
    let unit = systemd_service_contents(Path::new(defaults::CONFIG_PATH), &daemon);

    assert!(unit.contains("User=root\n"));
    assert!(unit.contains("ExecStart=/usr/local/bin/dbev daemon\n"));
    assert!(unit.contains("KillMode=process\n"));
    assert!(unit.contains("LimitNOFILE=1048576:1048576\n"));
    assert!(unit.contains("PartOf=docker.service\n"));
    assert!(!unit.contains("SupplementaryGroups="));
    assert!(!unit.contains("ProtectSystem="));
    assert!(!unit.contains("DBE_USE_SUDO"));
}

#[test]
fn generated_systemd_service_uses_selected_engine_and_custom_config() {
    let daemon = crate::config::DaemonConfig {
        engine: DaemonEngine::Podman,
        ..crate::config::DaemonConfig::default()
    };
    let unit = systemd_service_contents(Path::new("/srv/dbev/config.yml"), &daemon);

    assert!(unit.contains("After=podman.socket\n"));
    assert!(unit.contains("Requires=podman.socket\n"));
    assert!(unit.contains("PartOf=podman.socket\n"));
    assert!(unit.contains("ExecStart=/usr/local/bin/dbev --config /srv/dbev/config.yml daemon\n"));
}

#[test]
fn generated_systemd_service_tracks_the_rootless_podman_user_manager() {
    let daemon = crate::config::DaemonConfig {
        engine: DaemonEngine::Podman,
        socket_path: "/run/user/1001/podman/podman.sock".to_string(),
        ..crate::config::DaemonConfig::default()
    };

    let unit = systemd_service_contents(Path::new(defaults::CONFIG_PATH), &daemon);

    assert!(unit.contains("After=user@1001.service\n"));
    assert!(unit.contains("Requires=user@1001.service\n"));
    assert!(unit.contains("RequiresMountsFor=/run/user/1001\n"));
    assert!(!unit.contains("Requires=podman.socket"));
}

#[test]
fn generated_systemd_service_leaves_custom_podman_socket_lifecycle_external() {
    let daemon = crate::config::DaemonConfig {
        engine: DaemonEngine::Podman,
        socket_path: "/srv/podman/api.sock".to_string(),
        ..crate::config::DaemonConfig::default()
    };

    let unit = systemd_service_contents(Path::new(defaults::CONFIG_PATH), &daemon);

    assert!(unit.contains("After=network.target\n"));
    assert!(!unit.contains("Requires=podman.socket"));
}

#[test]
fn rootless_podman_custom_paths_require_traversable_ancestors() {
    use std::os::unix::fs::MetadataExt;

    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let managed = temp.path().join("managed");
    fs::create_dir(&managed).unwrap();
    let metadata = fs::metadata(temp.path()).unwrap();

    validate_rootless_podman_ancestor_traversal(&managed, metadata.uid(), metadata.gid()).unwrap();
    let error = validate_rootless_podman_ancestor_traversal(
        &managed,
        metadata.uid().saturating_add(1),
        metadata.gid().saturating_add(1),
    )
    .unwrap_err();
    assert!(error.to_string().contains("cannot traverse"));
}

#[test]
fn daemon_lock_is_private_and_exclusive() {
    let temp = tempfile::tempdir().unwrap();
    let locks = temp.path().join("locks");
    fs::create_dir(&locks).unwrap();
    harden_runtime_directory(&locks).unwrap();

    let first = acquire_daemon_lock(&locks).unwrap();
    let lock_path = locks.join(DAEMON_LOCK_FILE);
    let mode = fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    let error = acquire_daemon_lock(&locks).err().unwrap();
    assert!(error.to_string().contains("another dbev daemon"));
    drop(first);

    acquire_daemon_lock(&locks).unwrap();
}

#[test]
fn process_umask_limits_new_files_to_owner_access() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "cli::tests::restrictive_umask_child",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "umask child failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "runs in an isolated child process from process_umask_limits_new_files_to_owner_access"]
fn restrictive_umask_child() {
    harden_process_file_creation();
    let temp = tempfile::tempdir().unwrap();
    let file_path = temp.path().join("created");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o666)
        .open(&file_path)
        .unwrap();

    let mode = fs::metadata(file_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}
