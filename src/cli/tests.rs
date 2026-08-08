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
    let limiter = Arc::new(ApiConnectionLimiter::new(2));
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
    let limiter = Arc::new(ApiConnectionLimiter::new(1));
    let ipv4: IpAddr = "192.0.2.10".parse().unwrap();
    let mapped: IpAddr = "::ffff:192.0.2.10".parse().unwrap();

    let _permit = limiter.try_acquire(ipv4).unwrap();

    assert!(limiter.try_acquire(mapped).is_none());
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

fn recovery_test_metadata() -> InstanceMetadata {
    InstanceMetadata {
        schema_version: SCHEMA_VERSION,
        instance_id: "inst_recovery".to_string(),
        protocol: Protocol::Postgres,
        status: InstanceStatus::Running,
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
        limits: InstanceLimits::default(),
        image: None,
        database_version: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    }
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
    assert_eq!(managed_boot_action(InstanceStatus::Running), None);
    assert_eq!(
        managed_boot_action(InstanceStatus::Failed),
        Some(ManagedBootAction::Restart)
    );
    assert_eq!(
        managed_boot_action(InstanceStatus::Stopped),
        Some(ManagedBootAction::Start)
    );
    assert_eq!(managed_boot_action(InstanceStatus::Booting), None);
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
fn setup_config_path_rejects_unit_file_metacharacters() {
    assert!(validate_setup_config_path(Path::new("/etc/dbev/config.yml")).is_ok());
    assert!(validate_setup_config_path(Path::new("relative.yml")).is_err());
    assert!(validate_setup_config_path(Path::new("/etc/dbev/../config.yml")).is_err());
    assert!(validate_setup_config_path(Path::new("/etc/dbev/config\nExecStart=evil")).is_err());
}

#[test]
fn generated_systemd_service_runs_as_root_without_service_account_sandboxing() {
    let daemon = crate::config::DaemonConfig::default();
    let unit = systemd_service_contents(Path::new(defaults::CONFIG_PATH), &daemon);

    assert!(unit.contains("User=root\n"));
    assert!(unit.contains("ExecStart=/usr/local/bin/dbev daemon\n"));
    assert!(unit.contains("KillMode=process\n"));
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
