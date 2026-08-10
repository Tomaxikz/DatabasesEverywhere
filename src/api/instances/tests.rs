use super::*;

fn sample_lifecycle_metadata() -> InstanceMetadata {
    InstanceMetadata {
        schema_version: crate::instances::metadata::SCHEMA_VERSION,
        instance_id: "inst_lifecycle".to_string(),
        protocol: Protocol::Postgres,
        status: InstanceStatus::Running,
        desired_state: DesiredInstanceState::Running,
        disk_limit_blocked: false,
        public: crate::instances::metadata::PublicEndpoint {
            host: "127.0.0.1".to_string(),
            port: 5432,
        },
        backend: crate::shared::backend::BackendEndpoint::UnixSocket {
            socket_path: "/run/dbev/inst_lifecycle/.s.PGSQL.5432".to_string(),
        },
        runtime: crate::instances::metadata::RuntimeMetadata {
            kind: crate::instances::metadata::RuntimeKind::Docker,
            container_name: "dbe-postgres-inst_lifecycle".to_string(),
            network_mode: "none".to_string(),
        },
        database: crate::instances::metadata::DatabaseIdentity {
            name: "app".to_string(),
            username: "tenant".to_string(),
        },
        route_key_sha256: None,
        mariadb_native_password_sha1_stage2: None,
        mariadb_root_password: None,
        mysql_native_password_sha1_stage2: None,
        mysql_root_password: None,
        mongodb_root_password: None,
        postgres_admin_password: None,
        tenant_password: Some("old-password".to_string()),
        limits: crate::shared::limits::InstanceLimits::default(),
        image: None,
        database_version: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    }
}

#[test]
fn major_upgrade_commit_resolution_accepts_only_the_exact_intended_row() {
    let previous = sample_lifecycle_metadata();
    let mut intended = previous.clone();
    intended.updated_at = "2026-01-02T00:00:00Z".to_string();
    intended.tenant_password = Some("replacement-password".to_string());

    assert_eq!(
        classify_major_upgrade_commit(&intended, &previous, &intended),
        MajorUpgradeCommitResolution::Committed
    );

    let mut mismatched_secret = intended.clone();
    mismatched_secret.tenant_password = Some("unexpected-password".to_string());
    assert!(matches!(
        classify_major_upgrade_commit(&mismatched_secret, &previous, &intended),
        MajorUpgradeCommitResolution::Uncertain(_)
    ));
}

#[test]
fn major_upgrade_commit_resolution_rolls_back_only_the_exact_previous_row() {
    let previous = sample_lifecycle_metadata();
    let mut intended = previous.clone();
    intended.updated_at = "2026-01-02T00:00:00Z".to_string();

    assert_eq!(
        classify_major_upgrade_commit(&previous, &previous, &intended),
        MajorUpgradeCommitResolution::NotCommitted
    );

    let mut divergent = previous.clone();
    divergent.status = InstanceStatus::Failed;
    assert!(matches!(
        classify_major_upgrade_commit(&divergent, &previous, &intended),
        MajorUpgradeCommitResolution::Uncertain(_)
    ));
}

#[test]
fn failed_image_update_quarantine_is_fail_closed() {
    let metadata = sample_lifecycle_metadata();
    let quarantined = quarantined_image_update_metadata(&metadata);

    assert_eq!(quarantined.status, InstanceStatus::Quarantined);
    assert_eq!(quarantined.desired_state, DesiredInstanceState::Stopped);
    assert_eq!(quarantined.instance_id, metadata.instance_id);
    assert_eq!(quarantined.tenant_password, metadata.tenant_password);
}

#[tokio::test]
async fn retained_instance_volume_paths_are_scoped_to_the_exact_instance() {
    let root = tempfile::tempdir().unwrap();
    let data_path = root.path().join("inst_customer_db");
    let old_upgrade = root
        .path()
        .join(".dbe-major-upgrade-old-inst_customer_db-550e8400-e29b-41d4-a716-446655440000");
    let failed_restore = root
        .path()
        .join(".dbe-restore-inst_customer_db-550e8400-e29b-41d4-a716-446655440001");
    let unrelated = root
        .path()
        .join(".dbe-major-upgrade-old-inst_customer_db-other-550e8400-e29b-41d4-a716-446655440002");
    tokio::fs::create_dir(&old_upgrade).await.unwrap();
    tokio::fs::create_dir(&failed_restore).await.unwrap();
    tokio::fs::create_dir(&unrelated).await.unwrap();

    let mut paths = retained_instance_volume_paths(&data_path).await.unwrap();
    paths.sort();
    let mut expected = vec![old_upgrade, failed_restore];
    expected.sort();

    assert_eq!(paths, expected);
}

#[tokio::test]
async fn major_upgrade_rollback_location_never_guesses_which_volume_is_authoritative() {
    let root = tempfile::tempdir().unwrap();
    let data = root.path().join("data");
    let backup = root.path().join("backup");

    tokio::fs::create_dir(&data).await.unwrap();
    assert_eq!(
        classify_major_upgrade_rollback_location(&data, &backup)
            .await
            .unwrap(),
        MajorUpgradeRollbackLocation::OriginalDataInPlace
    );

    tokio::fs::rename(&data, &backup).await.unwrap();
    assert_eq!(
        classify_major_upgrade_rollback_location(&data, &backup)
            .await
            .unwrap(),
        MajorUpgradeRollbackLocation::OldVolumeBackup
    );

    tokio::fs::create_dir(&data).await.unwrap();
    assert!(
        classify_major_upgrade_rollback_location(&data, &backup)
            .await
            .is_err()
    );

    tokio::fs::remove_dir(&data).await.unwrap();
    tokio::fs::remove_dir(&backup).await.unwrap();
    assert!(
        classify_major_upgrade_rollback_location(&data, &backup)
            .await
            .is_err()
    );
}

#[test]
fn deletion_preserves_quarantine_to_avoid_claiming_a_duplicate_route() {
    assert_eq!(
        deletion_status(InstanceStatus::Quarantined),
        InstanceStatus::Quarantined
    );
    assert_eq!(
        deletion_status(InstanceStatus::Running),
        InstanceStatus::Deleting
    );
    assert_eq!(
        deletion_status(InstanceStatus::Deleting),
        InstanceStatus::Deleting
    );
}

#[test]
fn parses_major_version_from_common_image_tags() {
    assert_eq!(image_major_version("mongo:7.0.37"), Some(7));
    assert_eq!(
        image_major_version("docker.io/library/postgres:18.4"),
        Some(18)
    );
    assert_eq!(
        image_major_version("registry.example.com:5000/db/mariadb:12.3.2"),
        Some(12)
    );
    assert_eq!(image_major_version("mysql:8.4"), Some(8));
}

#[test]
fn rejects_unpinned_images_for_existing_instance_updates() {
    assert!(image_major_version("mongo:latest").is_none());
    assert!(image_major_version("mongo@sha256:abc").is_none());
    assert!(image_major_version("mongo").is_none());
}

#[test]
fn parses_major_version_values() {
    assert_eq!(parse_major_version_value("8.3"), Some(8));
    assert_eq!(parse_major_version_value("v7.0"), None);
    assert_eq!(parse_major_version_value("latest"), None);
}

#[test]
fn classifies_major_version_changes() {
    let change = classify_image_update(Protocol::Mongodb, "mongo:7.0.37", "mongo:8.3.4").unwrap();
    assert_eq!(change, ImageVersionChange::Major);

    let change =
        classify_image_update(Protocol::Postgres, "postgres:18.3", "postgres:18.4").unwrap();
    assert_eq!(change, ImageVersionChange::SameMajorOrUnknown);
}

#[test]
fn requires_parseable_tags_for_different_existing_images() {
    let error =
        classify_image_update(Protocol::Mongodb, "mongo:7.0.37", "mongo:latest").unwrap_err();
    assert!(error.to_string().contains("cannot compare requested image"));
}

#[test]
fn major_upgrade_path_blocks_downgrades() {
    let error = validate_major_upgrade_path(Protocol::Postgres, 18, 17).unwrap_err();
    assert!(error.to_string().contains("downgrade is blocked"));
}

#[test]
fn mongodb_major_upgrade_path_blocks_skipped_versions() {
    let error = validate_major_upgrade_path(Protocol::Mongodb, 6, 8).unwrap_err();
    assert!(error.to_string().contains("cannot skip versions"));

    assert!(validate_major_upgrade_path(Protocol::Mongodb, 7, 8).is_ok());
}

#[test]
fn non_mongodb_dump_upgrade_path_allows_skipped_versions() {
    assert!(validate_major_upgrade_path(Protocol::Postgres, 14, 18).is_ok());
}

#[test]
fn major_migration_support_is_limited_to_logical_dump_protocols() {
    assert!(ensure_major_upgrade_supported(Protocol::Postgres).is_ok());
    assert!(ensure_major_upgrade_supported(Protocol::Mysql).is_ok());
    assert!(ensure_major_upgrade_supported(Protocol::Mongodb).is_ok());
    assert!(ensure_major_upgrade_supported(Protocol::Redis).is_err());
    assert!(ensure_major_upgrade_supported(Protocol::Valkey).is_err());
    assert!(ensure_major_upgrade_supported(Protocol::Qdrant).is_err());
}

#[test]
fn replacement_validation_uses_managed_database_unix_sockets() {
    let postgres =
        replacement_validation_command(Protocol::Postgres, "app_user", "app_db").unwrap();
    assert!(postgres.contains("-h /var/run/postgresql"));
    assert!(!postgres.contains("-h 127.0.0.1"));

    let mariadb = replacement_validation_command(Protocol::Mariadb, "app_user", "app_db").unwrap();
    assert!(mariadb.contains("--protocol=socket"));
    assert!(mariadb.contains("--socket=/run/mysqld/mysqld.sock"));
    assert!(!mariadb.contains("-h 127.0.0.1"));

    let mysql = replacement_validation_command(Protocol::Mysql, "app_user", "app_db").unwrap();
    assert!(mysql.contains("--protocol=socket"));
    assert!(mysql.contains("--socket=/var/run/mysqld/mysqld.sock"));
}

#[test]
fn normalizes_database_version_outputs() {
    assert_eq!(
        normalize_database_version(Protocol::Postgres, "postgres (PostgreSQL) 18.4\n"),
        Some("18.4".to_string())
    );
    assert_eq!(
        normalize_database_version(
            Protocol::Mariadb,
            "mariadb  Ver 15.1 Distrib 12.3.2-MariaDB, for Linux (x86_64)\n"
        ),
        Some("12.3.2-MariaDB".to_string())
    );
    assert_eq!(
        normalize_database_version(
            Protocol::Mysql,
            "mysqld  Ver 8.4.6 for Linux on x86_64 (MySQL Community Server - GPL)\n"
        ),
        Some("8.4.6".to_string())
    );
    assert_eq!(
        normalize_database_version(
            Protocol::Redis,
            "Redis server v=8.8.0 sha=00000000:0 malloc=jemalloc-5.3.0 bits=64\n"
        ),
        Some("8.8.0".to_string())
    );
    assert_eq!(
        normalize_database_version(
            Protocol::Valkey,
            "Valkey server v=9.1.1 sha=00000000:0 malloc=jemalloc-5.3.0 bits=64\n"
        ),
        Some("9.1.1".to_string())
    );
    assert_eq!(
        normalize_database_version(Protocol::Mongodb, "v8.3.4\n"),
        Some("8.3.4".to_string())
    );
    assert_eq!(
        normalize_database_version(
            Protocol::Clickhouse,
            "ClickHouse server version 25.8.25.37 (official build).\n"
        ),
        Some("25.8.25.37".to_string())
    );
    assert_eq!(
        normalize_database_version(Protocol::Qdrant, "qdrant 1.18.2\n"),
        Some("1.18.2".to_string())
    );
}
