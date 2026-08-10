use std::{io::Cursor, sync::Arc};

use super::{archive::*, files::*, logical::*, physical::*, protocol::*, *};
use crate::{
    auth::api_token::ApiToken,
    config::Config,
    instances::{manager::InstanceManager, state::InstanceStore},
    jobs::import_export::ImportExportJobs,
    runtime::docker::DockerRuntime,
    storage::{repositories::InstanceRepository, sqlite},
};

#[tokio::test]
async fn public_job_response_never_exposes_a_host_path() {
    let dir = tempfile::tempdir().unwrap();
    let artifact = dir.path().join("dump.postgres.sql");
    tokio::fs::write(&artifact, b"select 1").await.unwrap();
    let job = ImportExportJob {
        job_id: "job-1".to_string(),
        instance_id: "instance-1".to_string(),
        action: ImportExportAction::Export,
        status: ImportExportStatus::Succeeded,
        artifact_path: Some(artifact.display().to_string()),
        replay_options: None,
        error: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };

    let response = serde_json::to_value(public_job_response(job).await).unwrap();

    assert_eq!(response["artifact_id"], "dump.postgres.sql");
    assert_eq!(response["artifact_size_bytes"], 8);
    assert!(response.get("artifact_path").is_none());
    assert!(
        !response
            .to_string()
            .contains(&dir.path().display().to_string())
    );
}

#[tokio::test]
async fn public_job_response_redacts_legacy_internal_failure_text() {
    let job = ImportExportJob {
        job_id: "job-legacy".to_string(),
        instance_id: "instance-1".to_string(),
        action: ImportExportAction::Import,
        status: ImportExportStatus::Failed,
        artifact_path: None,
        replay_options: None,
        error: Some("password=hunter2 /var/lib/private".to_string()),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };

    let response = serde_json::to_string(&public_job_response(job).await).unwrap();
    assert!(response.contains("internal_error"));
    assert!(!response.contains("hunter2"));
    assert!(!response.contains("/var/lib/private"));
}

#[test]
fn archive_copy_stops_at_expired_deadline() {
    let mut input = Cursor::new(b"contents".as_slice());
    let mut output = Vec::new();
    let expired = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();

    let error = copy_limited_until(&mut input, &mut output, u64::MAX, expired).unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(output.is_empty());
}

#[test]
fn physical_operation_preserves_primary_error_over_restart_error() {
    let result = preserve_primary_error(
        Err(ApiError::BadRequest("restore failed".to_string())),
        Err(ApiError::Runtime("restart failed".to_string())),
    );

    assert!(matches!(result, Err(ApiError::BadRequest(message)) if message == "restore failed"));
}

#[test]
fn physical_operation_returns_restart_error_after_primary_success() {
    let result =
        preserve_primary_error(Ok(()), Err(ApiError::Runtime("restart failed".to_string())));

    assert!(matches!(result, Err(ApiError::Runtime(message)) if message == "restart failed"));
}

#[test]
fn physical_upload_expansion_is_capped_by_the_instance_disk_limit() {
    let one_gib = 1024_u64 * 1024 * 1024;
    for protocol in [Protocol::Redis, Protocol::Valkey, Protocol::Qdrant] {
        assert_eq!(
            physical_staging_bytes_for(protocol, 1024).unwrap(),
            Some(one_gib)
        );
        assert_eq!(
            physical_staging_bytes_for(protocol, u64::MAX / (1024 * 1024)).unwrap(),
            Some(crate::jobs::import_export::MAX_DATA_ARCHIVE_BYTES)
        );
    }
    assert_eq!(
        physical_staging_bytes_for(Protocol::Postgres, 1024).unwrap(),
        None
    );
    assert!(physical_staging_bytes_for(Protocol::Redis, 0).is_err());
    assert!(physical_staging_bytes_for(Protocol::Redis, u64::MAX).is_err());
}

#[test]
fn upload_staging_is_bound_to_target_generation_and_disk_limit() {
    let staging = UploadStagingBudget::Physical {
        extracted_bytes: 1024,
        target_created_at: "2026-01-01T00:00:00Z".to_string(),
        disk_mib: 512,
    };

    assert!(upload_staging_matches_target(
        &staging,
        "2026-01-01T00:00:00Z",
        512
    ));
    assert!(!upload_staging_matches_target(
        &staging,
        "2026-01-02T00:00:00Z",
        512
    ));
    assert!(!upload_staging_matches_target(
        &staging,
        "2026-01-01T00:00:00Z",
        1024
    ));
}

#[test]
fn allows_only_supported_import_artifact_extensions() {
    assert!(artifact_has_allowed_extension(FsPath::new(
        "instance-1.postgres.sql"
    )));
    assert!(artifact_has_allowed_extension(FsPath::new(
        "instance-1.redis.tar.gz"
    )));
    assert!(artifact_has_allowed_extension(FsPath::new(
        "instance-1.valkey.tar.gz"
    )));
    assert!(artifact_has_allowed_extension(FsPath::new(
        "instance-1.mongodb.archive.gz"
    )));
    assert!(artifact_has_allowed_extension(FsPath::new(
        "instance-1.qdrant.tar.gz"
    )));
    assert!(!artifact_has_allowed_extension(FsPath::new(
        "instance-1.sh"
    )));
    assert!(!artifact_has_allowed_extension(FsPath::new(
        "instance-1.sql.exe"
    )));
}

#[test]
fn recovery_restore_is_destructive_and_infers_only_real_wrapper_formats() {
    let postgres = ImportOptions::recovery_restore("export.postgres.sql.gz", Protocol::Postgres);
    assert_eq!(postgres.mode, ImportMode::Wipe);
    assert_eq!(postgres.archive_format.as_deref(), Some("gzip"));

    let mongo_native =
        ImportOptions::recovery_restore("export.mongodb.archive.gz", Protocol::Mongodb);
    assert_eq!(mongo_native.mode, ImportMode::Wipe);
    assert_eq!(mongo_native.archive_format, None);

    let mongo_wrapped =
        ImportOptions::recovery_restore("export.mongodb.archive.gz.gz", Protocol::Mongodb);
    assert_eq!(mongo_wrapped.archive_format.as_deref(), Some("gzip"));

    let redis_physical = ImportOptions::recovery_restore("export.redis.tar.gz", Protocol::Redis);
    assert_eq!(redis_physical.archive_format, None);

    let valkey_physical = ImportOptions::recovery_restore("export.valkey.tar.gz", Protocol::Valkey);
    assert_eq!(valkey_physical.archive_format, None);
}

#[test]
fn rar_is_rejected_instead_of_being_advertised_but_unimplemented() {
    let error = ImportArchiveFormat::parse("rar").unwrap_err();
    assert!(error.to_string().contains("unsupported archive_format"));
}

#[tokio::test]
async fn remote_import_staging_budget_is_aggregate() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source");
    let rollback = directory.path().join("rollback");
    tokio::fs::write(&source, [0_u8; 4]).await.unwrap();
    tokio::fs::write(&rollback, [0_u8; 5]).await.unwrap();

    ensure_remote_import_staging_budget(&[&source, &rollback], 9)
        .await
        .unwrap();
    let error = ensure_remote_import_staging_budget(&[&source, &rollback], 8)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("configured 8-byte staging limit")
    );

    tokio::fs::remove_file(&source).await.unwrap();
    assert_eq!(
        ensure_remote_import_staging_budget_with_retained_bytes(&[&rollback], 4, 9)
            .await
            .unwrap(),
        9
    );
    let error = ensure_remote_import_staging_budget_with_retained_bytes(&[&rollback], 4, 8)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("configured 8-byte staging limit")
    );
}

#[test]
fn qdrant_uses_physical_archive_extension() {
    assert_eq!(dump_extension(Protocol::Qdrant), "qdrant.tar.gz");
    assert!(dump_candidate_suffixes(Protocol::Qdrant).contains(&".qdrant.tar.gz"));
}

#[test]
fn mongodb_namespace_pattern_escapes_literal_database_wildcards() {
    assert_eq!(mongodb_namespace_pattern("analytics"), "analytics.*");
    assert_eq!(
        mongodb_namespace_pattern("tenant*archive"),
        r"tenant\*archive.*"
    );
    assert_eq!(mongodb_namespace_pattern(r"legacy\name"), r"legacy\\name.*");
    assert_eq!(
        sh_quote(&mongodb_namespace_pattern("tenant*archive")),
        r"'tenant\*archive.*'"
    );
}

#[test]
fn managed_logical_scripts_use_unix_sockets_and_scoped_credentials() {
    use crate::{
        instances::metadata::{
            DatabaseIdentity, PublicEndpoint, RuntimeKind, RuntimeMetadata, SCHEMA_VERSION,
        },
        shared::{backend::BackendEndpoint, limits::InstanceLimits},
    };

    let metadata = InstanceMetadata {
        schema_version: SCHEMA_VERSION,
        instance_id: "inst_mysql_1".to_string(),
        protocol: Protocol::Mysql,
        status: InstanceStatus::Running,
        desired_state: crate::instances::metadata::DesiredInstanceState::Running,
        disk_limit_blocked: false,
        public: PublicEndpoint {
            host: "db.example.com".to_string(),
            port: 3308,
        },
        backend: BackendEndpoint::UnixSocket {
            socket_path: "/run/dbev/sockets/inst_mysql_1/mysqld.sock".to_string(),
        },
        runtime: RuntimeMetadata {
            kind: RuntimeKind::Docker,
            container_name: "dbe-mysql-inst-mysql-1".to_string(),
            network_mode: "none".to_string(),
        },
        database: DatabaseIdentity {
            name: "mysql_1".to_string(),
            username: "app_mysql_1".to_string(),
        },
        route_key_sha256: None,
        mariadb_native_password_sha1_stage2: None,
        mariadb_root_password: None,
        mysql_native_password_sha1_stage2: Some(
            "0123456789abcdef0123456789abcdef01234567".to_string(),
        ),
        mysql_root_password: Some("internal-root-password".to_string()),
        mongodb_root_password: None,
        postgres_admin_password: None,
        tenant_password: Some("internal-tenant-password".to_string()),
        limits: InstanceLimits::default(),
        image: None,
        database_version: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };

    let export = export_script(
        &metadata,
        "/tmp/export.mysql.sql",
        &ImportExportSelection::default(),
        false,
    )
    .unwrap();
    let rollback_export = export_script(
        &metadata,
        "/tmp/rollback.mysql.sql",
        &ImportExportSelection::default(),
        true,
    )
    .unwrap();
    let selection = ImportExportSelection::default();
    let import =
        import_script(&metadata, "/tmp/import.mysql.sql", None, &selection, false).unwrap();
    let rollback_import =
        import_script(&metadata, "/tmp/rollback.mysql.sql", None, &selection, true).unwrap();
    let wipe = wipe_logical_script(&metadata, false).unwrap();
    let rollback_wipe = wipe_logical_script(&metadata, true).unwrap();

    assert_eq!(dump_extension(Protocol::Mysql), "mysql.sql");
    assert!(dump_candidate_suffixes(Protocol::Mysql).contains(&".mysql.sql"));
    assert!(export.contains("mysqldump"));
    assert!(export.contains("--socket=/var/run/mysqld/mysqld.sock"));
    assert!(export.contains("--single-transaction"));
    assert!(export.contains("--events"));
    assert!(export.contains("--hex-blob"));
    assert!(export.contains("MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\""));
    assert!(import.contains("mysql \\"));
    assert!(import.contains("--binary-mode"));
    assert!(import.contains("--socket=/var/run/mysqld/mysqld.sock"));
    assert!(import.contains("MYSQL_PWD=\"$DBE_IMPORT_PASSWORD\""));
    assert!(import.contains("-u \"$DBE_IMPORT_USER\""));
    assert!(!import.contains("MYSQL_ROOT_PASSWORD"));
    assert!(!import.contains("-u root"));
    assert!(wipe.contains("--socket=/var/run/mysqld/mysqld.sock"));
    assert!(wipe.contains("MYSQL_PWD=\"$DBE_IMPORT_PASSWORD\""));
    assert!(wipe.contains("-u \"$DBE_IMPORT_USER\""));
    assert!(!wipe.contains("MYSQL_ROOT_PASSWORD"));
    assert!(!wipe.contains("-u root"));
    assert!(wipe.contains("SELECT @@character_set_database, @@collation_database"));
    assert!(wipe.contains("CHARACTER SET $1 COLLATE $2"));
    assert!(rollback_wipe.contains("DROP DATABASE IF EXISTS"));
    assert!(!rollback_wipe.contains("CREATE DATABASE"));
    assert!(!rollback_import.contains("\"$MYSQL_DATABASE\""));
    assert!(rollback_import.contains("-u root"));
    assert!(rollback_import.contains("--binary-mode"));
    assert!(rollback_import.contains("MYSQL_ROOT_PASSWORD"));
    assert!(!export.contains("--databases"));
    assert!(rollback_export.contains("--databases"));
    assert!(!export.contains("internal-root-password"));
    assert!(!import.contains("internal-root-password"));
    assert!(!import.contains("internal-tenant-password"));
    assert!(
        mysql_tenant_import_credentials(&metadata, false)
            .unwrap()
            .is_some()
    );
    assert!(
        mysql_tenant_import_credentials(&metadata, true)
            .unwrap()
            .is_none()
    );

    let mut postgres = metadata.clone();
    postgres.protocol = Protocol::Postgres;
    let postgres_export = export_script(
        &postgres,
        "/tmp/export.postgres.sql",
        &ImportExportSelection::default(),
        false,
    )
    .unwrap();
    let postgres_import = import_script(
        &postgres,
        "/tmp/import.postgres.sql",
        None,
        &selection,
        false,
    )
    .unwrap();
    let postgres_wipe = wipe_logical_script(&postgres, false).unwrap();
    for script in [&postgres_export, &postgres_import, &postgres_wipe] {
        assert!(script.contains("-h /var/run/postgresql"));
        assert!(!script.contains("-h 127.0.0.1"));
    }
    assert!(postgres_import.contains("\\restrict dbev"));
    assert!(postgres_import.contains("--no-psqlrc"));
    assert!(postgres_import.contains("-f -"));
    assert!(postgres_import.contains("cat /tmp/import.postgres.sql"));
    assert!(!postgres_import.contains("\\unrestrict"));
    let restrict_key = postgres_import
        .split_once("\\restrict ")
        .and_then(|(_, suffix)| suffix.split_once('\''))
        .map(|(key, _)| key)
        .unwrap();
    assert_eq!(restrict_key.len(), 36);
    assert!(restrict_key.starts_with("dbev"));
    assert!(
        restrict_key
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    );

    let mut mariadb = metadata.clone();
    mariadb.protocol = Protocol::Mariadb;
    let mariadb_export = export_script(
        &mariadb,
        "/tmp/export.mariadb.sql",
        &ImportExportSelection::default(),
        false,
    )
    .unwrap();
    let mariadb_rollback_export = export_script(
        &mariadb,
        "/tmp/rollback.mariadb.sql",
        &ImportExportSelection::default(),
        true,
    )
    .unwrap();
    let mariadb_import =
        import_script(&mariadb, "/tmp/import.mariadb.sql", None, &selection, false).unwrap();
    let mariadb_rollback_import = import_script(
        &mariadb,
        "/tmp/rollback.mariadb.sql",
        None,
        &selection,
        true,
    )
    .unwrap();
    let mariadb_wipe = wipe_logical_script(&mariadb, false).unwrap();
    let mariadb_rollback_wipe = wipe_logical_script(&mariadb, true).unwrap();
    for script in [&mariadb_export, &mariadb_import, &mariadb_wipe] {
        assert!(script.contains("--protocol=socket"));
        assert!(script.contains("--socket=/run/mysqld/mysqld.sock"));
        assert!(!script.contains("-h 127.0.0.1"));
    }
    assert!(mariadb_export.contains("-u \"$MARIADB_USER\""));
    assert!(mariadb_import.contains("-u \"$MARIADB_USER\""));
    assert!(mariadb_export.contains("DBE_MARIADB_PASSWORD"));
    assert!(mariadb_import.contains("DBE_MARIADB_PASSWORD"));
    assert!(mariadb_import.contains("--binary-mode"));
    assert!(mariadb_wipe.contains("DBE_MARIADB_ROOT_PASSWORD"));
    assert!(mariadb_wipe.contains("-u root"));
    assert!(mariadb_wipe.contains("SELECT @@character_set_database, @@collation_database"));
    assert!(mariadb_wipe.contains("CHARACTER SET $1 COLLATE $2"));
    assert!(mariadb_rollback_wipe.contains("DROP DATABASE IF EXISTS"));
    assert!(!mariadb_rollback_wipe.contains("CREATE DATABASE"));
    assert!(!mariadb_rollback_import.contains("\"$MARIADB_DATABASE\""));
    assert!(mariadb_rollback_import.contains("-u root"));
    assert!(mariadb_rollback_import.contains("--binary-mode"));
    assert!(!mariadb_export.contains("--databases"));
    assert!(mariadb_rollback_export.contains("--databases"));

    let mut mongodb = metadata;
    mongodb.protocol = Protocol::Mongodb;
    mongodb.mongodb_root_password = Some("internal-mongodb-password".to_string());
    let mongodb_selection = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["orders".to_string(), "customers".to_string()],
        ..ImportExportSelection::default()
    };
    let mongodb_import = import_script(
        &mongodb,
        "/tmp/import.mongodb.archive",
        None,
        &mongodb_selection,
        false,
    )
    .unwrap();
    assert!(mongodb_import.contains("mongorestore"));
    assert!(mongodb_import.contains("--nsInclude \"$DBE_MONGO_DATABASE\".'orders'"));
    assert!(mongodb_import.contains("--nsInclude \"$DBE_MONGO_DATABASE\".'customers'"));
    assert!(!mongodb_import.contains("internal-mongodb-password"));
}

#[tokio::test]
async fn artifact_imports_are_scoped_to_the_requested_instance() {
    let dir = tempfile::tempdir().unwrap();
    let artifacts = dir.path().join("artifacts");
    let exports = artifacts.join("exports").join("instance-1");
    let foreign_exports = artifacts.join("exports").join("instance-2");
    std::fs::create_dir_all(&exports).unwrap();
    std::fs::create_dir_all(&foreign_exports).unwrap();
    let allowed = exports.join("dump.postgres.sql");
    let outside = foreign_exports.join("dump.postgres.sql");
    std::fs::write(&allowed, b"select 1").unwrap();
    std::fs::write(&outside, b"select 1").unwrap();
    let state = test_state_with_config(Config {
        paths: crate::config::PathConfig {
            artifacts: artifacts.display().to_string(),
            ..Default::default()
        },
        ..Default::default()
    })
    .await;

    assert_eq!(
        validate_artifact_path(&state, "instance-1", FsPath::new("dump.postgres.sql"))
            .await
            .unwrap(),
        allowed.canonicalize().unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            std::fs::metadata(&allowed).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&exports).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    let error = validate_artifact_path(&state, "instance-1", &outside)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("requested instance"));
}

#[cfg(unix)]
#[tokio::test]
async fn artifact_import_rejects_symlinks_inside_allowed_root() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let artifacts = dir.path().join("artifacts");
    let exports = artifacts.join("exports").join("instance-1");
    std::fs::create_dir_all(&exports).unwrap();
    let real = exports.join("real.postgres.sql");
    let link = exports.join("linked.postgres.sql");
    std::fs::write(&real, b"select 1").unwrap();
    symlink(&real, &link).unwrap();
    let state = test_state_with_config(Config {
        paths: crate::config::PathConfig {
            artifacts: artifacts.display().to_string(),
            ..Default::default()
        },
        ..Default::default()
    })
    .await;

    let error = validate_artifact_path(&state, "instance-1", &link)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("real regular file"));
}

#[tokio::test]
async fn artifact_import_rejects_relative_path_traversal() {
    let dir = tempfile::tempdir().unwrap();
    let artifacts = dir.path().join("missing-artifacts");
    let state = test_state_with_config(Config {
        paths: crate::config::PathConfig {
            artifacts: artifacts.display().to_string(),
            ..Default::default()
        },
        ..Default::default()
    })
    .await;

    let error = validate_artifact_path(&state, "instance-1", FsPath::new("../../etc/passwd"))
        .await
        .unwrap_err();

    assert!(error.to_string().contains("invalid artifact_id"));
}

#[tokio::test]
async fn artifact_import_rejects_outside_absolute_path_when_exports_root_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let artifacts = dir.path().join("artifacts");
    let outside = dir.path().join("outside.postgres.sql");
    std::fs::write(&outside, b"select 1").unwrap();
    let state = test_state_with_config(Config {
        paths: crate::config::PathConfig {
            artifacts: artifacts.display().to_string(),
            ..Default::default()
        },
        ..Default::default()
    })
    .await;

    let error = validate_artifact_path(&state, "instance-1", &outside)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("requested instance"));
    assert!(artifacts.join("exports").join("instance-1").is_dir());
}

#[test]
fn remote_import_source_is_typed_and_does_not_accept_a_protocol_override() {
    let request = serde_json::from_value::<ImportRequest>(serde_json::json!({
        "source": {
            "type": "remote",
            "host": "db.example.com",
            "port": 5432,
            "tls": true,
            "database": "app",
            "username": "operator",
            "password": "secret"
        },
        "mode": "wipe"
    }))
    .unwrap();
    assert_eq!(request.mode, ImportMode::Wipe);
    assert!(matches!(request.source, ImportSource::Remote(_)));

    let override_attempt = serde_json::from_value::<ImportRequest>(serde_json::json!({
        "source": {
            "type": "remote",
            "protocol": "postgres",
            "host": "db.example.com",
            "database": "app",
            "username": "operator",
            "password": "secret"
        }
    }));
    assert!(override_attempt.is_err());
}

#[test]
fn mongodb_upload_source_database_is_validated_and_preserved_for_replay() {
    let request = serde_json::from_value::<ImportRequest>(serde_json::json!({
        "source": {
            "type": "upload",
            "upload_id": "upload-1",
            "source_database": "legacy_tenant"
        },
        "mode": "wipe"
    }))
    .unwrap();
    let options = ImportOptions::from(&request);

    assert_eq!(options.source_database.as_deref(), Some("legacy_tenant"));
    validate_upload_source_database(Protocol::Mongodb, &options).unwrap();
    let replay = serde_json::to_string(&ReplayDescriptor::UploadImport {
        upload_id: "upload-1".to_string(),
        source_database: options.source_database.clone(),
        mode: options.mode,
        selection: options.selection.clone(),
    })
    .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&replay).unwrap()["source_database"],
        "legacy_tenant"
    );
}

#[test]
fn mongodb_upload_requires_a_safe_source_database_before_job_admission() {
    let missing = ImportOptions {
        source: ImportSourceOptions::Upload {
            upload_id: "upload-1".to_string(),
            path: PathBuf::new(),
        },
        ..ImportOptions::default()
    };
    let error = validate_upload_source_database(Protocol::Mongodb, &missing).unwrap_err();
    assert!(matches!(error, ApiError::Conflict(_)));
    assert!(error.to_string().contains("source.source_database"));

    let invalid = ImportOptions {
        source_database: Some("unsafe.name".to_string()),
        ..missing.clone()
    };
    let error = validate_upload_source_database(Protocol::Mongodb, &invalid).unwrap_err();
    assert!(matches!(error, ApiError::BadRequest(_)));
    assert!(error.to_string().contains("1-63 UTF-8 bytes"));

    let wrong_protocol = ImportOptions {
        source_database: Some("legacy_tenant".to_string()),
        ..missing
    };
    let error = validate_upload_source_database(Protocol::Postgres, &wrong_protocol).unwrap_err();
    assert!(error.to_string().contains("only for mongodb"));
}

#[test]
fn import_archive_settings_are_rejected_at_the_top_level() {
    let request = serde_json::from_value::<ImportRequest>(serde_json::json!({
        "source": {
            "type": "artifact",
            "artifact_id": "dump.postgres.sql.gz"
        },
        "unarchive": true,
        "archive_format": "gzip"
    }));

    assert!(request.is_err());
}

#[test]
fn legacy_archive_flags_are_rejected_instead_of_ignored() {
    let export = serde_json::from_value::<ExportRequest>(serde_json::json!({
        "archive": true,
        "archive_format": "gzip"
    }));
    assert!(export.is_err());

    let import = serde_json::from_value::<ImportRequest>(serde_json::json!({
        "source": {
            "type": "artifact",
            "artifact_id": "dump.postgres.sql.gz",
            "unarchive": true,
            "archive_format": "gzip"
        }
    }));
    assert!(import.is_err());
}

#[test]
fn export_selection_accepts_legacy_empty_fields_array() {
    let request = serde_json::from_value::<ExportRequest>(serde_json::json!({
        "selection": {
            "mode": "selective",
            "include": ["users"],
            "exclude": [],
            "fields": []
        }
    }))
    .unwrap();

    assert!(request.selection.unwrap().fields.is_empty());
}

#[test]
fn export_selection_rejects_nonempty_fields_array() {
    let error = serde_json::from_value::<ExportRequest>(serde_json::json!({
        "selection": {
            "mode": "selective",
            "include": ["users"],
            "exclude": [],
            "fields": ["id"]
        }
    }))
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("selection.fields must be an object or an empty array")
    );
}

#[test]
fn selective_import_cannot_exclude_an_included_object() {
    let selection = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["orders".to_string()],
        exclude: vec!["orders".to_string()],
        ..ImportExportSelection::default()
    };

    for protocol in [
        Protocol::Postgres,
        Protocol::Mariadb,
        Protocol::Mysql,
        Protocol::Mongodb,
        Protocol::Clickhouse,
        Protocol::Qdrant,
    ] {
        let error = validate_selection(protocol, &selection, SelectionUse::Import).unwrap_err();
        assert!(error.to_string().contains("both include and exclude"));
    }
}

#[test]
fn mongodb_dump_selection_uses_supported_collection_flags() {
    let selection = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["orders".to_string()],
        exclude: vec!["audit".to_string()],
        ..ImportExportSelection::default()
    };

    let args = mongodb_dump_selection_args(&selection).unwrap();

    assert!(args.contains("--collection='orders'"));
    assert!(!args.contains("--excludeCollection"));
    assert!(!args.contains("--nsInclude"));
    assert!(!args.contains("--nsExclude"));
}

#[test]
fn only_mongodb_logical_artifacts_accept_selective_imports() {
    let selection = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["orders".to_string()],
        ..ImportExportSelection::default()
    };

    validate_logical_artifact_selection(Protocol::Mongodb, &selection).unwrap();
    for protocol in [
        Protocol::Postgres,
        Protocol::Mariadb,
        Protocol::Mysql,
        Protocol::Clickhouse,
        Protocol::Redis,
        Protocol::Valkey,
        Protocol::Qdrant,
    ] {
        let error = validate_logical_artifact_selection(protocol, &selection).unwrap_err();
        assert!(error.to_string().contains("selection.mode=full"));
    }
}

#[test]
fn local_mongodb_rollback_import_keeps_selection_but_prefiltered_remote_does_not() {
    let options = ImportOptions {
        selection: ImportExportSelection {
            mode: SelectionMode::Selective,
            include: vec!["orders".to_string(), "customers".to_string()],
            ..ImportExportSelection::default()
        },
        ..ImportOptions::default()
    };

    let local = logical_apply_options(&options, false);
    assert_eq!(local.selection.mode, SelectionMode::Selective);
    assert_eq!(
        local.selection.include,
        ["orders".to_string(), "customers".to_string()]
    );

    let remote = logical_apply_options(&options, true);
    assert_eq!(remote.selection.mode, SelectionMode::Full);
    assert!(remote.selection.include.is_empty());
}

#[test]
fn mongodb_local_restore_filters_multiple_collections_in_target_database() {
    let selection = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["orders".to_string(), "customers_2026".to_string()],
        exclude: vec!["audit-log".to_string()],
        ..ImportExportSelection::default()
    };

    let args = mongodb_restore_namespace_args(&selection, None).unwrap();

    assert_eq!(
        args,
        concat!(
            "--nsInclude \"$DBE_MONGO_DATABASE\".'orders' \\\n",
            "  --nsInclude \"$DBE_MONGO_DATABASE\".'customers_2026' \\\n",
            "  --nsExclude \"$DBE_MONGO_DATABASE\".'audit-log'"
        )
    );
    assert!(!args.contains("--nsFrom"));
    assert!(!args.contains("--nsTo"));
}

#[test]
fn mongodb_remote_restore_preserves_namespace_remapping_with_selection() {
    let selection = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["orders".to_string(), "customers".to_string()],
        exclude: vec!["audit".to_string()],
        ..ImportExportSelection::default()
    };

    let args = mongodb_restore_namespace_args(&selection, Some("tenant*archive")).unwrap();

    assert_eq!(
        args,
        concat!(
            "--nsInclude 'tenant\\*archive.orders' \\\n",
            "  --nsInclude 'tenant\\*archive.customers' \\\n",
            "  --nsExclude 'tenant\\*archive.audit' \\\n",
            "  --nsFrom 'tenant\\*archive.*' \\\n",
            "  --nsTo \"$DBE_MONGO_DATABASE.*\""
        )
    );
}

#[test]
fn mongodb_restore_selection_rejects_overlap_and_shell_injection() {
    let overlap = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["orders".to_string()],
        exclude: vec!["orders".to_string()],
        ..ImportExportSelection::default()
    };
    let overlap_error = mongodb_restore_namespace_args(&overlap, None).unwrap_err();
    assert!(
        overlap_error
            .to_string()
            .contains("both include and exclude")
    );

    let injection = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["orders'; touch /tmp/pwn; #".to_string()],
        ..ImportExportSelection::default()
    };
    let injection_error = mongodb_restore_namespace_args(&injection, Some("source")).unwrap_err();
    assert!(
        injection_error
            .to_string()
            .contains("invalid mongodb collection")
    );
}

#[test]
fn mongodb_full_restore_namespace_arguments_remain_compatible() {
    let selection = ImportExportSelection::default();

    assert_eq!(
        mongodb_restore_namespace_args(&selection, None).unwrap(),
        "--nsInclude \"$DBE_MONGO_DATABASE.*\""
    );
    assert_eq!(
        mongodb_restore_namespace_args(&selection, Some("analytics")).unwrap(),
        concat!(
            "--nsInclude 'analytics.*' \\\n",
            "  --nsFrom 'analytics.*' \\\n",
            "  --nsTo \"$DBE_MONGO_DATABASE.*\""
        )
    );
}

#[test]
fn mongodb_remote_import_accepts_multiple_collections_but_export_stays_single_collection() {
    let selection = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["orders".to_string(), "customers".to_string()],
        ..ImportExportSelection::default()
    };

    validate_selection(Protocol::Mongodb, &selection, SelectionUse::Import).unwrap();
    let export_error =
        validate_selection(Protocol::Mongodb, &selection, SelectionUse::Export).unwrap_err();
    assert!(
        export_error
            .to_string()
            .contains("exactly one included collection")
    );
}

#[test]
fn mongodb_selection_rejects_duplicate_included_collections() {
    let selection = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["orders".to_string(), "orders".to_string()],
        ..ImportExportSelection::default()
    };

    let error =
        validate_selection(Protocol::Mongodb, &selection, SelectionUse::Import).unwrap_err();
    assert!(error.to_string().contains("more than once"));
}

#[tokio::test]
async fn qdrant_artifact_selection_must_be_full_but_remote_may_be_selective() {
    let state = test_state_with_config(Config::default()).await;
    let selection = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["events".to_string()],
        ..ImportExportSelection::default()
    };
    let artifact = ImportOptions {
        source: ImportSourceOptions::Artifact(PathBuf::from("backup.qdrant.tar.gz")),
        selection: selection.clone(),
        ..ImportOptions::default()
    };

    let error = validate_import_source(&state, Protocol::Qdrant, &artifact)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("selection.mode=full"));

    let request: RemoteImportRequest = serde_json::from_value(serde_json::json!({
        "host": "qdrant.example.com",
        "port": 6333,
        "tls": true
    }))
    .unwrap();
    let remote = ImportOptions {
        source: ImportSourceOptions::RemoteRequest(request),
        selection,
        ..ImportOptions::default()
    };
    validate_import_source(&state, Protocol::Qdrant, &remote)
        .await
        .unwrap();
}

async fn test_state_with_config(config: Config) -> AppState {
    let dir = tempfile::tempdir().unwrap();
    let pool = sqlite::connect(dir.path()).await.unwrap();
    let store = InstanceStore::default();
    let manager = InstanceManager::new(store.clone(), InstanceRepository::new(pool.clone()));
    test_state_with_store(store, manager, config, pool)
}

fn test_state_with_store(
    store: InstanceStore,
    manager: InstanceManager,
    config: Config,
    pool: sqlx::SqlitePool,
) -> AppState {
    AppState::new(crate::api::routes::AppStateData {
        config: Arc::new(config),
        config_path: std::path::PathBuf::from("/tmp/dbev-test-config.yml"),
        config_patches: crate::api::config_admin::ConfigPatchCoordinator::default(),
        api_token: ApiToken::new("secret"),
        instances: store,
        manager,
        docker: DockerRuntime::offline_for_tests(&Default::default(), false),
        import_export_jobs: ImportExportJobs::default(),
        import_uploads: crate::api::import_export::ImportUploadService::new(
            crate::storage::import_uploads::ImportUploadRepository::new(pool),
            2,
        ),
        api_rate_limiter: crate::api::security::ApiRateLimiter::default(),
        install_progress: crate::api::progress::InstallProgressStore::default(),
        artifact_downloads: crate::api::artifacts::ArtifactDownloadTickets::default(),
        resource_cache: crate::api::resources::ResourceCache::default(),
        soft_disk_limiter: crate::disk::soft::SoftDiskLimiter::new(Default::default()),
        monitoring_cache: crate::api::websocket::MonitoringSnapshotCache::default(),
        instance_runtime_cache: crate::api::instances::InstanceRuntimeInfoCache::default(),
        instance_locks: crate::instances::locks::InstanceLocks::default(),
        gateway_supervisor: crate::gateway::supervisor::GatewaySupervisor::default(),
        daemon_shutdown: crate::api::routes::DaemonShutdown::default(),
    })
}
