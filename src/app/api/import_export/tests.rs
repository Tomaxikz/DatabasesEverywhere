use std::io::Cursor;

use super::{archive::*, files::*, logical::*, physical::*, protocol::*, *};
use crate::{
    api::test_support,
    auth::api_token::ApiToken,
    config::Config,
    instances::{manager::InstanceManager, state::InstanceStore},
    storage::{repositories::InstanceRepository, sqlite},
};

pub(super) fn assert_failed_clickhouse_listing(script: &str) {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let client = directory.path().join("clickhouse-client");
    std::fs::write(&client, b"#!/bin/sh\ncase \"$*\" in *'SELECT version()'*) echo 26.4; exit 0 ;; esac\necho 'simulated catalog failure' >&2\nexit 7\n").unwrap();
    std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o700)).unwrap();
    // The remote helper normally uses /work. Keep every test write private.
    let script = script.replace("/work/", &format!("{}/", directory.path().display()));
    let output = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .current_dir(directory.path())
        .env_clear()
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", directory.path().display()),
        )
        .env("CLICKHOUSE_DB", "tenant")
        .env("CLICKHOUSE_USER", "user")
        .env("CLICKHOUSE_PASSWORD", "test-only")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(44),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("failed to list ClickHouse tables"));
}

#[test]
fn clickhouse_export_and_wipe_cannot_hide_a_catalog_failure() {
    let mut metadata = crate::instances::test_support::shared_metadata();
    metadata.protocol = Protocol::Clickhouse;
    assert_failed_clickhouse_listing(
        &export_script(
            &metadata,
            "/dev/stdout",
            &ImportExportSelection::default(),
            false,
        )
        .unwrap(),
    );
    assert_failed_clickhouse_listing(&wipe_logical_script(&metadata, false).unwrap());
}

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

#[tokio::test]
async fn failed_export_does_not_advertise_a_nonexistent_artifact() {
    let job = ImportExportJob {
        job_id: "job-failed-export".to_string(),
        instance_id: "instance-1".to_string(),
        action: ImportExportAction::Export,
        status: ImportExportStatus::Failed,
        artifact_path: Some("/private/pending.postgres.sql".to_string()),
        replay_options: None,
        error: Some("streaming exec failed".to_string()),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };

    let response = public_job_response(job).await;

    assert!(response.artifact_id.is_none());
    assert!(response.artifact_size_bytes.is_none());
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
fn logical_archive_accounting_includes_empty_entry_filesystem_overhead() {
    let accounted =
        (0..MAX_ARCHIVE_ENTRIES).try_fold(0_u64, |total, _| archive_accounted_bytes(total, 0));

    assert_eq!(
        accounted,
        Some(ARCHIVE_ENTRY_DISK_OVERHEAD_BYTES * MAX_ARCHIVE_ENTRIES as u64)
    );
}

#[test]
fn compressed_export_capacity_covers_worst_case_expansion() {
    let bound =
        export_artifact_capacity_bytes(MAX_UNARCHIVED_BYTES, ExportArchiveFormat::Bzip2).unwrap();

    assert!(bound > MAX_UNARCHIVED_BYTES + 64 * 1024 * 1024);
    assert_eq!(
        bound,
        MAX_UNARCHIVED_BYTES + MAX_UNARCHIVED_BYTES.div_ceil(50) + 1024 * 1024
    );
}

#[test]
fn logical_export_capacity_tracks_managed_database_usage() {
    const MIB: u64 = 1024 * 1024;
    assert_eq!(jobs::estimate_export_bytes(Protocol::Mongodb, 0), 64 * MIB);
    assert_eq!(
        jobs::estimate_export_bytes(Protocol::Mongodb, 10 * MIB),
        84 * MIB
    );
    assert_eq!(
        jobs::estimate_export_bytes(Protocol::Postgres, 10 * MIB),
        104 * MIB
    );
    assert_eq!(
        jobs::estimate_export_bytes(Protocol::Postgres, 7 * MIB),
        92 * MIB
    );
    assert_eq!(
        jobs::estimate_export_bytes(Protocol::Mysql, 3 * 1024 * MIB),
        MAX_UNARCHIVED_BYTES
    );
}

#[test]
fn plain_export_on_one_filesystem_does_not_reserve_the_dump_twice() {
    assert!(!jobs::needs_separate_export_staging(
        ExportArchiveFormat::Plain,
        true,
    ));
    assert!(jobs::needs_separate_export_staging(
        ExportArchiveFormat::Plain,
        false,
    ));
    assert!(jobs::needs_separate_export_staging(
        ExportArchiveFormat::Gzip,
        true,
    ));
}

#[tokio::test]
async fn compressed_export_cannot_write_past_its_reserved_bound() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("source.sql");
    let target = directory.path().join("target.sql.gz");
    tokio::fs::write(&source, vec![0x5a; 4096]).await.unwrap();

    let error = compress_gzip(&source, &target, 1).await.unwrap_err();

    assert!(matches!(error, ApiError::Runtime(_)));
    assert!(!target.exists());
}

#[test]
fn physical_operation_preserves_primary_or_restart_error_order() {
    let result = preserve_primary_error(
        Err(ApiError::BadRequest("restore failed".to_string())),
        Err(ApiError::Runtime("restart failed".to_string())),
    );

    assert!(matches!(result, Err(ApiError::BadRequest(message)) if message == "restore failed"));
    let result =
        preserve_primary_error(Ok(()), Err(ApiError::Runtime("restart failed".to_string())));

    assert!(matches!(result, Err(ApiError::Runtime(message)) if message == "restart failed"));
}

#[test]
fn physical_upload_expansion_is_capped_by_the_instance_disk_limit() {
    let one_gib = 1024_u64 * 1024 * 1024;
    for protocol in [Protocol::Redis, Protocol::Valkey, Protocol::Qdrant] {
        assert_eq!(
            physical_staging_bytes(protocol, 1024).unwrap(),
            Some(one_gib)
        );
        assert_eq!(
            physical_staging_bytes(protocol, u64::MAX / (1024 * 1024)).unwrap(),
            Some(crate::jobs::import_export::MAX_DATA_ARCHIVE_BYTES)
        );
    }
    assert_eq!(
        physical_staging_bytes(Protocol::Postgres, 1024).unwrap(),
        None
    );
    assert!(physical_staging_bytes(Protocol::Redis, 0).is_err());
    assert!(physical_staging_bytes(Protocol::Redis, u64::MAX).is_err());
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
    assert!(has_allowed_artifact_extension(FsPath::new(
        "instance-1.postgres.sql"
    )));
    assert!(has_allowed_artifact_extension(FsPath::new(
        "instance-1.redis.tar.gz"
    )));
    assert!(has_allowed_artifact_extension(FsPath::new(
        "instance-1.valkey.tar.gz"
    )));
    assert!(has_allowed_artifact_extension(FsPath::new(
        "instance-1.mongodb.archive.gz"
    )));
    assert!(has_allowed_artifact_extension(FsPath::new(
        "instance-1.qdrant.tar.gz"
    )));
    assert!(!has_allowed_artifact_extension(FsPath::new(
        "instance-1.sh"
    )));
    assert!(!has_allowed_artifact_extension(FsPath::new(
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

    check_remote_staging_space(&[&source, &rollback], 0, 9)
        .await
        .unwrap();
    let error = check_remote_staging_space(&[&source, &rollback], 0, 8)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("configured 8-byte staging limit")
    );

    tokio::fs::remove_file(&source).await.unwrap();
    assert_eq!(
        check_remote_staging_space(&[&rollback], 4, 9)
            .await
            .unwrap(),
        9
    );
    let error = check_remote_staging_space(&[&rollback], 4, 8)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("configured 8-byte staging limit")
    );
}

#[test]
fn remote_logical_import_reserves_source_and_private_recovery_copies() {
    const MIB: u64 = 1024 * 1024;
    for protocol in [
        Protocol::Postgres,
        Protocol::Mariadb,
        Protocol::Mysql,
        Protocol::Mongodb,
        Protocol::Clickhouse,
    ] {
        assert_eq!(
            jobs::import_staging_bytes(protocol, 8 * MIB).unwrap(),
            16 * MIB
        );
    }
    for protocol in [Protocol::Redis, Protocol::Valkey, Protocol::Qdrant] {
        assert_eq!(
            jobs::import_staging_bytes(protocol, 8 * MIB).unwrap(),
            8 * MIB
        );
    }
    assert!(jobs::import_staging_bytes(Protocol::Mysql, u64::MAX).is_err());
}

#[test]
fn qdrant_uses_physical_archive_extension() {
    assert_eq!(dump_extension(Protocol::Qdrant), "qdrant.tar.gz");
    assert!(dump_candidate_suffixes(Protocol::Qdrant).contains(&".qdrant.tar.gz"));
}

#[test]
fn mongodb_gzip_export_is_normalized_to_its_native_gzip_archive() {
    assert_eq!(
        export_archive_format(Protocol::Mongodb, ExportArchiveFormat::Gzip),
        ExportArchiveFormat::Plain
    );
    assert_eq!(
        export_archive_format(Protocol::Mongodb, ExportArchiveFormat::Bzip2),
        ExportArchiveFormat::Bzip2
    );
    assert_eq!(
        export_archive_format(Protocol::Postgres, ExportArchiveFormat::Gzip),
        ExportArchiveFormat::Gzip
    );
}

#[tokio::test]
async fn mongodb_native_gzip_import_keeps_the_stream_mongorestore_expects() {
    let directory = tempfile::tempdir().unwrap();
    let raw = directory.path().join("raw.archive");
    let native_gzip = directory.path().join("dump.mongodb.archive.gz");
    let prepared = directory.path().join("prepared.mongodb.archive.gz");
    tokio::fs::write(&raw, b"mongodb archive bytes")
        .await
        .unwrap();
    compress_gzip(&raw, &native_gzip, 1024).await.unwrap();
    let options = ImportOptions {
        archive_format: Some("gzip".to_string()),
        ..ImportOptions::default()
    };

    prepare_import_artifact(
        Protocol::Mongodb,
        &native_gzip,
        &prepared,
        directory.path(),
        &options,
        1024,
    )
    .await
    .unwrap();

    assert_eq!(
        tokio::fs::read(&prepared).await.unwrap(),
        tokio::fs::read(&native_gzip).await.unwrap()
    );
}

#[test]
fn stored_native_uploads_use_conservative_compressed_scheduler_costs() {
    let options = ImportOptions {
        source: ImportSourceOptions::Upload {
            upload_id: "upload-id".to_string(),
            path: PathBuf::from("upload-id.upload"),
        },
        ..ImportOptions::default()
    };
    for protocol in [
        Protocol::Mongodb,
        Protocol::Redis,
        Protocol::Valkey,
        Protocol::Qdrant,
    ] {
        assert!(jobs::is_compressed_import(protocol, &options));
    }
    assert!(!jobs::is_compressed_import(Protocol::Postgres, &options));

    let prepared_ceiling = 8 * 1024 * 1024 * 1024;
    assert_eq!(
        conservative_import_input_bytes(Protocol::Mongodb, 1, prepared_ceiling, 4096, true),
        prepared_ceiling
    );
    for protocol in [Protocol::Redis, Protocol::Valkey, Protocol::Qdrant] {
        assert_eq!(
            conservative_import_input_bytes(protocol, 1, prepared_ceiling, 4096, true),
            4 * 1024 * 1024 * 1024
        );
    }
}

#[test]
fn prepared_scheduler_ceilings_follow_each_source_specific_limit() {
    const MIB: u64 = 1024 * 1024;
    let upload_limit = 64 * MIB;
    let remote_limit = 3 * 1024 * MIB;
    let artifact = ImportOptions {
        source: ImportSourceOptions::Artifact(PathBuf::from("dump.sql.gz")),
        ..ImportOptions::default()
    };
    assert_eq!(
        jobs::prepared_import_bytes(&artifact, upload_limit, remote_limit, true),
        MAX_UNARCHIVED_BYTES
    );

    let upload = ImportOptions {
        source: ImportSourceOptions::Upload {
            upload_id: "upload-id".to_string(),
            path: PathBuf::from("upload-id.upload"),
        },
        upload_staging: Some(UploadStagingBudget::Logical {
            budget: UploadLogicalStagingBudget {
                prepared_bytes: 32 * MIB,
                rollback_bytes: 0,
                reservation_bytes: 32 * MIB,
            },
            target_created_at: "created".to_string(),
            disk_mib: 1024,
        }),
        ..ImportOptions::default()
    };
    assert_eq!(
        jobs::prepared_import_bytes(&upload, upload_limit, remote_limit, true),
        upload_limit
    );

    let remote = ImportOptions {
        source: ImportSourceOptions::RemoteRequest(RemoteImportRequest {
            host: "source.example".to_string(),
            port: None,
            tls: true,
            database: None,
            username: None,
            password: None,
            authentication_database: None,
            database_index: None,
            api_key: None,
        }),
        ..ImportOptions::default()
    };
    assert_eq!(
        jobs::prepared_import_bytes(&remote, upload_limit, remote_limit, true),
        remote_limit
    );
}

#[test]
fn queued_replay_payloads_have_a_bounded_node_wide_memory_envelope() {
    let scheduler = crate::config::ImportExportSchedulerConfig::default();
    assert_eq!(scheduler.max_queued_jobs, 1024);
    assert_eq!(
        scheduler
            .max_queued_jobs
            .checked_mul(jobs::MAX_REPLAY_OPTIONS_BYTES),
        Some(64 * 1024 * 1024)
    );

    let oversized = ReplayDescriptor::Export {
        selection: ImportExportSelection {
            mode: SelectionMode::Selective,
            include: vec!["x".repeat(jobs::MAX_REPLAY_OPTIONS_BYTES)],
            ..ImportExportSelection::default()
        },
        archive_format: ExportArchiveFormat::Plain,
    };
    assert!(jobs::serialize_replay_descriptor(&oversized).is_err());
}

#[test]
fn mongodb_namespace_pattern_escapes_literal_database_wildcards() {
    assert_eq!(mongodb_database_pattern("analytics"), "analytics.*");
    assert_eq!(
        mongodb_database_pattern("tenant*archive"),
        r"tenant\*archive.*"
    );
    assert_eq!(mongodb_database_pattern(r"legacy\name"), r"legacy\\name.*");
    assert_eq!(
        sh_quote(&mongodb_database_pattern("tenant*archive")),
        r"'tenant\*archive.*'"
    );
}

#[test]
fn managed_logical_scripts_use_unix_sockets_and_scoped_credentials() {
    use crate::shared::backend::BackendEndpoint;

    let mut metadata = crate::instances::test_support::metadata("inst_mysql_1", Protocol::Mysql);
    metadata.public.port = 3308;
    metadata.backend = BackendEndpoint::UnixSocket {
        socket_path: "/run/dbev/sockets/inst_mysql_1/mysqld.sock".to_string(),
    };
    metadata.runtime.container_name = "dbe-mysql-inst-mysql-1".to_string();
    metadata.database.name = "mysql_1".to_string();
    metadata.database.username = "app_mysql_1".to_string();
    metadata.mysql_native_password_sha1_stage2 =
        Some("0123456789abcdef0123456789abcdef01234567".to_string());
    metadata.mysql_root_password = Some("internal-root-password".to_string());
    metadata.tenant_password = Some("internal-tenant-password".to_string());

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
        assert!(script.contains("DBE_POSTGRES_PASSWORD"));
        assert!(script.contains("DBE_POSTGRES_USER"));
        assert!(!script.contains("$POSTGRES_PASSWORD"));
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
    let wrapped_postgres_import = build_import_script(
        &postgres,
        "/dev/stdin",
        None,
        &selection,
        false,
        Some((5, 900)),
        ImportConnection::LocalSocket,
    )
    .unwrap();
    assert!(wrapped_postgres_import.contains("sed -e '5d' -e '900d' /dev/stdin"));
    assert!(wrapped_postgres_import.contains("\\restrict dbev"));
    assert!(!wrapped_postgres_import.contains("\\unrestrict"));

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

    let mut shared_mysql = metadata.clone();
    shared_mysql.deployment_mode = crate::placement::DeploymentMode::Shared;
    shared_mysql.runtime_id = "pool_mysql_1".to_string();
    assert_eq!(
        logical_exec_recovery(&metadata),
        crate::runtime::docker::ExecRecovery::RestartRuntime
    );
    assert_eq!(
        logical_exec_recovery(&shared_mysql),
        crate::runtime::docker::ExecRecovery::CallerHandles
    );
    let shared_export = export_script(
        &shared_mysql,
        "/tmp/shared.mysql.sql",
        &ImportExportSelection::default(),
        false,
    )
    .unwrap();
    let shared_wipe = wipe_logical_script(&shared_mysql, false).unwrap();
    assert!(shared_export.contains("-u \"$MYSQL_USER\""));
    assert!(shared_export.contains("DBE_MYSQL_PASSWORD"));
    assert!(!shared_export.contains("MYSQL_ROOT_PASSWORD"));
    assert!(shared_export.contains("--skip-routines --skip-events --skip-triggers"));
    assert!(!shared_export.contains("information_schema.ROUTINES"));
    assert!(shared_wipe.contains("information_schema.TABLES"));
    assert!(!shared_wipe.contains("DROP DATABASE"));
    let shared_mysql_helper = build_import_script(
        &shared_mysql,
        crate::runtime::docker::IMPORT_HELPER_INPUT_PATH,
        None,
        &ImportExportSelection::default(),
        false,
        None,
        ImportConnection::PoolLoopback,
    )
    .unwrap();
    assert!(shared_mysql_helper.contains("--protocol=TCP"));
    assert!(shared_mysql_helper.contains("--host=127.0.0.1"));
    assert!(!shared_mysql_helper.contains("mysqld.sock"));
    assert!(!shared_mysql_helper.contains("MYSQL_ROOT_PASSWORD"));
    assert!(
        export_script(
            &shared_mysql,
            "/tmp/shared-definition.mysql.sql",
            &ImportExportSelection::default(),
            true,
        )
        .is_err()
    );

    let mut shared_postgres = shared_mysql.clone();
    shared_postgres.protocol = Protocol::Postgres;
    let shared_postgres_wipe = wipe_logical_script(&shared_postgres, false).unwrap();
    assert!(shared_postgres_wipe.contains("c.relowner"));
    assert!(!shared_postgres_wipe.contains("CREATE SCHEMA public"));
    let shared_postgres_helper = build_import_script(
        &shared_postgres,
        crate::runtime::docker::IMPORT_HELPER_INPUT_PATH,
        None,
        &ImportExportSelection::default(),
        false,
        None,
        ImportConnection::PoolLoopback,
    )
    .unwrap();
    assert!(shared_postgres_helper.contains("-h 127.0.0.1"));
    assert!(!shared_postgres_helper.contains("/var/run/postgresql"));
    assert!(!shared_postgres_helper.contains("$POSTGRES_PASSWORD"));

    let mut shared_mariadb = shared_mysql.clone();
    shared_mariadb.protocol = Protocol::Mariadb;
    let shared_mariadb_export = export_script(
        &shared_mariadb,
        "/tmp/shared.mariadb.sql",
        &ImportExportSelection::default(),
        false,
    )
    .unwrap();
    let shared_mariadb_wipe = wipe_logical_script(&shared_mariadb, false).unwrap();
    assert!(shared_mariadb_export.contains("--skip-routines --skip-events --skip-triggers"));
    assert!(!shared_mariadb_export.contains("information_schema.ROUTINES"));
    assert!(shared_mariadb_wipe.contains("DBE_MARIADB_PASSWORD"));
    assert!(!shared_mariadb_wipe.contains("DBE_MARIADB_ROOT_PASSWORD"));
    assert!(!shared_mariadb_wipe.contains("DROP DATABASE"));
    let shared_mariadb_helper = build_import_script(
        &shared_mariadb,
        crate::runtime::docker::IMPORT_HELPER_INPUT_PATH,
        None,
        &ImportExportSelection::default(),
        false,
        None,
        ImportConnection::PoolLoopback,
    )
    .unwrap();
    assert!(shared_mariadb_helper.contains("--protocol=TCP"));
    assert!(shared_mariadb_helper.contains("--host=127.0.0.1"));
    assert!(!shared_mariadb_helper.contains("mysqld.sock"));
    assert!(!shared_mariadb_helper.contains("DBE_MARIADB_ROOT_PASSWORD"));

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

    let mut shared_mongodb = mongodb.clone();
    shared_mongodb.deployment_mode = crate::placement::DeploymentMode::Shared;
    shared_mongodb.runtime_id = "pool_mongodb_1".to_string();
    let shared_mongodb_import = import_script(
        &shared_mongodb,
        "/tmp/shared.mongodb.archive",
        None,
        &ImportExportSelection::default(),
        false,
    )
    .unwrap();
    let shared_mongodb_wipe = wipe_logical_script(&shared_mongodb, false).unwrap();
    assert!(shared_mongodb_import.contains("DBE_MONGO_USER"));
    assert!(shared_mongodb_import.contains("DBE_MONGO_PASSWORD"));
    assert!(!shared_mongodb_import.contains("DBE_MONGO_ROOT_PASSWORD"));
    assert!(shared_mongodb_wipe.contains("getCollectionInfos"));
    assert!(!shared_mongodb_wipe.contains("dropDatabase"));

    let mut shared_clickhouse = shared_mongodb;
    shared_clickhouse.protocol = Protocol::Clickhouse;
    let shared_clickhouse_export = export_script(
        &shared_clickhouse,
        "/tmp/shared.clickhouse.sql",
        &ImportExportSelection::default(),
        false,
    )
    .unwrap();
    let shared_clickhouse_wipe = wipe_logical_script(&shared_clickhouse, false).unwrap();
    assert!(shared_clickhouse_export.contains("ORDER BY engine = 'View'"));
    assert!(shared_clickhouse_export.contains("DROP VIEW IF EXISTS"));
    assert!(shared_clickhouse_export.contains("MaterializedView|LiveView|WindowView"));
    assert!(shared_clickhouse_wipe.contains("ORDER BY engine != 'View'"));
    assert!(shared_clickhouse_wipe.contains("drop='DROP VIEW'"));
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
    validate_source_database(Protocol::Mongodb, &options).unwrap();
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
fn mongodb_upload_allows_catalog_resolution_but_rejects_unsafe_manual_database() {
    let missing = ImportOptions {
        source: ImportSourceOptions::Upload {
            upload_id: "upload-1".to_string(),
            path: PathBuf::new(),
        },
        ..ImportOptions::default()
    };
    validate_source_database(Protocol::Mongodb, &missing).unwrap();

    let invalid = ImportOptions {
        source_database: Some("unsafe.name".to_string()),
        ..missing.clone()
    };
    let error = validate_source_database(Protocol::Mongodb, &invalid).unwrap_err();
    assert!(matches!(error, ApiError::BadRequest(_)));
    assert!(error.to_string().contains("1-63 UTF-8 bytes"));

    let wrong_protocol = ImportOptions {
        source_database: Some("legacy_tenant".to_string()),
        ..missing
    };
    let error = validate_source_database(Protocol::Postgres, &wrong_protocol).unwrap_err();
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
fn export_selection_accepts_only_the_legacy_empty_fields_array() {
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

    validate_artifact_selection(Protocol::Mongodb, &selection).unwrap();
    for protocol in [
        Protocol::Postgres,
        Protocol::Mariadb,
        Protocol::Mysql,
        Protocol::Clickhouse,
        Protocol::Redis,
        Protocol::Valkey,
        Protocol::Qdrant,
    ] {
        let error = validate_artifact_selection(protocol, &selection).unwrap_err();
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
    test_support::state(
        config,
        std::path::PathBuf::from("/tmp/dbev-test-config.yml"),
        ApiToken::new("secret"),
        store,
        manager,
        pool,
    )
}
