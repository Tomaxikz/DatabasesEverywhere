use super::*;
use crate::config::Config;

#[test]
fn validates_global_sql_buffer_capacity() {
    let mut config = valid_config();
    for mib in [1, 1024, 2048] {
        config.daemon.sql_buffer_global_mib = mib;
        validate_config(&config).unwrap();
        assert_eq!(
            config.daemon.sql_buffer_global_bytes().unwrap() as u64,
            mib * 1024 * 1024
        );
    }
    let maximum = (tokio::sync::Semaphore::MAX_PERMITS / (1024 * 1024)) as u64;
    for mib in [0, maximum + 1, u64::MAX] {
        config.daemon.sql_buffer_global_mib = mib;
        assert!(matches!(
            validate_config(&config),
            Err(ConfigValidationError::InvalidDaemonLimit {
                field: "sql_buffer_global_mib",
                ..
            })
        ));
    }
}

#[test]
fn legacy_recovery_list_is_accepted_but_no_longer_serialized() {
    let config: Config =
        yaml_serde::from_str("daemon:\n  recover_shared_pools: ['*', 'pool_old']\n").unwrap();
    assert_eq!(config.daemon.recover_shared_pools.len(), 2);
    assert!(
        serde_json::to_value(config).unwrap()["daemon"]
            .get("recover_shared_pools")
            .is_none()
    );
}

#[test]
fn rejects_missing_node_identity_and_api_token() {
    let config = Config::default();
    assert!(matches!(
        validate_config(&config),
        Err(ConfigValidationError::EmptyUuid)
    ));

    let mut config = valid_config();
    config.token.clear();
    assert!(matches!(
        validate_config(&config),
        Err(ConfigValidationError::EmptyApiToken)
    ));
}

#[test]
fn rejects_relative_paths() {
    let mut config = valid_config();
    config.paths.data = "relative".to_string();

    let error = validate_config(&config).unwrap_err();

    assert!(matches!(
        error,
        ConfigValidationError::UnsafeRuntimePath(HostPathPolicyError::Relative { .. })
    ));
}

#[test]
fn rejects_invalid_pids_limits() {
    let mut config = valid_config();
    config.security.pids_limit = 0;

    let error = validate_config(&config).unwrap_err();

    assert!(matches!(
        error,
        ConfigValidationError::InvalidSecurityLimit {
            field: "pids_limit"
        }
    ));

    let mut config = valid_config();
    config.security.pids_limits.clickhouse = Some(-1);

    let error = validate_config(&config).unwrap_err();

    assert!(matches!(
        error,
        ConfigValidationError::InvalidSecurityLimit {
            field: "pids_limits.clickhouse"
        }
    ));
}

#[test]
fn remote_import_security_defaults_are_valid() {
    let config = valid_config();

    validate_config(&config).unwrap();

    let remote = &config.security.remote_import;
    assert!(remote.enabled);
    assert!(!remote.allow_plaintext);
    assert!(remote.allowed_private_hosts.is_empty());
    assert_eq!(remote.max_concurrent_jobs, 4);
    assert_eq!(remote.connect_timeout_seconds, 15);
    assert_eq!(remote.operation_timeout_seconds, 900);
    assert_eq!(remote.max_staged_bytes, 8 * 1024 * 1024 * 1024);
}

#[test]
fn rejects_out_of_range_remote_import_limits() {
    for value in [0, 65] {
        let mut config = valid_config();
        config.security.remote_import.max_concurrent_jobs = value;
        assert!(matches!(
            validate_config(&config).unwrap_err(),
            ConfigValidationError::InvalidRemoteImportLimit {
                field: "max_concurrent_jobs",
                ..
            }
        ));
    }

    for value in [0, MAX_REMOTE_IMPORT_CONNECT_TIMEOUT_SECONDS + 1] {
        let mut config = valid_config();
        config.security.remote_import.connect_timeout_seconds = value;
        assert!(matches!(
            validate_config(&config).unwrap_err(),
            ConfigValidationError::InvalidRemoteImportLimit {
                field: "connect_timeout_seconds",
                ..
            }
        ));
    }

    for value in [0, MAX_REMOTE_IMPORT_OPERATION_TIMEOUT_SECONDS + 1] {
        let mut config = valid_config();
        config.security.remote_import.operation_timeout_seconds = value;
        assert!(matches!(
            validate_config(&config).unwrap_err(),
            ConfigValidationError::InvalidRemoteImportLimit {
                field: "operation_timeout_seconds",
                ..
            }
        ));
    }

    for value in [0, MAX_REMOTE_IMPORT_STAGED_BYTES + 1] {
        let mut config = valid_config();
        config.security.remote_import.max_staged_bytes = value;
        assert!(matches!(
            validate_config(&config).unwrap_err(),
            ConfigValidationError::InvalidRemoteImportLimit {
                field: "max_staged_bytes",
                ..
            }
        ));
    }
}

#[test]
fn remote_import_operation_timeout_must_cover_connect_timeout() {
    let mut config = valid_config();
    config.security.remote_import.connect_timeout_seconds = 30;
    config.security.remote_import.operation_timeout_seconds = 29;

    assert!(matches!(
        validate_config(&config).unwrap_err(),
        ConfigValidationError::InvalidRemoteImportTimeoutOrder
    ));
}

#[test]
fn validates_remote_import_private_host_allowlist_syntax() {
    let mut config = valid_config();
    config.security.remote_import.allowed_private_hosts = vec![
        "db.internal.example".to_string(),
        "10.20.30.40".to_string(),
        "[fd00::1234]".to_string(),
    ];
    validate_config(&config).unwrap();

    for invalid in [
        "",
        "https://db.internal",
        "db.internal/path",
        "db_name.internal",
        "-db.internal",
        "db..internal",
        "127.1",
        "2130706433",
        "0x7f.0.0.1",
    ] {
        let mut config = valid_config();
        config.security.remote_import.allowed_private_hosts = vec![invalid.to_string()];
        assert!(matches!(
            validate_config(&config).unwrap_err(),
            ConfigValidationError::InvalidRemoteImportHost { .. }
        ));
    }
}

#[test]
fn rejects_zero_or_unrepresentable_allocation_limits() {
    let mut config = valid_config();
    config.allocation.max_memory_mib = Some(0);
    assert!(matches!(
        validate_config(&config).unwrap_err(),
        ConfigValidationError::InvalidAllocationLimit {
            field: "max_memory_mib"
        }
    ));

    let mut config = valid_config();
    config.allocation.reserved_disk_mib = u64::MAX;
    assert!(matches!(
        validate_config(&config).unwrap_err(),
        ConfigValidationError::InvalidAllocationLimit {
            field: "reserved_disk_mib"
        }
    ));
}

#[test]
fn accepts_zero_allocation_reserves() {
    let mut config = valid_config();
    config.allocation.reserved_memory_mib = 0;
    config.allocation.reserved_disk_mib = 0;

    validate_config(&config).unwrap();
}

#[test]
fn rejects_api_self_upgrade() {
    let mut config = valid_config();
    config.security.self_upgrade_enabled = true;

    assert!(matches!(
        validate_config(&config).unwrap_err(),
        ConfigValidationError::UnsupportedSelfUpgrade
    ));
}

#[test]
fn rejects_weak_or_placeholder_secrets() {
    let mut config = valid_config();
    config.token = "short-token".to_string();
    assert!(matches!(
        validate_config(&config).unwrap_err(),
        ConfigValidationError::WeakApiToken
    ));

    let mut config = valid_config();
    config.token = "REPLACE_WITH_32_BYTE_RANDOM_API_TOKEN".to_string();
    assert!(matches!(
        validate_config(&config).unwrap_err(),
        ConfigValidationError::PlaceholderApiToken
    ));

    let mut config = valid_config();
    config.jwt_signing_key = "REPLACE_WITH_32_BYTE_RANDOM_JWT_SIGNING_KEY".to_string();
    assert!(matches!(
        validate_config(&config).unwrap_err(),
        ConfigValidationError::PlaceholderJwtSigningKey
    ));
}

#[test]
fn rejects_reusing_api_token_as_jwt_signing_key() {
    let mut config = valid_config();
    config.jwt_signing_key = config.token.clone();

    assert!(matches!(
        validate_config(&config).unwrap_err(),
        ConfigValidationError::ReusedJwtSigningKey
    ));
}

#[test]
fn accepts_authenticated_database_gateways_on_public_cleartext_binds() {
    let mut config = valid_config();
    config.postgres.bind = "0.0.0.0:5432".to_string();
    config.mariadb.bind = "0.0.0.0:3306".to_string();
    config.redis.bind = "0.0.0.0:6379".to_string();
    config.valkey.enabled = true;
    config.valkey.bind = "0.0.0.0:6381".to_string();
    config.mongodb.bind = "0.0.0.0:27017".to_string();
    config.clickhouse.bind = "0.0.0.0:9000".to_string();
    config.clickhouse.http_bind = "0.0.0.0:8123".to_string();
    config.qdrant.bind = "0.0.0.0:6334".to_string();
    validate_config(&config).unwrap();
}

#[test]
fn accepts_public_api_with_plain_http_or_native_tls() {
    let mut config = valid_config();
    config.api.host = "0.0.0.0".to_string();
    validate_config(&config).unwrap();

    let directory = tempfile::tempdir().unwrap();
    let certificate = directory.path().join("certificate.pem");
    let private_key = directory.path().join("private-key.pem");
    std::fs::write(&certificate, b"test certificate").unwrap();
    std::fs::write(&private_key, b"test key").unwrap();
    config.api.ssl.enabled = true;
    config.api.ssl.cert = certificate.display().to_string();
    config.api.ssl.key = private_key.display().to_string();
    validate_config(&config).unwrap();
}

#[test]
fn accepts_supported_hostname_and_loopback_api_binds() {
    for host in ["localhost", "dbe.internal", "127.0.0.1", "::1"] {
        let mut config = valid_config();
        config.api.host = host.to_string();

        validate_config(&config).unwrap();
    }
}

#[test]
fn accepts_exposed_listeners_when_tls_is_configured() {
    let directory = tempfile::tempdir().unwrap();
    let certificate = directory.path().join("certificate.pem");
    let private_key = directory.path().join("private-key.pem");
    std::fs::write(&certificate, b"test certificate").unwrap();
    std::fs::write(&private_key, b"test key").unwrap();

    let mut config = valid_config();
    config.api.ssl.enabled = true;
    config.api.ssl.cert = certificate.display().to_string();
    config.api.ssl.key = private_key.display().to_string();
    config.postgres.bind = "0.0.0.0:5432".to_string();
    config.postgres.tls = true;
    config.tls.cert = certificate.display().to_string();
    config.tls.key = private_key.display().to_string();

    validate_config(&config).unwrap();
}

#[test]
fn container_engine_socket_path_must_be_absolute() {
    let mut config = valid_config();
    config.daemon.socket_path = "/run/podman/podman.sock".to_string();

    validate_config(&config).unwrap();
    config.daemon.socket_path = "podman.sock".to_string();

    let error = validate_config(&config).unwrap_err();

    assert!(matches!(
        error,
        ConfigValidationError::RelativePath {
            field: "daemon.socket_path",
            ..
        }
    ));
}

#[test]
fn accepts_s3_backup_storage_with_configured_credentials() {
    let mut config = valid_config();
    config.backups.storage.driver = BackupStorageDriver::S3;
    config.backups.storage.s3.bucket = "node-backups".to_string();
    config.backups.storage.s3.region = "eu-central-1".to_string();
    config.backups.storage.s3.access_key_id = "test-access-key".to_string();
    config.backups.storage.s3.secret_access_key =
        crate::config::SensitiveString("test-secret-key".to_string());

    validate_config(&config).unwrap();
}

#[test]
fn s3_plaintext_endpoint_requires_explicit_opt_in() {
    let mut config = valid_config();
    config.backups.storage.driver = BackupStorageDriver::S3;
    config.backups.storage.s3.bucket = "node-backups".to_string();
    config.backups.storage.s3.endpoint = "http://127.0.0.1:9000".to_string();
    config.backups.storage.s3.access_key_id = "test-access-key".to_string();
    config.backups.storage.s3.secret_access_key =
        crate::config::SensitiveString("test-secret-key".to_string());

    assert!(matches!(
        validate_config(&config).unwrap_err(),
        ConfigValidationError::InvalidBackupConfig {
            field: "storage.s3.endpoint",
            ..
        }
    ));
    config.backups.storage.s3.allow_http = true;
    validate_config(&config).unwrap();
}

#[test]
fn identifies_mongodb_8_images_and_incompatible_kernels() {
    assert!(!kernel_is_6_19_or_newer("6.18.20"));
    assert!(kernel_is_6_19_or_newer("6.19.0"));
    assert!(kernel_is_6_19_or_newer("7.0.12-1-cachyos"));
    assert!(!mongodb_image_is_8_or_newer("mongo:7.0.37"));
    assert!(mongodb_image_is_8_or_newer("mongo:8.3.4"));
    assert!(mongodb_image_is_8_or_newer(
        "mongo:8.3.4@sha256:0f887198e29c093fd2b36c3e2eb43c7b98e47c081d89fbd5bc212da0cd43ec58"
    ));
    assert!(mongodb_image_is_8_or_newer("mongo:latest"));
    assert!(mongodb_image_is_8_or_newer("docker.io/library/mongo:8"));
}

#[test]
fn accepts_normal_version_tags_and_rejects_unversioned_runtime_images() {
    let mut config = valid_config();
    config.images.clickhouse = "clickhouse/clickhouse-server:26.4.4.38".to_string();
    config.images.postgres = "ghcr.io/example/postgres:18.4".to_string();
    validate_config(&config).unwrap();

    let mut config = valid_config();
    config.images.qdrant = "qdrant/qdrant".to_string();

    let error = validate_config(&config).unwrap_err();

    assert!(matches!(
        error,
        ConfigValidationError::InvalidImageReference {
            field: "images.qdrant",
            ..
        }
    ));
}

#[test]
fn accepts_normal_allowed_tags_and_rejects_latest() {
    let mut config = valid_config();
    config.images.allowed.postgres = vec!["postgres:18.4".to_string()];
    validate_config(&config).unwrap();

    let mut config = valid_config();
    config.images.allowed.postgres = vec!["postgres:latest".to_string()];

    let error = validate_config(&config).unwrap_err();

    assert!(matches!(
        error,
        ConfigValidationError::InvalidImageReference {
            field: "images.allowed.postgres",
            ..
        }
    ));
}

#[test]
fn rejects_zero_project_id_base() {
    let mut config = valid_config();
    config.disk.project_id_base = 0;

    let error = validate_config(&config).unwrap_err();

    assert!(matches!(error, ConfigValidationError::InvalidProjectIdBase));
}

#[test]
fn validates_hybrid_soft_scanner_bounds() {
    let mut config = valid_config();
    config.disk.soft_scanner.scan_interval_seconds = 30;
    config.disk.soft_scanner.full_scan_interval_seconds = 30;
    config.disk.soft_scanner.inotify_debounce_milliseconds = 0;
    assert!(matches!(
        validate_config(&config),
        Err(ConfigValidationError::InvalidSoftDiskScanner {
            field: "inotify_debounce_milliseconds"
        })
    ));

    config.disk.soft_scanner.inotify_debounce_milliseconds = 500;
    config.disk.soft_scanner.max_dirty_paths_per_instance = 0;
    assert!(matches!(
        validate_config(&config),
        Err(ConfigValidationError::InvalidSoftDiskScanner {
            field: "max_dirty_paths_per_instance"
        })
    ));

    config.disk.soft_scanner.max_dirty_paths_per_instance = 512;
    validate_config(&config).unwrap();

    // Older configurations could set a longer base interval before the
    // hybrid full-scan field existed. Runtime normalization uses the
    // greater interval instead of rejecting that valid configuration.
    config.disk.soft_scanner.scan_interval_seconds = 3_600;
    config.disk.soft_scanner.full_scan_interval_seconds = 90;
    validate_config(&config).unwrap();
}

#[test]
fn external_fuse_helper_requires_absolute_path_and_sha256() {
    let mut config = valid_config();
    config.disk.fuse_quota_binary = "bin/fusequota".to_string();
    config.disk.fuse_quota_binary_sha256 = "a".repeat(64);

    assert!(matches!(
        validate_config(&config).unwrap_err(),
        ConfigValidationError::RelativePath {
            field: "disk.fuse_quota_binary",
            ..
        }
    ));

    config.disk.fuse_quota_binary = "/usr/local/libexec/fusequota".to_string();
    config.disk.fuse_quota_binary_sha256 = "A".repeat(64);
    assert!(matches!(
        validate_config(&config).unwrap_err(),
        ConfigValidationError::InvalidFuseQuotaBinarySha256
    ));

    config.disk.fuse_quota_binary_sha256 = "a".repeat(64);
    validate_config(&config).unwrap();
}

#[test]
fn rejects_trusted_origins_with_paths_or_unsupported_schemes() {
    for origin in [
        "https://panel.example.com/path",
        "https://panel.example.com?query=1",
        "ftp://panel.example.com",
        "https://user@panel.example.com",
        "https://panel.example.com:not-a-port",
        "https://panel.example.com:99999",
        "panel.example.com",
    ] {
        let mut config = valid_config();
        config.api.trusted_origins = vec![origin.to_string()];

        assert!(matches!(
            validate_config(&config),
            Err(ConfigValidationError::InvalidApiOrigin { .. })
        ));
    }
}

#[test]
fn rejects_url_shaped_api_host() {
    let mut config = valid_config();
    config.api.host = "https://dbe.example.com".to_string();

    let error = validate_config(&config).unwrap_err();

    assert!(matches!(
        error,
        ConfigValidationError::InvalidApiHost { .. }
    ));
}

#[test]
fn rejects_invalid_remote() {
    let mut config = valid_config();
    config.remote = "panel.example.com".to_string();

    let error = validate_config(&config).unwrap_err();

    assert!(matches!(error, ConfigValidationError::InvalidRemoteUrl));
}

#[test]
fn rejects_unsafe_import_upload_limits() {
    for maximum in [0, 10_001] {
        let mut config = valid_config();
        config.artifacts.max_artifacts_per_instance = maximum;
        assert!(matches!(
            validate_config(&config),
            Err(ConfigValidationError::InvalidImportUploadConfig {
                field: "max_artifacts_per_instance"
            })
        ));
    }

    let mut config = valid_config();
    config.artifacts.import_upload_max_total_bytes = config.artifacts.import_upload_max_bytes - 1;
    assert!(matches!(
        validate_config(&config),
        Err(ConfigValidationError::InvalidImportUploadConfig {
            field: "import_upload_max_total_bytes"
        })
    ));

    let mut config = valid_config();
    config.artifacts.import_upload_idle_timeout_seconds =
        config.artifacts.import_upload_timeout_seconds + 1;
    assert!(matches!(
        validate_config(&config),
        Err(ConfigValidationError::InvalidImportUploadConfig {
            field: "import_upload_idle_timeout_seconds"
        })
    ));
}

fn valid_config() -> Config {
    Config {
        uuid: "node-uuid".to_string(),
        token_id: "token-id".to_string(),
        token: "test-api-token-0123456789abcdef-01".to_string(),
        jwt_signing_key: "test-jwt-signing-key-0123456789abcdef-02".to_string(),
        remote: "https://panel.example.com".to_string(),
        ..Default::default()
    }
}
