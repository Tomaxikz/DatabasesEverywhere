use std::{net::SocketAddr, path::Path};

use super::{
    ApiSslConfig, BackupStorageDriver, ClickhouseConfig, Config, ListenerConfig, TlsConfig,
    path_policy::{HostPathPolicy, HostPathPolicyError},
};
use crate::shared::images::is_pinned_image_reference;

mod api;
mod artifact_policy;
mod import_export_scheduler;

use api::{validate_api_host, validate_api_hosts};

const MAX_REMOTE_IMPORT_JOBS: usize = 64;
const MAX_REMOTE_IMPORT_CONNECT_TIMEOUT_SECONDS: u64 = 5 * 60;
const MAX_REMOTE_IMPORT_OPERATION_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;
// Container upload/download operations use the same hard ceiling. Keeping the
// configurable bound at or below it prevents a remote acquisition from
// succeeding only to fail deterministically during target staging.
const MAX_REMOTE_IMPORT_STAGED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_BACKUP_CATALOG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ConfigValidationError {
    #[error("uuid must not be empty")]
    EmptyUuid,
    #[error("token_id must not be empty")]
    EmptyTokenId,
    #[error("token must not be empty")]
    EmptyApiToken,
    #[error("token must contain at least 32 bytes of secret material")]
    WeakApiToken,
    #[error("token must be replaced with a randomly generated production secret")]
    PlaceholderApiToken,
    #[error("jwt_signing_key must not be empty")]
    EmptyJwtSigningKey,
    #[error("jwt_signing_key must contain at least 32 bytes of secret material")]
    WeakJwtSigningKey,
    #[error("jwt_signing_key must be replaced with a randomly generated production secret")]
    PlaceholderJwtSigningKey,
    #[error("jwt_signing_key must be different from token")]
    ReusedJwtSigningKey,
    #[error("remote must be a full URL such as https://panel.example.com")]
    InvalidRemoteUrl,
    #[error("api.host must be a host or IP address, not a URL/path: {value}")]
    InvalidApiHost { value: String },
    #[error(
        "api.fqdn must be a fully qualified DNS hostname without a scheme, port, path, wildcard, or trailing dot: {value}"
    )]
    InvalidApiFqdn { value: String },
    #[error("api.fqdn is required when api.host binds all interfaces")]
    MissingApiFqdn,
    #[error(
        "api.trusted_origins must contain only HTTP(S) origins without paths, queries, or credentials: {value}"
    )]
    InvalidApiOrigin { value: String },
    #[error("{field} bind address is invalid: {value}")]
    InvalidBind { field: &'static str, value: String },
    #[error("{field} must be an absolute path: {value}")]
    RelativePath { field: &'static str, value: String },
    #[error("{field} must not contain parent directory segments: {value}")]
    ParentPath { field: &'static str, value: String },
    #[error(transparent)]
    UnsafeRuntimePath(#[from] HostPathPolicyError),
    #[error("{field} TLS requires both cert and key")]
    IncompleteTls { field: &'static str },
    #[error("{field} TLS cert does not exist: {path}")]
    MissingTlsCert { field: &'static str, path: String },
    #[error("{field} TLS key does not exist: {path}")]
    MissingTlsKey { field: &'static str, path: String },
    #[error("api.ssl.require_client_cert requires api.ssl.enabled=true")]
    ClientCertRequiresApiTls,
    #[error("api.ssl.require_client_cert requires api.ssl.client_ca")]
    MissingClientCa,
    #[error("api.ssl.client_ca does not exist: {path}")]
    MissingClientCaFile { path: String },
    #[error("security.{field} must be greater than zero")]
    InvalidSecurityLimit { field: &'static str },
    #[error("security.remote_import.{field} must be between {minimum} and {maximum}, inclusive")]
    InvalidRemoteImportLimit {
        field: &'static str,
        minimum: u64,
        maximum: u64,
    },
    #[error(
        "security.remote_import.operation_timeout_seconds must be greater than or equal to connect_timeout_seconds"
    )]
    InvalidRemoteImportTimeoutOrder,
    #[error(
        "security.remote_import.allowed_private_hosts contains an invalid host name or IP address: {value}"
    )]
    InvalidRemoteImportHost { value: String },
    #[error(
        "allocation.{field} must fit in bytes, and configured maxima must be greater than zero"
    )]
    InvalidAllocationLimit { field: &'static str },
    #[error(
        "security.self_upgrade_enabled is unsupported; deploy upgrades through a signed package or immutable container image"
    )]
    UnsupportedSelfUpgrade,
    #[error("disk.project_id_base must be greater than zero for automatic native quota detection")]
    InvalidProjectIdBase,
    #[error(
        "disk.fuse_quota_binary_sha256 must be the lowercase 64-character SHA-256 of the configured external helper"
    )]
    InvalidFuseQuotaBinarySha256,
    #[error("disk.soft_scanner.{field} is outside the supported range")]
    InvalidSoftDiskScanner { field: &'static str },
    #[error("artifacts.retention_keep_latest must be greater than zero")]
    InvalidArtifactRetention,
    #[error("artifacts.{field} is outside the supported range")]
    InvalidImportUploadConfig { field: &'static str },
    #[error("artifacts.import_export_scheduler.{field} is outside the supported range")]
    InvalidImportExportSchedulerConfig { field: &'static str },
    #[error("backups.interval_minutes must be greater than zero")]
    InvalidBackupInterval,
    #[error("backups.retention_keep_latest_per_instance must be greater than zero")]
    InvalidBackupRetentionKeepLatest,
    #[error("backups.{field} is invalid: {message}")]
    InvalidBackupConfig {
        field: &'static str,
        message: String,
    },
    #[error("{field} must include a non-latest tag or valid sha256 digest: {image}")]
    InvalidImageReference { field: &'static str, image: String },
    #[error(
        "images.mongodb={image} is not compatible with Linux kernel {kernel}; MongoDB 8.0+ is affected by SERVER-121912 on kernel 6.19+"
    )]
    MongodbKernelIncompatible { image: String, kernel: String },
}

pub fn validate_config(config: &Config) -> Result<(), ConfigValidationError> {
    if config.uuid.trim().is_empty() {
        return Err(ConfigValidationError::EmptyUuid);
    }
    if config.token_id.trim().is_empty() {
        return Err(ConfigValidationError::EmptyTokenId);
    }
    validate_api_token(&config.token)?;
    validate_jwt_signing_key(&config.jwt_signing_key, &config.token)?;

    validate_api_host(&config.api.host)?;
    validate_api_hosts(config)?;
    validate_listener("postgres", &config.postgres, &config.tls)?;
    validate_listener("mariadb", &config.mariadb, &config.tls)?;
    validate_listener("mysql", &config.mysql, &config.tls)?;
    validate_listener("redis", &config.redis, &config.tls)?;
    validate_listener("valkey", &config.valkey, &config.tls)?;
    validate_listener("mongodb", &config.mongodb, &config.tls)?;
    validate_clickhouse(&config.clickhouse, &config.tls)?;
    validate_listener("qdrant", &config.qdrant, &config.tls)?;
    validate_api_tls(&config.api.ssl)?;
    validate_security(&config.security)?;
    validate_allocation(&config.allocation)?;
    validate_disk(&config.disk)?;
    if config.artifacts.retention_keep_latest == 0 {
        return Err(ConfigValidationError::InvalidArtifactRetention);
    }
    validate_import_uploads(&config.artifacts)?;
    if config.backups.interval_minutes == 0 {
        return Err(ConfigValidationError::InvalidBackupInterval);
    }
    if config.backups.retention_keep_latest_per_instance == 0 {
        return Err(ConfigValidationError::InvalidBackupRetentionKeepLatest);
    }
    validate_backups(config)?;

    if let Some(socket_path) = config.daemon.configured_socket_path() {
        validate_absolute_path("daemon.socket_path", socket_path)?;
    }

    HostPathPolicy::validate(&config.paths)?;
    validate_images(&config.images)?;
    validate_mongodb_kernel_compatibility(&config.images.mongodb)?;

    Ok(())
}

fn validate_import_uploads(
    artifacts: &crate::config::ArtifactConfig,
) -> Result<(), ConfigValidationError> {
    let invalid = |field| ConfigValidationError::InvalidImportUploadConfig { field };
    artifact_policy::validate(artifacts)?;
    if artifacts.import_upload_max_bytes == 0
        || artifacts.import_upload_max_bytes > 8 * 1024 * 1024 * 1024
    {
        return Err(invalid("import_upload_max_bytes"));
    }
    if artifacts.import_upload_max_total_bytes < artifacts.import_upload_max_bytes
        || artifacts.import_upload_max_total_bytes > i64::MAX as u64
    {
        return Err(invalid("import_upload_max_total_bytes"));
    }
    if !(1..=64).contains(&artifacts.import_upload_max_per_instance) {
        return Err(invalid("import_upload_max_per_instance"));
    }
    if !(1..=32).contains(&artifacts.import_upload_max_concurrent) {
        return Err(invalid("import_upload_max_concurrent"));
    }
    if !(1..=168).contains(&artifacts.import_upload_ttl_hours) {
        return Err(invalid("import_upload_ttl_hours"));
    }
    if !(60..=86_400).contains(&artifacts.import_upload_timeout_seconds) {
        return Err(invalid("import_upload_timeout_seconds"));
    }
    if !(5..=300).contains(&artifacts.import_upload_idle_timeout_seconds) {
        return Err(invalid("import_upload_idle_timeout_seconds"));
    }
    if artifacts.import_upload_idle_timeout_seconds > artifacts.import_upload_timeout_seconds {
        return Err(invalid("import_upload_idle_timeout_seconds"));
    }
    import_export_scheduler::validate(artifacts)?;
    Ok(())
}

fn validate_backups(config: &Config) -> Result<(), ConfigValidationError> {
    let browsing = &config.backups.browsing;
    if browsing.max_objects == 0 || browsing.max_objects > 1_000 {
        return invalid_backup("browsing.max_objects", "must be between 1 and 1000");
    }
    if browsing.max_preview_objects > browsing.max_objects {
        return invalid_backup(
            "browsing.max_preview_objects",
            "must not exceed browsing.max_objects",
        );
    }
    if browsing.preview_rows_per_object > 100 {
        return invalid_backup("browsing.preview_rows_per_object", "must not exceed 100");
    }
    if !(256..=16 * 1024).contains(&browsing.max_row_bytes) {
        return invalid_backup("browsing.max_row_bytes", "must be between 256 and 16384");
    }
    if !(64 * 1024..=MAX_BACKUP_CATALOG_BYTES).contains(&browsing.max_catalog_bytes) {
        return invalid_backup(
            "browsing.max_catalog_bytes",
            "must be between 65536 and 1048576",
        );
    }

    match config.backups.storage.driver {
        BackupStorageDriver::Local => Ok(()),
        BackupStorageDriver::S3 => validate_s3_backup(&config.backups.storage.s3),
        BackupStorageDriver::Kopia => validate_kopia_backup(&config.backups.storage.kopia),
    }
}

fn validate_s3_backup(s3: &crate::config::BackupS3Config) -> Result<(), ConfigValidationError> {
    let bucket = s3.bucket.trim();
    if bucket.len() < 3
        || bucket.len() > 63
        || bucket.starts_with('.')
        || bucket.starts_with('-')
        || bucket.ends_with('.')
        || bucket.ends_with('-')
        || !bucket.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
    {
        return invalid_backup(
            "storage.s3.bucket",
            "must be a valid lowercase S3 bucket name",
        );
    }
    if s3.region.trim().is_empty()
        || !s3
            .region
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return invalid_backup("storage.s3.region", "contains unsupported characters");
    }
    validate_s3_prefix(&s3.prefix)?;
    if s3.request_timeout_seconds == 0 || s3.request_timeout_seconds > 24 * 60 * 60 {
        return invalid_backup(
            "storage.s3.request_timeout_seconds",
            "must be between 1 and 86400",
        );
    }
    if s3.max_retries > 10 {
        return invalid_backup("storage.s3.max_retries", "must not exceed 10");
    }
    if s3.access_key_id.trim().is_empty() != s3.secret_access_key.expose().trim().is_empty() {
        return invalid_backup(
            "storage.s3 credentials",
            "access_key_id and secret_access_key must be configured together",
        );
    }
    if !s3.endpoint.trim().is_empty() {
        let endpoint = reqwest::Url::parse(s3.endpoint.trim()).map_err(|_| {
            ConfigValidationError::InvalidBackupConfig {
                field: "storage.s3.endpoint",
                message: "must be a full HTTP(S) URL".to_string(),
            }
        })?;
        if endpoint.scheme() != "https" && !(endpoint.scheme() == "http" && s3.allow_http) {
            return invalid_backup(
                "storage.s3.endpoint",
                "must use HTTPS unless allow_http is explicitly enabled",
            );
        }
        if endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return invalid_backup(
                "storage.s3.endpoint",
                "must have a host and may not contain credentials, a query, or a fragment",
            );
        }
    }
    Ok(())
}

fn validate_s3_prefix(prefix: &str) -> Result<(), ConfigValidationError> {
    let prefix = prefix.trim_matches('/');
    if prefix.is_empty() {
        return Ok(());
    }
    if prefix.len() > 512
        || prefix.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.contains('\\')
                || part.bytes().any(|byte| byte.is_ascii_control())
        })
    {
        return invalid_backup(
            "storage.s3.prefix",
            "must contain only non-empty, normalized key segments",
        );
    }
    Ok(())
}

fn validate_kopia_backup(
    kopia: &crate::config::BackupKopiaConfig,
) -> Result<(), ConfigValidationError> {
    validate_absolute_path("backups.storage.kopia.executable", &kopia.executable)?;
    if !kopia.config_file.trim().is_empty() {
        validate_absolute_path("backups.storage.kopia.config_file", &kopia.config_file)?;
    }
    if kopia.operation_timeout_seconds == 0 || kopia.operation_timeout_seconds > 24 * 60 * 60 {
        return invalid_backup(
            "storage.kopia.operation_timeout_seconds",
            "must be between 1 and 86400",
        );
    }
    Ok(())
}

fn invalid_backup<T>(
    field: &'static str,
    message: impl Into<String>,
) -> Result<T, ConfigValidationError> {
    Err(ConfigValidationError::InvalidBackupConfig {
        field,
        message: message.into(),
    })
}

fn validate_allocation(
    allocation: &crate::config::AllocationConfig,
) -> Result<(), ConfigValidationError> {
    for (field, value) in [
        ("max_memory_mib", allocation.max_memory_mib),
        ("max_disk_mib", allocation.max_disk_mib),
    ] {
        if value.is_some_and(|value| value == 0 || value.checked_mul(1024 * 1024).is_none()) {
            return Err(ConfigValidationError::InvalidAllocationLimit { field });
        }
    }
    for (field, value) in [
        ("reserved_memory_mib", allocation.reserved_memory_mib),
        ("reserved_disk_mib", allocation.reserved_disk_mib),
    ] {
        if value.checked_mul(1024 * 1024).is_none() {
            return Err(ConfigValidationError::InvalidAllocationLimit { field });
        }
    }
    Ok(())
}

fn validate_api_token(token: &str) -> Result<(), ConfigValidationError> {
    if token.trim().is_empty() {
        return Err(ConfigValidationError::EmptyApiToken);
    }
    if token.trim().len() < 32 {
        return Err(ConfigValidationError::WeakApiToken);
    }
    if looks_like_placeholder(token) {
        return Err(ConfigValidationError::PlaceholderApiToken);
    }
    Ok(())
}

fn validate_jwt_signing_key(key: &str, api_token: &str) -> Result<(), ConfigValidationError> {
    if key.trim().is_empty() {
        return Err(ConfigValidationError::EmptyJwtSigningKey);
    }
    if key.trim().len() < 32 {
        return Err(ConfigValidationError::WeakJwtSigningKey);
    }
    if looks_like_placeholder(key) {
        return Err(ConfigValidationError::PlaceholderJwtSigningKey);
    }
    if key.as_bytes() == api_token.as_bytes() {
        return Err(ConfigValidationError::ReusedJwtSigningKey);
    }
    Ok(())
}

fn looks_like_placeholder(secret: &str) -> bool {
    let normalized = secret.trim().to_ascii_lowercase();
    normalized.contains("change-me")
        || normalized.contains("changeme")
        || normalized.contains("replace_with")
        || normalized.contains("replace-with")
        || normalized.contains("generated-by-panel")
        || normalized
            .as_bytes()
            .first()
            .is_some_and(|first| normalized.bytes().all(|byte| byte == *first))
}

fn validate_images(images: &crate::config::ImageConfig) -> Result<(), ConfigValidationError> {
    for (field, image) in [
        ("images.postgres", images.postgres.as_str()),
        ("images.redis", images.redis.as_str()),
        ("images.valkey", images.valkey.as_str()),
        ("images.mariadb", images.mariadb.as_str()),
        ("images.mysql", images.mysql.as_str()),
        ("images.mongodb", images.mongodb.as_str()),
        ("images.clickhouse", images.clickhouse.as_str()),
        ("images.qdrant", images.qdrant.as_str()),
    ] {
        validate_image_reference(field, image)?;
    }
    for (field, allowed) in [
        (
            "images.allowed.postgres",
            images.allowed.postgres.as_slice(),
        ),
        ("images.allowed.redis", images.allowed.redis.as_slice()),
        ("images.allowed.valkey", images.allowed.valkey.as_slice()),
        ("images.allowed.mariadb", images.allowed.mariadb.as_slice()),
        ("images.allowed.mysql", images.allowed.mysql.as_slice()),
        ("images.allowed.mongodb", images.allowed.mongodb.as_slice()),
        (
            "images.allowed.clickhouse",
            images.allowed.clickhouse.as_slice(),
        ),
        ("images.allowed.qdrant", images.allowed.qdrant.as_slice()),
    ] {
        for image in allowed {
            validate_image_reference(field, image)?;
        }
    }
    Ok(())
}

fn validate_image_reference(field: &'static str, image: &str) -> Result<(), ConfigValidationError> {
    let image = image.trim();
    if image.is_empty() || image.chars().any(char::is_whitespace) {
        return Err(ConfigValidationError::InvalidImageReference {
            field,
            image: image.to_string(),
        });
    }
    if is_pinned_image_reference(image) {
        return Ok(());
    }
    Err(ConfigValidationError::InvalidImageReference {
        field,
        image: image.to_string(),
    })
}

fn validate_mongodb_kernel_compatibility(image: &str) -> Result<(), ConfigValidationError> {
    let Some(kernel) = linux_kernel_release() else {
        return Ok(());
    };
    if kernel_is_6_19_or_newer(&kernel) && mongodb_image_is_8_or_newer(image) {
        return Err(ConfigValidationError::MongodbKernelIncompatible {
            image: image.to_string(),
            kernel,
        });
    }
    Ok(())
}

fn linux_kernel_release() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn kernel_is_6_19_or_newer(release: &str) -> bool {
    let mut parts = release
        .split(|character: char| !character.is_ascii_digit())
        .filter(|part| !part.is_empty());
    let major = parts
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or_default();
    let minor = parts
        .next()
        .and_then(|part| part.parse::<u32>().ok())
        .unwrap_or_default();

    major > 6 || (major == 6 && minor >= 19)
}

fn mongodb_image_is_8_or_newer(image: &str) -> bool {
    let image = image.split_once('@').map_or(image, |(name, _)| name);
    let tag = image
        .rsplit_once(':')
        .filter(|(name, _)| !name.contains('/'))
        .map(|(_, tag)| tag)
        .or_else(|| {
            let (name, tag) = image.rsplit_once(':')?;
            if name.rsplit('/').next()?.contains(':') {
                None
            } else {
                Some(tag)
            }
        })
        .unwrap_or("latest");
    tag == "latest"
        || tag
            .split(|character: char| !character.is_ascii_digit())
            .next()
            .and_then(|major| major.parse::<u32>().ok())
            .is_some_and(|major| major >= 8)
}

fn validate_disk(disk: &crate::config::DiskConfig) -> Result<(), ConfigValidationError> {
    if disk.project_id_base == 0 {
        return Err(ConfigValidationError::InvalidProjectIdBase);
    }
    let binary = disk.fuse_quota_binary();
    if !binary.eq_ignore_ascii_case("embedded") {
        validate_absolute_path("disk.fuse_quota_binary", binary)?;
        let digest = disk.fuse_quota_binary_sha256.trim();
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ConfigValidationError::InvalidFuseQuotaBinarySha256);
        }
    }
    let scanner = &disk.soft_scanner;
    for (field, value, maximum) in [
        (
            "scan_interval_seconds",
            scanner.scan_interval_seconds,
            3_600,
        ),
        (
            "full_scan_interval_seconds",
            scanner.full_scan_interval_seconds,
            3_600,
        ),
        (
            "inotify_debounce_milliseconds",
            scanner.inotify_debounce_milliseconds,
            60_000,
        ),
        ("scan_timeout_seconds", scanner.scan_timeout_seconds, 3_600),
        (
            "shutdown_grace_seconds",
            scanner.shutdown_grace_seconds,
            300,
        ),
    ] {
        if value == 0 || value > maximum {
            return Err(ConfigValidationError::InvalidSoftDiskScanner { field });
        }
    }
    if scanner.max_dirty_paths_per_instance == 0 || scanner.max_dirty_paths_per_instance > 65_536 {
        return Err(ConfigValidationError::InvalidSoftDiskScanner {
            field: "max_dirty_paths_per_instance",
        });
    }
    if scanner.max_concurrent_scans == 0 || scanner.max_concurrent_scans > 64 {
        return Err(ConfigValidationError::InvalidSoftDiskScanner {
            field: "max_concurrent_scans",
        });
    }
    if scanner.max_entries_per_scan == 0 || scanner.max_entries_per_scan > 10_000_000 {
        return Err(ConfigValidationError::InvalidSoftDiskScanner {
            field: "max_entries_per_scan",
        });
    }
    if scanner.max_consecutive_scan_failures == 0 || scanner.max_consecutive_scan_failures > 10 {
        return Err(ConfigValidationError::InvalidSoftDiskScanner {
            field: "max_consecutive_scan_failures",
        });
    }
    if !(1..=99).contains(&scanner.recovery_percent) {
        return Err(ConfigValidationError::InvalidSoftDiskScanner {
            field: "recovery_percent",
        });
    }
    Ok(())
}

fn validate_listener(
    name: &'static str,
    listener: &ListenerConfig,
    tls: &TlsConfig,
) -> Result<(), ConfigValidationError> {
    if listener.enabled {
        validate_bind(name, &listener.bind)?;
    }
    if listener.tls {
        validate_tls_pair(name, &tls.cert, &tls.key)?;
    }
    Ok(())
}

fn validate_clickhouse(
    listener: &ClickhouseConfig,
    tls: &TlsConfig,
) -> Result<(), ConfigValidationError> {
    if listener.enabled {
        validate_bind("clickhouse", &listener.bind)?;
        validate_bind("clickhouse.http_bind", &listener.http_bind)?;
    }
    if listener.tls {
        validate_tls_pair("clickhouse", &tls.cert, &tls.key)?;
    }
    Ok(())
}

fn validate_api_tls(ssl: &ApiSslConfig) -> Result<(), ConfigValidationError> {
    if ssl.enabled {
        validate_tls_pair("api.ssl", &ssl.cert, &ssl.key)?;
    }
    if ssl.require_client_cert {
        if !ssl.enabled {
            return Err(ConfigValidationError::ClientCertRequiresApiTls);
        }
        if ssl.client_ca.trim().is_empty() {
            return Err(ConfigValidationError::MissingClientCa);
        }
        if !Path::new(&ssl.client_ca).exists() {
            return Err(ConfigValidationError::MissingClientCaFile {
                path: ssl.client_ca.clone(),
            });
        }
    }
    Ok(())
}

fn validate_security(
    security: &crate::config::SecurityConfig,
) -> Result<(), ConfigValidationError> {
    if security.self_upgrade_enabled {
        return Err(ConfigValidationError::UnsupportedSelfUpgrade);
    }
    if security.api_body_limit_bytes == 0 {
        return Err(ConfigValidationError::InvalidSecurityLimit {
            field: "api_body_limit_bytes",
        });
    }
    if security.api_rate_limit_per_minute == 0 {
        return Err(ConfigValidationError::InvalidSecurityLimit {
            field: "api_rate_limit_per_minute",
        });
    }
    if security.db_connection_limit_per_minute == 0 {
        return Err(ConfigValidationError::InvalidSecurityLimit {
            field: "db_connection_limit_per_minute",
        });
    }
    if security.pids_limit <= 0 {
        return Err(ConfigValidationError::InvalidSecurityLimit {
            field: "pids_limit",
        });
    }
    for (field, value) in [
        ("pids_limits.postgres", security.pids_limits.postgres),
        ("pids_limits.redis", security.pids_limits.redis),
        ("pids_limits.valkey", security.pids_limits.valkey),
        ("pids_limits.mariadb", security.pids_limits.mariadb),
        ("pids_limits.mysql", security.pids_limits.mysql),
        ("pids_limits.mongodb", security.pids_limits.mongodb),
        ("pids_limits.clickhouse", security.pids_limits.clickhouse),
        ("pids_limits.qdrant", security.pids_limits.qdrant),
    ] {
        if value.is_some_and(|value| value <= 0) {
            return Err(ConfigValidationError::InvalidSecurityLimit { field });
        }
    }
    validate_remote_import_security(&security.remote_import)?;
    Ok(())
}

fn validate_remote_import_security(
    remote: &crate::config::RemoteImportSecurityConfig,
) -> Result<(), ConfigValidationError> {
    validate_remote_import_limit(
        "max_concurrent_jobs",
        remote.max_concurrent_jobs as u64,
        1,
        MAX_REMOTE_IMPORT_JOBS as u64,
    )?;
    validate_remote_import_limit(
        "connect_timeout_seconds",
        remote.connect_timeout_seconds,
        1,
        MAX_REMOTE_IMPORT_CONNECT_TIMEOUT_SECONDS,
    )?;
    validate_remote_import_limit(
        "operation_timeout_seconds",
        remote.operation_timeout_seconds,
        1,
        MAX_REMOTE_IMPORT_OPERATION_TIMEOUT_SECONDS,
    )?;
    validate_remote_import_limit(
        "max_staged_bytes",
        remote.max_staged_bytes,
        1,
        MAX_REMOTE_IMPORT_STAGED_BYTES,
    )?;
    if remote.operation_timeout_seconds < remote.connect_timeout_seconds {
        return Err(ConfigValidationError::InvalidRemoteImportTimeoutOrder);
    }
    for host in &remote.allowed_private_hosts {
        if super::normalize_remote_import_host(host).is_none() {
            return Err(ConfigValidationError::InvalidRemoteImportHost {
                value: host.clone(),
            });
        }
    }
    Ok(())
}

fn validate_remote_import_limit(
    field: &'static str,
    value: u64,
    minimum: u64,
    maximum: u64,
) -> Result<(), ConfigValidationError> {
    if !(minimum..=maximum).contains(&value) {
        return Err(ConfigValidationError::InvalidRemoteImportLimit {
            field,
            minimum,
            maximum,
        });
    }
    Ok(())
}

fn validate_bind(field: &'static str, value: &str) -> Result<(), ConfigValidationError> {
    value
        .parse::<SocketAddr>()
        .map(|_| ())
        .map_err(|_| ConfigValidationError::InvalidBind {
            field,
            value: value.to_string(),
        })
}

fn validate_tls_pair(
    field: &'static str,
    cert: &str,
    key: &str,
) -> Result<(), ConfigValidationError> {
    if cert.trim().is_empty() || key.trim().is_empty() {
        return Err(ConfigValidationError::IncompleteTls { field });
    }
    if !Path::new(cert).exists() {
        return Err(ConfigValidationError::MissingTlsCert {
            field,
            path: cert.to_string(),
        });
    }
    if !Path::new(key).exists() {
        return Err(ConfigValidationError::MissingTlsKey {
            field,
            path: key.to_string(),
        });
    }
    Ok(())
}

fn validate_absolute_path(field: &'static str, value: &str) -> Result<(), ConfigValidationError> {
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(ConfigValidationError::RelativePath {
            field,
            value: value.to_string(),
        });
    }
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(ConfigValidationError::ParentPath {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn rejects_empty_api_token() {
        let config = Config::default();

        let error = validate_config(&config).unwrap_err();

        assert!(matches!(error, ConfigValidationError::EmptyUuid));
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
    fn accepts_simple_valid_config() {
        validate_config(&valid_config()).unwrap();
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
    fn rejects_missing_token() {
        let mut config = valid_config();
        config.token = String::new();

        let error = validate_config(&config).unwrap_err();

        assert!(matches!(error, ConfigValidationError::EmptyApiToken));
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
        config.api.fqdn = "db.example.com".to_string();
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
    fn accepts_hostname_api_bind_without_native_tls() {
        for host in ["localhost", "dbe.internal"] {
            let mut config = valid_config();
            config.api.host = host.to_string();

            validate_config(&config).unwrap();
        }
    }

    #[test]
    fn accepts_literal_ipv4_and_ipv6_loopback_api_binds() {
        for host in ["127.0.0.1", "::1"] {
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
    fn accepts_absolute_container_engine_socket_path() {
        let mut config = valid_config();
        config.daemon.socket_path = "/run/podman/podman.sock".to_string();

        validate_config(&config).unwrap();
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
    fn rejects_relative_container_engine_socket_path() {
        let mut config = valid_config();
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
    fn identifies_kernels_affected_by_mongodb_8_incompatibility() {
        assert!(!kernel_is_6_19_or_newer("6.18.20"));
        assert!(kernel_is_6_19_or_newer("6.19.0"));
        assert!(kernel_is_6_19_or_newer("7.0.12-1-cachyos"));
    }

    #[test]
    fn identifies_mongodb_8_or_latest_images() {
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
    fn accepts_remote_for_cors() {
        let mut config = valid_config();
        config.remote = "https://panel.example.com".to_string();

        validate_config(&config).unwrap();

        assert_eq!(config.api.bind_addr(), "127.0.0.1:8090");
        assert_eq!(
            config.cors_allowed_origins(),
            vec!["https://panel.example.com:443"]
        );
        assert_eq!(config.request_allowed_hosts(), vec!["127.0.0.1"]);
    }

    #[test]
    fn accepts_explicit_reverse_proxy_fqdn() {
        let mut config = valid_config();
        config.api.fqdn = "node.example.com".to_string();

        validate_config(&config).unwrap();

        assert!(
            config
                .request_allowed_hosts()
                .contains(&"node.example.com".to_string())
        );
    }

    #[test]
    fn accepts_and_normalizes_explicit_browser_origins() {
        let mut config = valid_config();
        config.api.trusted_origins = vec![
            "http://localhost:3000/".to_string(),
            "https://PANEL.example.com:443".to_string(),
        ];

        validate_config(&config).unwrap();

        assert_eq!(
            config.cors_allowed_origins(),
            vec!["https://panel.example.com:443", "http://localhost:3000"]
        );
        assert!(
            !config
                .request_allowed_hosts()
                .contains(&"localhost".to_string())
        );
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
    fn accepts_default_import_upload_limits() {
        validate_config(&valid_config()).unwrap();
    }

    #[test]
    fn rejects_unsafe_import_upload_limits() {
        let mut config = valid_config();
        config.artifacts.import_upload_max_total_bytes =
            config.artifacts.import_upload_max_bytes - 1;
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
}
