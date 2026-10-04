use super::{
    ConfigValidationError, MAX_BACKUP_CATALOG_BYTES, SECONDS_PER_DAY,
    network::validate_absolute_path,
};
use crate::config::{BackupStorageDriver, Config};

pub(super) fn validate_backups(config: &Config) -> Result<(), ConfigValidationError> {
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

pub(super) fn validate_s3_backup(
    s3: &crate::config::BackupS3Config,
) -> Result<(), ConfigValidationError> {
    if !is_valid_s3_bucket_name(s3.bucket.trim()) {
        return invalid_backup(
            "storage.s3.bucket",
            "must be a valid lowercase S3 bucket name",
        );
    }
    let region_has_valid_characters = s3
        .region
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    if s3.region.trim().is_empty() || !region_has_valid_characters {
        return invalid_backup("storage.s3.region", "contains unsupported characters");
    }
    validate_s3_prefix(&s3.prefix)?;
    if s3.request_timeout_seconds == 0 || s3.request_timeout_seconds > SECONDS_PER_DAY {
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
        validate_s3_endpoint(s3.endpoint.trim(), s3.allow_http)?;
    }
    Ok(())
}

pub(super) fn is_valid_s3_bucket_name(bucket: &str) -> bool {
    let has_valid_characters = bucket.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
    });
    (3..=63).contains(&bucket.len())
        && !bucket.starts_with('.')
        && !bucket.starts_with('-')
        && !bucket.ends_with('.')
        && !bucket.ends_with('-')
        && has_valid_characters
}

pub(super) fn validate_s3_endpoint(
    endpoint: &str,
    allow_http: bool,
) -> Result<(), ConfigValidationError> {
    let endpoint =
        reqwest::Url::parse(endpoint).map_err(|_| ConfigValidationError::InvalidBackupConfig {
            field: "storage.s3.endpoint",
            message: "must be a full HTTP(S) URL".to_string(),
        })?;
    let scheme_allowed =
        endpoint.scheme() == "https" || (endpoint.scheme() == "http" && allow_http);
    if !scheme_allowed {
        return invalid_backup(
            "storage.s3.endpoint",
            "must use HTTPS unless allow_http is explicitly enabled",
        );
    }
    let has_extra_parts = !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some();
    if endpoint.host_str().is_none() || has_extra_parts {
        return invalid_backup(
            "storage.s3.endpoint",
            "must have a host and may not contain credentials, a query, or a fragment",
        );
    }
    Ok(())
}

pub(super) fn validate_s3_prefix(prefix: &str) -> Result<(), ConfigValidationError> {
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

pub(super) fn validate_kopia_backup(
    kopia: &crate::config::BackupKopiaConfig,
) -> Result<(), ConfigValidationError> {
    validate_absolute_path("backups.storage.kopia.executable", &kopia.executable)?;
    if !kopia.config_file.trim().is_empty() {
        validate_absolute_path("backups.storage.kopia.config_file", &kopia.config_file)?;
    }
    if kopia.operation_timeout_seconds == 0 || kopia.operation_timeout_seconds > SECONDS_PER_DAY {
        return invalid_backup(
            "storage.kopia.operation_timeout_seconds",
            "must be between 1 and 86400",
        );
    }
    Ok(())
}

pub(super) fn invalid_backup<T>(
    field: &'static str,
    message: impl Into<String>,
) -> Result<T, ConfigValidationError> {
    Err(ConfigValidationError::InvalidBackupConfig {
        field,
        message: message.into(),
    })
}
