use super::{Config, path_policy::HostPathPolicy};

mod api;
mod import_export_scheduler;

use api::{validate_api_host, validate_api_hosts};

mod backups;
mod disk;
mod error;
mod images;
mod network;
mod secrets;
#[cfg(test)]
mod tests;

use backups::validate_backups;
use disk::validate_disk;
pub use error::ConfigValidationError;
use images::{check_mongodb_kernel, validate_images};
use network::{
    validate_absolute_path, validate_api_tls, validate_clickhouse, validate_listener,
    validate_security,
};
use secrets::{validate_api_token, validate_jwt_signing_key};

const MAX_REMOTE_IMPORT_JOBS: usize = 64;
const MAX_REMOTE_IMPORT_CONNECT_TIMEOUT_SECONDS: u64 = 5 * 60;
const MAX_REMOTE_IMPORT_OPERATION_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;
// Container upload/download operations use the same hard ceiling. Keeping the
// configurable bound at or below it prevents a remote acquisition from
// succeeding only to fail deterministically during target staging.
const MAX_REMOTE_IMPORT_STAGED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_BACKUP_CATALOG_BYTES: u64 = 1024 * 1024;
const SECONDS_PER_DAY: u64 = 24 * 60 * 60;
const MIN_SECRET_LEN: usize = 32;
const BYTES_PER_MIB: u64 = 1024 * 1024;

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
    config.daemon.validate_runtime_limits()?;

    if let Some(socket_path) = config.daemon.configured_socket_path() {
        validate_absolute_path("daemon.socket_path", socket_path)?;
    }

    HostPathPolicy::validate(&config.paths)?;
    validate_images(&config.images)?;
    check_mongodb_kernel(&config.images.mongodb)?;

    Ok(())
}

fn validate_import_uploads(
    artifacts: &crate::config::ArtifactConfig,
) -> Result<(), ConfigValidationError> {
    let invalid = |field| ConfigValidationError::InvalidImportUploadConfig { field };
    if !(1..=10_000).contains(&artifacts.max_artifacts_per_instance) {
        return Err(invalid("max_artifacts_per_instance"));
    }
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

fn validate_allocation(
    allocation: &crate::config::AllocationConfig,
) -> Result<(), ConfigValidationError> {
    for (field, value) in [
        ("max_memory_mib", allocation.max_memory_mib),
        ("max_disk_mib", allocation.max_disk_mib),
    ] {
        if value.is_some_and(|value| value == 0 || value.checked_mul(BYTES_PER_MIB).is_none()) {
            return Err(ConfigValidationError::InvalidAllocationLimit { field });
        }
    }
    for (field, value) in [
        ("reserved_memory_mib", allocation.reserved_memory_mib),
        ("reserved_disk_mib", allocation.reserved_disk_mib),
    ] {
        if value.checked_mul(BYTES_PER_MIB).is_none() {
            return Err(ConfigValidationError::InvalidAllocationLimit { field });
        }
    }
    Ok(())
}
