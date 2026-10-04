use crate::config::path_policy::HostPathPolicyError;

#[derive(Debug, thiserror::Error)]
pub enum ConfigValidationError {
    #[error("daemon.{field} must be between 1 and {maximum}, inclusive")]
    InvalidDaemonLimit { field: &'static str, maximum: u64 },
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
