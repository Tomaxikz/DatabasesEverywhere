use super::ImportUploadState;

#[derive(Debug, thiserror::Error)]
pub enum ImportUploadStorageError {
    #[error("sqlite query failed: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("import upload row parse failed: {0}")]
    Parse(#[from] ImportUploadParseError),
    #[error("invalid import upload: {0}")]
    Validation(#[from] ImportUploadValidationError),
    #[error("import upload {upload_id} already exists")]
    AlreadyExists { upload_id: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ImportUploadParseError {
    #[error("unsupported protocol value {0:?}")]
    Protocol(String),
    #[error("unsupported state value {0:?}")]
    State(String),
    #[error("unsupported archive format value {0:?}")]
    ArchiveFormat(String),
    #[error("{field} contains negative sqlite integer {value}")]
    NegativeInteger { field: &'static str, value: i64 },
}

#[derive(Debug, thiserror::Error)]
pub enum ImportUploadValidationError {
    #[error("{field} must contain 1-128 ASCII letters, digits, dots, dashes, or underscores")]
    InvalidToken { field: &'static str },
    #[error("original_filename must be a safe 1-255 byte filename")]
    InvalidOriginalFilename,
    #[error("stored_filename must be a safe 1-255 byte ASCII filename")]
    InvalidStoredFilename,
    #[error("sha256 must contain exactly 64 lowercase hexadecimal characters")]
    InvalidSha256,
    #[error("catalog_json must be valid JSON no larger than 1 MiB")]
    InvalidCatalogJson,
    #[error("last_error must contain 1-16384 bytes without NUL characters")]
    InvalidLastError,
    #[error("{field} must be an RFC 3339 timestamp")]
    InvalidTimestamp { field: &'static str },
    #[error("updated_at cannot precede created_at")]
    InvalidTimestampOrder,
    #[error("expires_at must be later than created_at")]
    InvalidExpiration,
    #[error("{field} exceeds SQLite's signed integer range")]
    IntegerOutOfRange { field: &'static str },
    #[error("size_bytes must be greater than zero")]
    EmptyUpload,
    #[error("state {state:?} requires a SHA-256 digest")]
    MissingSha256 { state: ImportUploadState },
    #[error("state {state:?} has inconsistent claimed_job_id")]
    InvalidClaim { state: ImportUploadState },
}
