use super::*;

pub(super) fn row_to_upload(
    row: sqlx::sqlite::SqliteRow,
) -> Result<ImportUpload, ImportUploadStorageError> {
    let protocol: String = row.try_get("protocol")?;
    let state: String = row.try_get("state")?;
    let archive_format: Option<String> = row.try_get("archive_format")?;
    let size_bytes: i64 = row.try_get("size_bytes")?;
    let upload = ImportUpload {
        upload_id: row.try_get("upload_id")?,
        instance_id: row.try_get("instance_id")?,
        original_filename: row.try_get("original_filename")?,
        stored_filename: row.try_get("stored_filename")?,
        protocol: parse_protocol(&protocol)?,
        archive_format: archive_format
            .as_deref()
            .map(ImportUploadArchiveFormat::parse)
            .transpose()?,
        state: ImportUploadState::parse(&state)?,
        size_bytes: from_sqlite_integer(size_bytes, "size_bytes")?,
        sha256: row.try_get("sha256")?,
        catalog_json: row.try_get("catalog_json")?,
        last_error: row.try_get("last_error")?,
        claimed_job_id: row.try_get("claimed_job_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        expires_at: row.try_get("expires_at")?,
    };
    validate_upload(&upload)?;
    Ok(upload)
}

pub(super) fn parse_protocol(value: &str) -> Result<Protocol, ImportUploadParseError> {
    Protocol::ALL
        .into_iter()
        .find(|protocol| protocol.as_str() == value)
        .ok_or_else(|| ImportUploadParseError::Protocol(value.to_string()))
}

pub(super) fn validate_upload(upload: &ImportUpload) -> Result<(), ImportUploadValidationError> {
    validate_token("upload_id", &upload.upload_id)?;
    validate_token("instance_id", &upload.instance_id)?;
    validate_filename(&upload.original_filename)?;
    validate_stored_filename(&upload.stored_filename)?;
    let created_at = validate_timestamp("created_at", &upload.created_at)?;
    let updated_at = validate_timestamp("updated_at", &upload.updated_at)?;
    let expires_at = validate_timestamp("expires_at", &upload.expires_at)?;
    if updated_at < created_at {
        return Err(ImportUploadValidationError::InvalidTimestampOrder);
    }
    if expires_at <= created_at {
        return Err(ImportUploadValidationError::InvalidExpiration);
    }
    to_sqlite_integer(upload.size_bytes, "size_bytes")?;
    if upload.size_bytes == 0 {
        return Err(ImportUploadValidationError::EmptyUpload);
    }
    if let Some(sha256) = upload.sha256.as_deref() {
        validate_sha256(sha256)?;
    }
    validate_catalog_json(upload.catalog_json.as_deref())?;
    if let Some(last_error) = upload.last_error.as_deref() {
        validate_last_error(last_error)?;
    }
    if let Some(job_id) = upload.claimed_job_id.as_deref() {
        validate_token("claimed_job_id", job_id)?;
    }
    let requires_digest = matches!(
        upload.state,
        ImportUploadState::Uploaded
            | ImportUploadState::Processing
            | ImportUploadState::Ready
            | ImportUploadState::Importing
            | ImportUploadState::Consumed
    );
    if requires_digest && upload.sha256.is_none() {
        return Err(ImportUploadValidationError::MissingSha256 {
            state: upload.state,
        });
    }
    let requires_claim = matches!(
        upload.state,
        ImportUploadState::Importing | ImportUploadState::Consumed
    );
    if requires_claim != upload.claimed_job_id.is_some() {
        return Err(ImportUploadValidationError::InvalidClaim {
            state: upload.state,
        });
    }
    Ok(())
}

pub(super) fn is_safe_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

pub(super) fn validate_token(
    field: &'static str,
    value: &str,
) -> Result<(), ImportUploadValidationError> {
    if value.is_empty() || value.len() > MAX_TOKEN_BYTES || !value.bytes().all(is_safe_name_byte) {
        return Err(ImportUploadValidationError::InvalidToken { field });
    }
    Ok(())
}

pub(super) fn validate_filename(value: &str) -> Result<(), ImportUploadValidationError> {
    if value.is_empty()
        || value.len() > MAX_FILENAME_BYTES
        || matches!(value, "." | "..")
        || value.chars().any(|character| {
            character == '/' || character == '\\' || character == '\0' || character.is_control()
        })
    {
        return Err(ImportUploadValidationError::InvalidOriginalFilename);
    }
    Ok(())
}

pub(super) fn validate_stored_filename(value: &str) -> Result<(), ImportUploadValidationError> {
    if value.is_empty()
        || value.len() > MAX_FILENAME_BYTES
        || matches!(value, "." | "..")
        || !value.bytes().all(is_safe_name_byte)
    {
        return Err(ImportUploadValidationError::InvalidStoredFilename);
    }
    Ok(())
}

pub(super) fn validate_sha256(value: &str) -> Result<(), ImportUploadValidationError> {
    if value.len() != SHA256_HEX_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ImportUploadValidationError::InvalidSha256);
    }
    Ok(())
}

pub(super) fn validate_catalog_json(
    value: Option<&str>,
) -> Result<(), ImportUploadValidationError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.len() > MAX_CATALOG_JSON_BYTES
        || serde_json::from_str::<serde_json::Value>(value).is_err()
    {
        return Err(ImportUploadValidationError::InvalidCatalogJson);
    }
    Ok(())
}

pub(super) fn validate_last_error(value: &str) -> Result<(), ImportUploadValidationError> {
    if value.is_empty() || value.len() > MAX_LAST_ERROR_BYTES || value.contains('\0') {
        return Err(ImportUploadValidationError::InvalidLastError);
    }
    Ok(())
}

pub(super) fn validate_timestamp(
    field: &'static str,
    value: &str,
) -> Result<OffsetDateTime, ImportUploadValidationError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| ImportUploadValidationError::InvalidTimestamp { field })
}

pub(super) fn to_sqlite_integer(
    value: u64,
    field: &'static str,
) -> Result<i64, ImportUploadValidationError> {
    i64::try_from(value).map_err(|_| ImportUploadValidationError::IntegerOutOfRange { field })
}

pub(super) fn from_sqlite_integer(
    value: i64,
    field: &'static str,
) -> Result<u64, ImportUploadParseError> {
    u64::try_from(value).map_err(|_| ImportUploadParseError::NegativeInteger { field, value })
}

pub(super) fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
}
