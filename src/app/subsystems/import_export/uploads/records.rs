use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    routes::http::{response::ApiError, router::AppState},
    storage::import_uploads::{ImportUpload, ImportUploadArchiveFormat},
};

use super::{
    super::{
        ImportExportSelection, ImportSourceOptions, SelectionMode, inspection::DumpInspection,
    },
    ImportUploadResponse, UPLOAD_ID_LEN, UPLOAD_ID_PREFIX,
};

pub(super) fn public_upload(upload: ImportUpload) -> ImportUploadResponse {
    ImportUploadResponse {
        upload_id: upload.upload_id,
        instance_id: upload.instance_id,
        original_filename: upload.original_filename,
        protocol: upload.protocol,
        archive_format: upload.archive_format.map(ImportUploadArchiveFormat::as_str),
        state: upload.state.as_str(),
        size_bytes: upload.size_bytes,
        sha256: upload.sha256,
        catalog_available: upload.catalog_json.is_some(),
        error: upload.last_error,
        created_at: upload.created_at,
        updated_at: upload.updated_at,
        expires_at: upload.expires_at,
    }
}

pub(super) async fn load_upload(
    state: &AppState,
    instance_id: &str,
    upload_id: &str,
) -> Result<ImportUpload, ApiError> {
    state
        .import_uploads
        .repo()
        .get(instance_id, upload_id)
        .await
        .map_err(upload_storage_error)?
        .ok_or(ApiError::NotFound)
}

pub(super) async fn require_instance(state: &AppState, instance_id: &str) -> Result<(), ApiError> {
    state
        .instances
        .get(instance_id)
        .await
        .map(|_| ())
        .ok_or(ApiError::NotFound)
}

pub(in super::super) async fn check_upload_selection(
    state: &AppState,
    instance_id: &str,
    source: &ImportSourceOptions,
    selection: &ImportExportSelection,
) -> Result<(), ApiError> {
    let ImportSourceOptions::Upload { upload_id, .. } = source else {
        return Ok(());
    };
    if selection.mode == SelectionMode::Full {
        return Ok(());
    }
    let upload = state
        .import_uploads
        .repo()
        .get(instance_id, upload_id)
        .await
        .map_err(upload_storage_error)?
        .ok_or(ApiError::NotFound)?;
    let catalog_json = upload.catalog_json.as_deref().ok_or_else(|| {
        ApiError::Conflict(
            "inspect the temporary upload before requesting selective import".to_string(),
        )
    })?;
    let catalog: DumpInspection = serde_json::from_str(catalog_json)
        .map_err(|_| ApiError::Runtime("stored upload catalog is invalid".to_string()))?;
    if !catalog.selective_supported {
        return Err(ApiError::NotImplemented(
            catalog.selective_unavailable_reason.unwrap_or_else(|| {
                "selective import is not safely supported for this uploaded dump".to_string()
            }),
        ));
    }
    let available = catalog
        .objects
        .iter()
        .map(|object| object.selection_key.as_str())
        .collect::<std::collections::HashSet<_>>();
    if let Some(unknown) = selection
        .include
        .iter()
        .chain(selection.exclude.iter())
        .find(|item| !available.contains(item.as_str()))
    {
        return Err(ApiError::BadRequest(format!(
            "selection item {unknown} is not present in the inspected upload catalog"
        )));
    }
    Ok(())
}

pub(super) fn valid_upload_id(upload_id: &str) -> bool {
    upload_id.len() == UPLOAD_ID_LEN
        && upload_id
            .strip_prefix(UPLOAD_ID_PREFIX)
            .is_some_and(is_lowercase_hex)
}

pub(super) fn is_lowercase_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn expiration_timestamp(ttl_hours: u64) -> Result<String, ApiError> {
    let hours = i64::try_from(ttl_hours)
        .map_err(|_| ApiError::Runtime("upload TTL does not fit in time range".to_string()))?;
    (OffsetDateTime::now_utc() + time::Duration::hours(hours))
        .format(&Rfc3339)
        .map_err(|error| ApiError::Runtime(format!("failed to format upload expiry: {error}")))
}

pub(super) fn upload_storage_error(error: impl std::fmt::Display) -> ApiError {
    ApiError::Runtime(format!("import upload storage failed: {error}"))
}
