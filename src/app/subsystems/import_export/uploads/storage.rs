use std::path::PathBuf;

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    databases::protocol::Protocol,
    routes::http::{response::ApiError, router::AppState},
    server::{disk::capacity::CapacityError, paths::InstancePaths},
    storage::import_uploads::{ImportUpload, ImportUploadState},
};

use super::{
    super::ImportSourceOptions,
    DiskCapacityReservation, UPLOADS_DIRECTORY,
    ingest::hardened_upload_archive_format,
    records::{load_upload, valid_upload_id},
};

pub(in super::super) fn upload_file_path(
    state: &AppState,
    upload: &ImportUpload,
) -> Result<PathBuf, ApiError> {
    if !crate::io::files::is_safe_flat_file_name(&upload.stored_filename) {
        return Err(ApiError::Runtime(
            "stored import upload filename is invalid".to_string(),
        ));
    }
    let paths = InstancePaths::new(&state.config.paths, &upload.instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    Ok(paths
        .imports
        .join(UPLOADS_DIRECTORY)
        .join(&upload.stored_filename))
}

pub(in super::super) async fn harden_upload_source(
    state: &AppState,
    instance_id: &str,
    target_protocol: Protocol,
    upload_id: String,
) -> Result<(ImportSourceOptions, Option<String>), ApiError> {
    if !valid_upload_id(&upload_id) {
        return Err(ApiError::BadRequest("invalid import upload id".to_string()));
    }
    let upload = load_upload(state, instance_id, &upload_id).await?;
    if upload.protocol != target_protocol {
        return Err(ApiError::BadRequest(
            "the upload was created for a different database protocol".to_string(),
        ));
    }
    if upload.state != ImportUploadState::Ready {
        return Err(ApiError::Conflict(format!(
            "upload {upload_id} is {} and cannot be imported",
            upload.state.as_str()
        )));
    }
    let expires_at = OffsetDateTime::parse(&upload.expires_at, &Rfc3339)
        .map_err(|_| ApiError::Runtime("stored upload expiry is invalid".to_string()))?;
    if expires_at <= OffsetDateTime::now_utc() {
        return Err(ApiError::Conflict(
            "the temporary import upload has expired".to_string(),
        ));
    }
    if upload.sha256.is_none() {
        return Err(ApiError::Runtime(
            "ready import upload is missing its content digest".to_string(),
        ));
    }
    let path = upload_file_path(state, &upload)?;
    let metadata = tokio::fs::symlink_metadata(&path)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to inspect import upload: {error}")))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ApiError::BadRequest(
            "temporary import upload is not a regular file".to_string(),
        ));
    }
    if metadata.len() != upload.size_bytes {
        return Err(ApiError::Conflict(
            "temporary import upload size changed after reception".to_string(),
        ));
    }
    let archive_format = hardened_upload_archive_format(target_protocol, upload.archive_format);
    Ok((
        ImportSourceOptions::Upload { upload_id, path },
        archive_format,
    ))
}

pub(in super::super) async fn remove_upload_file(
    state: &AppState,
    upload: &ImportUpload,
) -> Result<(), ApiError> {
    let path = upload_file_path(state, upload)?;
    tokio::task::spawn_blocking(move || crate::io::files::remove_private_file_durable(&path))
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to join upload cleanup: {error}")))?
        .or_else(|error| {
            (error.kind() == std::io::ErrorKind::NotFound)
                .then_some(())
                .ok_or(error)
        })
        .map_err(|error| ApiError::Runtime(format!("failed to delete upload: {error}")))
}

pub(super) async fn reserve_upload_disk_space(
    state: &AppState,
    root: &std::path::Path,
    requested: u64,
) -> Result<DiskCapacityReservation, ApiError> {
    state
        .import_uploads
        .disk_capacity
        .reserve(root, requested)
        .await
        .map_err(|error| capacity_api_error(error, "output"))
}

pub(super) fn capacity_api_error(error: CapacityError, root_kind: &str) -> ApiError {
    match error {
        CapacityError::InspectRoot(error) => {
            ApiError::Runtime(format!("failed to inspect {root_kind} filesystem: {error}"))
        }
        CapacityError::InvalidRoot => ApiError::Runtime(format!(
            "{root_kind} filesystem root must be a real directory"
        )),
        CapacityError::IdentifyFilesystem(error) => {
            ApiError::Runtime(format!("failed to identify output filesystem: {error}"))
        }
        CapacityError::PathNotUtf8 => {
            ApiError::Runtime("storage path is not valid UTF-8".to_string())
        }
        CapacityError::InspectCapacity(error) => {
            ApiError::Runtime(format!("failed to inspect storage capacity: {error}"))
        }
        CapacityError::Overflow => {
            ApiError::Conflict("output capacity reservation overflowed".to_string())
        }
        CapacityError::Insufficient {
            required,
            available,
        } => ApiError::Conflict(format!(
            "operation needs {required} bytes of output capacity including the safety reserve, but only {available} bytes are available"
        )),
    }
}
