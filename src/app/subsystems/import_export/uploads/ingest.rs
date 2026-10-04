use std::{sync::Arc, time::Duration};

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, StatusCode, header},
};

use futures::StreamExt;

use sha2::{Digest, Sha256};

use tokio::io::AsyncWriteExt;

use crate::{
    databases::protocol::Protocol,
    routes::http::{
        response::{ApiError, ApiResponse, ApiResult},
        router::AppState,
    },
    server::paths::InstancePaths,
    storage::import_uploads::{
        ImportUpload, ImportUploadAdmission, ImportUploadArchiveFormat, NewImportUpload,
    },
    utils::{hex::nibble, time::now_rfc3339},
};

use super::{
    super::{
        files::{create_private_file_sync, has_allowed_artifact_extension, prepare_private_dir},
        inspection::DumpArchiveFormat,
    },
    FILENAME_HEADER, ImportUploadResponse, MAX_ORIGINAL_FILENAME_BYTES, SHA256_HEADER,
    SHA256_HEX_LEN, UPLOAD_ID_PREFIX, UPLOADS_DIRECTORY,
    records::{expiration_timestamp, is_lowercase_hex, public_upload, upload_storage_error},
    storage::reserve_upload_disk_space,
    worker::{
        UploadWorkerGuards, UploadWorkerOptions, UploadWorkerRecovery, recover_interrupted_upload,
        spawn_upload_worker,
    },
};

pub(super) async fn upload_dump(
    state: &AppState,
    instance_id: &str,
    request: Request,
) -> ApiResult<ImportUploadResponse> {
    if request
        .headers()
        .get(header::CONTENT_ENCODING)
        .is_some_and(|value| value != "identity")
    {
        return Err(ApiError::BadRequest(
            "Content-Encoding is not supported for import uploads".to_string(),
        ));
    }
    let filename = upload_filename(request.headers())?;
    let expected_sha256 = expected_sha256(request.headers())?;
    let declared_size = content_length(request.headers())?;
    let config = &state.config.artifacts;
    if declared_size == 0 || declared_size > config.import_upload_max_bytes {
        return Err(ApiError::RequestRejected {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            message: format!(
                "upload size must be between 1 and {} bytes",
                config.import_upload_max_bytes
            ),
        });
    }
    if !has_allowed_artifact_extension(std::path::Path::new(&filename)) {
        return Err(ApiError::BadRequest(
            "the uploaded filename has no supported database dump extension".to_string(),
        ));
    }
    let admission = state
        .import_uploads
        .admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::RateLimited)?;
    let instance_operation = state.instance_locks.lock(instance_id).await;
    let metadata = state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let root = paths.imports.join(UPLOADS_DIRECTORY);
    prepare_private_dir(&root, "managed import upload directory").await?;
    let disk_reservation = reserve_upload_disk_space(state, &root, declared_size).await?;

    let upload_id = format!("{UPLOAD_ID_PREFIX}{}", uuid::Uuid::new_v4().simple());
    let stored_filename = format!("{upload_id}.upload");
    let archive_format = upload_archive_format(&filename, metadata.protocol);
    let created_at = now_rfc3339();
    let expires_at = expiration_timestamp(config.import_upload_ttl_hours)?;
    let upload = insert_upload_record(
        state,
        NewImportUpload {
            upload_id: upload_id.clone(),
            instance_id: instance_id.to_string(),
            original_filename: filename,
            stored_filename: stored_filename.clone(),
            protocol: metadata.protocol,
            archive_format,
            size_bytes: declared_size,
            created_at,
            expires_at,
        },
    )
    .await?;
    let partial_path = root.join(format!(".{stored_filename}.partial"));
    let final_path = root.join(&stored_filename);
    let recovery = UploadWorkerRecovery::new(
        state.import_uploads.repo().clone(),
        upload,
        partial_path,
        final_path,
    );
    let guards = Arc::new(UploadWorkerGuards::new(
        admission,
        instance_operation,
        disk_reservation,
    ));
    let worker = spawn_upload_worker(
        recovery.clone(),
        guards.clone(),
        request.into_body(),
        UploadWorkerOptions {
            declared_size,
            expected_sha256,
            idle_timeout: Duration::from_secs(config.import_upload_idle_timeout_seconds),
            total_timeout: Duration::from_secs(config.import_upload_timeout_seconds),
        },
    );
    let committed = match worker.await {
        Ok(result) => result,
        Err(error) => {
            if let Err(cleanup_error) = recover_interrupted_upload(&recovery).await {
                tracing::error!(
                    upload_id,
                    %cleanup_error,
                    "failed upload join recovery will be retried during boot recovery"
                );
            }
            drop(guards);
            return Err(ApiError::Runtime(format!(
                "upload worker stopped before completion: {error}"
            )));
        }
    };
    drop(guards);
    let committed = committed?;
    Ok(ApiResponse::with_status(
        StatusCode::CREATED,
        public_upload(committed),
    ))
}

pub(super) async fn insert_upload_record(
    state: &AppState,
    new_upload: NewImportUpload,
) -> Result<ImportUpload, ApiError> {
    let config = &state.config.artifacts;
    let admission = state
        .import_uploads
        .repo()
        .insert_within_limits(
            new_upload,
            u64::try_from(config.import_upload_max_per_instance).unwrap_or(u64::MAX),
            config.import_upload_max_total_bytes,
        )
        .await
        .map_err(upload_storage_error)?;
    match admission {
        ImportUploadAdmission::Admitted(upload) => Ok(*upload),
        ImportUploadAdmission::InstanceCountExceeded { limit, .. } => Err(ApiError::Conflict(
            format!("instance already has the maximum of {limit} temporary import uploads"),
        )),
        ImportUploadAdmission::TotalBytesExceeded { limit, .. } => Err(ApiError::Conflict(
            format!("temporary import uploads have reached their configured {limit}-byte capacity"),
        )),
    }
}

pub(super) fn storage_archive_format(format: DumpArchiveFormat) -> ImportUploadArchiveFormat {
    match format {
        DumpArchiveFormat::Plain => ImportUploadArchiveFormat::Plain,
        DumpArchiveFormat::Gzip => ImportUploadArchiveFormat::Gzip,
        DumpArchiveFormat::Bzip2 => ImportUploadArchiveFormat::Bzip2,
        DumpArchiveFormat::Tar => ImportUploadArchiveFormat::Tar,
        DumpArchiveFormat::TarGzip => ImportUploadArchiveFormat::TarGzip,
        DumpArchiveFormat::Zip => ImportUploadArchiveFormat::Zip,
    }
}

pub(super) fn confirmed_storage_archive_format(
    protocol: Protocol,
    format: DumpArchiveFormat,
) -> Option<ImportUploadArchiveFormat> {
    format
        .import_archive_format(protocol)
        .map(|_| storage_archive_format(format))
}

pub(super) fn upload_archive_format(
    filename: &str,
    protocol: Protocol,
) -> Option<ImportUploadArchiveFormat> {
    if protocol.engine().is_physical() {
        return None;
    }
    let filename = filename.to_ascii_lowercase();
    if protocol.engine().native_gzip_logical_dump()
        && (filename.ends_with(".mongodb.archive.gz") || filename.ends_with(".archive.gz"))
    {
        return None;
    }
    if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") {
        Some(ImportUploadArchiveFormat::TarGzip)
    } else if filename.ends_with(".tar") {
        Some(ImportUploadArchiveFormat::Tar)
    } else if filename.ends_with(".zip") {
        Some(ImportUploadArchiveFormat::Zip)
    } else if filename.ends_with(".gzip") || filename.ends_with(".gz") {
        Some(ImportUploadArchiveFormat::Gzip)
    } else if filename.ends_with(".bzip2") || filename.ends_with(".bz2") {
        Some(ImportUploadArchiveFormat::Bzip2)
    } else {
        Some(ImportUploadArchiveFormat::Plain)
    }
}

pub(super) async fn receive_upload_body(
    body: Body,
    path: &std::path::Path,
    declared_size: u64,
    expected_sha256: Option<&str>,
    idle_timeout: Duration,
) -> Result<String, ApiError> {
    let path_owned = path.to_path_buf();
    let file = tokio::task::spawn_blocking(move || create_private_file_sync(&path_owned))
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to create upload file: {error}")))?
        .map_err(|error| ApiError::Runtime(format!("failed to create upload file: {error}")))?;
    let mut file = tokio::fs::File::from_std(file);
    let mut stream = body.into_data_stream();
    let mut size = 0_u64;
    let mut hash = Sha256::new();
    loop {
        let next = tokio::time::timeout(idle_timeout, stream.next())
            .await
            .map_err(|_| ApiError::RequestRejected {
                status: StatusCode::REQUEST_TIMEOUT,
                message: "upload body was idle for too long".to_string(),
            })?;
        let Some(chunk) = next else {
            break;
        };
        let chunk = chunk
            .map_err(|error| ApiError::BadRequest(format!("upload stream failed: {error}")))?;
        size = size
            .checked_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| ApiError::BadRequest("upload size overflowed".to_string()))?;
        if size > declared_size {
            return Err(ApiError::BadRequest(
                "upload contained more bytes than Content-Length declared".to_string(),
            ));
        }
        file.write_all(&chunk)
            .await
            .map_err(|error| ApiError::Runtime(format!("failed to write upload: {error}")))?;
        hash.update(&chunk);
    }
    if size != declared_size {
        return Err(ApiError::BadRequest(format!(
            "upload ended after {size} bytes; expected {declared_size}"
        )));
    }
    file.flush()
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to flush upload: {error}")))?;
    file.sync_all()
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to sync upload: {error}")))?;
    drop(file);
    let digest = crate::utils::hex::encode_lower(&hash.finalize());
    if expected_sha256.is_some_and(|expected| expected != digest) {
        return Err(ApiError::BadRequest(
            "uploaded content did not match x-dbev-sha256".to_string(),
        ));
    }
    Ok(digest)
}

pub(super) fn upload_filename(headers: &HeaderMap) -> Result<String, ApiError> {
    let encoded = headers
        .get(FILENAME_HEADER)
        .ok_or_else(|| ApiError::BadRequest(format!("missing {FILENAME_HEADER} header")))?
        .to_str()
        .map_err(|_| ApiError::BadRequest(format!("{FILENAME_HEADER} is not valid ASCII")))?;
    let filename = percent_decode_utf8(encoded)?;
    if filename.len() > MAX_ORIGINAL_FILENAME_BYTES
        || !crate::io::files::is_safe_flat_file_name(&filename)
        || filename.trim() != filename
    {
        return Err(ApiError::BadRequest(
            "upload filename must be a safe flat filename of at most 180 UTF-8 bytes".to_string(),
        ));
    }
    Ok(filename)
}

pub(super) fn expected_sha256(headers: &HeaderMap) -> Result<Option<String>, ApiError> {
    let Some(value) = headers.get(SHA256_HEADER) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| ApiError::BadRequest(format!("{SHA256_HEADER} is invalid")))?;
    if value.len() != SHA256_HEX_LEN || !is_lowercase_hex(value) {
        return Err(ApiError::BadRequest(format!(
            "{SHA256_HEADER} must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(Some(value.to_string()))
}

pub(super) fn content_length(headers: &HeaderMap) -> Result<u64, ApiError> {
    headers
        .get(header::CONTENT_LENGTH)
        .ok_or_else(|| ApiError::BadRequest("Content-Length is required for uploads".to_string()))?
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| ApiError::BadRequest("Content-Length must be a valid integer".to_string()))
}

pub(super) fn percent_decode_utf8(value: &str) -> Result<String, ApiError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(ApiError::BadRequest(
                "x-dbev-filename contains invalid percent encoding".to_string(),
            ));
        }
        let high = nibble(bytes[index + 1]);
        let low = nibble(bytes[index + 2]);
        let Some(byte) = high.zip(low).map(|(high, low)| (high << 4) | low) else {
            return Err(ApiError::BadRequest(
                "x-dbev-filename contains invalid percent encoding".to_string(),
            ));
        };
        decoded.push(byte);
        index += 3;
    }
    String::from_utf8(decoded)
        .map_err(|_| ApiError::BadRequest("x-dbev-filename is not valid UTF-8".to_string()))
}

pub(super) fn hardened_upload_archive_format(
    target_protocol: Protocol,
    archive_format: Option<ImportUploadArchiveFormat>,
) -> Option<String> {
    match (target_protocol, archive_format) {
        (protocol, _) if protocol.engine().is_physical() => None,
        (protocol, Some(ImportUploadArchiveFormat::Gzip))
            if protocol.engine().native_gzip_logical_dump() =>
        {
            None
        }
        (_, Some(ImportUploadArchiveFormat::Plain) | None) => None,
        (_, Some(format)) => Some(format.as_str().to_string()),
    }
}
