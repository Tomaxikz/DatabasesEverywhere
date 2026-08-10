use std::{
    collections::HashMap,
    future::Future,
    path::PathBuf,
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use axum::{
    body::Body,
    extract::{FromRequest, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures::StreamExt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{
    io::AsyncWriteExt,
    sync::{Mutex, Semaphore},
};

use crate::{
    api::api_response::{ApiError, ApiJson, ApiPath, ApiResponse},
    instances::paths::InstancePaths,
    shared::time::now_rfc3339,
    storage::import_uploads::{
        ImportUpload, ImportUploadAdmission, ImportUploadArchiveFormat, ImportUploadRepository,
        ImportUploadState, NewImportUpload,
    },
};

use super::{
    ImportRequest,
    files::{
        artifact_has_allowed_extension, create_private_directory, create_private_file_blocking,
    },
    inspection::{
        DumpArchiveFormat, DumpInspection, DumpInspectionFailure, inspect_uploaded_dump_with_format,
    },
    jobs::queue_import_instance,
    *,
};

const FILENAME_HEADER: &str = "x-dbev-filename";
const SHA256_HEADER: &str = "x-dbev-sha256";
const MAX_ORIGINAL_FILENAME_BYTES: usize = 180;
const DISK_SAFETY_RESERVE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LISTED_UPLOADS: u32 = 100;
const MAX_CONCURRENT_INSPECTIONS: usize = 2;
const MAX_CONCURRENT_IMPORT_STAGING: usize = 2;

mod mongodb;
#[cfg(test)]
mod tests;
mod worker;

pub(super) use mongodb::resolve_upload_source_database_catalog;
use worker::{
    UploadWorkerGuards, UploadWorkerOptions, UploadWorkerRecovery, recover_interrupted_upload,
    spawn_owned_upload_worker,
};

#[derive(Debug, Clone)]
pub struct ImportUploadService {
    repository: ImportUploadRepository,
    admission: Arc<Semaphore>,
    inspection_admission: Arc<Semaphore>,
    disk_reservation_gate: Arc<Mutex<()>>,
    reserved_disk_bytes_by_filesystem: Arc<StdMutex<HashMap<FilesystemIdentity, u64>>>,
    staging_admission: Arc<Semaphore>,
}

impl ImportUploadService {
    pub fn new(repository: ImportUploadRepository, max_concurrent: usize) -> Self {
        Self::new_with_staging_limit(
            repository,
            max_concurrent,
            max_concurrent.min(MAX_CONCURRENT_IMPORT_STAGING),
        )
    }

    pub fn new_with_staging_limit(
        repository: ImportUploadRepository,
        max_concurrent: usize,
        max_concurrent_staging: usize,
    ) -> Self {
        let max_concurrent = max_concurrent.max(1);
        Self {
            repository,
            admission: Arc::new(Semaphore::new(max_concurrent)),
            inspection_admission: Arc::new(Semaphore::new(
                max_concurrent.min(MAX_CONCURRENT_INSPECTIONS),
            )),
            disk_reservation_gate: Arc::new(Mutex::new(())),
            reserved_disk_bytes_by_filesystem: Arc::new(StdMutex::new(HashMap::new())),
            staging_admission: Arc::new(Semaphore::new(max_concurrent_staging.max(1))),
        }
    }

    pub fn repository(&self) -> &ImportUploadRepository {
        &self.repository
    }

    pub(super) async fn acquire_staging(
        &self,
        root: &std::path::Path,
        requested: u64,
    ) -> Result<ImportStagingPermit, ApiError> {
        create_private_directory(root, "logical import staging directory").await?;
        self.acquire_staging_on_existing_root(root, requested).await
    }

    pub(super) async fn acquire_staging_on_existing_root(
        &self,
        root: &std::path::Path,
        requested: u64,
    ) -> Result<ImportStagingPermit, ApiError> {
        let metadata = tokio::fs::symlink_metadata(root).await.map_err(|error| {
            ApiError::Runtime(format!(
                "failed to inspect import staging filesystem: {error}"
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ApiError::Runtime(
                "import staging filesystem root must be a real directory".to_string(),
            ));
        }
        let admission = self
            .staging_admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError::RateLimited)?;
        let reservation = reserve_shared_disk_capacity(
            &self.disk_reservation_gate,
            &self.reserved_disk_bytes_by_filesystem,
            root,
            requested,
        )
        .await?;
        Ok(ImportStagingPermit {
            _admission: admission,
            _reservation: reservation,
        })
    }

    pub(crate) async fn reserve_output_capacity(
        &self,
        root: &std::path::Path,
        requested: u64,
    ) -> Result<DiskCapacityReservation, ApiError> {
        let metadata = tokio::fs::symlink_metadata(root).await.map_err(|error| {
            ApiError::Runtime(format!("failed to inspect output filesystem: {error}"))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ApiError::Runtime(
                "output filesystem root must be a real directory".to_string(),
            ));
        }
        reserve_shared_disk_capacity(
            &self.disk_reservation_gate,
            &self.reserved_disk_bytes_by_filesystem,
            root,
            requested,
        )
        .await
    }
}

pub(super) struct ImportStagingPermit {
    _admission: tokio::sync::OwnedSemaphorePermit,
    _reservation: DiskCapacityReservation,
}

#[derive(Debug, Serialize)]
pub(crate) struct ImportUploadResponse {
    pub upload_id: String,
    pub instance_id: String,
    pub original_filename: String,
    pub protocol: Protocol,
    pub archive_format: Option<&'static str>,
    pub state: &'static str,
    pub size_bytes: u64,
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog: Option<DumpInspection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ImportUploadDeleteResponse {
    pub upload_id: String,
    pub deleted: bool,
}

pub(crate) async fn import_entry(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    request: Request,
) -> Result<Response, ApiError> {
    auth.require_scope(scopes::IMPORT_EXPORT_WRITE)?;
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match content_type.as_str() {
        "application/json" => {
            let ApiJson(request) = ApiJson::<ImportRequest>::from_request(request, &state).await?;
            Ok(queue_import_instance(&state, &instance_id, ImportOptions::from(&request))
                .await?
                .into_response())
        }
        "application/octet-stream" => {
            Ok(upload_dump(&state, &instance_id, request).await?.into_response())
        }
        _ => Err(ApiError::RequestRejected {
            status: StatusCode::UNSUPPORTED_MEDIA_TYPE,
            message: "use application/json to start an import or application/octet-stream to upload a dump"
                .to_string(),
        }),
    }
}

pub(crate) async fn list_import_uploads(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
) -> ApiResult<Vec<ImportUploadResponse>> {
    auth.require_scope(scopes::IMPORT_EXPORT_READ)?;
    ensure_instance_exists(&state, &instance_id).await?;
    let uploads = state
        .import_uploads
        .repository()
        .list_active_for_instance(&instance_id, MAX_LISTED_UPLOADS)
        .await
        .map_err(upload_storage_error)?;
    uploads
        .into_iter()
        .map(public_upload)
        .collect::<Result<Vec<_>, _>>()
        .map(ApiResponse::ok)
}

pub(crate) async fn get_import_upload(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, upload_id)): ApiPath<(String, String)>,
) -> ApiResult<ImportUploadResponse> {
    auth.require_scope(scopes::IMPORT_EXPORT_READ)?;
    ensure_instance_exists(&state, &instance_id).await?;
    let upload = load_upload(&state, &instance_id, &upload_id).await?;
    Ok(ApiResponse::ok(public_upload(upload)?))
}

pub(crate) async fn inspect_import_upload(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, upload_id)): ApiPath<(String, String)>,
) -> ApiResult<ImportUploadResponse> {
    auth.require_scope(scopes::IMPORT_EXPORT_WRITE)?;
    let instance_operation = state.instance_locks.lock(&instance_id).await;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let upload = load_upload(&state, &instance_id, &upload_id).await?;
    if upload.protocol != metadata.protocol {
        return Err(ApiError::Conflict(
            "the upload protocol no longer matches the instance protocol".to_string(),
        ));
    }
    if upload.state == ImportUploadState::Ready && upload.catalog_json.is_some() {
        return Ok(ApiResponse::ok(public_upload(upload)?));
    }
    if upload.state != ImportUploadState::Ready {
        return Err(ApiError::Conflict(format!(
            "upload {upload_id} is {} and cannot be inspected",
            upload.state.as_str()
        )));
    }
    let inspection_permit = state
        .import_uploads
        .inspection_admission
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::RateLimited)?;
    let now = now_rfc3339();
    if !state
        .import_uploads
        .repository()
        .mark_processing(&instance_id, &upload_id, &now)
        .await
        .map_err(upload_storage_error)?
    {
        return Err(ApiError::Conflict(
            "the upload changed while inspection was starting".to_string(),
        ));
    }
    let worker_state = state.clone();
    let worker_instance_id = instance_id.clone();
    let worker = spawn_owned_inspection(instance_operation, inspection_permit, async move {
        inspect_and_finalize_upload(&worker_state, &worker_instance_id, upload).await
    });
    let upload = match worker.await {
        Ok(result) => result?,
        Err(error) => {
            let _instance_operation = state.instance_locks.lock(&instance_id).await;
            let message = "dump inspection worker stopped before it could finalize durable state";
            let restored = state
                .import_uploads
                .repository()
                .restore_ready_after_processing(
                    &instance_id,
                    &upload_id,
                    None,
                    None,
                    Some(message),
                    &now_rfc3339(),
                )
                .await
                .map_err(upload_storage_error)?;
            if !restored {
                tracing::warn!(
                    instance_id,
                    upload_id,
                    "failed inspection worker did not leave an upload in processing state"
                );
            }
            return Err(ApiError::Runtime(format!(
                "dump inspection worker task failed: {error}"
            )));
        }
    };
    Ok(ApiResponse::ok(public_upload(upload)?))
}

fn spawn_owned_inspection<T>(
    instance_operation: tokio::sync::OwnedMutexGuard<()>,
    inspection_permit: tokio::sync::OwnedSemaphorePermit,
    operation: impl Future<Output = Result<T, ApiError>> + Send + 'static,
) -> tokio::task::JoinHandle<Result<T, ApiError>>
where
    T: Send + 'static,
{
    tokio::spawn(async move {
        let _instance_operation = instance_operation;
        let _inspection_permit = inspection_permit;
        operation.await
    })
}

async fn inspect_and_finalize_upload(
    state: &AppState,
    instance_id: &str,
    upload: ImportUpload,
) -> Result<ImportUpload, ApiError> {
    let upload_id = upload.upload_id.clone();
    let path = upload_file_path(state, &upload)?;
    let inspection = inspect_uploaded_dump_with_format(
        &path,
        upload.protocol,
        upload.archive_format.map(ImportUploadArchiveFormat::as_str),
    )
    .await;
    match inspection {
        Ok(catalog) => {
            if catalog.source_size_bytes != upload.size_bytes
                || upload.sha256.as_deref() != Some(catalog.sha256.as_str())
            {
                let message = "temporary import upload changed after reception";
                let _ = state
                    .import_uploads
                    .repository()
                    .mark_failed(instance_id, &upload_id, message, &now_rfc3339())
                    .await
                    .map_err(upload_storage_error)?;
                return Err(ApiError::Conflict(message.to_string()));
            }
            let catalog_json = serde_json::to_string(&catalog).map_err(|error| {
                ApiError::Runtime(format!("failed to encode upload catalog: {error}"))
            })?;
            let confirmed_archive_format =
                confirmed_storage_archive_format(upload.protocol, catalog.detected_archive_format);
            if !state
                .import_uploads
                .repository()
                .restore_ready_after_processing(
                    instance_id,
                    &upload_id,
                    confirmed_archive_format,
                    Some(&catalog_json),
                    None,
                    &now_rfc3339(),
                )
                .await
                .map_err(upload_storage_error)?
            {
                return Err(ApiError::Conflict(
                    "the upload changed while inspection was completing".to_string(),
                ));
            }
        }
        Err(DumpInspectionFailure {
            error: error @ ApiError::BadRequest(_),
            ..
        }) => {
            let message = PublicDiagnostic::from_api_error("dump inspection", &error).message;
            let _ = state
                .import_uploads
                .repository()
                .mark_failed(instance_id, &upload_id, &message, &now_rfc3339())
                .await
                .map_err(upload_storage_error)?;
            return Err(error);
        }
        Err(DumpInspectionFailure {
            error,
            detected_archive_format,
        }) => {
            let message = PublicDiagnostic::from_api_error("dump inspection", &error).message;
            let confirmed_archive_format = detected_archive_format
                .and_then(|format| confirmed_storage_archive_format(upload.protocol, format));
            let restored = state
                .import_uploads
                .repository()
                .restore_ready_after_processing(
                    instance_id,
                    &upload_id,
                    confirmed_archive_format,
                    None,
                    Some(&message),
                    &now_rfc3339(),
                )
                .await
                .map_err(upload_storage_error)?;
            if !restored {
                tracing::warn!(
                    instance_id,
                    upload_id,
                    "upload inspection failure could not restore ready state"
                );
            }
            return Err(error);
        }
    }
    load_upload(state, instance_id, &upload_id).await
}

pub(crate) async fn delete_import_upload(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, upload_id)): ApiPath<(String, String)>,
) -> ApiResult<ImportUploadDeleteResponse> {
    auth.require_scope(scopes::IMPORT_EXPORT_WRITE)?;
    let _instance_operation = state.instance_locks.lock(&instance_id).await;
    ensure_instance_exists(&state, &instance_id).await?;
    let upload = load_upload(&state, &instance_id, &upload_id).await?;
    if !state
        .import_uploads
        .repository()
        .claim_for_deletion(&instance_id, &upload_id, &now_rfc3339())
        .await
        .map_err(upload_storage_error)?
    {
        return Err(ApiError::Conflict(
            "an import is currently using this upload".to_string(),
        ));
    }
    remove_upload_file(&state, &upload).await?;
    if !state
        .import_uploads
        .repository()
        .finalize_delete(&instance_id, &upload_id)
        .await
        .map_err(upload_storage_error)?
    {
        return Err(ApiError::Runtime(
            "upload file was deleted but its cleanup state could not be finalized".to_string(),
        ));
    }
    tracing::info!(
        event = "audit import_upload_deleted",
        instance_id,
        upload_id
    );
    Ok(ApiResponse::ok(ImportUploadDeleteResponse {
        upload_id,
        deleted: true,
    }))
}

async fn upload_dump(
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
    if !artifact_has_allowed_extension(std::path::Path::new(&filename)) {
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
    let root = paths.imports.join(".uploads");
    create_private_directory(&root, "managed import upload directory").await?;
    let disk_reservation = reserve_upload_disk_space(state, &root, declared_size).await?;

    let upload_id = format!("upl_{}", uuid::Uuid::new_v4().simple());
    let stored_filename = format!("{upload_id}.upload");
    let archive_format = upload_archive_format(&filename, metadata.protocol);
    let created_at = now_rfc3339();
    let expires_at = expiration_timestamp(config.import_upload_ttl_hours)?;
    let upload = match state
        .import_uploads
        .repository()
        .insert_if_within_limits(
            NewImportUpload {
                upload_id: upload_id.clone(),
                instance_id: instance_id.to_string(),
                original_filename: filename,
                stored_filename: stored_filename.clone(),
                protocol: metadata.protocol,
                archive_format,
                size_bytes: declared_size,
                created_at: created_at.clone(),
                expires_at,
            },
            u64::try_from(config.import_upload_max_per_instance).unwrap_or(u64::MAX),
            config.import_upload_max_total_bytes,
        )
        .await
        .map_err(upload_storage_error)?
    {
        ImportUploadAdmission::Admitted(upload) => *upload,
        ImportUploadAdmission::InstanceCountExceeded { limit, .. } => {
            return Err(ApiError::Conflict(format!(
                "instance already has the maximum of {limit} temporary import uploads"
            )));
        }
        ImportUploadAdmission::TotalBytesExceeded { limit, .. } => {
            return Err(ApiError::Conflict(format!(
                "temporary import uploads have reached their configured {limit}-byte capacity"
            )));
        }
    };
    let partial_path = root.join(format!(".{stored_filename}.partial"));
    let final_path = root.join(&stored_filename);
    let recovery = UploadWorkerRecovery::new(
        state.import_uploads.repository().clone(),
        upload,
        partial_path,
        final_path,
    );
    let guards = Arc::new(UploadWorkerGuards::new(
        admission,
        instance_operation,
        disk_reservation,
    ));
    let worker = spawn_owned_upload_worker(
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
        public_upload(committed)?,
    ))
}

fn storage_archive_format(format: DumpArchiveFormat) -> ImportUploadArchiveFormat {
    match format {
        DumpArchiveFormat::Plain => ImportUploadArchiveFormat::Plain,
        DumpArchiveFormat::Gzip => ImportUploadArchiveFormat::Gzip,
        DumpArchiveFormat::Bzip2 => ImportUploadArchiveFormat::Bzip2,
        DumpArchiveFormat::Tar => ImportUploadArchiveFormat::Tar,
        DumpArchiveFormat::TarGzip => ImportUploadArchiveFormat::TarGzip,
        DumpArchiveFormat::Zip => ImportUploadArchiveFormat::Zip,
    }
}

fn confirmed_storage_archive_format(
    protocol: Protocol,
    format: DumpArchiveFormat,
) -> Option<ImportUploadArchiveFormat> {
    format
        .import_archive_format(protocol)
        .map(|_| storage_archive_format(format))
}

fn upload_archive_format(filename: &str, protocol: Protocol) -> Option<ImportUploadArchiveFormat> {
    if matches!(
        protocol,
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
    ) {
        return None;
    }
    let filename = filename.to_ascii_lowercase();
    if protocol == Protocol::Mongodb
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

async fn receive_upload_body(
    body: Body,
    path: &std::path::Path,
    declared_size: u64,
    expected_sha256: Option<&str>,
    idle_timeout: Duration,
) -> Result<String, ApiError> {
    let path_owned = path.to_path_buf();
    let file = tokio::task::spawn_blocking(move || create_private_file_blocking(&path_owned))
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
    let digest = format!("{:x}", hash.finalize());
    if expected_sha256.is_some_and(|expected| expected != digest) {
        return Err(ApiError::BadRequest(
            "uploaded content did not match x-dbev-sha256".to_string(),
        ));
    }
    Ok(digest)
}

fn upload_filename(headers: &HeaderMap) -> Result<String, ApiError> {
    let encoded = headers
        .get(FILENAME_HEADER)
        .ok_or_else(|| ApiError::BadRequest(format!("missing {FILENAME_HEADER} header")))?
        .to_str()
        .map_err(|_| ApiError::BadRequest(format!("{FILENAME_HEADER} is not valid ASCII")))?;
    let filename = percent_decode_utf8(encoded)?;
    if filename.len() > MAX_ORIGINAL_FILENAME_BYTES
        || !crate::shared::files::is_safe_flat_file_name(&filename)
        || filename.trim() != filename
    {
        return Err(ApiError::BadRequest(
            "upload filename must be a safe flat filename of at most 180 UTF-8 bytes".to_string(),
        ));
    }
    Ok(filename)
}

fn expected_sha256(headers: &HeaderMap) -> Result<Option<String>, ApiError> {
    let Some(value) = headers.get(SHA256_HEADER) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| ApiError::BadRequest(format!("{SHA256_HEADER} is invalid")))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::BadRequest(format!(
            "{SHA256_HEADER} must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(Some(value.to_string()))
}

fn content_length(headers: &HeaderMap) -> Result<u64, ApiError> {
    headers
        .get(header::CONTENT_LENGTH)
        .ok_or_else(|| ApiError::BadRequest("Content-Length is required for uploads".to_string()))?
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| ApiError::BadRequest("Content-Length must be a valid integer".to_string()))
}

fn percent_decode_utf8(value: &str) -> Result<String, ApiError> {
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
        let high = hex_value(bytes[index + 1]);
        let low = hex_value(bytes[index + 2]);
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

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn public_upload(upload: ImportUpload) -> Result<ImportUploadResponse, ApiError> {
    let catalog = upload
        .catalog_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|error| ApiError::Runtime(format!("stored upload catalog is invalid: {error}")))?;
    Ok(ImportUploadResponse {
        upload_id: upload.upload_id,
        instance_id: upload.instance_id,
        original_filename: upload.original_filename,
        protocol: upload.protocol,
        archive_format: upload.archive_format.map(ImportUploadArchiveFormat::as_str),
        state: upload.state.as_str(),
        size_bytes: upload.size_bytes,
        sha256: upload.sha256,
        catalog,
        error: upload.last_error,
        created_at: upload.created_at,
        updated_at: upload.updated_at,
        expires_at: upload.expires_at,
    })
}

async fn load_upload(
    state: &AppState,
    instance_id: &str,
    upload_id: &str,
) -> Result<ImportUpload, ApiError> {
    state
        .import_uploads
        .repository()
        .get(instance_id, upload_id)
        .await
        .map_err(upload_storage_error)?
        .ok_or(ApiError::NotFound)
}

async fn ensure_instance_exists(state: &AppState, instance_id: &str) -> Result<(), ApiError> {
    state
        .instances
        .get(instance_id)
        .await
        .map(|_| ())
        .ok_or(ApiError::NotFound)
}

pub(super) fn upload_file_path(
    state: &AppState,
    upload: &ImportUpload,
) -> Result<PathBuf, ApiError> {
    if !crate::shared::files::is_safe_flat_file_name(&upload.stored_filename) {
        return Err(ApiError::Runtime(
            "stored import upload filename is invalid".to_string(),
        ));
    }
    let paths = InstancePaths::new(&state.config.paths, &upload.instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    Ok(paths.imports.join(".uploads").join(&upload.stored_filename))
}

pub(super) async fn harden_upload_source(
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

fn hardened_upload_archive_format(
    target_protocol: Protocol,
    archive_format: Option<ImportUploadArchiveFormat>,
) -> Option<String> {
    match (target_protocol, archive_format) {
        (Protocol::Redis | Protocol::Valkey | Protocol::Qdrant, _)
        | (Protocol::Mongodb, Some(ImportUploadArchiveFormat::Gzip))
        | (_, Some(ImportUploadArchiveFormat::Plain) | None) => None,
        (_, Some(format)) => Some(format.as_str().to_string()),
    }
}

pub(super) async fn validate_upload_selection_capability(
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
        .repository()
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

fn valid_upload_id(upload_id: &str) -> bool {
    upload_id.len() == 36
        && upload_id.starts_with("upl_")
        && upload_id[4..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) async fn remove_upload_file(
    state: &AppState,
    upload: &ImportUpload,
) -> Result<(), ApiError> {
    let path = upload_file_path(state, upload)?;
    tokio::task::spawn_blocking(move || crate::shared::files::remove_private_file_durable(&path))
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to join upload cleanup: {error}")))?
        .or_else(|error| {
            (error.kind() == std::io::ErrorKind::NotFound)
                .then_some(())
                .ok_or(error)
        })
        .map_err(|error| ApiError::Runtime(format!("failed to delete upload: {error}")))
}

pub(super) async fn finish_upload_import_job(
    state: &AppState,
    instance_id: &str,
    upload_id: &str,
    job_id: &str,
    succeeded: bool,
    failure: Option<&str>,
) {
    let now = now_rfc3339();
    if !succeeded {
        match state
            .import_uploads
            .repository()
            .release_claim_after_failed_job(
                instance_id,
                upload_id,
                job_id,
                failure.unwrap_or("import job failed"),
                &now,
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => tracing::error!(
                instance_id,
                upload_id,
                job_id,
                "failed import could not release its upload claim"
            ),
            Err(error) => {
                tracing::error!(instance_id, upload_id, job_id, %error, "failed to persist import upload release")
            }
        }
        return;
    }
    match state
        .import_uploads
        .repository()
        .mark_consumed(instance_id, upload_id, job_id, &now)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::error!(
                instance_id,
                upload_id,
                job_id,
                "successful import could not mark its upload consumed"
            );
            return;
        }
        Err(error) => {
            tracing::error!(instance_id, upload_id, job_id, %error, "successful import could not persist upload consumption");
            return;
        }
    }
    let upload = match load_upload(state, instance_id, upload_id).await {
        Ok(upload) => upload,
        Err(error) => {
            tracing::error!(instance_id, upload_id, job_id, %error, "consumed upload could not be loaded for cleanup");
            return;
        }
    };
    match state
        .import_uploads
        .repository()
        .claim_for_deletion(instance_id, upload_id, &now_rfc3339())
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::error!(
                instance_id,
                upload_id,
                job_id,
                "consumed upload could not enter cleanup state"
            );
            return;
        }
        Err(error) => {
            tracing::error!(instance_id, upload_id, job_id, %error, "consumed upload cleanup claim failed");
            return;
        }
    }
    if let Err(error) = remove_upload_file(state, &upload).await {
        tracing::error!(instance_id, upload_id, job_id, %error, "consumed upload cleanup will be retried");
        return;
    }
    if let Err(error) = state
        .import_uploads
        .repository()
        .finalize_delete(instance_id, upload_id)
        .await
    {
        tracing::error!(instance_id, upload_id, job_id, %error, "consumed upload row cleanup will be retried");
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FilesystemIdentity(String);

pub(crate) struct DiskCapacityReservation {
    filesystem: FilesystemIdentity,
    bytes: u64,
    totals: Arc<StdMutex<HashMap<FilesystemIdentity, u64>>>,
}

impl Drop for DiskCapacityReservation {
    fn drop(&mut self) {
        let mut totals = self
            .totals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(total) = totals.get_mut(&self.filesystem) else {
            debug_assert!(false, "output capacity reservation identity was missing");
            return;
        };
        let Some(remaining) = total.checked_sub(self.bytes) else {
            debug_assert!(false, "output capacity reservation underflow");
            return;
        };
        if remaining == 0 {
            totals.remove(&self.filesystem);
        } else {
            *total = remaining;
        }
    }
}

async fn reserve_upload_disk_space(
    state: &AppState,
    root: &std::path::Path,
    requested: u64,
) -> Result<DiskCapacityReservation, ApiError> {
    reserve_shared_disk_capacity(
        &state.import_uploads.disk_reservation_gate,
        &state.import_uploads.reserved_disk_bytes_by_filesystem,
        root,
        requested,
    )
    .await
}

async fn reserve_shared_disk_capacity(
    gate: &Mutex<()>,
    totals: &Arc<StdMutex<HashMap<FilesystemIdentity, u64>>>,
    root: &std::path::Path,
    requested: u64,
) -> Result<DiskCapacityReservation, ApiError> {
    let _reservation_gate = gate.lock().await;
    let metadata = std::fs::metadata(root).map_err(|error| {
        ApiError::Runtime(format!("failed to identify output filesystem: {error}"))
    })?;
    let filesystem = filesystem_identity(root, &metadata)?;
    let already_reserved = totals
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&filesystem)
        .copied()
        .unwrap_or(0);
    ensure_disk_space(root, requested, already_reserved).await?;
    let mut totals_guard = totals
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let total = totals_guard.entry(filesystem.clone()).or_default();
    *total = total
        .checked_add(requested)
        .ok_or_else(|| ApiError::Conflict("output capacity reservation overflowed".to_string()))?;
    drop(totals_guard);
    Ok(DiskCapacityReservation {
        filesystem,
        bytes: requested,
        totals: totals.clone(),
    })
}

#[cfg(unix)]
fn filesystem_identity(
    _root: &std::path::Path,
    metadata: &std::fs::Metadata,
) -> Result<FilesystemIdentity, ApiError> {
    use std::os::unix::fs::MetadataExt;
    Ok(FilesystemIdentity(format!(
        "unix-device:{}",
        metadata.dev()
    )))
}

#[cfg(windows)]
fn filesystem_identity(
    root: &std::path::Path,
    _metadata: &std::fs::Metadata,
) -> Result<FilesystemIdentity, ApiError> {
    use std::path::Component;
    let prefix = root
        .components()
        .find_map(|component| match component {
            Component::Prefix(prefix) => Some(prefix.as_os_str().to_string_lossy().to_lowercase()),
            _ => None,
        })
        .ok_or_else(|| ApiError::Runtime("output path has no Windows volume prefix".to_string()))?;
    Ok(FilesystemIdentity(format!("windows-volume:{prefix}")))
}

#[cfg(not(any(unix, windows)))]
fn filesystem_identity(
    root: &std::path::Path,
    _metadata: &std::fs::Metadata,
) -> Result<FilesystemIdentity, ApiError> {
    let canonical = std::fs::canonicalize(root).map_err(|error| {
        ApiError::Runtime(format!("failed to resolve output filesystem: {error}"))
    })?;
    Ok(FilesystemIdentity(format!(
        "filesystem-root:{}",
        canonical.display()
    )))
}

async fn ensure_disk_space(
    root: &std::path::Path,
    requested: u64,
    already_reserved: u64,
) -> Result<(), ApiError> {
    let sample = crate::api::resources::read_host_disk(
        root.to_str()
            .ok_or_else(|| ApiError::Runtime("storage path is not valid UTF-8".to_string()))?,
    )
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to inspect storage capacity: {error}")))?;
    let required = required_disk_capacity(requested, already_reserved)?;
    if sample.available_bytes < required {
        return Err(ApiError::Conflict(format!(
            "operation needs {required} bytes of output capacity including the safety reserve, but only {} bytes are available",
            sample.available_bytes
        )));
    }
    Ok(())
}

fn required_disk_capacity(requested: u64, already_reserved: u64) -> Result<u64, ApiError> {
    requested
        .checked_add(already_reserved)
        .and_then(|bytes| bytes.checked_add(DISK_SAFETY_RESERVE_BYTES))
        .ok_or_else(|| ApiError::Conflict("output capacity reservation overflowed".to_string()))
}

fn expiration_timestamp(ttl_hours: u64) -> Result<String, ApiError> {
    let hours = i64::try_from(ttl_hours)
        .map_err(|_| ApiError::Runtime("upload TTL does not fit in time range".to_string()))?;
    (OffsetDateTime::now_utc() + time::Duration::hours(hours))
        .format(&Rfc3339)
        .map_err(|error| ApiError::Runtime(format!("failed to format upload expiry: {error}")))
}

fn upload_storage_error(error: impl std::fmt::Display) -> ApiError {
    ApiError::Runtime(format!("import upload storage failed: {error}"))
}

#[cfg(test)]
mod upload_tests {
    use super::*;

    #[test]
    fn filename_percent_decoding_is_strict() {
        assert_eq!(
            percent_decode_utf8("dump%20one.postgres.sql").unwrap(),
            "dump one.postgres.sql"
        );
        assert!(percent_decode_utf8("dump%2.sql").is_err());
        assert!(percent_decode_utf8("dump%GG.sql").is_err());
        assert!(percent_decode_utf8("%FF.sql").is_err());
    }

    #[test]
    fn sha256_header_is_lowercase_hex() {
        let mut headers = HeaderMap::new();
        headers.insert(SHA256_HEADER, "a".repeat(64).parse().unwrap());
        assert_eq!(expected_sha256(&headers).unwrap().unwrap().len(), 64);
        headers.insert(SHA256_HEADER, "A".repeat(64).parse().unwrap());
        assert!(expected_sha256(&headers).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn partial_cleanup_is_durable_missing_safe_and_does_not_follow_links() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let victim = directory.path().join("victim");
        let partial = directory.path().join(".upload.partial");
        std::fs::write(&victim, b"keep").unwrap();
        symlink(&victim, &partial).unwrap();

        worker::remove_worker_file(&partial).await.unwrap();
        assert!(!partial.exists());
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        worker::remove_worker_file(&partial).await.unwrap();

        let missing_parent = directory.path().join("missing").join("partial");
        assert!(worker::remove_worker_file(&missing_parent).await.is_err());
    }
}
