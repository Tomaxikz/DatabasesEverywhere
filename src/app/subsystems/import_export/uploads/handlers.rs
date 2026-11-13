use axum::{
    extract::{FromRequest, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::{
    auth::scopes,
    routes::http::{
        policy::ApiRequestContext,
        response::{ApiError, ApiJson, ApiPath, ApiResponse, ApiResult},
        router::AppState,
    },
    storage::import_uploads::ImportUploadState,
    utils::time::now_rfc3339,
};

use super::{
    super::{
        ImportOptions, ImportRequest, inspection::DumpInspection, jobs::queue_import_instance,
    },
    ImportUploadDeleteResponse, ImportUploadResponse, MAX_LISTED_UPLOADS,
    finalize::{
        inspect_and_finalize_upload, restore_after_inspection_worker_failure,
        spawn_owned_inspection, upload_catalog,
    },
    ingest::upload_dump,
    records::{load_upload, public_upload, require_instance, upload_storage_error},
    storage::remove_upload_file,
};

#[derive(utoipa::ToSchema)]
#[schema(format = Binary)]
#[allow(dead_code)]
struct DumpBytes(String);

#[utoipa::path(
    post,
    path = "/api/instances/{instance_id}/import",
    tag = "import-export",
    summary = "Upload a temporary dump or queue an import into one instance.",
    description = "application/octet-stream stores, hashes, and returns a temporary upload without starting an import. application/json queues an import from an artifact, typed remote source, or ready temporary upload. Temporary uploads are separate from generated artifacts. Shared tenants accept only tenant-scoped logical imports; physical restores and database-level statements that could affect the pool or another tenant are rejected.",
    extensions(("x-required-scope" = json!(scopes::IMPORT_EXPORT_WRITE))),
    params(
        ("instance_id" = String, Path),
        ("Content-Length" = Option<u64>, Header, nullable = false, minimum = 1, description = "Required for application/octet-stream and must exactly equal the bytes sent."),
        ("X-DBEV-Filename" = Option<String>, Header, nullable = false, description = "Required for application/octet-stream. Percent-encoded UTF-8 flat filename, at most 180 decoded bytes, with a supported native dump extension. Paths and traversal components are rejected."),
        ("X-DBEV-SHA256" = Option<String>, Header, nullable = false, pattern = "^[0-9a-f]{64}$", description = "Optional expected digest for application/octet-stream; exactly 64 lowercase hexadecimal characters."),
    ),
    request_body(content(
        (ImportRequest = "application/json"),
        (inline(DumpBytes) = "application/octet-stream"),
    )),
    responses(
        (status = 201, description = "Temporary upload committed, hashed, and ready for inspection or full import; no import job was started.", body = ImportUploadResponse),
        (
            status = 202,
            description = "Queued import job.",
            body = crate::subsystems::import_export::ImportExportJobResponse,
            headers(("Location" = String, description = "Origin-relative job status URL."))
        ),
    )
)]
pub(crate) async fn import_entry(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    request: Request,
) -> Result<Response, ApiError> {
    auth.require_scope(scopes::IMPORT_EXPORT_WRITE)?;
    let media_type = request_media_type(request.headers());
    match media_type.as_str() {
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

pub(super) fn request_media_type(headers: &HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

#[utoipa::path(
    get,
    path = "/api/instances/{instance_id}/import/uploads",
    tag = "import-export",
    summary = "List active temporary import uploads for one instance.",
    description = "Returns at most 100 instance-owned records. Temporary uploads never appear in the artifact inventory.",
    extensions(("x-required-scope" = json!(scopes::IMPORT_EXPORT_READ))),
    params(("instance_id" = String, Path)),
    responses((status = 200, description = "Temporary upload list.", body = Vec<ImportUploadResponse>))
)]
pub(crate) async fn list_import_uploads(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
) -> ApiResult<Vec<ImportUploadResponse>> {
    auth.require_scope(scopes::IMPORT_EXPORT_READ)?;
    require_instance(&state, &instance_id).await?;
    let uploads = state
        .import_uploads
        .repo()
        .list_active(&instance_id, MAX_LISTED_UPLOADS)
        .await
        .map_err(upload_storage_error)?;
    Ok(ApiResponse::ok(
        uploads.into_iter().map(public_upload).collect(),
    ))
}

#[utoipa::path(
    get,
    path = "/api/instances/{instance_id}/import/uploads/{upload_id}",
    tag = "import-export",
    summary = "Get one temporary import upload belonging to an instance.",
    extensions(("x-required-scope" = json!(scopes::IMPORT_EXPORT_READ))),
    params(("instance_id" = String, Path), ("upload_id" = String, Path, pattern = "^upl_[0-9a-f]{32}$")),
    responses((status = 200, description = "Temporary upload summary including catalog_available, without catalog contents.", body = ImportUploadResponse))
)]
pub(crate) async fn get_import_upload(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, upload_id)): ApiPath<(String, String)>,
) -> ApiResult<ImportUploadResponse> {
    auth.require_scope(scopes::IMPORT_EXPORT_READ)?;
    require_instance(&state, &instance_id).await?;
    let upload = load_upload(&state, &instance_id, &upload_id).await?;
    Ok(ApiResponse::ok(public_upload(upload)))
}

#[utoipa::path(
    post,
    path = "/api/instances/{instance_id}/import/uploads/{upload_id}/catalog",
    tag = "import-export",
    summary = "Inspect a ready temporary dump and cache its bounded catalog.",
    description = "Validates the archive wrapper and extracts a bounded metadata-only catalog without executing dump content. Inspection is lazy and idempotent once cached. The selective_supported response field is the authoritative capability; formats that report it as false are full-import only. A concurrency rejection or bounded inspection limit leaves the upload ready, so a full import remains available.",
    extensions(("x-required-scope" = json!(scopes::IMPORT_EXPORT_WRITE))),
    params(("instance_id" = String, Path), ("upload_id" = String, Path, pattern = "^upl_[0-9a-f]{32}$")),
    responses((status = 200, description = "DumpInspection at the JSON root, not wrapped in an upload summary.", body = DumpInspection))
)]
pub(crate) async fn inspect_import_upload(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, upload_id)): ApiPath<(String, String)>,
) -> ApiResult<DumpInspection> {
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
        return Ok(ApiResponse::ok(upload_catalog(&upload)?));
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
        .repo()
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
            return Err(restore_after_inspection_worker_failure(
                &state,
                &instance_id,
                &upload_id,
                error,
            )
            .await);
        }
    };
    Ok(ApiResponse::ok(upload_catalog(&upload)?))
}

#[utoipa::path(
    delete,
    path = "/api/instances/{instance_id}/import/uploads/{upload_id}",
    tag = "import-export",
    summary = "Cancel and durably delete one temporary import upload.",
    description = "Importing uploads return a conflict. Deletion never removes a DBEV-generated artifact or operator-staged import file.",
    extensions(("x-required-scope" = json!(scopes::IMPORT_EXPORT_WRITE))),
    params(("instance_id" = String, Path), ("upload_id" = String, Path, pattern = "^upl_[0-9a-f]{32}$")),
    responses((status = 200, description = "Upload deleted.", body = ImportUploadDeleteResponse))
)]
pub(crate) async fn delete_import_upload(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, upload_id)): ApiPath<(String, String)>,
) -> ApiResult<ImportUploadDeleteResponse> {
    auth.require_scope(scopes::IMPORT_EXPORT_WRITE)?;
    let _instance_operation = state.instance_locks.lock(&instance_id).await;
    require_instance(&state, &instance_id).await?;
    let upload = load_upload(&state, &instance_id, &upload_id).await?;
    if !state
        .import_uploads
        .repo()
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
        .repo()
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

#[utoipa::path(
    get,
    path = "/api/instances/{instance_id}/import/uploads/{upload_id}/catalog",
    tag = "import-export",
    summary = "Read a cached upload catalog without running inspection.",
    description = "Returns DumpInspection at the JSON root. Returns 409 when no catalog is cached; POST to this endpoint performs bounded inspection.",
    extensions(("x-required-scope" = json!(scopes::IMPORT_EXPORT_READ))),
    params(("instance_id" = String, Path), ("upload_id" = String, Path, pattern = "^upl_[0-9a-f]{32}$")),
    responses((status = 200, description = "Cached catalog.", body = DumpInspection))
)]
pub(crate) async fn get_import_catalog(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, upload_id)): ApiPath<(String, String)>,
) -> ApiResult<DumpInspection> {
    auth.require_scope(scopes::IMPORT_EXPORT_READ)?;
    require_instance(&state, &instance_id).await?;
    let upload = load_upload(&state, &instance_id, &upload_id).await?;
    Ok(ApiResponse::ok(upload_catalog(&upload)?))
}
