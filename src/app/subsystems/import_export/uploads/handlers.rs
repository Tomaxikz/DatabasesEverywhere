use super::*;

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
