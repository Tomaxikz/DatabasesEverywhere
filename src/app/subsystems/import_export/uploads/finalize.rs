use std::future::Future;

use crate::{
    routes::http::{diagnostics::PublicDiagnostic, response::ApiError, router::AppState},
    storage::import_uploads::{ImportUpload, ImportUploadArchiveFormat},
    utils::time::now_rfc3339,
};

use super::{
    super::inspection::{
        DumpArchiveFormat, DumpInspection, DumpInspectionFailure, inspect_uploaded_dump_with_format,
    },
    ingest::confirmed_storage_archive_format,
    records::{load_upload, upload_storage_error},
    storage::upload_file_path,
};

pub(super) async fn restore_after_inspection_worker_failure(
    state: &AppState,
    instance_id: &str,
    upload_id: &str,
    error: tokio::task::JoinError,
) -> ApiError {
    let _instance_operation = state.instance_locks.lock(instance_id).await;
    let message = "dump inspection worker stopped before it could finalize durable state";
    let restored = match state
        .import_uploads
        .repo()
        .restore_ready(
            instance_id,
            upload_id,
            None,
            None,
            Some(message),
            &now_rfc3339(),
        )
        .await
    {
        Ok(restored) => restored,
        Err(storage_error) => return upload_storage_error(storage_error),
    };
    if !restored {
        tracing::warn!(
            instance_id,
            upload_id,
            "failed inspection worker did not leave an upload in processing state"
        );
    }
    ApiError::Runtime(format!("dump inspection worker task failed: {error}"))
}

pub(super) fn spawn_owned_inspection<T>(
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

pub(super) async fn inspect_and_finalize_upload(
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
        Ok(catalog) => store_inspection_catalog(state, instance_id, &upload, &catalog).await?,
        Err(DumpInspectionFailure {
            error: error @ ApiError::BadRequest(_),
            ..
        }) => {
            let message = PublicDiagnostic::from_api_error("dump inspection", &error).message;
            let _ = state
                .import_uploads
                .repo()
                .mark_failed(instance_id, &upload_id, &message, &now_rfc3339())
                .await
                .map_err(upload_storage_error)?;
            return Err(error);
        }
        Err(DumpInspectionFailure {
            error,
            detected_archive_format,
        }) => {
            restore_after_inspection_failure(
                state,
                instance_id,
                &upload,
                &error,
                detected_archive_format,
            )
            .await?;
            return Err(error);
        }
    }
    load_upload(state, instance_id, &upload_id).await
}

pub(super) async fn store_inspection_catalog(
    state: &AppState,
    instance_id: &str,
    upload: &ImportUpload,
    catalog: &DumpInspection,
) -> Result<(), ApiError> {
    let upload_id = upload.upload_id.as_str();
    let content_changed = catalog.source_size_bytes != upload.size_bytes
        || upload.sha256.as_deref() != Some(catalog.sha256.as_str());
    if content_changed {
        let message = "temporary import upload changed after reception";
        let _ = state
            .import_uploads
            .repo()
            .mark_failed(instance_id, upload_id, message, &now_rfc3339())
            .await
            .map_err(upload_storage_error)?;
        return Err(ApiError::Conflict(message.to_string()));
    }
    let catalog_json = serde_json::to_string(catalog)
        .map_err(|error| ApiError::Runtime(format!("failed to encode upload catalog: {error}")))?;
    let confirmed_archive_format =
        confirmed_storage_archive_format(upload.protocol, catalog.detected_archive_format);
    let restored = state
        .import_uploads
        .repo()
        .restore_ready(
            instance_id,
            upload_id,
            confirmed_archive_format,
            Some(&catalog_json),
            None,
            &now_rfc3339(),
        )
        .await
        .map_err(upload_storage_error)?;
    if !restored {
        return Err(ApiError::Conflict(
            "the upload changed while inspection was completing".to_string(),
        ));
    }
    Ok(())
}

pub(super) async fn restore_after_inspection_failure(
    state: &AppState,
    instance_id: &str,
    upload: &ImportUpload,
    error: &ApiError,
    detected_archive_format: Option<DumpArchiveFormat>,
) -> Result<(), ApiError> {
    let upload_id = upload.upload_id.as_str();
    let message = PublicDiagnostic::from_api_error("dump inspection", error).message;
    let confirmed_archive_format = detected_archive_format
        .and_then(|format| confirmed_storage_archive_format(upload.protocol, format));
    let restored = state
        .import_uploads
        .repo()
        .restore_ready(
            instance_id,
            upload_id,
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
    Ok(())
}

pub(super) fn upload_catalog(upload: &ImportUpload) -> Result<DumpInspection, ApiError> {
    let catalog = upload.catalog_json.as_deref().ok_or_else(|| {
        ApiError::Conflict("upload catalog is unavailable; inspect this upload first".into())
    })?;
    serde_json::from_str(catalog)
        .map_err(|error| ApiError::Runtime(format!("stored upload catalog is invalid: {error}")))
}
