use std::{future::Future, panic::AssertUnwindSafe, path::PathBuf, sync::Arc, time::Duration};

use axum::body::Body;
use futures::FutureExt;

use super::*;

pub(super) struct UploadWorkerGuards {
    _admission: tokio::sync::OwnedSemaphorePermit,
    _instance_operation: tokio::sync::OwnedMutexGuard<()>,
    _disk_reservation: DiskCapacityReservation,
}

impl UploadWorkerGuards {
    pub(super) fn new(
        admission: tokio::sync::OwnedSemaphorePermit,
        instance_operation: tokio::sync::OwnedMutexGuard<()>,
        disk_reservation: DiskCapacityReservation,
    ) -> Self {
        Self {
            _admission: admission,
            _instance_operation: instance_operation,
            _disk_reservation: disk_reservation,
        }
    }
}

#[derive(Clone)]
pub(super) struct UploadWorkerRecovery {
    repository: ImportUploadRepository,
    upload: ImportUpload,
    partial_path: PathBuf,
    final_path: PathBuf,
}

impl UploadWorkerRecovery {
    pub(super) fn new(
        repository: ImportUploadRepository,
        upload: ImportUpload,
        partial_path: PathBuf,
        final_path: PathBuf,
    ) -> Self {
        Self {
            repository,
            upload,
            partial_path,
            final_path,
        }
    }
}

pub(super) struct UploadWorkerOptions {
    pub(super) declared_size: u64,
    pub(super) expected_sha256: Option<String>,
    pub(super) idle_timeout: Duration,
    pub(super) total_timeout: Duration,
}

pub(super) fn spawn_owned_upload_worker(
    recovery: UploadWorkerRecovery,
    guards: Arc<UploadWorkerGuards>,
    body: Body,
    options: UploadWorkerOptions,
) -> tokio::task::JoinHandle<Result<ImportUpload, ApiError>> {
    let operation_recovery = recovery.clone();
    spawn_owned_upload_task(guards, async move {
        finish_upload_operation(
            recovery,
            receive_and_finalize_upload(operation_recovery, body, options),
        )
        .await
    })
}

fn spawn_owned_upload_task<T>(
    guards: Arc<UploadWorkerGuards>,
    operation: impl Future<Output = T> + Send + 'static,
) -> tokio::task::JoinHandle<T>
where
    T: Send + 'static,
{
    tokio::spawn(async move {
        let _guards = guards;
        operation.await
    })
}

async fn finish_upload_operation(
    recovery: UploadWorkerRecovery,
    operation: impl Future<Output = Result<ImportUpload, ApiError>>,
) -> Result<ImportUpload, ApiError> {
    let outcome = AssertUnwindSafe(operation).catch_unwind().await;
    let result = match outcome {
        Ok(result) => result,
        Err(_) => Err(ApiError::Runtime(
            "upload worker failed unexpectedly".to_string(),
        )),
    };
    if result.is_err()
        && let Err(error) = recover_interrupted_upload(&recovery).await
    {
        tracing::error!(
            upload_id = recovery.upload.upload_id,
            %error,
            "failed upload worker cleanup will be retried during boot recovery"
        );
    }
    result
}

async fn receive_and_finalize_upload(
    recovery: UploadWorkerRecovery,
    body: Body,
    options: UploadWorkerOptions,
) -> Result<ImportUpload, ApiError> {
    let receive = receive_upload_body(
        body,
        &recovery.partial_path,
        options.declared_size,
        options.expected_sha256.as_deref(),
        options.idle_timeout,
    );
    let digest = match tokio::time::timeout(options.total_timeout, receive).await {
        Ok(result) => result?,
        Err(_) => {
            return Err(ApiError::RequestRejected {
                status: StatusCode::REQUEST_TIMEOUT,
                message: "upload exceeded its total time limit".to_string(),
            });
        }
    };
    tokio::fs::rename(&recovery.partial_path, &recovery.final_path)
        .await
        .map_err(|error| {
            ApiError::Runtime(format!("failed to publish completed upload: {error}"))
        })?;
    let durable_path = recovery.final_path.clone();
    tokio::task::spawn_blocking(move || {
        crate::shared::files::sync_private_regular_file_durable(&durable_path)
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to join durable upload sync: {error}")))?
    .map_err(|error| {
        ApiError::Runtime(format!("failed to make completed upload durable: {error}"))
    })?;

    let repository = &recovery.repository;
    let upload = &recovery.upload;
    let uploaded = repository
        .mark_uploaded(
            &upload.instance_id,
            &upload.upload_id,
            options.declared_size,
            &digest,
            &now_rfc3339(),
        )
        .await
        .map_err(upload_storage_error)?;
    let ready = uploaded
        && repository
            .mark_ready(&upload.instance_id, &upload.upload_id, None, &now_rfc3339())
            .await
            .map_err(upload_storage_error)?;
    if !ready {
        return Err(ApiError::Runtime(
            "completed upload could not be committed safely".to_string(),
        ));
    }
    tracing::info!(
        event = "audit import_upload_completed",
        instance_id = upload.instance_id,
        upload_id = upload.upload_id,
        size_bytes = options.declared_size,
        protocol = upload.protocol.as_str()
    );
    repository
        .get(&upload.instance_id, &upload.upload_id)
        .await
        .map_err(upload_storage_error)?
        .ok_or_else(|| ApiError::Runtime("completed upload row is missing".to_string()))
}

pub(super) async fn recover_interrupted_upload(
    recovery: &UploadWorkerRecovery,
) -> Result<(), ApiError> {
    let current = recovery
        .repository
        .get(&recovery.upload.instance_id, &recovery.upload.upload_id)
        .await
        .map_err(upload_storage_error)?;
    if current.as_ref().is_some_and(|upload| {
        matches!(
            upload.state,
            ImportUploadState::Processing | ImportUploadState::Importing
        )
    }) {
        return Err(ApiError::Conflict(
            "interrupted upload unexpectedly entered active processing".to_string(),
        ));
    }

    let partial_result = remove_worker_file(&recovery.partial_path).await;
    let final_result = remove_worker_file(&recovery.final_path).await;
    partial_result?;
    final_result?;

    let Some(current) = current else {
        return Ok(());
    };
    let repository = &recovery.repository;
    if current.state == ImportUploadState::Uploading {
        if repository
            .abort_uploading(&current.instance_id, &current.upload_id)
            .await
            .map_err(upload_storage_error)?
        {
            return Ok(());
        }
        return Err(ApiError::Runtime(
            "interrupted uploading row could not be reconciled".to_string(),
        ));
    }

    let deleting = current.state == ImportUploadState::Deleting
        || repository
            .claim_for_deletion(&current.instance_id, &current.upload_id, &now_rfc3339())
            .await
            .map_err(upload_storage_error)?;
    if !deleting
        || !repository
            .finalize_delete(&current.instance_id, &current.upload_id)
            .await
            .map_err(upload_storage_error)?
    {
        return Err(ApiError::Runtime(
            "interrupted upload row could not be reconciled".to_string(),
        ));
    }
    Ok(())
}

pub(super) async fn remove_worker_file(path: &std::path::Path) -> Result<(), ApiError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::shared::files::remove_private_file_durable(&path))
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to join upload cleanup: {error}")))?
        .map_err(|error| ApiError::Runtime(format!("failed to delete upload data: {error}")))
}
