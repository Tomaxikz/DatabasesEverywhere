use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, Uri},
};
use serde::Deserialize;

use crate::{
    api::{
        handlers::{ApiError, ApiResult, authorize_scope},
        import_export::ImportOptions,
        import_export::{ImportExportJobResponse, queue_export_instance, queue_import_instance},
        routes::AppState,
    },
    auth::scopes,
    jobs::import_export::{ImportExportAction, ImportExportStatus},
};

#[derive(Debug, Deserialize)]
pub struct RestoreArtifactRequest {
    pub instance_id: String,
    pub artifact_path: String,
    pub confirm: bool,
    pub reason: String,
}

pub async fn failed_jobs(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<Vec<ImportExportJobResponse>> {
    authorize_scope(&state, &headers, &uri, scopes::RECOVERY_ADMIN)?;
    let jobs = state
        .import_export_jobs
        .list(None, Some(ImportExportStatus::Failed), 100)
        .await;
    let mut response = Vec::with_capacity(jobs.len());
    for job in jobs {
        response.push(crate::api::import_export::public_job_response(job).await);
    }
    Ok(Json(response))
}

pub async fn retry_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<ImportExportJobResponse> {
    authorize_scope(&state, &headers, &uri, scopes::RECOVERY_ADMIN)?;
    let job = state
        .import_export_jobs
        .get(&job_id)
        .await
        .ok_or(ApiError::NotFound)?;
    if job.status != ImportExportStatus::Failed {
        return Err(ApiError::BadRequest(
            "only failed jobs can be retried".to_string(),
        ));
    }
    tracing::info!(
        event = "audit recovery_job_retry",
        original_job_id = %job.job_id,
        instance_id = %job.instance_id,
        action = job.action.as_str(),
    );
    match job.action {
        ImportExportAction::Export => queue_export_instance(&state, &job.instance_id).await,
        ImportExportAction::Import => {
            let artifact_path = job.artifact_path.ok_or_else(|| {
                ApiError::BadRequest("failed import job has no artifact_path".to_string())
            })?;
            queue_import_instance(
                &state,
                &job.instance_id,
                ImportOptions::artifact(artifact_path),
            )
            .await
        }
    }
}

pub async fn restore_artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Json(request): Json<RestoreArtifactRequest>,
) -> ApiResult<ImportExportJobResponse> {
    authorize_scope(&state, &headers, &uri, scopes::RECOVERY_ADMIN)?;
    if !request.confirm {
        return Err(ApiError::BadRequest(
            "restore requires confirm=true".to_string(),
        ));
    }
    if request.reason.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "restore requires a non-empty reason".to_string(),
        ));
    }
    tracing::info!(
        event = "audit recovery_restore_requested",
        instance_id = %request.instance_id,
        artifact_path = %request.artifact_path,
        reason = %request.reason,
    );
    queue_import_instance(
        &state,
        &request.instance_id,
        ImportOptions::artifact(request.artifact_path),
    )
    .await
}
