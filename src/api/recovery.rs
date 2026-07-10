use axum::extract::State;
use serde::Deserialize;

use crate::{
    api::{
        api_response::{ApiError, ApiJson, ApiPath, ApiResponse, ApiResult},
        import_export::ImportOptions,
        import_export::{ImportExportJobResponse, queue_export_instance, queue_import_instance},
        routes::AppState,
        security_policy::{
            ApiRequestContext, DestructiveActionConfirmation, DestructiveActionPolicy,
        },
    },
    auth::scopes,
    jobs::import_export::{ImportExportAction, ImportExportStatus},
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreArtifactRequest {
    pub artifact_id: String,
    pub confirm: bool,
    pub reason: String,
}

pub async fn failed_jobs(
    State(state): State<AppState>,
    auth: ApiRequestContext,
) -> ApiResult<Vec<ImportExportJobResponse>> {
    auth.require_scope(scopes::RECOVERY_ADMIN)?;
    let jobs = state
        .import_export_jobs
        .list(None, Some(ImportExportStatus::Failed), 100)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let mut response = Vec::with_capacity(jobs.len());
    for job in jobs {
        response.push(crate::api::import_export::public_job_response(job).await);
    }
    Ok(ApiResponse::ok(response))
}

pub async fn retry_job(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, job_id)): ApiPath<(String, String)>,
) -> ApiResult<ImportExportJobResponse> {
    auth.require_scope(scopes::RECOVERY_ADMIN)?;
    let job = state
        .import_export_jobs
        .get(&job_id)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?
        .ok_or(ApiError::NotFound)?;
    if job.instance_id != instance_id {
        return Err(ApiError::NotFound);
    }
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
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiJson(request): ApiJson<RestoreArtifactRequest>,
) -> ApiResult<ImportExportJobResponse> {
    auth.require_scope(scopes::RECOVERY_ADMIN)?;
    let confirmation = DestructiveActionConfirmation {
        confirm: request.confirm,
        reason: request.reason,
    };
    let authorization = DestructiveActionPolicy::authorize("recovery restore", &confirmation)?;
    tracing::info!(
        event = "audit recovery_restore_requested",
        instance_id,
        artifact_id = %request.artifact_id,
        reason = authorization.reason(),
    );
    state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let artifact_path = crate::api::artifacts::verified_artifact_path_for_instance(
        &state,
        &request.artifact_id,
        &instance_id,
    )
    .await?;
    queue_import_instance(&state, &instance_id, ImportOptions::artifact(artifact_path)).await
}
