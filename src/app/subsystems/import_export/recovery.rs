use axum::extract::State;
use serde::Deserialize;

use crate::{
    auth::scopes,
    routes::http::{
        policy::{ApiRequestContext, DestructiveActionConfirmation, DestructiveActionPolicy},
        response::{ApiError, ApiJson, ApiPath, ApiResponse, ApiResult},
        router::AppState,
    },
    server::jobs::import_export::ImportExportStatus,
    subsystems::import_export::{
        ImportExportJobResponse, ImportOptions, queue_import_instance, replay_failed_job,
    },
};

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RestoreArtifactRequest {
    pub artifact_id: String,
    pub confirm: bool,
    #[schema(min_length = 1, max_length = 512)]
    pub reason: String,
}

#[utoipa::path(
    get,
    path = "/api/admin/recovery/failed-jobs",
    tag = "admin",
    summary = "List failed import/export jobs across the node.",
    extensions(("x-required-scope" = json!(scopes::RECOVERY_ADMIN))),
    responses((status = 200, description = "Failed job list.", body = Vec<ImportExportJobResponse>))
)]
pub async fn failed_jobs(
    State(state): State<AppState>,
    auth: ApiRequestContext,
) -> ApiResult<Vec<ImportExportJobResponse>> {
    auth.require_scope(scopes::RECOVERY_ADMIN)?;
    let jobs = state
        .import_export_jobs
        .list(None, Some(ImportExportStatus::Failed), 100)
        .await
        .map_err(ApiError::runtime)?;
    let mut response = Vec::with_capacity(jobs.len());
    for job in jobs {
        response.push(crate::subsystems::import_export::public_job_response(job).await);
    }
    Ok(ApiResponse::ok(response))
}

#[utoipa::path(
    post,
    path = "/api/instances/{instance_id}/recovery/jobs/{job_id}/retry",
    tag = "import-export",
    summary = "Retry a failed export or artifact import from its sanitized replay options. Credential imports and legacy jobs must be resubmitted.",
    extensions(("x-required-scope" = json!(scopes::RECOVERY_ADMIN))),
    params(("instance_id" = String, Path), ("job_id" = String, Path)),
    responses((
        status = 202,
        description = "Replacement job.",
        body = ImportExportJobResponse,
        headers(("Location" = String, description = "Origin-relative replacement job status URL."))
    ))
)]
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
        .map_err(ApiError::runtime)?
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
    replay_failed_job(&state, &job).await
}

#[utoipa::path(
    post,
    path = "/api/instances/{instance_id}/recovery/restore",
    tag = "import-export",
    summary = "Restore an export artifact belonging to the same instance.",
    extensions(("x-required-scope" = json!(scopes::RECOVERY_ADMIN))),
    params(("instance_id" = String, Path)),
    request_body = inline(RestoreArtifactRequest),
    responses((
        status = 202,
        description = "Queued restore job.",
        body = ImportExportJobResponse,
        headers(("Location" = String, description = "Origin-relative restore job status URL."))
    ))
)]
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
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let artifact_path = crate::subsystems::artifacts::verified_artifact_path(
        &state,
        &request.artifact_id,
        &instance_id,
    )
    .await?;
    queue_import_instance(
        &state,
        &instance_id,
        ImportOptions::recovery_restore(artifact_path, metadata.protocol),
    )
    .await
}
