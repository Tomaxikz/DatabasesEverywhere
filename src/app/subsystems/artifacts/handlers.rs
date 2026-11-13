use super::download::{create_download_url, download};
use super::files::{
    downloadable_artifact_path, read_instance_artifacts, remove_artifact_files, require_instance,
    verified_artifact_path,
};
use super::types::{
    ArtifactInfo, CreateDownloadRequest, DownloadKind, DownloadQuery, RetentionResponse,
};
use super::types::{DeleteArtifactResponse, DownloadUrlResponse};
use crate::auth::scopes;
use crate::routes::http::policy::ApiRequestContext;
use crate::routes::http::response::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResponse, ApiResult};
use crate::routes::http::router::AppState;
use axum::extract::{ConnectInfo, State};
use axum::response::Response;
use std::net::SocketAddr;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[utoipa::path(
    get,
    path = "/api/instances/{instance_id}/artifacts",
    tag = "artifacts",
    summary = "List retained export artifacts belonging to one instance.",
    description = "One-use stream-only export spools never appear in this inventory.",
    extensions(("x-required-scope" = json!(scopes::ARTIFACTS_READ))),
    params(("instance_id" = String, Path)),
    responses((status = 200, description = "Artifact list.", body = Vec<ArtifactInfo>))
)]
pub async fn list_instance_artifacts(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
) -> ApiResult<Vec<ArtifactInfo>> {
    auth.require_scope(scopes::ARTIFACTS_READ)?;
    require_instance(&state, &instance_id).await?;
    Ok(ApiResponse::ok(
        read_instance_artifacts(&state, &instance_id).await?,
    ))
}

#[utoipa::path(
    delete,
    path = "/api/instances/{instance_id}/artifacts/{artifact_id}",
    tag = "artifacts",
    summary = "Delete one retained artifact or pending one-use export belonging to an instance.",
    extensions(("x-required-scope" = json!(scopes::ARTIFACTS_WRITE))),
    params(("instance_id" = String, Path), ("artifact_id" = String, Path)),
    responses((status = 200, description = "Delete result.", body = DeleteArtifactResponse))
)]
pub async fn delete_artifact(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, artifact_id)): ApiPath<(String, String)>,
) -> ApiResult<DeleteArtifactResponse> {
    auth.require_scope(scopes::ARTIFACTS_WRITE)?;
    require_instance(&state, &instance_id).await?;
    let path = downloadable_artifact_path(&state, &artifact_id, &instance_id)
        .await?
        .path;
    match remove_artifact_files(&path).await {
        Ok(true) => {
            tracing::info!(event = "audit artifact_deleted", instance_id, artifact_id);
            Ok(ApiResponse::ok(DeleteArtifactResponse {
                id: artifact_id,
                deleted: true,
            }))
        }
        Ok(false) => Err(ApiError::NotFound),
        Err(error) => Err(ApiError::Runtime(format!(
            "failed to delete artifact: {error}"
        ))),
    }
}

#[utoipa::path(
    post,
    path = "/api/instances/{instance_id}/artifacts/retention",
    tag = "artifacts",
    summary = "Apply artifact retention for one instance.",
    extensions(("x-required-scope" = json!(scopes::ARTIFACTS_WRITE))),
    params(("instance_id" = String, Path)),
    responses((status = 200, description = "Deleted artifact IDs.", body = RetentionResponse))
)]
pub async fn apply_retention(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
) -> ApiResult<RetentionResponse> {
    auth.require_scope(scopes::ARTIFACTS_WRITE)?;
    require_instance(&state, &instance_id).await?;
    let mut artifacts = read_instance_artifacts(&state, &instance_id).await?;
    artifacts.sort_by(|left, right| right.modified_at.cmp(&left.modified_at));
    let cutoff = OffsetDateTime::now_utc()
        - time::Duration::days(state.config.artifacts.retention_max_age_days as i64);
    let keep_latest = state.config.artifacts.retention_keep_latest;
    let mut deleted = Vec::new();

    for (index, artifact) in artifacts.into_iter().enumerate() {
        let modified = OffsetDateTime::parse(&artifact.modified_at, &Rfc3339)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        if index < keep_latest && modified >= cutoff {
            continue;
        }
        let path = verified_artifact_path(&state, &artifact.id, &instance_id).await?;
        match remove_artifact_files(&path).await {
            Ok(true) => {
                deleted.push(artifact.id);
            }
            Ok(false) => {}
            Err(error) => {
                return Err(ApiError::Runtime(format!(
                    "failed to delete artifact {}: {error}",
                    artifact.id
                )));
            }
        }
    }

    tracing::info!(event = "audit artifact_retention_applied", deleted = ?deleted);
    Ok(ApiResponse::ok(RetentionResponse { deleted }))
}

#[utoipa::path(
    post,
    path = "/api/instances/{instance_id}/artifacts/{artifact_id}/download",
    tag = "artifacts",
    summary = "Create a temporary download URL for one instance artifact.",
    extensions(("x-required-scope" = json!(scopes::ARTIFACTS_READ))),
    params(("instance_id" = String, Path), ("artifact_id" = String, Path)),
    request_body = CreateDownloadRequest,
    responses((status = 200, description = "Temporary download URL.", body = DownloadUrlResponse))
)]
pub async fn create_artifact_download(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, artifact_id)): ApiPath<(String, String)>,
    ApiJson(request): ApiJson<CreateDownloadRequest>,
) -> ApiResult<DownloadUrlResponse> {
    auth.require_scope(scopes::ARTIFACTS_READ)?;
    create_download_url(
        &state,
        &artifact_id,
        &instance_id,
        request,
        DownloadKind::Artifact,
    )
    .await
}

#[utoipa::path(
    post,
    path = "/api/instances/{instance_id}/backups/{backup_id}/download",
    tag = "backups",
    summary = "Create a temporary download URL for one instance backup.",
    extensions(("x-required-scope" = json!(scopes::BACKUPS_READ))),
    params(("instance_id" = String, Path), ("backup_id" = String, Path)),
    request_body = CreateDownloadRequest,
    responses((status = 200, description = "Temporary download URL.", body = DownloadUrlResponse))
)]
pub async fn create_backup_download(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, backup_id)): ApiPath<(String, String)>,
    ApiJson(request): ApiJson<CreateDownloadRequest>,
) -> ApiResult<DownloadUrlResponse> {
    auth.require_scope(scopes::BACKUPS_READ)?;
    create_download_url(
        &state,
        &backup_id,
        &instance_id,
        request,
        DownloadKind::Backup,
    )
    .await
}

pub(crate) async fn artifact_download_url(
    state: &AppState,
    name: &str,
    instance_id: &str,
    expires_in_seconds: Option<i64>,
    single_use: bool,
) -> Result<DownloadUrlResponse, ApiError> {
    create_download_url(
        state,
        name,
        instance_id,
        CreateDownloadRequest {
            expires_in_seconds,
            single_use: Some(single_use),
        },
        DownloadKind::Artifact,
    )
    .await
    .map(ApiResponse::into_body)
}

#[utoipa::path(
    get,
    path = "/api/instances/{instance_id}/artifacts/{artifact_id}/download",
    tag = "artifacts",
    summary = "Download an artifact using its temporary URL.",
    description = "The stream is admitted under node-wide and transport-peer concurrency caps. A 429 response does not consume a single-use ticket. A stream-only export is deleted when this response finishes or disconnects.",
    security(),
    params(("instance_id" = String, Path), ("artifact_id" = String, Path), DownloadQuery),
    responses((status = 200, description = "Artifact file stream."))
)]
pub async fn download_artifact(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    ApiPath((instance_id, artifact_id)): ApiPath<(String, String)>,
    ApiQuery(query): ApiQuery<DownloadQuery>,
) -> Result<Response, ApiError> {
    download(
        &state,
        &query.token,
        &instance_id,
        &artifact_id,
        DownloadKind::Artifact,
        Some(peer),
    )
    .await
}

#[utoipa::path(
    get,
    path = "/api/instances/{instance_id}/backups/{backup_id}/download",
    tag = "backups",
    summary = "Download a backup using its temporary URL.",
    description = "The stream is admitted under node-wide and transport-peer concurrency caps. A 429 response does not consume a single-use ticket.",
    security(),
    params(("instance_id" = String, Path), ("backup_id" = String, Path), DownloadQuery),
    responses((status = 200, description = "Backup file stream."))
)]
pub async fn download_backup(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    ApiPath((instance_id, backup_id)): ApiPath<(String, String)>,
    ApiQuery(query): ApiQuery<DownloadQuery>,
) -> Result<Response, ApiError> {
    download(
        &state,
        &query.token,
        &instance_id,
        &backup_id,
        DownloadKind::Backup,
        Some(peer),
    )
    .await
}
