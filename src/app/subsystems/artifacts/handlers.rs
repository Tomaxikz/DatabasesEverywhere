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
