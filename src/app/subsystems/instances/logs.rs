use super::docker_error;
use super::runtime_info::{LogsQuery, LogsResponse};
use super::shared;
use crate::auth::scopes;
use crate::routes::http::policy::ApiRequestContext;
use crate::routes::http::response::{ApiError, ApiPath, ApiQuery, ApiResponse, ApiResult};
use crate::routes::http::router::AppState;
use crate::server::metadata::InstanceMetadata;
use crate::utils::redaction;
use axum::extract::State;

pub async fn instance_logs(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<LogsQuery>,
) -> ApiResult<LogsResponse> {
    auth.require_scope(scopes::LOGS_READ)?;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    check_logs_available(&metadata)?;
    let output = state
        .docker
        .logs(metadata.protocol, &metadata.instance_id, query.tail)
        .await
        .map_err(docker_error)?;
    Ok(ApiResponse::ok(LogsResponse {
        instance_id,
        stdout: redaction::redact_connection_url(&output.stdout),
        stderr: redaction::redact_connection_url(&output.stderr),
    }))
}

pub(crate) fn check_logs_available(metadata: &InstanceMetadata) -> Result<(), ApiError> {
    if metadata.deployment_mode == crate::server::placement::DeploymentMode::Shared {
        Err(shared::reject_logs())
    } else {
        Ok(())
    }
}
