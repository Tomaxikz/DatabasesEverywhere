use axum::{
    Json,
    extract::State,
    http::{HeaderMap, Uri},
};
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        handlers::{ApiError, ApiResult, authorize_scope},
        routes::AppState,
    },
    auth::{jwt, scopes},
};

const DEFAULT_TTL_SECONDS: i64 = 900;
const MAX_TTL_SECONDS: i64 = 3600;

#[derive(Debug, Deserialize)]
pub struct IssueWsTokenRequest {
    pub subject: String,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub instances: Vec<String>,
    #[serde(default)]
    pub all_instances: bool,
    pub ttl_seconds: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct IssueWsTokenResponse {
    pub token_type: &'static str,
    pub token: String,
    pub expires_at_unix: i64,
}

pub async fn issue_ws_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Json(request): Json<IssueWsTokenRequest>,
) -> ApiResult<IssueWsTokenResponse> {
    authorize_scope(&state, &headers, &uri, scopes::WS_TOKENS_WRITE)?;
    validate_request(&request)?;
    let ttl_seconds = request.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
    let (token, expires_at_unix) = jwt::issue_ws_token(
        state.config.websocket_jwt_secret(),
        request.subject.trim(),
        request.scopes.clone(),
        request.instances.clone(),
        request.all_instances,
        ttl_seconds,
    )
    .map_err(|error| ApiError::Runtime(error.to_string()))?;

    tracing::info!(
        event = "audit ws_token_issued",
        subject = %request.subject,
        scopes = ?request.scopes,
        instances = ?request.instances,
        all_instances = request.all_instances,
        expires_at_unix,
    );

    Ok(Json(IssueWsTokenResponse {
        token_type: "Bearer",
        token,
        expires_at_unix,
    }))
}

fn validate_request(request: &IssueWsTokenRequest) -> Result<(), ApiError> {
    if request.subject.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "subject must not be empty".to_string(),
        ));
    }
    if request.scopes.is_empty() {
        return Err(ApiError::BadRequest("scopes must not be empty".to_string()));
    }
    if request.all_instances && !request.instances.is_empty() {
        return Err(ApiError::BadRequest(
            "all_instances=true may not be combined with an instance allow-list".to_string(),
        ));
    }
    if !request.all_instances && request.instances.is_empty() {
        return Err(ApiError::BadRequest(
            "provide at least one instance or explicitly set all_instances=true".to_string(),
        ));
    }
    if request.instances.len() > 256 {
        return Err(ApiError::BadRequest(
            "instances may contain at most 256 entries".to_string(),
        ));
    }
    for instance_id in &request.instances {
        crate::shared::ids::validate_instance_id(instance_id)
            .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    }
    for scope in &request.scopes {
        if !known_scope(scope) {
            return Err(ApiError::BadRequest(format!("unsupported scope {scope}")));
        }
    }
    let ttl_seconds = request.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
    if !(1..=MAX_TTL_SECONDS).contains(&ttl_seconds) {
        return Err(ApiError::BadRequest(format!(
            "ttl_seconds must be between 1 and {MAX_TTL_SECONDS}"
        )));
    }
    Ok(())
}

fn known_scope(scope: &str) -> bool {
    matches!(
        scope,
        scopes::MONITOR_READ | scopes::LOGS_READ | scopes::IMPORT_EXPORT_READ
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(instances: Vec<&str>, all_instances: bool) -> IssueWsTokenRequest {
        IssueWsTokenRequest {
            subject: "panel-user".to_string(),
            scopes: vec![scopes::MONITOR_READ.to_string()],
            instances: instances.into_iter().map(str::to_string).collect(),
            all_instances,
            ttl_seconds: Some(60),
        }
    }

    #[test]
    fn empty_instance_scope_is_not_implicitly_node_wide() {
        assert!(matches!(
            validate_request(&request(Vec::new(), false)),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn node_wide_scope_must_be_explicit_and_unambiguous() {
        validate_request(&request(Vec::new(), true)).unwrap();
        assert!(validate_request(&request(vec!["inst_one"], true)).is_err());
    }
}
