use axum::{
    Json,
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::{
    api::{allowed_hosts, routes::AppState},
    auth::jwt,
    constants,
};

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden: missing required scope {0}")]
    Forbidden(String),
    #[error("request host is not allowed")]
    HostNotAllowed,
    #[error("token in query string is not accepted")]
    QueryTokenRejected,
    #[error("websocket jwt is invalid: {0}")]
    InvalidWebSocketJwt(String),
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("rate limit exceeded")]
    RateLimited,
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),
    #[error("not implemented: {0}")]
    NotImplemented(String),
    #[error("runtime error: {0}")]
    Runtime(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized
            | Self::HostNotAllowed
            | Self::QueryTokenRejected
            | Self::InvalidWebSocketJwt(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            Self::Runtime(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let body = Json(ErrorBody {
            error: self.to_string(),
        });
        (status, body).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

pub fn authorize_scope(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    required_scope: &str,
) -> Result<(), ApiError> {
    reject_query_token(uri)?;
    authorize_allowed_host(state, headers, uri)?;
    let header = headers
        .get(constants::AUTHORIZATION_HEADER)
        .and_then(|value| value.to_str().ok());

    let accepted = state
        .api_token
        .accepted_from_authorization_header(header)
        .ok_or(ApiError::Unauthorized)?;
    if accepted.has_scope(required_scope) {
        Ok(())
    } else {
        Err(ApiError::Forbidden(required_scope.to_string()))
    }
}

pub fn authorize_websocket_jwt(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
    required_scope: &str,
    instance_id: Option<&str>,
) -> Result<jwt::Claims, ApiError> {
    reject_query_token(uri)?;
    authorize_allowed_host(state, headers, uri)?;
    let token = websocket_token(headers).ok_or(ApiError::Unauthorized)?;
    jwt::validate_ws_token(
        token,
        state.config.websocket_jwt_secret(),
        required_scope,
        instance_id,
    )
    .map_err(|error| ApiError::InvalidWebSocketJwt(error.to_string()))
}

fn reject_query_token(uri: &Uri) -> Result<(), ApiError> {
    if uri
        .query()
        .map(|query| query.split('&').any(|part| part.starts_with("token=")))
        .unwrap_or(false)
    {
        return Err(ApiError::QueryTokenRejected);
    }
    Ok(())
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(constants::AUTHORIZATION_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

pub(crate) fn websocket_token(headers: &HeaderMap) -> Option<&str> {
    bearer_token(headers).or_else(|| websocket_protocol_token(headers))
}

fn websocket_protocol_token(headers: &HeaderMap) -> Option<&str> {
    let header = headers
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())?;
    let protocols = header
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    for pair in protocols.windows(2) {
        if matches!(pair[0], "dbe.jwt" | "bearer") {
            return Some(pair[1]);
        }
    }

    protocols
        .iter()
        .find_map(|protocol| protocol.strip_prefix("dbe.jwt."))
}

fn authorize_allowed_host(
    state: &AppState,
    headers: &HeaderMap,
    _uri: &Uri,
) -> Result<(), ApiError> {
    let allowed_hosts = state.config.cors_allowed_hosts();
    if allowed_hosts.is_empty() {
        return Err(ApiError::HostNotAllowed);
    }

    let Some(origin) = headers.get("origin").and_then(|value| value.to_str().ok()) else {
        return Ok(());
    };

    let allowed = allowed_hosts::origin_is_allowed(origin, &allowed_hosts);

    if allowed {
        Ok(())
    } else {
        Err(ApiError::HostNotAllowed)
    }
}

pub type ApiResult<T> = Result<Json<T>, ApiError>;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::{HeaderMap, HeaderValue, Uri};

    use super::*;
    use crate::{
        auth::api_token::ApiToken,
        config::Config,
        instances::{manager::InstanceManager, state::InstanceStore},
        jobs::import_export::ImportExportJobs,
        runtime::docker::DockerRuntime,
        storage::{repositories::InstanceRepository, sqlite},
    };

    #[tokio::test]
    async fn rejects_token_in_query_string() {
        let state = test_state().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            constants::AUTHORIZATION_HEADER,
            HeaderValue::from_static("Bearer secret"),
        );
        headers.insert("host", HeaderValue::from_static("panel.example.com"));
        let uri = "/api/system?token=secret".parse::<Uri>().unwrap();

        let error =
            authorize_scope(&state, &headers, &uri, crate::auth::scopes::SYSTEM_READ).unwrap_err();

        assert!(matches!(error, ApiError::QueryTokenRejected));
    }

    #[tokio::test]
    async fn rejects_origin_not_matching_remote() {
        let state = test_state().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            constants::AUTHORIZATION_HEADER,
            HeaderValue::from_static("Bearer secret"),
        );
        headers.insert(
            "origin",
            HeaderValue::from_static("https://other.example.com"),
        );
        let uri = "/api/system".parse::<Uri>().unwrap();

        let error =
            authorize_scope(&state, &headers, &uri, crate::auth::scopes::SYSTEM_READ).unwrap_err();

        assert!(matches!(error, ApiError::HostNotAllowed));
    }

    #[tokio::test]
    async fn accepts_websocket_jwt_from_subprotocol_pair() {
        let state = test_state().await;
        let (token, _) = crate::auth::jwt::issue_ws_token(
            state.config.websocket_jwt_secret(),
            "test-subject",
            vec![crate::auth::scopes::MONITOR_READ.to_string()],
            Vec::new(),
            true,
            60,
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "sec-websocket-protocol",
            HeaderValue::from_str(&format!("dbe.jwt, {token}")).unwrap(),
        );
        headers.insert(
            "origin",
            HeaderValue::from_static("https://panel.example.com"),
        );
        let uri = "/ws/monitoring".parse::<Uri>().unwrap();

        authorize_websocket_jwt(
            &state,
            &headers,
            &uri,
            crate::auth::scopes::MONITOR_READ,
            None,
        )
        .unwrap();
    }

    async fn test_state() -> AppState {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let store = InstanceStore::default();
        let manager = InstanceManager::new(store.clone(), InstanceRepository::new(pool));
        AppState {
            config: Arc::new(Config {
                uuid: "node-uuid".to_string(),
                token_id: "token-id".to_string(),
                token: "secret".to_string(),
                jwt_signing_key: "test-jwt-signing-key-at-least-32-bytes".to_string(),
                remote: "https://panel.example.com".to_string(),
                api: crate::config::ApiConfig {
                    host: "127.0.0.1".to_string(),
                    port: 8090,
                    ..Default::default()
                },
                ..Default::default()
            }),
            config_path: dir.path().join("config.yml"),
            api_token: ApiToken::new("secret"),
            instances: store,
            manager,
            instance_locks: crate::instances::locks::InstanceLocks::default(),
            docker: DockerRuntime::new(&Default::default(), false).unwrap(),
            import_export_jobs: ImportExportJobs::default(),
            api_rate_limiter: crate::api::security::ApiRateLimiter::default(),
            install_progress: crate::api::progress::InstallProgressStore::default(),
            artifact_downloads: crate::api::artifacts::ArtifactDownloadTickets::default(),
            resource_cache: crate::api::resources::ResourceCache::default(),
            instance_runtime_cache: crate::api::instances::InstanceRuntimeInfoCache::default(),
        }
    }
}
