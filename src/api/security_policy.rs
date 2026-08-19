use axum::{
    body::Body,
    extract::{FromRequestParts, State},
    http::{HeaderMap, HeaderValue, Method, Request, Uri, header, request::Parts},
    middleware::Next,
    response::Response,
};
use serde::Deserialize;
use std::{collections::HashSet, sync::Arc};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::{
    api::{
        allowed_hosts, api_response::ApiError, routes::AppState, security::RequestAuthentication,
    },
    auth::{api_token::AcceptedApiToken, jwt},
    config::Config,
    constants,
};

#[derive(Debug, Clone)]
pub struct HostPolicy {
    request_hosts: Arc<HashSet<String>>,
    allowed_origins: Arc<HashSet<String>>,
}

impl HostPolicy {
    pub fn from_config(config: &Config) -> Self {
        Self {
            request_hosts: normalized_hosts(config.request_allowed_hosts()),
            allowed_origins: Arc::new(config.cors_allowed_origins().into_iter().collect()),
        }
    }

    fn allows_request_host(&self, host: &str) -> bool {
        self.request_hosts.contains(host)
    }

    fn allows_origin(&self, origin: &str) -> bool {
        crate::config::normalize_http_origin(origin)
            .map(|origin| self.allowed_origins.contains(&origin))
            .unwrap_or(false)
    }

    fn is_complete(&self) -> bool {
        !self.request_hosts.is_empty() && !self.allowed_origins.is_empty()
    }
}

fn normalized_hosts(hosts: Vec<String>) -> Arc<HashSet<String>> {
    Arc::new(
        hosts
            .into_iter()
            .map(|host| allowed_hosts::normalize_host(&host))
            .collect(),
    )
}

/// Authentication extracted before path, query, or body parsing.
///
/// Handlers still name their required scope explicitly, but token and
/// query-token policy is evaluated before path, query, or body deserialization.
/// Host and Origin policy is enforced globally by `enforce_request_host_policy`.
#[derive(Debug, Clone)]
pub struct ApiRequestContext {
    actor: AcceptedApiToken,
}

#[derive(Debug, Clone)]
pub struct WebSocketRequestContext {
    claims: Arc<jwt::Claims>,
}

impl WebSocketRequestContext {
    pub fn require_scope(
        &self,
        required_scope: &str,
        instance_id: Option<&str>,
    ) -> Result<Arc<jwt::Claims>, ApiError> {
        if !self
            .claims
            .scopes
            .iter()
            .any(|scope| scope == required_scope)
        {
            return Err(ApiError::Forbidden(required_scope.to_string()));
        }
        if let Some(instance_id) = instance_id
            && !self.claims.allows_instance(instance_id)
        {
            return Err(ApiError::Forbidden(format!("instance:{instance_id}")));
        }
        Ok(Arc::clone(&self.claims))
    }
}

impl FromRequestParts<AppState> for WebSocketRequestContext {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        reject_query_token(&parts.uri)?;
        if let Some(authentication) = parts.extensions.get::<RequestAuthentication>() {
            return match authentication {
                RequestAuthentication::WebSocket(claims) => Ok(Self {
                    claims: Arc::clone(claims),
                }),
                _ => Err(ApiError::Unauthorized),
            };
        }
        let token = websocket_token(&parts.headers).ok_or(ApiError::Unauthorized)?;
        let claims = jwt::validate_ws_token_claims(token, state.config.websocket_jwt_secret())
            .map_err(|error| ApiError::InvalidWebSocketJwt(error.to_string()))?;
        Ok(Self {
            claims: Arc::new(claims),
        })
    }
}

impl ApiRequestContext {
    pub fn require_scope(&self, required_scope: &str) -> Result<(), ApiError> {
        if self.actor.has_scope(required_scope) {
            Ok(())
        } else {
            Err(ApiError::Forbidden(required_scope.to_string()))
        }
    }

    pub fn actor_name(&self) -> &str {
        &self.actor.name
    }
}

impl FromRequestParts<AppState> for ApiRequestContext {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        reject_query_token(&parts.uri)?;
        if let Some(authentication) = parts.extensions.get::<RequestAuthentication>() {
            return match authentication {
                RequestAuthentication::Api(actor) => Ok(Self {
                    actor: actor.clone(),
                }),
                _ => Err(ApiError::Unauthorized),
            };
        }
        let authorization = parts
            .headers
            .get(constants::AUTHORIZATION_HEADER)
            .and_then(|value| value.to_str().ok());
        let actor = state
            .api_token
            .accepted_from_authorization_header(authorization)
            .ok_or(ApiError::Unauthorized)?;
        Ok(Self { actor })
    }
}

pub fn enforce_allowed_request_hosts(
    state: &AppState,
    headers: &HeaderMap,
    uri: &Uri,
) -> Result<(), ApiError> {
    validate_allowed_request_hosts(headers, uri, state.host_policy())
}

pub async fn enforce_request_host_policy(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    enforce_allowed_request_hosts(&state, request.headers(), request.uri())?;
    Ok(next.run(request).await)
}

pub fn cors_layer(policy: HostPolicy) -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(
            move |origin: &HeaderValue, _request_parts| {
                origin
                    .to_str()
                    .map(|origin| policy.allows_origin(origin))
                    .unwrap_or(false)
            },
        ))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::CONTENT_LENGTH,
            http::HeaderName::from_static("x-dbev-filename"),
            http::HeaderName::from_static("x-dbev-sha256"),
        ])
}

fn validate_allowed_request_hosts(
    headers: &HeaderMap,
    uri: &Uri,
    policy: &HostPolicy,
) -> Result<(), ApiError> {
    if !policy.is_complete() {
        return Err(ApiError::HostNotAllowed);
    }

    let request_host =
        allowed_hosts::request_host_with_uri(headers, Some(uri)).ok_or(ApiError::HostNotAllowed)?;
    if !policy.allows_request_host(&request_host) {
        return Err(ApiError::HostNotAllowed);
    }

    if let Some(origin) = headers.get("origin") {
        let origin = origin.to_str().map_err(|_| ApiError::HostNotAllowed)?;
        if !policy.allows_origin(origin) {
            return Err(ApiError::HostNotAllowed);
        }
    }
    Ok(())
}

pub fn reject_query_token(uri: &Uri) -> Result<(), ApiError> {
    if uri
        .query()
        .map(|query| {
            query.split('&').any(|part| {
                part.split_once('=')
                    .map(|(name, _)| name == "token")
                    .unwrap_or(part == "token")
            })
        })
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestructiveActionConfirmation {
    pub confirm: bool,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct AuthorizedDestructiveAction {
    reason: String,
}

impl AuthorizedDestructiveAction {
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

pub struct DestructiveActionPolicy;

impl DestructiveActionPolicy {
    pub fn authorize(
        action: &str,
        confirmation: &DestructiveActionConfirmation,
    ) -> Result<AuthorizedDestructiveAction, ApiError> {
        if !confirmation.confirm {
            return Err(ApiError::BadRequest(format!(
                "{action} requires confirm=true"
            )));
        }
        let reason = confirmation.reason.trim();
        if reason.is_empty() {
            return Err(ApiError::BadRequest(format!(
                "{action} requires a non-empty reason"
            )));
        }
        if reason.chars().count() > 512 {
            return Err(ApiError::BadRequest(format!(
                "{action} reason must be at most 512 characters"
            )));
        }
        Ok(AuthorizedDestructiveAction {
            reason: reason.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destructive_actions_require_confirmation_and_reason() {
        let missing_confirmation = DestructiveActionConfirmation {
            confirm: false,
            reason: "maintenance".to_string(),
        };
        assert!(DestructiveActionPolicy::authorize("restore", &missing_confirmation).is_err());

        let missing_reason = DestructiveActionConfirmation {
            confirm: true,
            reason: "   ".to_string(),
        };
        assert!(DestructiveActionPolicy::authorize("restore", &missing_reason).is_err());

        let valid = DestructiveActionConfirmation {
            confirm: true,
            reason: " operator approved ".to_string(),
        };
        assert_eq!(
            DestructiveActionPolicy::authorize("restore", &valid)
                .unwrap()
                .reason(),
            "operator approved"
        );
    }

    #[test]
    fn rejects_any_query_token_parameter() {
        for uri in [
            "/api/system?token=secret",
            "/api/system?other=1&token=secret",
            "/api/system?token",
        ] {
            assert!(matches!(
                reject_query_token(&uri.parse().unwrap()),
                Err(ApiError::QueryTokenRejected)
            ));
        }
    }

    #[test]
    fn validates_host_and_origin_independently() {
        let policy = HostPolicy {
            request_hosts: normalized_hosts(vec!["panel.example.com".to_string()]),
            allowed_origins: Arc::new(HashSet::from(["https://panel.example.com:443".to_string()])),
        };
        let uri = "/api/system".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("host", "evil.example.com".parse().unwrap());
        headers.insert("origin", "https://panel.example.com".parse().unwrap());

        assert!(matches!(
            validate_allowed_request_hosts(&headers, &uri, &policy),
            Err(ApiError::HostNotAllowed)
        ));

        headers.insert("host", "panel.example.com".parse().unwrap());
        assert!(validate_allowed_request_hosts(&headers, &uri, &policy).is_ok());

        headers.insert("origin", "https://evil.example.com".parse().unwrap());
        assert!(matches!(
            validate_allowed_request_hosts(&headers, &uri, &policy),
            Err(ApiError::HostNotAllowed)
        ));
    }

    #[test]
    fn origin_policy_matches_scheme_host_and_effective_port() {
        let mut config = Config {
            remote: "https://panel.example.com/app".to_string(),
            ..Config::default()
        };
        config.api.trusted_origins = vec!["http://localhost:3000/".to_string()];
        let policy = HostPolicy::from_config(&config);

        assert!(policy.allows_origin("https://panel.example.com"));
        assert!(policy.allows_origin("https://PANEL.example.com:443"));
        assert!(policy.allows_origin("http://localhost:3000"));
        assert!(!policy.allows_origin("http://panel.example.com"));
        assert!(!policy.allows_origin("https://panel.example.com:444"));
        assert!(!policy.allows_origin("https://localhost:3000"));
        assert!(!policy.allows_origin("http://localhost"));
        assert!(!policy.allows_origin("https://panel.example.com/path"));
    }

    #[test]
    fn fqdn_and_cors_origin_are_independent_trust_boundaries() {
        let config = Config {
            remote: "https://panel.example.com".to_string(),
            api: crate::config::ApiConfig {
                host: "0.0.0.0".to_string(),
                fqdn: "db.example.com".to_string(),
                ..crate::config::ApiConfig::default()
            },
            ..Config::default()
        };
        let policy = HostPolicy::from_config(&config);

        assert!(policy.allows_request_host("db.example.com"));
        assert!(!policy.allows_request_host("panel.example.com"));
        assert!(policy.allows_origin("https://panel.example.com"));
        assert!(!policy.allows_origin("https://db.example.com"));
    }
}
