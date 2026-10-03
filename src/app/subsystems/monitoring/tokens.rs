use std::collections::HashSet;

use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::{
    auth::{jwt, scopes},
    routes::http::{
        policy::ApiRequestContext,
        response::{ApiError, ApiJson, ApiResponse, ApiResult},
        router::AppState,
    },
};

const DEFAULT_TTL_SECONDS: i64 = 900;
const MAX_TTL_SECONDS: i64 = 3600;
const MAX_TARGETS: usize = 256;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueWsTokenRequest {
    #[serde(default)]
    pub pools: Vec<String>,
    pub server_id: Option<String>,
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
    auth: ApiRequestContext,
    ApiJson(request): ApiJson<IssueWsTokenRequest>,
) -> ApiResult<IssueWsTokenResponse> {
    auth.require_scope(scopes::WS_TOKENS_WRITE)?;
    validate_request(&request)?;
    let ttl_seconds = request.ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
    let targets = if request.pools.is_empty() {
        instance_targets(&state, &request).await?
    } else {
        pool_targets(&state, &request).await?
    };
    let (token, expires_at_unix) = jwt::issue_ws_token(
        state.config.websocket_jwt_secret(),
        request.subject.trim(),
        request.scopes.clone(),
        targets,
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

    Ok(ApiResponse::ok(IssueWsTokenResponse {
        token_type: "Bearer",
        token,
        expires_at_unix,
    }))
}

async fn instance_targets(
    state: &AppState,
    request: &IssueWsTokenRequest,
) -> Result<jwt::WsTargets, ApiError> {
    let generation = if request.all_instances {
        None
    } else {
        Some(instance_generation_digest(state, &request.instances).await?)
    };
    Ok(jwt::WsTargets::Instances {
        instances: request.instances.clone(),
        all_instances: request.all_instances,
        generation,
    })
}

async fn instance_generation_digest(
    state: &AppState,
    instance_ids: &[String],
) -> Result<String, ApiError> {
    let mut generations = Vec::with_capacity(instance_ids.len());
    for instance_id in instance_ids {
        let metadata = state
            .instances
            .get(instance_id)
            .await
            .ok_or(ApiError::NotFound)?;
        generations.push((instance_id.clone(), metadata.created_at));
    }
    Ok(jwt::instance_generation_digest(&generations))
}

async fn pool_targets(
    state: &AppState,
    request: &IssueWsTokenRequest,
) -> Result<jwt::WsTargets, ApiError> {
    let server_id = request
        .server_id
        .clone()
        .ok_or_else(|| ApiError::BadRequest("pool tokens require server_id".into()))?;
    let owner = crate::server::placement::PoolOwner {
        panel_id: state.config.token_id.clone(),
        server_id,
    };
    owner.check().map_err(ApiError::BadRequest)?;
    let mut grants = Vec::new();
    for pool_id in &request.pools {
        let pool = crate::subsystems::pools::load(state, pool_id).await?;
        if pool.owner.as_ref() != Some(&owner) {
            return Err(ApiError::Forbidden("pool ownership".into()));
        }
        grants.push(jwt::PoolGrant {
            runtime_id: pool.runtime_id,
            owner: owner.clone(),
            created_at: pool.created_at,
        });
    }
    Ok(jwt::WsTargets::Pools(grants))
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
    if !request.all_instances && request.instances.is_empty() && request.pools.is_empty() {
        return Err(ApiError::BadRequest(
            "provide at least one instance or explicitly set all_instances=true".to_string(),
        ));
    }
    if request.instances.len() > MAX_TARGETS {
        return Err(ApiError::BadRequest(
            "instances may contain at most 256 entries".to_string(),
        ));
    }
    let mut unique_instances = HashSet::with_capacity(request.instances.len());
    for instance_id in &request.instances {
        crate::utils::ids::validate_instance_id(instance_id)
            .map_err(|error| ApiError::BadRequest(error.to_string()))?;
        if !unique_instances.insert(instance_id) {
            return Err(ApiError::BadRequest(
                "instances must not contain duplicates".to_string(),
            ));
        }
    }
    if !request.pools.is_empty() {
        if request.pools.len() > MAX_TARGETS
            || request.all_instances
            || !request.instances.is_empty()
            || request.server_id.is_none()
        {
            return Err(ApiError::BadRequest("pool tokens require an explicit pool allow-list and server_id, without instance targets".into()));
        }
        let mut seen = HashSet::new();
        for id in &request.pools {
            crate::utils::ids::validate_instance_id(id)
                .map_err(|error| ApiError::BadRequest(error.to_string()))?;
            if !seen.insert(id) {
                return Err(ApiError::BadRequest("duplicate pool target".into()));
            }
        }
    } else if request.server_id.is_some() {
        return Err(ApiError::BadRequest(
            "server_id applies only to pool tokens".into(),
        ));
    }
    for scope in &request.scopes {
        let allowed = if request.pools.is_empty() {
            known_scope(scope)
        } else {
            matches!(scope.as_str(), scopes::POOLS_LOGS | scopes::POOLS_MONITOR)
        };
        if !allowed {
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
            pools: Vec::new(),
            server_id: None,
            subject: "panel-user".to_string(),
            scopes: vec![scopes::MONITOR_READ.to_string()],
            instances: instances.into_iter().map(str::to_string).collect(),
            all_instances,
            ttl_seconds: Some(60),
        }
    }

    #[test]
    fn node_wide_scope_must_be_explicit_and_unambiguous() {
        assert!(matches!(
            validate_request(&request(Vec::new(), false)),
            Err(ApiError::BadRequest(_))
        ));
        validate_request(&request(Vec::new(), true)).unwrap();
        assert!(validate_request(&request(vec!["inst_one"], true)).is_err());
    }

    #[test]
    fn selected_instance_ids_must_be_unique() {
        assert!(matches!(
            validate_request(&request(vec!["inst_one", "inst_one"], false)),
            Err(ApiError::BadRequest(_))
        ));
    }
}
