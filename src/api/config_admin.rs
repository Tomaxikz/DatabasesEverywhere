use axum::{
    Json,
    extract::State,
    http::{HeaderMap, Uri},
};
use serde::Serialize;
use serde_json::Value;

use crate::{
    api::{
        handlers::{ApiError, ApiResult, authorize_scope},
        routes::AppState,
    },
    auth::scopes,
    config::{Config, validate::validate_config},
};

const FORBIDDEN_PATCH_PATHS: &[&[&str]] = &[&["token"], &["token_id"], &["uuid"]];

#[derive(Debug, Serialize)]
pub struct ConfigPatchResponse {
    pub applied: bool,
    pub restart_required: bool,
    pub config_path: String,
}

pub async fn patch_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Json(patch): Json<Value>,
) -> ApiResult<ConfigPatchResponse> {
    authorize_scope(&state, &headers, &uri, scopes::CONFIG_ADMIN)?;
    if !patch.is_object() {
        return Err(ApiError::BadRequest(
            "config patch must be a JSON object".to_string(),
        ));
    }
    reject_forbidden_paths(&patch)?;

    let mut document = serde_json::to_value(state.config.as_ref())
        .map_err(|error| ApiError::Runtime(format!("failed to serialize config: {error}")))?;
    merge_json(&mut document, patch);
    let config: Config = serde_json::from_value(document)
        .map_err(|error| ApiError::BadRequest(format!("invalid config patch: {error}")))?;
    validate_config(&config).map_err(|error| ApiError::BadRequest(error.to_string()))?;

    let yaml = serde_yaml::to_string(&config)
        .map_err(|error| ApiError::Runtime(format!("failed to encode config: {error}")))?;
    tokio::fs::write(&state.config_path, yaml)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to write config: {error}")))?;

    tracing::info!(
        event = "audit config_patch_applied",
        config = %state.config_path.display(),
        "config patch written; daemon restart required"
    );

    Ok(Json(ConfigPatchResponse {
        applied: true,
        restart_required: true,
        config_path: state.config_path.display().to_string(),
    }))
}

fn merge_json(target: &mut Value, patch: Value) {
    match (target, patch) {
        (Value::Object(target), Value::Object(patch)) => {
            for (key, value) in patch {
                if value.is_null() {
                    target.remove(&key);
                } else {
                    merge_json(target.entry(key).or_insert(Value::Null), value);
                }
            }
        }
        (target, patch) => *target = patch,
    }
}

fn reject_forbidden_paths(patch: &Value) -> Result<(), ApiError> {
    for path in FORBIDDEN_PATCH_PATHS {
        if value_has_path(patch, path) {
            return Err(ApiError::BadRequest(format!(
                "config patch may not modify {}",
                path.join(".")
            )));
        }
    }
    Ok(())
}

fn value_has_path(value: &Value, path: &[&str]) -> bool {
    let mut current = value;
    for segment in path {
        let Some(next) = current.get(*segment) else {
            return false;
        };
        current = next;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_json_replaces_scalars_and_merges_objects() {
        let mut target = serde_json::json!({
            "api": { "host": "127.0.0.1", "port": 8090 },
            "debug": false
        });
        merge_json(
            &mut target,
            serde_json::json!({
                "api": { "port": 9090 },
                "debug": true
            }),
        );

        assert_eq!(target["api"]["host"], "127.0.0.1");
        assert_eq!(target["api"]["port"], 9090);
        assert_eq!(target["debug"], true);
    }

    #[test]
    fn rejects_token_patch() {
        let patch = serde_json::json!({ "token": "new" });

        assert!(reject_forbidden_paths(&patch).is_err());
    }
}
