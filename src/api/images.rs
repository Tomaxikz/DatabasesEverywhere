use axum::{
    Json,
    extract::State,
    http::{HeaderMap, Uri},
};
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        handlers::{ApiError, ApiResult, authorize_scope},
        instances::docker_error,
        routes::AppState,
    },
    auth::scopes,
    shared::{images::is_pinned_image_reference, protocol::Protocol},
};

#[derive(Debug, Deserialize)]
pub struct PullImageRequest {
    pub protocol: Protocol,
    pub image: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PullImageResponse {
    pub protocol: Protocol,
    pub image: String,
    pub pulled: bool,
}

pub async fn pull_image(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Json(request): Json<PullImageRequest>,
) -> ApiResult<PullImageResponse> {
    authorize_scope(&state, &headers, &uri, scopes::IMAGES_ADMIN)?;
    let image = request
        .image
        .as_deref()
        .map(validate_image)
        .transpose()?
        .map(str::to_string)
        .unwrap_or_else(|| configured_image(&state, request.protocol).to_string());

    state
        .docker
        .pull_image(&image)
        .await
        .map_err(docker_error)?;

    Ok(Json(PullImageResponse {
        protocol: request.protocol,
        image,
        pulled: true,
    }))
}

pub(crate) fn validate_image(image: &str) -> Result<&str, ApiError> {
    let image = image.trim();
    if image.is_empty() {
        return Err(ApiError::BadRequest("image must not be empty".to_string()));
    }
    if image.chars().any(char::is_whitespace) {
        return Err(ApiError::BadRequest(
            "image must not contain whitespace".to_string(),
        ));
    }
    if !is_pinned_image_reference(image) {
        return Err(ApiError::BadRequest(
            "custom image must include a non-latest tag or sha256 digest".to_string(),
        ));
    }
    Ok(image)
}

fn configured_image(state: &AppState, protocol: Protocol) -> &str {
    match protocol {
        Protocol::Postgres => &state.config.images.postgres,
        Protocol::Redis => &state.config.images.redis,
        Protocol::Mariadb => &state.config.images.mariadb,
        Protocol::Mongodb => &state.config.images.mongodb,
        Protocol::Clickhouse => &state.config.images.clickhouse,
        Protocol::Qdrant => &state.config.images.qdrant,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_custom_latest_or_untagged_images() {
        assert!(validate_image("postgres").is_err());
        assert!(validate_image("postgres:latest").is_err());
        assert!(validate_image("registry.example.com:5000/postgres:latest").is_err());
    }

    #[test]
    fn accepts_custom_tagged_or_digest_pinned_images() {
        let digest = format!("postgres@sha256:{}", "a".repeat(64));

        assert_eq!(validate_image("postgres:18.4").unwrap(), "postgres:18.4");
        assert_eq!(
            validate_image("registry.example.com:5000/postgres:18.4").unwrap(),
            "registry.example.com:5000/postgres:18.4"
        );
        assert_eq!(validate_image(&digest).unwrap(), digest);
    }
}
