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
    ensure_image_allowed(&state, request.protocol, &image)?;

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

pub(crate) fn ensure_image_allowed(
    state: &AppState,
    protocol: Protocol,
    image: &str,
) -> Result<(), ApiError> {
    let allowed = state.config.images.allowed_for_protocol(protocol);
    if allowed.contains(&image) {
        return Ok(());
    }
    Err(ApiError::BadRequest(format!(
        "image {image} is not allowed for {}; allowed images: {}",
        protocol.as_str(),
        allowed.join(", ")
    )))
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
    state.config.images.configured_for_protocol(protocol)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        auth::api_token::ApiToken,
        config::{Config, ImageAllowlistConfig},
        instances::{manager::InstanceManager, state::InstanceStore},
        jobs::import_export::ImportExportJobs,
        runtime::docker::DockerRuntime,
        storage::{repositories::InstanceRepository, sqlite},
    };

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

    #[tokio::test]
    async fn image_allowlist_implicitly_allows_configured_image() {
        let state = test_state(Config {
            images: crate::config::ImageConfig {
                postgres: "postgres:18.4".to_string(),
                allowed: ImageAllowlistConfig::default(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;

        ensure_image_allowed(&state, Protocol::Postgres, "postgres:18.4").unwrap();
    }

    #[tokio::test]
    async fn image_allowlist_allows_protocol_specific_entries() {
        let state = test_state(Config {
            images: crate::config::ImageConfig {
                postgres: "postgres:18.4".to_string(),
                allowed: ImageAllowlistConfig {
                    postgres: vec!["postgres:18.5".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        })
        .await;

        ensure_image_allowed(&state, Protocol::Postgres, "postgres:18.5").unwrap();
    }

    #[tokio::test]
    async fn image_allowlist_rejects_unlisted_pinned_image() {
        let state = test_state(Config {
            images: crate::config::ImageConfig {
                postgres: "postgres:18.4".to_string(),
                allowed: ImageAllowlistConfig {
                    postgres: vec!["postgres:18.5".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        })
        .await;

        let error = ensure_image_allowed(&state, Protocol::Postgres, "postgres:18.6").unwrap_err();

        assert!(error.to_string().contains("is not allowed"));
    }

    async fn test_state(config: Config) -> AppState {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let store = InstanceStore::default();
        let manager = InstanceManager::new(store.clone(), InstanceRepository::new(pool));
        AppState {
            config: Arc::new(config),
            config_path: dir.path().join("config.yml"),
            api_token: ApiToken::new("secret"),
            instances: store,
            manager,
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
