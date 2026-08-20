use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::{
    api::{
        api_response::{ApiError, ApiJson, ApiResponse, ApiResult},
        instances::docker_error,
        routes::AppState,
        security_policy::ApiRequestContext,
    },
    auth::scopes,
    shared::{images::is_pinned_image_reference, protocol::Protocol},
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
    auth: ApiRequestContext,
    ApiJson(request): ApiJson<PullImageRequest>,
) -> ApiResult<PullImageResponse> {
    auth.require_scope(scopes::IMAGES_ADMIN)?;
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

    Ok(ApiResponse::ok(PullImageResponse {
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
    fn validates_custom_image_references() {
        let digest = format!("postgres@sha256:{}", "a".repeat(64));
        for (image, valid) in [
            ("postgres", false),
            ("postgres:latest", false),
            ("registry.example.com:5000/postgres:latest", false),
            ("postgres:18.4", true),
            ("registry.example.com:5000/postgres:18.4", true),
            (&digest, true),
        ] {
            assert_eq!(
                validate_image(image).is_ok(),
                valid,
                "unexpected image validation result: {image}"
            );
        }
    }

    #[tokio::test]
    async fn image_allowlist_accepts_configured_and_protocol_entries_only() {
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

        ensure_image_allowed(&state, Protocol::Postgres, "postgres:18.4").unwrap();
        ensure_image_allowed(&state, Protocol::Postgres, "postgres:18.5").unwrap();
        let error = ensure_image_allowed(&state, Protocol::Postgres, "postgres:18.6").unwrap_err();

        assert!(error.to_string().contains("is not allowed"));
    }

    async fn test_state(config: Config) -> AppState {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let store = InstanceStore::default();
        let manager = InstanceManager::new(store.clone(), InstanceRepository::new(pool.clone()));
        AppState::new(crate::api::routes::AppStateData {
            config: Arc::new(config),
            config_path: dir.path().join("config.yml"),
            config_patches: crate::api::config_admin::ConfigPatchCoordinator::default(),
            api_token: ApiToken::new("secret"),
            instances: store,
            manager,
            instance_locks: crate::instances::locks::InstanceLocks::default(),
            docker: DockerRuntime::offline_for_tests(&Default::default(), false),
            import_export_jobs: ImportExportJobs::default(),
            import_uploads: crate::api::import_export::ImportUploadService::new(
                crate::storage::import_uploads::ImportUploadRepository::new(pool),
                2,
            ),
            api_rate_limiter: crate::api::security::ApiRateLimiter::default(),
            install_progress: crate::api::progress::InstallProgressStore::default(),
            artifact_downloads: crate::api::artifacts::ArtifactDownloadTickets::default(),
            resource_cache: crate::api::resources::ResourceCache::default(),
            soft_disk_limiter: crate::disk::soft::SoftDiskLimiter::new(Default::default()),
            monitoring_cache: crate::api::websocket::MonitoringSnapshotCache::default(),
            instance_runtime_cache: crate::api::instances::InstanceRuntimeInfoCache::default(),
            gateway_supervisor: crate::gateway::supervisor::GatewaySupervisor::default(),
            daemon_shutdown: crate::api::routes::DaemonShutdown::default(),
        })
    }
}
