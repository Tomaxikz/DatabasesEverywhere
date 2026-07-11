use std::{path::PathBuf, sync::Arc};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{delete, get, patch, post},
};

use crate::{
    api::{
        api_response, artifacts, backups, config_admin, images, import_export,
        instances as instance_api, metrics, recovery, resources, security_policy, system,
        websocket, ws_tokens,
    },
    auth::api_token::ApiToken,
    config::Config,
    instances::manager::InstanceManager,
    instances::state::InstanceStore,
    jobs::import_export::ImportExportJobs,
    runtime::docker::DockerRuntime,
};

#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub config_path: PathBuf,
    pub config_patches: crate::api::config_admin::ConfigPatchCoordinator,
    pub api_token: ApiToken,
    pub instances: InstanceStore,
    pub manager: InstanceManager,
    pub instance_locks: crate::instances::locks::InstanceLocks,
    pub docker: DockerRuntime,
    pub import_export_jobs: ImportExportJobs,
    pub api_rate_limiter: crate::api::security::ApiRateLimiter,
    pub install_progress: crate::api::progress::InstallProgressStore,
    pub artifact_downloads: crate::api::artifacts::ArtifactDownloadTickets,
    pub resource_cache: crate::api::resources::ResourceCache,
    pub instance_runtime_cache: crate::api::instances::InstanceRuntimeInfoCache,
    pub gateway_supervisor: crate::gateway::supervisor::GatewaySupervisor,
}

pub fn build_router(state: AppState) -> Router {
    let cors = security_policy::cors_layer(&state.config.cors_allowed_hosts());

    Router::new()
        .merge(system_routes())
        .merge(instance_routes())
        .merge(resource_routes())
        .merge(image_routes())
        .merge(import_export_routes())
        .merge(artifact_routes())
        .merge(backup_routes())
        .merge(recovery_routes())
        .merge(websocket_routes())
        .fallback(api_response::route_not_found)
        .method_not_allowed_fallback(api_response::method_not_allowed)
        .layer(DefaultBodyLimit::max(
            state.config.security.api_body_limit_bytes,
        ))
        .layer(cors)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::api::security_policy::enforce_request_host_policy,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::api::request_trace::trace_request,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::api::security::rate_limit,
        ))
        .with_state(state)
}

fn system_routes() -> Router<AppState> {
    Router::new()
        .route("/api/system", get(system::system))
        .route("/api/system/config", patch(config_admin::patch_config))
        .route("/api/heartbeat", get(system::heartbeat))
        .route("/metrics", get(metrics::metrics))
}

fn instance_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/instances",
            get(instance_api::list_instances).post(instance_api::create_instance),
        )
        .route(
            "/api/instances/{instance_id}",
            get(instance_api::get_instance).delete(instance_api::delete_instance),
        )
        .route(
            "/api/instances/{instance_id}/status",
            get(instance_api::get_instance_status),
        )
        .route(
            "/api/instances/{instance_id}/reconcile",
            post(instance_api::reconcile_instance),
        )
        .route(
            "/api/instances/{instance_id}/power",
            post(instance_api::power_instance),
        )
        .route(
            "/api/instances/{instance_id}/logs",
            get(instance_api::instance_logs),
        )
        .route(
            "/api/instances/{instance_id}/image",
            patch(instance_api::update_instance_image),
        )
        .route(
            "/api/instances/{instance_id}/limits",
            patch(instance_api::update_instance_limits),
        )
}

fn resource_routes() -> Router<AppState> {
    Router::new()
        .route("/api/admin/resources", get(resources::list_resources))
        .route(
            "/api/instances/{instance_id}/resources",
            get(resources::instance_resources),
        )
}

fn image_routes() -> Router<AppState> {
    Router::new().route("/api/admin/images/pull", post(images::pull_image))
}

fn import_export_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/instances/{instance_id}/export",
            post(import_export::export_instance),
        )
        .route(
            "/api/instances/{instance_id}/import",
            post(import_export::import_instance),
        )
        .route(
            "/api/instances/{instance_id}/import-export/jobs",
            get(import_export::list_import_export_jobs),
        )
        .route(
            "/api/instances/{instance_id}/import-export/jobs/{job_id}",
            get(import_export::get_import_export_job),
        )
}

fn artifact_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/instances/{instance_id}/artifacts",
            get(artifacts::list_instance_artifacts),
        )
        .route(
            "/api/instances/{instance_id}/artifacts/retention",
            post(artifacts::apply_retention),
        )
        .route(
            "/api/instances/{instance_id}/artifacts/{artifact_id}",
            delete(artifacts::delete_artifact),
        )
        .route(
            "/api/instances/{instance_id}/artifacts/{artifact_id}/download",
            get(artifacts::download_artifact).post(artifacts::create_artifact_download),
        )
}

fn backup_routes() -> Router<AppState> {
    Router::new()
        .route("/api/admin/backups/status", get(backups::backup_status))
        .route("/api/admin/backups/run", post(backups::run_all_backups))
        .route(
            "/api/instances/{instance_id}/backups",
            get(backups::list_instance_backups).post(backups::run_instance_backup),
        )
        .route(
            "/api/instances/{instance_id}/backups/{backup_id}",
            delete(backups::delete_instance_backup),
        )
        .route(
            "/api/instances/{instance_id}/backups/{backup_id}/download",
            get(artifacts::download_backup).post(artifacts::create_backup_download),
        )
        .route(
            "/api/instances/{instance_id}/backups/{backup_id}/restore",
            post(backups::restore_instance_backup),
        )
}

fn recovery_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/admin/recovery/failed-jobs",
            get(recovery::failed_jobs),
        )
        .route(
            "/api/instances/{instance_id}/recovery/jobs/{job_id}/retry",
            post(recovery::retry_job),
        )
        .route(
            "/api/instances/{instance_id}/recovery/restore",
            post(recovery::restore_artifact),
        )
}

fn websocket_routes() -> Router<AppState> {
    Router::new()
        .route("/api/ws-token", post(ws_tokens::issue_ws_token))
        .route("/ws/monitoring", get(websocket::monitoring))
        .route("/ws/instances/{instance_id}/logs", get(websocket::logs))
        .route(
            "/ws/instances/{instance_id}/import-export",
            get(websocket::import_export),
        )
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header},
    };
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::{
        auth::api_token::ApiToken,
        instances::{manager::InstanceManager, state::InstanceStore},
        storage::{repositories::InstanceRepository, sqlite},
    };

    #[tokio::test]
    async fn host_policy_checks_host_even_when_origin_is_allowed() {
        let response = build_router(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/api/heartbeat")
                    .header(header::HOST, "evil.example.com")
                    .header(header::ORIGIN, "https://panel.example.com")
                    .header(header::AUTHORIZATION, "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(response).await["code"], "host_not_allowed");
    }

    #[tokio::test]
    async fn heartbeat_is_independent_of_gateway_readiness() {
        let state = test_state().await;
        state
            .gateway_supervisor
            .mark_failed("test gateway startup failure");
        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/heartbeat")
                    .header(header::HOST, "panel.example.com")
                    .header(header::AUTHORIZATION, "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await,
            serde_json::json!({ "status": "ok" })
        );
    }

    #[tokio::test]
    async fn authentication_precedes_json_deserialization() {
        let response = build_router(test_state().await)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/images/pull")
                    .header(header::HOST, "panel.example.com")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(response).await["code"], "unauthorized");
    }

    #[tokio::test]
    async fn extractor_rejections_use_the_api_error_envelope() {
        let response = build_router(test_state().await)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/images/pull")
                    .header(header::HOST, "panel.example.com")
                    .header(header::AUTHORIZATION, "Bearer secret")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(json_body(response).await["code"], "bad_request");
    }

    async fn json_body(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn test_state() -> AppState {
        let directory = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(directory.path()).await.unwrap();
        let instances = InstanceStore::default();
        let manager = InstanceManager::new(instances.clone(), InstanceRepository::new(pool));
        let config = Arc::new(Config {
            remote: "https://panel.example.com".to_string(),
            token_id: "test-token".to_string(),
            token: "secret".to_string(),
            jwt_signing_key: "test-jwt-signing-key-at-least-32-bytes".to_string(),
            ..Default::default()
        });
        AppState {
            config: config.clone(),
            config_path: directory.path().join("config.yml"),
            config_patches: crate::api::config_admin::ConfigPatchCoordinator::default(),
            api_token: ApiToken::from_config(&config),
            instances,
            manager,
            instance_locks: crate::instances::locks::InstanceLocks::default(),
            docker: DockerRuntime::new(&Default::default(), false).unwrap(),
            import_export_jobs: ImportExportJobs::default(),
            api_rate_limiter: crate::api::security::ApiRateLimiter::default(),
            install_progress: crate::api::progress::InstallProgressStore::default(),
            artifact_downloads: crate::api::artifacts::ArtifactDownloadTickets::default(),
            resource_cache: crate::api::resources::ResourceCache::default(),
            instance_runtime_cache: crate::api::instances::InstanceRuntimeInfoCache::default(),
            gateway_supervisor: crate::gateway::supervisor::GatewaySupervisor::default(),
        }
    }
}
