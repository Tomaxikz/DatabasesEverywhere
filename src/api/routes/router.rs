use std::{path::PathBuf, sync::Arc};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{HeaderValue, Method, header},
    middleware,
    routing::{delete, get, patch, post},
};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::{
    api::{
        allowed_hosts, artifacts, backups, config_admin, images, import_export,
        instances as instance_api, metrics, recovery, resources, system, websocket, ws_tokens,
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
}

pub fn build_router(state: AppState) -> Router {
    let cors = strict_cors_layer(&state.config.cors_allowed_hosts());

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
        .layer(DefaultBodyLimit::max(
            state.config.security.api_body_limit_bytes,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::api::security::rate_limit,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::api::request_trace::trace_request,
        ))
        .layer(cors)
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
        .route(
            "/api/admin/runtime-instances",
            get(instance_api::runtime_instances),
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

fn strict_cors_layer(allowed_hosts: &[String]) -> CorsLayer {
    let allowed_hosts = Arc::new(allowed_hosts.to_vec());
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(
            move |origin: &HeaderValue, _request_parts| {
                origin
                    .to_str()
                    .map(|origin| allowed_hosts::origin_is_allowed(origin, &allowed_hosts))
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
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
}
