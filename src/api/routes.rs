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
    api::allowed_hosts, auth::api_token::ApiToken, config::Config,
    instances::manager::InstanceManager, instances::state::InstanceStore,
    jobs::import_export::ImportExportJobs, runtime::docker::DockerRuntime,
};

#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub config_path: PathBuf,
    pub api_token: ApiToken,
    pub instances: InstanceStore,
    pub manager: InstanceManager,
    pub docker: DockerRuntime,
    pub import_export_jobs: ImportExportJobs,
    pub api_rate_limiter: crate::api::security::ApiRateLimiter,
    pub install_progress: crate::api::progress::InstallProgressStore,
    pub artifact_downloads: crate::api::artifacts::ArtifactDownloadTickets,
}

pub fn build_router(state: AppState) -> Router {
    let cors = strict_cors_layer(&state.config.cors_allowed_hosts());

    Router::new()
        .route("/api/system", get(crate::api::system::system))
        .route("/api/heartbeat", post(crate::api::system::heartbeat))
        .route(
            "/api/system/config",
            patch(crate::api::config_admin::patch_config),
        )
        .route(
            "/api/system/upgrade",
            post(crate::api::upgrade::self_upgrade),
        )
        .route("/metrics", get(crate::api::metrics::metrics))
        .route(
            "/api/backups",
            get(crate::api::backups::list_backups).post(crate::api::backups::run_backup),
        )
        .route(
            "/api/backups/status",
            get(crate::api::backups::backup_status),
        )
        .route("/api/backups/run", post(crate::api::backups::run_backup))
        .route(
            "/api/backups/download",
            get(crate::api::backups::download_backup_query),
        )
        .route(
            "/api/backups/download/{name}",
            get(crate::api::backups::download_backup_path),
        )
        .route(
            "/api/backups/download-signed",
            get(crate::api::artifacts::signed_backup_download),
        )
        .route(
            "/api/backups/{name}/download-token",
            post(crate::api::artifacts::issue_backup_download_token),
        )
        .route(
            "/api/backups/{name}/restore",
            post(crate::api::backups::restore_backup),
        )
        .route(
            "/api/backups/{name}",
            delete(crate::api::backups::delete_backup),
        )
        .route("/api/artifacts", get(crate::api::artifacts::list_artifacts))
        .route(
            "/api/artifacts/download-signed",
            get(crate::api::artifacts::signed_artifact_download),
        )
        .route(
            "/api/artifacts/retention",
            post(crate::api::artifacts::apply_retention),
        )
        .route(
            "/api/artifacts/{name}/download-token",
            post(crate::api::artifacts::issue_artifact_download_token),
        )
        .route(
            "/api/artifacts/{name}",
            delete(crate::api::artifacts::delete_artifact),
        )
        .route(
            "/api/recovery/failed-jobs",
            get(crate::api::recovery::failed_jobs),
        )
        .route(
            "/api/recovery/jobs/{job_id}/retry",
            post(crate::api::recovery::retry_job),
        )
        .route(
            "/api/recovery/restore",
            post(crate::api::recovery::restore_artifact),
        )
        .route("/api/resources", get(crate::api::resources::list_resources))
        .route("/api/images/pull", post(crate::api::images::pull_image))
        .route(
            "/api/instances",
            get(crate::api::instances::list_instances).post(crate::api::instances::create_instance),
        )
        .route(
            "/api/instances/{instance_id}",
            get(crate::api::instances::get_instance).delete(crate::api::instances::delete_instance),
        )
        .route(
            "/api/instances/{instance_id}/status",
            get(crate::api::instances::get_instance_status),
        )
        .route(
            "/api/instances/{instance_id}/resources",
            get(crate::api::resources::instance_resources),
        )
        .route(
            "/api/instances/{instance_id}/reconcile",
            post(crate::api::instances::reconcile_instance),
        )
        .route(
            "/api/instances/{instance_id}/start",
            post(crate::api::instances::start_instance),
        )
        .route(
            "/api/instances/{instance_id}/stop",
            post(crate::api::instances::stop_instance),
        )
        .route(
            "/api/instances/{instance_id}/restart",
            post(crate::api::instances::restart_instance),
        )
        .route(
            "/api/instances/{instance_id}/power",
            post(crate::api::instances::power_instance),
        )
        .route(
            "/api/instances/{instance_id}/logs",
            get(crate::api::instances::instance_logs),
        )
        .route(
            "/api/instances/{instance_id}/image",
            patch(crate::api::instances::update_instance_image),
        )
        .route(
            "/api/instances/{instance_id}/export",
            post(crate::api::import_export::export_instance),
        )
        .route(
            "/api/instances/{instance_id}/import",
            post(crate::api::import_export::import_instance),
        )
        .route(
            "/api/import-export/{job_id}",
            get(crate::api::import_export::get_import_export_job),
        )
        .route(
            "/api/import-export",
            get(crate::api::import_export::list_import_export_jobs),
        )
        .route("/api/ws-token", post(crate::api::ws_tokens::issue_ws_token))
        .route(
            "/api/instances/{instance_id}/limits",
            patch(crate::api::instances::update_instance_limits),
        )
        .route(
            "/api/runtime-instances",
            get(crate::api::instances::runtime_instances),
        )
        .route(
            "/api/logs/{instance_id}",
            get(crate::api::instances::instance_logs),
        )
        .route("/ws/monitoring", get(crate::api::websocket::monitoring))
        .route("/ws/logs", get(crate::api::websocket::logs))
        .route(
            "/ws/import-export",
            get(crate::api::websocket::import_export),
        )
        .layer(DefaultBodyLimit::max(
            state.config.security.api_body_limit_bytes,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::api::security::rate_limit,
        ))
        .layer(middleware::from_fn(
            crate::api::request_trace::trace_request,
        ))
        .layer(cors)
        .with_state(state)
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
