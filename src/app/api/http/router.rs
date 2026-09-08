use std::{
    ops::Deref,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    extract::{DefaultBodyLimit, Request, State},
    http::Method,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
};
use tokio::sync::{Notify, watch};
use tower_http::timeout::TimeoutBody;

const API_REQUEST_EXECUTION_TIMEOUT: Duration = Duration::from_secs(15 * 60);

use crate::{
    api::{
        artifacts, backups,
        http::{policy as security_policy, response as api_response},
        import_export::{self, recovery},
        instances::{self as instance_api, images},
        monitoring::{activity, metrics, resources, tokens as ws_tokens, websocket},
        system::{self, config as config_admin},
    },
    auth::api_token::ApiToken,
    config::Config,
    instances::{manager::InstanceManager, state::InstanceStore},
    jobs::import_export::ImportExportJobs,
    runtime::docker::DockerRuntime,
};

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateData>,
    origin_policy: Arc<security_policy::OriginPolicy>,
}

#[cfg_attr(test, derive(Clone))]
pub struct AppStateData {
    pub config: Arc<Config>,
    pub config_path: PathBuf,
    pub config_patches: crate::api::system::config::ConfigPatchCoordinator,
    pub api_token: ApiToken,
    pub instances: InstanceStore,
    pub manager: InstanceManager,
    pub placements: crate::placement::PlacementRepository,
    pub instance_locks: crate::instances::locks::InstanceLocks,
    pub docker: DockerRuntime,
    pub import_export_jobs: ImportExportJobs,
    pub import_uploads: crate::api::import_export::ImportUploadService,
    pub api_rate_limiter: crate::api::http::limits::ApiRateLimiter,
    pub install_progress: crate::api::instances::progress::InstallProgressStore,
    pub artifact_downloads: crate::api::artifacts::ArtifactDownloadTickets,
    pub resource_cache: crate::api::monitoring::resources::ResourceCache,
    pub soft_disk_limiter: crate::disk::soft::SoftDiskLimiter,
    pub monitoring_cache: crate::api::monitoring::websocket::MonitoringSnapshotCache,
    pub instance_runtime_cache: crate::api::instances::InstanceRuntimeInfoCache,
    pub gateway_supervisor: crate::gateway::supervisor::GatewaySupervisor,
    pub daemon_shutdown: DaemonShutdown,
}

impl AppState {
    pub fn new(data: AppStateData) -> Self {
        let origin_policy = Arc::new(security_policy::OriginPolicy::from_config(&data.config));
        Self {
            inner: Arc::new(data),
            origin_policy,
        }
    }

    pub fn origin_policy(&self) -> &security_policy::OriginPolicy {
        &self.origin_policy
    }
}

impl Deref for AppState {
    type Target = AppStateData;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Debug, Clone)]
pub struct DaemonShutdown {
    sender: watch::Sender<bool>,
    accepting_mutations: Arc<AtomicBool>,
    active_mutations: Arc<AtomicUsize>,
    mutation_drain: Arc<Notify>,
}

#[derive(Debug)]
pub(crate) struct MutationPermit {
    active: Arc<AtomicUsize>,
    drain: Arc<Notify>,
}

impl Default for DaemonShutdown {
    fn default() -> Self {
        let (sender, _) = watch::channel(false);
        Self {
            sender,
            accepting_mutations: Arc::new(AtomicBool::new(true)),
            active_mutations: Arc::default(),
            mutation_drain: Arc::default(),
        }
    }
}

impl DaemonShutdown {
    pub fn trigger(&self) {
        self.accepting_mutations.store(false, Ordering::Release);
        self.sender.send_replace(true);
    }

    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.sender.subscribe()
    }

    pub fn is_triggered(&self) -> bool {
        *self.sender.borrow()
    }

    fn try_admit_mutation(&self) -> Option<MutationPermit> {
        if !self.accepting_mutations.load(Ordering::Acquire) {
            return None;
        }
        self.active_mutations.fetch_add(1, Ordering::AcqRel);
        if !self.accepting_mutations.load(Ordering::Acquire) {
            release_mutation(&self.active_mutations, &self.mutation_drain);
            return None;
        }
        Some(MutationPermit {
            active: Arc::clone(&self.active_mutations),
            drain: Arc::clone(&self.mutation_drain),
        })
    }

    /// Keeps detached daemon-owned mutation work inside the same shutdown
    /// fence as the HTTP request that started it. This is intentionally
    /// separate from request middleware because a disconnected client drops
    /// the request permit while its owned worker must continue safely.
    pub(crate) fn try_admit_background_mutation(&self) -> Option<MutationPermit> {
        self.try_admit_mutation()
    }

    pub fn active_mutation_count(&self) -> usize {
        self.active_mutations.load(Ordering::Acquire)
    }

    pub async fn wait_for_mutation_drain(&self, deadline: Duration) -> bool {
        let drained = async {
            loop {
                let notified = self.mutation_drain.notified();
                if self.active_mutation_count() == 0 {
                    return;
                }
                notified.await;
            }
        };
        tokio::time::timeout(deadline, drained).await.is_ok()
    }
}

impl Drop for MutationPermit {
    fn drop(&mut self) {
        release_mutation(&self.active, &self.drain);
    }
}

fn release_mutation(active: &AtomicUsize, drain: &Notify) {
    let previous = active.fetch_sub(1, Ordering::AcqRel);
    debug_assert!(previous > 0, "active API mutation count underflow");
    if previous == 1 {
        drain.notify_waiters();
    }
}

pub fn build_router(state: AppState) -> Router {
    let cors = security_policy::cors_layer(state.origin_policy().clone());

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
        .layer(middleware::from_fn_with_state(
            state.clone(),
            apply_request_body_timeout,
        ))
        .layer(middleware::from_fn(apply_request_timeout))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            track_mutating_request,
        ))
        .layer(cors)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::api::http::policy::check_request_origin,
        ))
        .layer(middleware::from_fn(crate::api::http::trace::trace_request))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::api::http::limits::rate_limit,
        ))
        .with_state(state)
}

async fn apply_request_body_timeout(
    State(_state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if is_streaming_import_upload(&request) {
        // The streaming upload handler applies both its configured idle and
        // total deadlines and maps either one to a stable 408 response.
        return next.run(request).await;
    }
    let timeout = Duration::from_secs(60);
    let (parts, body) = request.into_parts();
    let body = Body::new(TimeoutBody::new(timeout, body));
    next.run(Request::from_parts(parts, body)).await
}

fn is_streaming_import_upload(request: &Request) -> bool {
    request.method() == Method::POST
        && request.uri().path().ends_with("/import")
        && request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value.split(';').next().is_some_and(|value| {
                    value
                        .trim()
                        .eq_ignore_ascii_case("application/octet-stream")
                })
            })
}

async fn apply_request_timeout(request: Request, next: Next) -> Response {
    if is_streaming_import_upload(&request) {
        return next.run(request).await;
    }
    match tokio::time::timeout(API_REQUEST_EXECUTION_TIMEOUT, next.run(request)).await {
        Ok(response) => response,
        Err(_) => crate::api::http::response::ApiError::ServiceUnavailable(
            "API request exceeded the 900-second execution deadline".to_string(),
        )
        .into_response(),
    }
}

async fn track_mutating_request(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if !matches!(
        request.method(),
        &Method::POST | &Method::PUT | &Method::PATCH | &Method::DELETE
    ) {
        return next.run(request).await;
    }
    let Some(_mutation) = state.daemon_shutdown.try_admit_mutation() else {
        return crate::api::http::response::ApiError::ServiceUnavailable(
            "daemon shutdown is in progress".to_string(),
        )
        .into_response();
    };
    next.run(request).await
}

fn system_routes() -> Router<AppState> {
    Router::new()
        .route("/api/system", get(system::system))
        .route(
            "/api/system/import-export-scheduler/recommendation",
            get(system::scheduler_recommendation),
        )
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
            "/api/instances/{instance_id}/password",
            patch(instance_api::reset_instance_password),
        )
        .route(
            "/api/instances/{instance_id}/deployment-migrations",
            get(instance_api::list_deployment_migrations)
                .post(instance_api::start_deployment_migration),
        )
        .route(
            "/api/instances/{instance_id}/deployment-migrations/{migration_id}",
            get(instance_api::get_deployment_migration),
        )
}

fn resource_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/pools/{runtime_id}/image",
            patch(crate::api::pools::image::update),
        )
        .route(
            "/api/pools/{runtime_id}/logs",
            get(crate::api::pools::streams::logs),
        )
        .route(
            "/api/pools/{runtime_id}/backups",
            get(crate::api::pools::streams::backups),
        )
        .route(
            "/ws/pools/{runtime_id}/logs",
            get(crate::api::pools::streams::log_socket),
        )
        .route(
            "/ws/pools/{runtime_id}/monitoring",
            get(crate::api::pools::streams::monitoring),
        )
        .route(
            "/api/pools/{runtime_id}/status",
            get(crate::api::pools::status),
        )
        .route(
            "/api/pools/{runtime_id}/power",
            post(crate::api::pools::power),
        )
        .route("/api/admin/resources", get(resources::list_resources))
        .route(
            "/api/admin/resources/summary",
            get(resources::node_resource_summary),
        )
        .route(
            "/api/pools",
            get(resources::list_shared_pools).post(crate::api::pools::create),
        )
        .route(
            "/api/pools/{runtime_id}",
            get(resources::get_shared_pool)
                .patch(crate::api::pools::resize_pool)
                .delete(crate::api::pools::delete),
        )
        .route(
            "/api/pools/{runtime_id}/instances",
            get(resources::list_pool_tenants).post(crate::api::pools::create_database),
        )
        .route(
            "/api/instances/{instance_id}/resources",
            get(resources::instance_resources),
        )
        .route(
            "/api/instances/{instance_id}/activity",
            get(activity::current),
        )
        .route(
            "/api/instances/{instance_id}/activity/history",
            get(activity::history),
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
            post(import_export::import_entry),
        )
        .route(
            "/api/instances/{instance_id}/import/uploads",
            get(import_export::list_import_uploads),
        )
        .route(
            "/api/instances/{instance_id}/import/uploads/{upload_id}",
            get(import_export::get_import_upload).delete(import_export::delete_import_upload),
        )
        .route(
            "/api/instances/{instance_id}/import/uploads/{upload_id}/catalog",
            get(import_export::get_import_catalog).post(import_export::inspect_import_upload),
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
            "/api/instances/{instance_id}/backups/{backup_id}/contents",
            get(backups::browse_instance_backup),
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
        api::test_support,
        auth::api_token::ApiToken,
        instances::{manager::InstanceManager, state::InstanceStore},
        storage::{repositories::InstanceRepository, sqlite},
    };

    #[tokio::test]
    async fn public_host_is_panel_owned_while_browser_origin_remains_restricted() {
        let response = build_router(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/api/heartbeat")
                    .header(header::HOST, "any-public-address.example.com")
                    .header(header::ORIGIN, "https://panel.example.com")
                    .header(header::AUTHORIZATION, "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = build_router(test_state().await)
            .oneshot(
                Request::builder()
                    .uri("/api/heartbeat")
                    .header(header::HOST, "panel.example.com")
                    .header(header::ORIGIN, "http://panel.example.com")
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
    async fn system_reports_api_readiness_separately_from_database_gateways() {
        let state = test_state().await;
        state
            .gateway_supervisor
            .mark_failed("test gateway startup failure");
        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/system")
                    .header(header::HOST, "panel.example.com")
                    .header(header::AUTHORIZATION, "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["api_readiness"], "ready");
        assert_eq!(body["gateways"]["status"], "failed");
        assert_eq!(body["api_rate_limit_per_minute"], 600);
        assert_eq!(body["api_rate_limit_scope"], "credential_and_peer_ip");
    }

    #[tokio::test]
    async fn authentication_precedes_json_deserialization() {
        for uri in [
            "/api/admin/images/pull",
            "/api/instances/inst-one/deployment-migrations",
        ] {
            let response = build_router(test_state().await)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(uri)
                        .header(header::HOST, "panel.example.com")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from("{"))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
            assert_eq!(json_body(response).await["code"], "unauthorized", "{uri}");
        }
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

    #[tokio::test]
    async fn import_upload_stream_bypasses_json_limit_and_deletes_durably() {
        use sha2::{Digest, Sha256};

        let (state, _directory) = upload_test_state().await;
        let content = vec![b'x'; 64];
        let digest = format!("{:x}", Sha256::digest(&content));
        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/instances/inst_upload/import")
                    .header(header::HOST, "panel.example.com")
                    .header(header::AUTHORIZATION, "Bearer secret")
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .header(header::CONTENT_LENGTH, content.len())
                    .header("x-dbev-filename", "dump.postgres.sql")
                    .header("x-dbev-sha256", digest)
                    .body(Body::from(content))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);
        let upload_id = json_body(response).await["upload_id"]
            .as_str()
            .unwrap()
            .to_string();
        let upload = state
            .import_uploads
            .repo()
            .get("inst_upload", &upload_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            upload.state,
            crate::storage::import_uploads::ImportUploadState::Ready
        );
        let upload_path =
            crate::instances::paths::InstancePaths::new(&state.config.paths, "inst_upload")
                .unwrap()
                .imports
                .join(".uploads")
                .join(&upload.stored_filename);
        assert_eq!(tokio::fs::metadata(upload_path).await.unwrap().len(), 64);

        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/api/instances/inst_upload/import/uploads/{upload_id}"
                    ))
                    .header(header::HOST, "panel.example.com")
                    .header(header::AUTHORIZATION, "Bearer secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            state
                .import_uploads
                .repo()
                .get("inst_upload", &upload_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn ordinary_json_requests_still_obey_the_small_body_limit() {
        let (state, _directory) = upload_test_state().await;
        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/admin/images/pull")
                    .header(header::HOST, "panel.example.com")
                    .header(header::AUTHORIZATION, "Bearer secret")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"protocol":"postgres","padding":"xxxxxxxxxxxxxxxx"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn shutdown_closes_mutation_admission_and_drains_existing_work() {
        let shutdown = DaemonShutdown::default();
        let mutation = shutdown.try_admit_mutation().unwrap();
        let background = shutdown.try_admit_background_mutation().unwrap();
        assert_eq!(shutdown.active_mutation_count(), 2);
        shutdown.trigger();
        assert!(shutdown.try_admit_mutation().is_none());
        assert!(shutdown.try_admit_background_mutation().is_none());

        tokio::spawn(async move {
            tokio::task::yield_now().await;
            drop(mutation);
            tokio::task::yield_now().await;
            drop(background);
        });
        assert!(
            shutdown
                .wait_for_mutation_drain(Duration::from_secs(1))
                .await
        );
        assert_eq!(shutdown.active_mutation_count(), 0);
    }

    async fn json_body(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn test_state() -> AppState {
        let directory = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(directory.path()).await.unwrap();
        let instances = InstanceStore::default();
        let manager =
            InstanceManager::new(instances.clone(), InstanceRepository::new(pool.clone()));
        let config = Config {
            remote: "https://panel.example.com".to_string(),
            token_id: "test-token".to_string(),
            token: "secret".to_string(),
            jwt_signing_key: "test-jwt-signing-key-at-least-32-bytes".to_string(),
            ..Default::default()
        };
        let api_token = ApiToken::from_config(&config);
        test_support::state(
            config,
            directory.path().join("config.yml"),
            api_token,
            instances,
            manager,
            pool,
        )
    }

    async fn upload_test_state() -> (AppState, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(directory.path()).await.unwrap();
        let instances = InstanceStore::default();
        let manager =
            InstanceManager::new(instances.clone(), InstanceRepository::new(pool.clone()));
        manager
            .upsert(upload_test_metadata("inst_upload"))
            .await
            .unwrap();
        let root = directory.path();
        let mut config = Config {
            remote: "https://panel.example.com".to_string(),
            token_id: "test-token".to_string(),
            token: "secret".to_string(),
            jwt_signing_key: "test-jwt-signing-key-at-least-32-bytes".to_string(),
            paths: crate::config::PathConfig {
                data: root.join("data").display().to_string(),
                sockets: root.join("sockets").display().to_string(),
                locks: root.join("locks").display().to_string(),
                logs: root.join("logs").display().to_string(),
                artifacts: root.join("artifacts").display().to_string(),
                ..Default::default()
            },
            ..Default::default()
        };
        config.security.api_body_limit_bytes = 16;
        let api_token = ApiToken::from_config(&config);
        let state = test_support::state(
            config,
            root.join("config.yml"),
            api_token,
            instances,
            manager,
            pool,
        );
        (state, directory)
    }

    fn upload_test_metadata(instance_id: &str) -> crate::instances::metadata::InstanceMetadata {
        let mut metadata = crate::instances::test_support::metadata(
            instance_id,
            crate::shared::protocol::Protocol::Postgres,
        );
        metadata.backend = crate::shared::backend::BackendEndpoint::UnixSocket {
            socket_path: format!("/run/dbev/sockets/{instance_id}/.s.PGSQL.5432"),
        };
        metadata.database.name = "db".to_string();
        metadata.database.username = "user".to_string();
        metadata
    }
}
