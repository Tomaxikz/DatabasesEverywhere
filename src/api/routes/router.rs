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
    inner: Arc<AppStateData>,
    host_policy: Arc<security_policy::HostPolicy>,
}

#[derive(Debug)]
pub struct AppStateData {
    pub config: Arc<Config>,
    pub config_path: PathBuf,
    pub config_patches: crate::api::config_admin::ConfigPatchCoordinator,
    pub api_token: ApiToken,
    pub instances: InstanceStore,
    pub manager: InstanceManager,
    pub instance_locks: crate::instances::locks::InstanceLocks,
    pub docker: DockerRuntime,
    pub import_export_jobs: ImportExportJobs,
    pub import_uploads: crate::api::import_export::ImportUploadService,
    pub api_rate_limiter: crate::api::security::ApiRateLimiter,
    pub install_progress: crate::api::progress::InstallProgressStore,
    pub artifact_downloads: crate::api::artifacts::ArtifactDownloadTickets,
    pub resource_cache: crate::api::resources::ResourceCache,
    pub soft_disk_limiter: crate::disk::soft::SoftDiskLimiter,
    pub monitoring_cache: crate::api::websocket::MonitoringSnapshotCache,
    pub instance_runtime_cache: crate::api::instances::InstanceRuntimeInfoCache,
    pub gateway_supervisor: crate::gateway::supervisor::GatewaySupervisor,
    pub daemon_shutdown: DaemonShutdown,
}

impl AppState {
    pub fn new(data: AppStateData) -> Self {
        let host_policy = Arc::new(security_policy::HostPolicy::from_config(&data.config));
        Self {
            inner: Arc::new(data),
            host_policy,
        }
    }

    pub fn host_policy(&self) -> &security_policy::HostPolicy {
        &self.host_policy
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
struct MutationPermit {
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
    let cors = security_policy::cors_layer(state.host_policy().clone());

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
        .layer(middleware::from_fn_with_state(
            state.clone(),
            track_mutating_request,
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

async fn apply_request_body_timeout(
    State(_state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let is_import_upload = request.method() == Method::POST
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
            });
    if is_import_upload {
        // The streaming upload handler applies both its configured idle and
        // total deadlines and maps either one to a stable 408 response.
        return next.run(request).await;
    }
    let timeout = Duration::from_secs(60);
    let (parts, body) = request.into_parts();
    let body = Body::new(TimeoutBody::new(timeout, body));
    next.run(Request::from_parts(parts, body)).await
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
        return crate::api::api_response::ApiError::ServiceUnavailable(
            "daemon shutdown is in progress".to_string(),
        )
        .into_response();
    };
    next.run(request).await
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
            "/api/instances/{instance_id}/password",
            patch(instance_api::reset_instance_password),
        )
}

fn resource_routes() -> Router<AppState> {
    Router::new()
        .route("/api/admin/resources", get(resources::list_resources))
        .route(
            "/api/admin/resources/summary",
            get(resources::node_resource_summary),
        )
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
            post(import_export::inspect_import_upload),
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
    async fn browser_origin_policy_rejects_same_host_on_the_wrong_scheme() {
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
            .repository()
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
                .repository()
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
        assert_eq!(shutdown.active_mutation_count(), 1);
        shutdown.trigger();
        assert!(shutdown.try_admit_mutation().is_none());

        tokio::spawn(async move {
            tokio::task::yield_now().await;
            drop(mutation);
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
        let config = Arc::new(Config {
            remote: "https://panel.example.com".to_string(),
            token_id: "test-token".to_string(),
            token: "secret".to_string(),
            jwt_signing_key: "test-jwt-signing-key-at-least-32-bytes".to_string(),
            ..Default::default()
        });
        AppState::new(AppStateData {
            config: config.clone(),
            config_path: directory.path().join("config.yml"),
            config_patches: crate::api::config_admin::ConfigPatchCoordinator::default(),
            api_token: ApiToken::from_config(&config),
            instances,
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
            daemon_shutdown: DaemonShutdown::default(),
        })
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
        let config = Arc::new(config);
        let state = AppState::new(AppStateData {
            config: config.clone(),
            config_path: root.join("config.yml"),
            config_patches: crate::api::config_admin::ConfigPatchCoordinator::default(),
            api_token: ApiToken::from_config(&config),
            instances,
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
            daemon_shutdown: DaemonShutdown::default(),
        });
        (state, directory)
    }

    fn upload_test_metadata(instance_id: &str) -> crate::instances::metadata::InstanceMetadata {
        use crate::{
            instances::metadata::{
                DatabaseIdentity, DesiredInstanceState, InstanceStatus, PublicEndpoint,
                RuntimeKind, RuntimeMetadata,
            },
            shared::{backend::BackendEndpoint, limits::InstanceLimits, protocol::Protocol},
        };

        crate::instances::metadata::InstanceMetadata {
            schema_version: 1,
            instance_id: instance_id.to_string(),
            protocol: Protocol::Postgres,
            status: InstanceStatus::Running,
            desired_state: DesiredInstanceState::Running,
            disk_limit_blocked: false,
            public: PublicEndpoint {
                host: "db.example.com".to_string(),
                port: 5432,
            },
            backend: BackendEndpoint::UnixSocket {
                socket_path: format!("/run/dbev/sockets/{instance_id}/.s.PGSQL.5432"),
            },
            runtime: RuntimeMetadata {
                kind: RuntimeKind::Docker,
                container_name: format!("dbe-postgres-{instance_id}"),
                network_mode: "none".to_string(),
            },
            database: DatabaseIdentity {
                name: "db".to_string(),
                username: "user".to_string(),
            },
            route_key_sha256: None,
            mariadb_native_password_sha1_stage2: None,
            mariadb_root_password: None,
            mysql_native_password_sha1_stage2: None,
            mysql_root_password: None,
            mongodb_root_password: None,
            postgres_admin_password: None,
            tenant_password: None,
            limits: InstanceLimits::default(),
            image: None,
            database_version: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }
}
