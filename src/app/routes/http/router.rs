use std::time::Duration;

use axum::{
    Router,
    body::Body,
    extract::{DefaultBodyLimit, Request, State},
    http::Method,
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use tower_http::timeout::TimeoutBody;

const API_REQUEST_EXECUTION_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const API_REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(60);

use crate::routes::http::{policy as security_policy, response as api_response};

pub(crate) use crate::state::MutationPermit;
pub use crate::state::{AppState, AppStateData, DaemonShutdown};

pub fn build_router(state: AppState) -> Router {
    let cors = security_policy::cors_layer(state.origin_policy().clone());

    Router::new()
        .merge(crate::routes::router())
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
            crate::routes::http::policy::check_request_origin,
        ))
        .layer(middleware::from_fn(
            crate::routes::http::trace::trace_request,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::routes::http::limits::rate_limit,
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
    let (parts, body) = request.into_parts();
    let body = Body::new(TimeoutBody::new(API_REQUEST_BODY_TIMEOUT, body));
    next.run(Request::from_parts(parts, body)).await
}

fn is_streaming_import_upload(request: &Request) -> bool {
    request.method() == Method::POST
        && request.uri().path().ends_with("/import")
        && has_octet_stream_content_type(request)
}

fn has_octet_stream_content_type(request: &Request) -> bool {
    let Some(content_type) = request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let media_type = content_type.split(';').next().unwrap_or_default();
    media_type
        .trim()
        .eq_ignore_ascii_case("application/octet-stream")
}

fn is_mutating_method(method: &Method) -> bool {
    matches!(
        method,
        &Method::POST | &Method::PUT | &Method::PATCH | &Method::DELETE
    )
}

async fn apply_request_timeout(request: Request, next: Next) -> Response {
    if is_streaming_import_upload(&request) {
        return next.run(request).await;
    }
    match tokio::time::timeout(API_REQUEST_EXECUTION_TIMEOUT, next.run(request)).await {
        Ok(response) => response,
        Err(_) => crate::routes::http::response::ApiError::ServiceUnavailable(
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
    if !is_mutating_method(request.method()) {
        return next.run(request).await;
    }
    let Some(_mutation) = state.daemon_shutdown.try_admit_mutation() else {
        return crate::routes::http::response::ApiError::ServiceUnavailable(
            "daemon shutdown is in progress".to_string(),
        )
        .into_response();
    };
    next.run(request).await
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
        config::Config,
        instance::{manager::InstanceManager, state::InstanceStore},
        storage::{repositories::InstanceRepository, sqlite},
        subsystems::test_support,
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
        let digest = crate::utils::hex::encode_lower(&Sha256::digest(&content));
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
            crate::instance::paths::InstancePaths::new(&state.config.paths, "inst_upload")
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

    fn upload_test_metadata(instance_id: &str) -> crate::instance::metadata::InstanceMetadata {
        let mut metadata = crate::instance::test_support::metadata(
            instance_id,
            crate::utils::protocol::Protocol::Postgres,
        );
        metadata.backend = crate::utils::backend::BackendEndpoint::UnixSocket {
            socket_path: format!("/run/dbev/sockets/{instance_id}/.s.PGSQL.5432"),
        };
        metadata.database.name = "db".to_string();
        metadata.database.username = "user".to_string();
        metadata
    }
}
