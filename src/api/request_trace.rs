use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request},
    middleware::Next,
    response::Response,
};

use crate::{api::routes::AppState, constants};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

pub async fn trace_request(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let request_id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let host = header_value(request.headers(), "host");
    let user_agent = header_value(request.headers(), "user-agent");
    let actor = authenticated_actor(&state, request.headers());
    let peer_ip = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|connect| connect.0.ip().to_string())
        .unwrap_or_else(|| "-".to_string());

    tracing::info!(
        request_id,
        actor,
        peer_ip,
        method = %method,
        path = %path,
        host = %host,
        user_agent = %user_agent,
        "api request started"
    );

    let response = next.run(request).await;
    let status = response.status();
    let elapsed_ms = started.elapsed().as_millis();

    if status.is_server_error() {
        tracing::error!(
            request_id,
            method = %method,
            path = %path,
            status = status.as_u16(),
            elapsed_ms,
            "api request failed"
        );
    } else if status.is_client_error() {
        tracing::warn!(
            request_id,
            method = %method,
            path = %path,
            status = status.as_u16(),
            elapsed_ms,
            "api request rejected"
        );
    } else {
        tracing::info!(
            request_id,
            method = %method,
            path = %path,
            status = status.as_u16(),
            elapsed_ms,
            "api request completed"
        );
    }

    response
}

fn authenticated_actor(state: &AppState, headers: &HeaderMap) -> String {
    let authorization = headers
        .get(constants::AUTHORIZATION_HEADER)
        .and_then(|value| value.to_str().ok());
    state
        .api_token
        .accepted_from_authorization_header(authorization)
        .map(|token| token.name)
        .unwrap_or_else(|| "-".to_string())
}

fn header_value(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-")
        .to_string()
}
