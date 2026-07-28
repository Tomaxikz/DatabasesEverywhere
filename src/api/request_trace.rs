use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::Request,
    middleware::Next,
    response::Response,
};

use crate::api::{routes::AppState, security::RequestAuthentication};

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

pub async fn trace_request(
    State(_state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let request_id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();
    if tracing::enabled!(tracing::Level::INFO) {
        let host = header_value(request.headers(), "host");
        let user_agent = header_value(request.headers(), "user-agent");
        let actor = authenticated_actor(&request);
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
            path = %uri.path(),
            host,
            user_agent,
            "api request started"
        );
    }

    let response = next.run(request).await;
    let status = response.status();
    let elapsed_ms = started.elapsed().as_millis();

    if status.is_server_error() {
        tracing::error!(
            request_id,
            method = %method,
            path = %uri.path(),
            status = status.as_u16(),
            elapsed_ms,
            "api request failed"
        );
    } else if status == axum::http::StatusCode::TOO_MANY_REQUESTS {
        tracing::debug!(
            request_id,
            method = %method,
            path = %uri.path(),
            status = status.as_u16(),
            elapsed_ms,
            "api request throttled"
        );
    } else if status.is_client_error() {
        tracing::warn!(
            request_id,
            method = %method,
            path = %uri.path(),
            status = status.as_u16(),
            elapsed_ms,
            "api request rejected"
        );
    } else {
        tracing::info!(
            request_id,
            method = %method,
            path = %uri.path(),
            status = status.as_u16(),
            elapsed_ms,
            "api request completed"
        );
    }

    response
}

fn authenticated_actor(request: &Request<Body>) -> &str {
    match request.extensions().get::<RequestAuthentication>() {
        Some(RequestAuthentication::Api(actor)) => &actor.name,
        _ => "-",
    }
}

fn header_value<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("-")
}
