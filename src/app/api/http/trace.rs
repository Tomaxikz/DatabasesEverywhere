use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

use axum::{body::Body, extract::ConnectInfo, http::Request, middleware::Next, response::Response};

use crate::api::http::limits::RequestAuthentication;

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

pub async fn trace_request(request: Request<Body>, next: Next) -> Response {
    let request_id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let actor = authenticated_actor(&request).to_owned();
    let peer_ip = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|connect| connect.0.ip().to_string())
        .unwrap_or_else(|| "-".to_string());
    if tracing::enabled!(tracing::Level::DEBUG) {
        let host = header_value(request.headers(), "host");
        let user_agent = header_value(request.headers(), "user-agent");
        tracing::debug!(
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
            actor,
            peer_ip,
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
            actor,
            peer_ip,
            method = %method,
            path = %uri.path(),
            status = status.as_u16(),
            elapsed_ms,
            "api request rejected"
        );
    } else {
        tracing::debug!(
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

#[cfg(test)]
mod tests {
    use std::{
        io,
        sync::{Arc, Mutex},
    };

    use axum::{Router, http::StatusCode, middleware, routing::get};
    use tower::ServiceExt;
    use tracing::instrument::WithSubscriber;

    use super::*;

    #[derive(Clone, Default)]
    struct Logs(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Logs {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn request_logs_are_quiet_by_default_but_keep_failures() {
        for level in [tracing::Level::INFO, tracing::Level::DEBUG] {
            let logs = Logs::default();
            let writer = logs.clone();
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(level)
                .with_ansi(false)
                .without_time()
                .with_writer(move || writer.clone())
                .finish();
            async {
                for status in [200, 101, 401, 403, 404, 429, 500] {
                    let status = StatusCode::from_u16(status).unwrap();
                    let app = Router::new()
                        .route("/api/system", get(move || async move { status }))
                        .layer(middleware::from_fn(trace_request));
                    let response = app
                        .oneshot(
                            Request::builder()
                                .uri("/api/system?token=do-not-log-this")
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(response.status(), status);
                }
            }
            .with_subscriber(subscriber)
            .await;
            let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
            assert!(!text.contains("do-not-log-this"));
            assert_eq!(text.matches("api request rejected").count(), 3, "{text}");
            assert_eq!(text.matches("api request failed").count(), 1, "{text}");
            for status in [401, 403, 404, 500] {
                assert!(text.contains(&format!("status={status}")), "{text}");
            }
            if level == tracing::Level::INFO {
                assert!(!text.contains("api request started"), "{text}");
                assert!(!text.contains("api request completed"), "{text}");
                assert!(!text.contains("api request throttled"), "{text}");
            } else {
                assert_eq!(text.matches("api request started").count(), 7, "{text}");
                assert_eq!(text.matches("api request completed").count(), 2, "{text}");
                assert_eq!(text.matches("api request throttled").count(), 1, "{text}");
            }
        }
    }
}
