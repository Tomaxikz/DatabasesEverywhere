use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request},
    middleware::Next,
    response::Response,
};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::api::{handlers::ApiError, routes::AppState};

const API_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const MAX_API_RATE_LIMIT_KEYS: usize = 8192;

#[derive(Debug, Clone)]
pub struct ApiRateLimiter {
    inner: Arc<Mutex<HashMap<String, RateWindow>>>,
    max_requests: u32,
}

impl Default for ApiRateLimiter {
    fn default() -> Self {
        Self::new(600)
    }
}

impl ApiRateLimiter {
    pub fn new(max_requests: u32) -> Self {
        Self {
            inner: Arc::default(),
            max_requests: max_requests.max(1),
        }
    }

    pub async fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        evict_expired_windows(&mut inner, now);
        if inner.len() >= MAX_API_RATE_LIMIT_KEYS && !inner.contains_key(key) {
            tracing::warn!(
                keys = inner.len(),
                "audit api_rate_limit_key_capacity_reached"
            );
            return false;
        }
        let window = inner.entry(key.to_string()).or_insert(RateWindow {
            started_at: now,
            count: 0,
        });
        if now.duration_since(window.started_at) >= API_RATE_LIMIT_WINDOW {
            window.started_at = now;
            window.count = 0;
        }
        window.count += 1;
        window.count <= self.max_requests
    }
}

fn evict_expired_windows(inner: &mut HashMap<String, RateWindow>, now: Instant) {
    if inner.len() < MAX_API_RATE_LIMIT_KEYS {
        return;
    }
    inner.retain(|_, window| now.duration_since(window.started_at) < API_RATE_LIMIT_WINDOW);
}

#[derive(Debug, Clone)]
struct RateWindow {
    started_at: Instant,
    count: u32,
}

pub async fn rate_limit(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let key = rate_limit_key(request.headers());
    if state.api_rate_limiter.allow(&key).await {
        Ok(next.run(request).await)
    } else {
        tracing::warn!(key, "audit api_rate_limited");
        Err(ApiError::RateLimited)
    }
}

fn rate_limit_key(headers: &HeaderMap) -> String {
    headers
        .get(crate::constants::AUTHORIZATION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(fingerprint_header)
        .unwrap_or_else(|| "anonymous".to_string())
}

fn fingerprint_header(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("auth:{digest:x}")
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn ignores_forwarded_for_header_for_rate_limit_key() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));

        assert_eq!(rate_limit_key(&headers), "anonymous");
    }

    #[test]
    fn uses_authorization_fingerprint_without_leaking_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            crate::constants::AUTHORIZATION_HEADER,
            HeaderValue::from_static("Bearer super-secret"),
        );

        let key = rate_limit_key(&headers);

        assert!(key.starts_with("auth:"));
        assert!(!key.contains("super-secret"));
    }
}
