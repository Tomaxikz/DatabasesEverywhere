use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request, Uri},
    middleware::Next,
    response::Response,
};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use crate::{
    api::{
        handlers::{ApiError, websocket_token},
        routes::AppState,
    },
    auth::{api_token::ApiToken, jwt},
};

const API_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const MAX_API_RATE_LIMIT_KEYS: usize = 8192;
const UNAUTHENTICATED_RATE_LIMIT_BUCKETS: u16 = 4096;
const MAX_ACTIVE_WEBSOCKETS: usize = 1024;
const MAX_ACTIVE_API_REQUESTS: usize = 1024;
const MAX_CONSUMED_WEBSOCKET_JTIS: usize = 65_536;

#[derive(Debug, Clone)]
pub struct ApiRateLimiter {
    inner: Arc<Mutex<HashMap<String, RateWindow>>>,
    consumed_websocket_jtis: Arc<Mutex<HashMap<String, i64>>>,
    active_websockets: Arc<Semaphore>,
    active_requests: Arc<Semaphore>,
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
            consumed_websocket_jtis: Arc::default(),
            active_websockets: Arc::new(Semaphore::new(MAX_ACTIVE_WEBSOCKETS)),
            active_requests: Arc::new(Semaphore::new(MAX_ACTIVE_API_REQUESTS)),
            max_requests: max_requests.max(1),
        }
    }

    pub async fn admit_websocket(
        &self,
        jti: &str,
        expires_at: i64,
    ) -> Result<WebSocketConnectionPermit, WebSocketAdmissionError> {
        let connection = Arc::clone(&self.active_websockets)
            .try_acquire_owned()
            .map_err(|_| WebSocketAdmissionError::ConnectionCapacity)?;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        if expires_at <= now {
            return Err(WebSocketAdmissionError::Expired);
        }

        let mut consumed = self.consumed_websocket_jtis.lock().await;
        consumed.retain(|_, expiration| *expiration > now);
        if consumed.contains_key(jti) {
            return Err(WebSocketAdmissionError::Replay);
        }
        if consumed.len() >= MAX_CONSUMED_WEBSOCKET_JTIS {
            return Err(WebSocketAdmissionError::TokenCapacity);
        }
        consumed.insert(jti.to_string(), expires_at);
        Ok(WebSocketConnectionPermit {
            _connection: connection,
        })
    }

    fn admit_request(&self) -> Result<OwnedSemaphorePermit, ApiError> {
        Arc::clone(&self.active_requests)
            .try_acquire_owned()
            .map_err(|_| ApiError::RateLimited)
    }

    async fn allow(&self, identity: &RateLimitIdentity) -> bool {
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        evict_expired_windows(&mut inner, now);
        if inner.len() >= MAX_API_RATE_LIMIT_KEYS && !inner.contains_key(&identity.key) {
            let eviction_candidate = inner
                .iter()
                .filter(|(_, window)| !window.trusted)
                .min_by_key(|(_, window)| window.last_seen)
                .map(|(key, _)| key.clone());
            if let Some(key) = eviction_candidate {
                inner.remove(&key);
            } else if !identity.trusted {
                tracing::warn!(
                    keys = inner.len(),
                    "audit api_rate_limit_key_capacity_reached"
                );
                return false;
            } else if let Some(key) = inner
                .iter()
                .min_by_key(|(_, window)| window.last_seen)
                .map(|(key, _)| key.clone())
            {
                inner.remove(&key);
            }
        }
        let window = inner.entry(identity.key.clone()).or_insert(RateWindow {
            started_at: now,
            last_seen: now,
            count: 0,
            trusted: identity.trusted,
        });
        if now.duration_since(window.started_at) >= API_RATE_LIMIT_WINDOW {
            window.started_at = now;
            window.count = 0;
        }
        window.last_seen = now;
        window.count = window.count.saturating_add(1);
        window.count <= self.max_requests
    }
}

#[derive(Debug)]
pub struct WebSocketConnectionPermit {
    _connection: OwnedSemaphorePermit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketAdmissionError {
    Replay,
    Expired,
    TokenCapacity,
    ConnectionCapacity,
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
    last_seen: Instant,
    count: u32,
    trusted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RateLimitIdentity {
    key: String,
    trusted: bool,
}

pub async fn rate_limit(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let _request = state
        .api_rate_limiter
        .admit_request()
        .inspect_err(|_| tracing::warn!("audit api_request_capacity_reached"))?;
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| *address);
    let identity = rate_limit_identity(
        &state.api_token,
        state.config.websocket_jwt_secret(),
        request.headers(),
        request.uri(),
        peer,
    );
    if state.api_rate_limiter.allow(&identity).await {
        Ok(next.run(request).await)
    } else {
        tracing::warn!(key = %identity.key, "audit api_rate_limited");
        Err(ApiError::RateLimited)
    }
}

fn rate_limit_identity(
    api_token: &ApiToken,
    jwt_secret: &[u8],
    headers: &HeaderMap,
    uri: &Uri,
    peer: Option<SocketAddr>,
) -> RateLimitIdentity {
    let authorization = headers
        .get(crate::constants::AUTHORIZATION_HEADER)
        .and_then(|value| value.to_str().ok());
    if let Some(accepted) = api_token.accepted_from_authorization_header(authorization) {
        return RateLimitIdentity {
            key: fingerprint_identity("api", &accepted.name),
            trusted: true,
        };
    }

    if let Some(token) = websocket_token(headers).or_else(|| signed_download_query_token(uri))
        && let Ok(jti) = jwt::validated_token_jti(token, jwt_secret)
    {
        return RateLimitIdentity {
            key: fingerprint_identity("jwt", &jti),
            trusted: true,
        };
    }

    RateLimitIdentity {
        key: peer_rate_limit_key(peer),
        trusted: false,
    }
}

fn signed_download_query_token(uri: &Uri) -> Option<&str> {
    if !is_download_path(uri.path()) {
        return None;
    }
    uri.query()?
        .split('&')
        .find_map(|part| part.strip_prefix("token="))
        .filter(|token| !token.is_empty())
}

fn is_download_path(path: &str) -> bool {
    let mut segments = path.trim_start_matches('/').split('/');
    matches!(
        (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ),
        (
            Some("api"),
            Some("instances"),
            Some(instance_id),
            Some("artifacts" | "backups"),
            Some(artifact_id),
            Some("download"),
            None,
        ) if !instance_id.is_empty() && !artifact_id.is_empty()
    )
}

fn peer_rate_limit_key(peer: Option<SocketAddr>) -> String {
    let group = peer_rate_limit_group(peer);
    let digest = Sha256::digest(group.as_bytes());
    let bucket = u16::from_be_bytes([digest[0], digest[1]]) % UNAUTHENTICATED_RATE_LIMIT_BUCKETS;
    format!("peer-bucket:{bucket}")
}

fn peer_rate_limit_group(peer: Option<SocketAddr>) -> String {
    match peer.map(|address| address.ip()) {
        Some(IpAddr::V4(address)) => format!("peer:{address}"),
        Some(IpAddr::V6(address)) => {
            let segments = address.segments();
            format!(
                "peer:{:x}:{:x}:{:x}:{:x}::/64",
                segments[0], segments[1], segments[2], segments[3]
            )
        }
        None => "peer:unknown".to_string(),
    }
}

fn fingerprint_identity(kind: &str, value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{kind}:{digest:x}")
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, net::Ipv4Addr};

    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn recognizes_only_instance_scoped_download_paths() {
        assert!(is_download_path(
            "/api/instances/inst_one/artifacts/dump.sql/download"
        ));
        assert!(is_download_path(
            "/api/instances/inst_one/backups/backup.tar.gz/download"
        ));
        assert!(!is_download_path("/api/artifacts/download-signed"));
        assert!(!is_download_path(
            "/api/instances/inst_one/artifacts/dump.sql/delete"
        ));
    }

    #[test]
    fn ignores_forwarded_for_header_for_rate_limit_identity() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
        let peer = "192.0.2.7:5000".parse().unwrap();

        let identity = rate_limit_identity(
            &ApiToken::new("secret"),
            b"jwt-secret",
            &headers,
            &Uri::from_static("/api/system"),
            Some(peer),
        );

        assert_eq!(
            identity.key,
            peer_rate_limit_key(Some("192.0.2.7:1234".parse().unwrap()))
        );
        assert!(!identity.trusted);
    }

    #[test]
    fn invalid_authorization_uses_peer_bucket_without_leaking_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            crate::constants::AUTHORIZATION_HEADER,
            HeaderValue::from_static("Bearer super-secret"),
        );
        let peer = "192.0.2.7:5000".parse().unwrap();

        let identity = rate_limit_identity(
            &ApiToken::new("different-secret"),
            b"jwt-secret",
            &headers,
            &Uri::from_static("/api/system"),
            Some(peer),
        );

        assert_eq!(
            identity.key,
            peer_rate_limit_key(Some("192.0.2.7:1234".parse().unwrap()))
        );
        assert!(!identity.key.contains("super-secret"));
        assert!(!identity.trusted);

        headers.insert(
            crate::constants::AUTHORIZATION_HEADER,
            HeaderValue::from_static("Bearer a-different-guess"),
        );
        let next_guess = rate_limit_identity(
            &ApiToken::new("different-secret"),
            b"jwt-secret",
            &headers,
            &Uri::from_static("/api/system"),
            Some(peer),
        );
        assert_eq!(identity, next_guess);
    }

    #[test]
    fn valid_api_token_gets_a_stable_trusted_bucket() {
        let mut headers = HeaderMap::new();
        headers.insert(
            crate::constants::AUTHORIZATION_HEADER,
            HeaderValue::from_static("Bearer secret"),
        );

        let identity = rate_limit_identity(
            &ApiToken::new("secret"),
            b"jwt-secret",
            &headers,
            &Uri::from_static("/api/system"),
            Some("192.0.2.7:5000".parse().unwrap()),
        );

        assert!(identity.key.starts_with("api:"));
        assert!(!identity.key.contains("secret"));
        assert!(identity.trusted);
    }

    #[test]
    fn valid_websocket_jwt_gets_a_trusted_jti_bucket() {
        let secret = b"test-jwt-signing-key-at-least-32-bytes";
        let (token, _) = jwt::issue_ws_token(
            secret,
            "browser-user",
            vec![crate::auth::scopes::MONITOR_READ.to_string()],
            vec!["inst_allowed".to_string()],
            false,
            60,
        )
        .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            crate::constants::AUTHORIZATION_HEADER,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );

        let identity = rate_limit_identity(
            &ApiToken::new("api-secret"),
            secret,
            &headers,
            &Uri::from_static("/ws/monitoring"),
            Some("192.0.2.7:5000".parse().unwrap()),
        );

        assert!(identity.key.starts_with("jwt:"));
        assert!(!identity.key.contains(&token));
        assert!(identity.trusted);
    }

    #[test]
    fn ipv6_peers_are_grouped_by_64_bit_prefix() {
        let first = peer_rate_limit_group(Some("[2001:db8:1234:5678::1]:5000".parse().unwrap()));
        let second = peer_rate_limit_group(Some("[2001:db8:1234:5678::2]:5000".parse().unwrap()));

        assert_eq!(first, second);
        assert_eq!(first, "peer:2001:db8:1234:5678::/64");
    }

    #[test]
    fn unauthenticated_peer_key_cardinality_is_bounded() {
        let keys = (0..10_000_u32)
            .map(|index| {
                let address = Ipv4Addr::from(index);
                peer_rate_limit_key(Some(SocketAddr::from((address, 5000))))
            })
            .collect::<HashSet<_>>();

        assert!(keys.len() <= usize::from(UNAUTHENTICATED_RATE_LIMIT_BUCKETS));
    }

    #[tokio::test]
    async fn websocket_jti_is_single_use_until_expiration() {
        let limiter = ApiRateLimiter::default();
        let expiration = time::OffsetDateTime::now_utc().unix_timestamp() + 60;

        let permit = limiter
            .admit_websocket("single-use-jti", expiration)
            .await
            .unwrap();
        drop(permit);

        assert_eq!(
            limiter
                .admit_websocket("single-use-jti", expiration)
                .await
                .unwrap_err(),
            WebSocketAdmissionError::Replay
        );
    }

    #[tokio::test]
    async fn expired_websocket_jti_is_rejected() {
        let limiter = ApiRateLimiter::default();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();

        assert_eq!(
            limiter
                .admit_websocket("expired-jti", now)
                .await
                .unwrap_err(),
            WebSocketAdmissionError::Expired
        );
    }

    #[test]
    fn concurrent_api_requests_are_bounded() {
        let limiter = ApiRateLimiter::default();
        let mut permits = Vec::with_capacity(MAX_ACTIVE_API_REQUESTS);
        for _ in 0..MAX_ACTIVE_API_REQUESTS {
            permits.push(limiter.admit_request().unwrap());
        }

        assert!(matches!(
            limiter.admit_request(),
            Err(ApiError::RateLimited)
        ));
        drop(permits.pop());
        assert!(limiter.admit_request().is_ok());
    }
}
