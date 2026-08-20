use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
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
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore};

use crate::{
    api::{api_response::ApiError, routes::AppState, security_policy::websocket_token},
    auth::{api_token::AcceptedApiToken, jwt},
};

const API_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const MAX_API_RATE_LIMIT_KEYS: usize = 65_536;
const API_RATE_LIMIT_SHARDS: usize = 64;
const MAX_API_RATE_LIMIT_KEYS_PER_SHARD: usize = MAX_API_RATE_LIMIT_KEYS / API_RATE_LIMIT_SHARDS;
const UNAUTHENTICATED_RATE_LIMIT_BUCKETS: u16 = 4096;
const MAX_ACTIVE_WEBSOCKETS: usize = 1024;
const MAX_ACTIVE_API_REQUESTS: usize = 1024;
const MAX_ACTIVE_HEARTBEAT_REQUESTS: usize = 16;
const MAX_CONSUMED_WEBSOCKET_JTIS: usize = 65_536;

#[derive(Debug, Clone)]
pub struct ApiRateLimiter {
    inner: Arc<[Mutex<RateLimitShard>; API_RATE_LIMIT_SHARDS]>,
    consumed_websocket_jtis: Arc<Mutex<HashMap<String, i64>>>,
    active_websockets: Arc<Semaphore>,
    websocket_drain: Arc<Notify>,
    active_requests: Arc<Semaphore>,
    active_heartbeat_requests: Arc<Semaphore>,
    request_capacity_logged: Arc<AtomicBool>,
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
            inner: Arc::new(std::array::from_fn(|_| {
                Mutex::new(RateLimitShard::default())
            })),
            consumed_websocket_jtis: Arc::default(),
            active_websockets: Arc::new(Semaphore::new(MAX_ACTIVE_WEBSOCKETS)),
            websocket_drain: Arc::default(),
            active_requests: Arc::new(Semaphore::new(MAX_ACTIVE_API_REQUESTS)),
            active_heartbeat_requests: Arc::new(Semaphore::new(MAX_ACTIVE_HEARTBEAT_REQUESTS)),
            request_capacity_logged: Arc::new(AtomicBool::new(false)),
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
        let connection = WebSocketConnectionPermit {
            _connection: connection,
            drain_notify: Arc::clone(&self.websocket_drain),
        };
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
        Ok(connection)
    }

    fn admit_request(&self, heartbeat: bool) -> Result<ApiRequestPermit, ApiError> {
        let admission = if heartbeat {
            Arc::clone(&self.active_heartbeat_requests)
        } else {
            Arc::clone(&self.active_requests)
        };
        match admission.try_acquire_owned() {
            Ok(permit) => Ok(ApiRequestPermit {
                _permit: permit,
                capacity_logged: Arc::clone(&self.request_capacity_logged),
            }),
            Err(_) => {
                if !self.request_capacity_logged.swap(true, Ordering::AcqRel) {
                    tracing::warn!("audit api_request_capacity_reached");
                }
                Err(ApiError::RateLimited)
            }
        }
    }

    async fn allow(&self, identity: &RateLimitIdentity) -> RateLimitDecision {
        let now = Instant::now();
        let shard = rate_limit_shard(&identity.key);
        let mut inner = self.inner[shard].lock().await;
        evict_expired_windows(&mut inner, now);
        if inner.windows.len() >= MAX_API_RATE_LIMIT_KEYS_PER_SHARD
            && !inner.windows.contains_key(&identity.key)
        {
            let eviction_candidate = inner
                .windows
                .iter()
                .filter(|(_, window)| !window.trusted)
                .min_by_key(|(_, window)| window.last_seen)
                .map(|(key, _)| key.clone());
            if let Some(key) = eviction_candidate {
                inner.windows.remove(&key);
                inner.capacity_rejection_logged = false;
            } else if !identity.trusted {
                let should_log = !inner.capacity_rejection_logged;
                inner.capacity_rejection_logged = true;
                return RateLimitDecision::Rejected { should_log };
            } else if let Some(key) = inner
                .windows
                .iter()
                .min_by_key(|(_, window)| window.last_seen)
                .map(|(key, _)| key.clone())
            {
                inner.windows.remove(&key);
                inner.capacity_rejection_logged = false;
            }
        }
        if !inner.windows.contains_key(&identity.key) {
            inner.windows.insert(
                identity.key.clone(),
                RateWindow {
                    started_at: now,
                    last_seen: now,
                    count: 0,
                    trusted: identity.trusted,
                    rejection_logged: false,
                },
            );
        }
        let window = inner
            .windows
            .get_mut(&identity.key)
            .expect("rate-limit window was inserted");
        if now.duration_since(window.started_at) >= API_RATE_LIMIT_WINDOW {
            window.started_at = now;
            window.count = 0;
            window.rejection_logged = false;
        }
        window.last_seen = now;
        window.count = window.count.saturating_add(1);
        if window.count <= self.max_requests {
            RateLimitDecision::Allowed
        } else {
            let should_log = !window.rejection_logged;
            window.rejection_logged = true;
            RateLimitDecision::Rejected { should_log }
        }
    }

    pub(crate) fn active_websocket_count(&self) -> usize {
        MAX_ACTIVE_WEBSOCKETS.saturating_sub(self.active_websockets.available_permits())
    }

    pub(crate) fn active_request_count(&self) -> usize {
        MAX_ACTIVE_API_REQUESTS.saturating_sub(self.active_requests.available_permits())
    }

    pub(crate) async fn wait_for_websocket_drain(&self, deadline: Duration) -> bool {
        let drained = async {
            loop {
                let notified = self.websocket_drain.notified();
                if self.active_websocket_count() == 0 {
                    return;
                }
                notified.await;
            }
        };
        tokio::time::timeout(deadline, drained).await.is_ok()
    }
}

#[derive(Debug)]
pub struct WebSocketConnectionPermit {
    _connection: OwnedSemaphorePermit,
    drain_notify: Arc<Notify>,
}

impl Drop for WebSocketConnectionPermit {
    fn drop(&mut self) {
        self.drain_notify.notify_waiters();
    }
}

#[derive(Debug)]
struct ApiRequestPermit {
    _permit: OwnedSemaphorePermit,
    capacity_logged: Arc<AtomicBool>,
}

impl Drop for ApiRequestPermit {
    fn drop(&mut self) {
        self.capacity_logged.store(false, Ordering::Release);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebSocketAdmissionError {
    Replay,
    Expired,
    TokenCapacity,
    ConnectionCapacity,
}

#[derive(Debug, Default)]
struct RateLimitShard {
    windows: HashMap<RateLimitKey, RateWindow>,
    capacity_rejection_logged: bool,
}

fn evict_expired_windows(inner: &mut RateLimitShard, now: Instant) {
    if inner.windows.len() < MAX_API_RATE_LIMIT_KEYS_PER_SHARD {
        inner.capacity_rejection_logged = false;
        return;
    }
    inner
        .windows
        .retain(|_, window| now.duration_since(window.started_at) < API_RATE_LIMIT_WINDOW);
    if inner.windows.len() < MAX_API_RATE_LIMIT_KEYS_PER_SHARD {
        inner.capacity_rejection_logged = false;
    }
}

fn rate_limit_shard(key: &RateLimitKey) -> usize {
    match key {
        RateLimitKey::Authenticated {
            fingerprint, peer, ..
        } => {
            let mut folded = fingerprint
                .iter()
                .fold(0_u8, |value, byte| value.rotate_left(1) ^ byte);
            let peer_bytes: &[u8] = match peer {
                PeerGroup::V4(address) => address,
                PeerGroup::V6(prefix) => prefix,
                PeerGroup::Unknown => &[0],
            };
            for byte in peer_bytes {
                folded = folded.rotate_left(1) ^ byte;
            }
            usize::from(folded) % API_RATE_LIMIT_SHARDS
        }
        RateLimitKey::Anonymous { bucket } => usize::from(*bucket) % API_RATE_LIMIT_SHARDS,
    }
}

#[derive(Debug, Clone)]
struct RateWindow {
    started_at: Instant,
    last_seen: Instant,
    count: u32,
    trusted: bool,
    rejection_logged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RateLimitDecision {
    Allowed,
    Rejected { should_log: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RateLimitIdentity {
    key: RateLimitKey,
    trusted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RateLimitKey {
    Authenticated {
        kind: CredentialKind,
        fingerprint: [u8; 32],
        peer: PeerGroup,
    },
    Anonymous {
        bucket: u16,
    },
}

impl RateLimitKey {
    fn audit_label(&self) -> String {
        match self {
            Self::Authenticated {
                kind, fingerprint, ..
            } => {
                use std::fmt::Write as _;

                let mut label = format!("{}-peer:", kind.as_str());
                for byte in fingerprint {
                    write!(&mut label, "{byte:02x}").expect("writing to a String cannot fail");
                }
                label
            }
            Self::Anonymous { bucket } => format!("peer-bucket:{bucket}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CredentialKind {
    Api,
    Jwt,
}

impl CredentialKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Jwt => "jwt",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PeerGroup {
    V4([u8; 4]),
    V6([u8; 8]),
    Unknown,
}

#[derive(Debug, Clone)]
pub(crate) enum RequestAuthentication {
    Api(AcceptedApiToken),
    WebSocket(Arc<jwt::Claims>),
    SignedJwt { fingerprint: [u8; 32] },
    Unauthenticated,
}

pub async fn rate_limit(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let heartbeat = request.uri().path() == "/api/heartbeat";
    let _request = state.api_rate_limiter.admit_request(heartbeat)?;
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| *address);
    let authentication = authenticate_request(
        &state,
        state.config.websocket_jwt_secret(),
        request.headers(),
        request.uri(),
    );
    let identity = rate_limit_identity(&authentication, peer);
    request.extensions_mut().insert(authentication);
    match state.api_rate_limiter.allow(&identity).await {
        RateLimitDecision::Allowed => Ok(next.run(request).await),
        RateLimitDecision::Rejected { should_log } => {
            if should_log {
                tracing::warn!(key = %identity.key.audit_label(), "audit api_rate_limited");
            }
            Err(ApiError::RateLimited)
        }
    }
}

fn authenticate_request(
    state: &AppState,
    jwt_secret: &[u8],
    headers: &HeaderMap,
    uri: &Uri,
) -> RequestAuthentication {
    let authorization = headers
        .get(crate::constants::AUTHORIZATION_HEADER)
        .and_then(|value| value.to_str().ok());
    if let Some(accepted) = state
        .api_token
        .accepted_from_authorization_header(authorization)
    {
        return RequestAuthentication::Api(accepted);
    }

    if let Some(token) = websocket_token(headers)
        && let Ok(claims) = jwt::validate_ws_token_claims(token, jwt_secret)
    {
        return RequestAuthentication::WebSocket(Arc::new(claims));
    }

    if let Some(token) = signed_download_query_token(uri)
        && let Ok(jti) = jwt::validated_token_jti(token, jwt_secret)
    {
        return RequestAuthentication::SignedJwt {
            fingerprint: credential_fingerprint(CredentialKind::Jwt, &jti),
        };
    }

    RequestAuthentication::Unauthenticated
}

fn rate_limit_identity(
    authentication: &RequestAuthentication,
    peer: Option<SocketAddr>,
) -> RateLimitIdentity {
    let peer = peer_rate_limit_group(peer);
    match authentication {
        RequestAuthentication::Api(accepted) => RateLimitIdentity {
            key: RateLimitKey::Authenticated {
                kind: CredentialKind::Api,
                fingerprint: accepted.rate_limit_fingerprint(),
                peer,
            },
            trusted: true,
        },
        RequestAuthentication::WebSocket(claims) => RateLimitIdentity {
            key: RateLimitKey::Authenticated {
                kind: CredentialKind::Jwt,
                fingerprint: credential_fingerprint(CredentialKind::Jwt, &claims.jti),
                peer,
            },
            trusted: true,
        },
        RequestAuthentication::SignedJwt { fingerprint } => RateLimitIdentity {
            key: RateLimitKey::Authenticated {
                kind: CredentialKind::Jwt,
                fingerprint: *fingerprint,
                peer,
            },
            trusted: true,
        },
        RequestAuthentication::Unauthenticated => RateLimitIdentity {
            key: peer_rate_limit_key(peer),
            trusted: false,
        },
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

fn peer_rate_limit_key(group: PeerGroup) -> RateLimitKey {
    let digest = match group {
        PeerGroup::V4(address) => Sha256::digest(address),
        PeerGroup::V6(prefix) => Sha256::digest(prefix),
        PeerGroup::Unknown => Sha256::digest([0]),
    };
    let bucket = u16::from_be_bytes([digest[0], digest[1]]) % UNAUTHENTICATED_RATE_LIMIT_BUCKETS;
    RateLimitKey::Anonymous { bucket }
}

fn peer_rate_limit_group(peer: Option<SocketAddr>) -> PeerGroup {
    match peer.map(|address| address.ip()) {
        Some(IpAddr::V4(address)) => PeerGroup::V4(address.octets()),
        Some(IpAddr::V6(address)) => address.to_ipv4_mapped().map_or_else(
            || {
                let mut prefix = [0_u8; 8];
                prefix.copy_from_slice(&address.octets()[..8]);
                PeerGroup::V6(prefix)
            },
            |address| PeerGroup::V4(address.octets()),
        ),
        None => PeerGroup::Unknown,
    }
}

fn credential_fingerprint(kind: CredentialKind, credential_identity: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(kind.as_str().as_bytes());
    digest.update([0]);
    digest.update(credential_identity.as_bytes());
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, net::Ipv4Addr};

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
    fn unauthenticated_identity_uses_the_socket_peer() {
        let peer = "192.0.2.7:5000".parse().unwrap();

        let identity = rate_limit_identity(&RequestAuthentication::Unauthenticated, Some(peer));

        assert_eq!(
            identity.key,
            peer_rate_limit_key(peer_rate_limit_group(Some(
                "192.0.2.7:1234".parse().unwrap()
            )))
        );
        assert!(!identity.trusted);
    }

    #[test]
    fn unauthenticated_guesses_share_the_same_bounded_peer_bucket() {
        let peer = "192.0.2.7:5000".parse().unwrap();

        let identity = rate_limit_identity(&RequestAuthentication::Unauthenticated, Some(peer));
        let next_guess = rate_limit_identity(&RequestAuthentication::Unauthenticated, Some(peer));
        assert_eq!(identity, next_guess);
        assert!(!identity.trusted);
    }

    #[test]
    fn valid_api_token_gets_a_stable_trusted_peer_bucket() {
        let accepted = crate::auth::api_token::ApiToken::new("secret")
            .accepted_from_authorization_header(Some("Bearer secret"))
            .unwrap();
        let authentication = RequestAuthentication::Api(accepted);
        let identity =
            rate_limit_identity(&authentication, Some("192.0.2.7:5000".parse().unwrap()));

        assert!(matches!(
            identity.key,
            RateLimitKey::Authenticated {
                kind: CredentialKind::Api,
                ..
            }
        ));
        assert!(!identity.key.audit_label().contains("secret"));
        assert!(identity.trusted);

        let same_ip_new_port =
            rate_limit_identity(&authentication, Some("192.0.2.7:9000".parse().unwrap()));
        let other_ip =
            rate_limit_identity(&authentication, Some("192.0.2.8:5000".parse().unwrap()));
        assert_eq!(identity, same_ip_new_port);
        assert_ne!(identity, other_ip);
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
        let claims = jwt::validate_ws_token_claims(&token, secret).unwrap();
        let authentication = RequestAuthentication::WebSocket(Arc::new(claims));
        let identity =
            rate_limit_identity(&authentication, Some("192.0.2.7:5000".parse().unwrap()));

        assert!(matches!(
            identity.key,
            RateLimitKey::Authenticated {
                kind: CredentialKind::Jwt,
                ..
            }
        ));
        assert!(!identity.key.audit_label().contains(&token));
        assert!(identity.trusted);
    }

    #[test]
    fn ipv6_peers_are_grouped_by_64_bit_prefix() {
        let first = peer_rate_limit_group(Some("[2001:db8:1234:5678::1]:5000".parse().unwrap()));
        let second = peer_rate_limit_group(Some("[2001:db8:1234:5678::2]:5000".parse().unwrap()));

        assert_eq!(first, second);
        assert!(matches!(first, PeerGroup::V6(_)));
    }

    #[test]
    fn ipv4_mapped_ipv6_peers_use_their_ipv4_bucket() {
        let ipv4 = peer_rate_limit_group(Some("192.0.2.7:5000".parse().unwrap()));
        let mapped = peer_rate_limit_group(Some("[::ffff:192.0.2.7]:5000".parse().unwrap()));
        let other_mapped = peer_rate_limit_group(Some("[::ffff:192.0.2.8]:5000".parse().unwrap()));

        assert_eq!(mapped, ipv4);
        assert_ne!(mapped, other_mapped);
        assert!(matches!(mapped, PeerGroup::V4([192, 0, 2, 7])));
    }

    #[test]
    fn unauthenticated_peer_key_cardinality_is_bounded() {
        let keys = (0..10_000_u32)
            .map(|index| {
                let address = Ipv4Addr::from(index);
                peer_rate_limit_key(peer_rate_limit_group(Some(SocketAddr::from((
                    address, 5000,
                )))))
            })
            .collect::<HashSet<_>>();

        assert!(keys.len() <= usize::from(UNAUTHENTICATED_RATE_LIMIT_BUCKETS));
    }

    #[tokio::test]
    async fn request_rate_windows_are_per_credential_and_peer_and_log_once() {
        let limiter = ApiRateLimiter::new(2);
        let first_peer = RateLimitIdentity {
            key: RateLimitKey::Authenticated {
                kind: CredentialKind::Api,
                fingerprint: [1; 32],
                peer: PeerGroup::V4([192, 0, 2, 1]),
            },
            trusted: true,
        };
        let second_peer = RateLimitIdentity {
            key: RateLimitKey::Authenticated {
                kind: CredentialKind::Api,
                // The same credential from a different transport peer retains
                // its own minute bucket. Global pre-request socket admission
                // is enforced separately by the API listener.
                fingerprint: [1; 32],
                peer: PeerGroup::V4([192, 0, 2, 2]),
            },
            trusted: true,
        };

        assert_eq!(limiter.allow(&first_peer).await, RateLimitDecision::Allowed);
        assert_eq!(limiter.allow(&first_peer).await, RateLimitDecision::Allowed);
        assert_eq!(
            limiter.allow(&first_peer).await,
            RateLimitDecision::Rejected { should_log: true }
        );
        assert_eq!(
            limiter.allow(&first_peer).await,
            RateLimitDecision::Rejected { should_log: false }
        );
        assert_eq!(
            limiter.allow(&second_peer).await,
            RateLimitDecision::Allowed
        );
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

    #[tokio::test]
    async fn websocket_connections_are_counted_and_can_be_drained() {
        let limiter = ApiRateLimiter::default();
        let expiration = time::OffsetDateTime::now_utc().unix_timestamp() + 60;
        let permit = limiter
            .admit_websocket("drainable-jti", expiration)
            .await
            .unwrap();
        assert_eq!(limiter.active_websocket_count(), 1);

        tokio::spawn(async move {
            tokio::task::yield_now().await;
            drop(permit);
        });
        assert!(
            limiter
                .wait_for_websocket_drain(Duration::from_secs(1))
                .await
        );
        assert_eq!(limiter.active_websocket_count(), 0);
    }

    #[test]
    fn concurrent_api_requests_are_bounded() {
        let limiter = ApiRateLimiter::default();
        let mut permits = Vec::with_capacity(MAX_ACTIVE_API_REQUESTS);
        for _ in 0..MAX_ACTIVE_API_REQUESTS {
            permits.push(limiter.admit_request(false).unwrap());
        }

        assert!(matches!(
            limiter.admit_request(false),
            Err(ApiError::RateLimited)
        ));
        assert!(limiter.admit_request(true).is_ok());
        drop(permits.pop());
        assert!(limiter.admit_request(false).is_ok());
    }
}
