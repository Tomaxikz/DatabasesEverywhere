use std::{
    collections::HashMap,
    future::Future,
    io::{Error as IoError, ErrorKind},
    pin::Pin,
    sync::{Arc, Mutex as StdMutex, OnceLock},
    task::{Context, Poll},
    time::Instant as StdInstant,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    time::{Duration, timeout},
};

mod clickhouse_listener;
mod listener_io;
mod mongodb_listener;
mod mysql_listener;
mod postgres_listener;
mod qdrant_listener;
mod resp_listener;
use clickhouse_listener::{handle_clickhouse_client, handle_clickhouse_http};
use mongodb_listener::handle_mongodb_client;
use mysql_listener::{handle_mariadb_client, handle_mysql_client};
use postgres_listener::handle_postgres_client;
use qdrant_listener::handle_qdrant_client;
use resp_listener::{handle_redis_client, handle_valkey_client};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use super::{
    resolver::RouteResolver,
    security::{
        GatewayConnectionLimiter, GatewayConnectionRejection, GatewayConnectionRejectionReason,
    },
    supervisor::GatewayConnectionTracker,
    tunnel,
};
use crate::protocols::{clickhouse, mariadb, mongodb, postgres, qdrant, redis};

#[derive(Debug, thiserror::Error)]
pub enum ListenerError {
    #[error("listener io failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("postgres routing failed: {0}")]
    Postgres(#[from] postgres::PostgresParseError),
    #[error("postgres session routing failed: {0}")]
    PostgresSession(String),
    #[error("RESP routing failed: {0}")]
    Resp(#[from] redis::RedisParseError),
    #[error("mariadb routing failed: {0}")]
    Mariadb(#[from] mariadb::MariadbProxyError),
    #[error("mongodb routing failed: {0}")]
    Mongodb(#[from] mongodb::MongodbProxyError),
    #[error("clickhouse routing failed: {0}")]
    Clickhouse(#[from] clickhouse::ClickhouseParseError),
    #[error("qdrant routing failed: {0}")]
    Qdrant(#[from] qdrant::QdrantProxyError),
    #[error("no backend route found")]
    RouteNotFound,
    #[error("{protocol} database-less route is ambiguous")]
    AmbiguousDatabaseRoute { protocol: &'static str },
    #[error("clickhouse backend endpoint is invalid")]
    InvalidClickhouseBackend,
    #[error("qdrant backend endpoint is invalid")]
    InvalidQdrantBackend,
    #[error("tunnel failed: {0}")]
    Tunnel(#[from] tunnel::TunnelError),
    #[error("backend for managed instance {instance_id} failed: {source}")]
    Backend {
        instance_id: String,
        #[source]
        source: tunnel::TunnelError,
    },
    #[error("{protocol} client handshake timed out after {timeout_secs}s")]
    HandshakeTimeout {
        protocol: &'static str,
        timeout_secs: u64,
    },
    #[error("{protocol} client exceeded the handshake message limit")]
    HandshakeMessageLimit { protocol: &'static str },
    #[error("{protocol} connection attempted to change its authenticated tenant identity")]
    IdentitySwitchRejected { protocol: &'static str },
}

enum GatewayStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for GatewayStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buffer),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buffer),
        }
    }
}

impl AsyncWrite for GatewayStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, bytes),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, bytes),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

const CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_ACTIVE_CONNECTIONS_PER_LISTENER: usize = 1024;
const MAX_CONCURRENT_CLIENT_HANDSHAKES: usize = 256;
const MAX_ROUTING_HANDSHAKE_BYTES: usize = 64 * 1024;
const BACKEND_FAILURE_WARNING_INTERVAL: Duration = Duration::from_secs(30);
const MAX_BACKEND_FAILURE_LOG_KEYS: usize = 4_096;

static CLIENT_HANDSHAKE_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
static BACKEND_FAILURE_LOGS: OnceLock<StdMutex<HashMap<String, BackendFailureLogWindow>>> =
    OnceLock::new();

#[derive(Debug)]
struct BackendFailureLogWindow {
    last_logged: StdInstant,
    suppressed: u64,
}

struct ListenerRuntime {
    listener: TcpListener,
    bind: String,
    protocol: &'static str,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
    limiter: GatewayConnectionLimiter,
    shutdown: watch::Receiver<bool>,
    connections: GatewayConnectionTracker,
}

pub async fn run_postgres_listener(
    listener: TcpListener,
    bind: &str,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
    limiter: GatewayConnectionLimiter,
    shutdown: watch::Receiver<bool>,
    connections: GatewayConnectionTracker,
) -> Result<(), ListenerError> {
    run_listener(
        ListenerRuntime {
            listener,
            bind: bind.to_string(),
            protocol: "postgres",
            resolver,
            tls,
            limiter,
            shutdown,
            connections,
        },
        handle_postgres_client,
    )
    .await
}

pub async fn run_redis_listener(
    listener: TcpListener,
    bind: &str,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
    limiter: GatewayConnectionLimiter,
    shutdown: watch::Receiver<bool>,
    connections: GatewayConnectionTracker,
) -> Result<(), ListenerError> {
    run_listener(
        ListenerRuntime {
            listener,
            bind: bind.to_string(),
            protocol: "redis",
            resolver,
            tls,
            limiter,
            shutdown,
            connections,
        },
        handle_redis_client,
    )
    .await
}

pub async fn run_valkey_listener(
    listener: TcpListener,
    bind: &str,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
    limiter: GatewayConnectionLimiter,
    shutdown: watch::Receiver<bool>,
    connections: GatewayConnectionTracker,
) -> Result<(), ListenerError> {
    run_listener(
        ListenerRuntime {
            listener,
            bind: bind.to_string(),
            protocol: "valkey",
            resolver,
            tls,
            limiter,
            shutdown,
            connections,
        },
        handle_valkey_client,
    )
    .await
}

pub async fn run_mariadb_listener(
    listener: TcpListener,
    bind: &str,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
    limiter: GatewayConnectionLimiter,
    shutdown: watch::Receiver<bool>,
    connections: GatewayConnectionTracker,
) -> Result<(), ListenerError> {
    run_listener(
        ListenerRuntime {
            listener,
            bind: bind.to_string(),
            protocol: "mariadb",
            resolver,
            tls,
            limiter,
            shutdown,
            connections,
        },
        handle_mariadb_client,
    )
    .await
}

pub async fn run_mysql_listener(
    listener: TcpListener,
    bind: &str,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
    limiter: GatewayConnectionLimiter,
    shutdown: watch::Receiver<bool>,
    connections: GatewayConnectionTracker,
) -> Result<(), ListenerError> {
    run_listener(
        ListenerRuntime {
            listener,
            bind: bind.to_string(),
            protocol: "mysql",
            resolver,
            tls,
            limiter,
            shutdown,
            connections,
        },
        handle_mysql_client,
    )
    .await
}

pub async fn run_mongodb_listener(
    listener: TcpListener,
    bind: &str,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
    limiter: GatewayConnectionLimiter,
    shutdown: watch::Receiver<bool>,
    connections: GatewayConnectionTracker,
) -> Result<(), ListenerError> {
    run_listener(
        ListenerRuntime {
            listener,
            bind: bind.to_string(),
            protocol: "mongodb",
            resolver,
            tls,
            limiter,
            shutdown,
            connections,
        },
        handle_mongodb_client,
    )
    .await
}

pub async fn run_clickhouse_listener(
    listener: TcpListener,
    bind: &str,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
    limiter: GatewayConnectionLimiter,
    shutdown: watch::Receiver<bool>,
    connections: GatewayConnectionTracker,
) -> Result<(), ListenerError> {
    run_listener(
        ListenerRuntime {
            listener,
            bind: bind.to_string(),
            protocol: "clickhouse",
            resolver,
            tls,
            limiter,
            shutdown,
            connections,
        },
        handle_clickhouse_client,
    )
    .await
}

pub async fn run_clickhouse_http_listener(
    listener: TcpListener,
    bind: &str,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
    limiter: GatewayConnectionLimiter,
    shutdown: watch::Receiver<bool>,
    connections: GatewayConnectionTracker,
) -> Result<(), ListenerError> {
    run_listener(
        ListenerRuntime {
            listener,
            bind: bind.to_string(),
            protocol: "clickhouse_http",
            resolver,
            tls,
            limiter,
            shutdown,
            connections,
        },
        handle_clickhouse_http,
    )
    .await
}

pub async fn run_qdrant_listener(
    listener: TcpListener,
    bind: &str,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
    limiter: GatewayConnectionLimiter,
    shutdown: watch::Receiver<bool>,
    connections: GatewayConnectionTracker,
) -> Result<(), ListenerError> {
    run_listener(
        ListenerRuntime {
            listener,
            bind: bind.to_string(),
            protocol: "qdrant",
            resolver,
            tls,
            limiter,
            shutdown,
            connections,
        },
        handle_qdrant_client,
    )
    .await
}

async fn run_listener<H, F>(runtime: ListenerRuntime, handler: H) -> Result<(), ListenerError>
where
    H: Fn(TcpStream, RouteResolver, Option<TlsAcceptor>) -> F + Copy + Send + Sync + 'static,
    F: Future<Output = Result<(), ListenerError>> + Send + 'static,
{
    let ListenerRuntime {
        listener,
        bind,
        protocol,
        resolver,
        tls,
        limiter,
        mut shutdown,
        connections,
    } = runtime;
    tracing::info!(
        bind,
        tls = tls.is_some(),
        protocol,
        max_active_connections = MAX_ACTIVE_CONNECTIONS_PER_LISTENER,
        "database listener started"
    );
    let active_connections = Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS_PER_LISTENER));
    let mut global_limit_logged = false;

    loop {
        if *shutdown.borrow() {
            tracing::info!(bind, protocol, "database listener stopping");
            return Ok(());
        }
        let accepted = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    tracing::info!(bind, protocol, "database listener stopping");
                    return Ok(());
                }
                continue;
            }
            accepted = listener.accept() => accepted,
        };
        let (client, peer) = accepted?;
        if let Err(error) = client.set_nodelay(true) {
            tracing::debug!(%peer, %error, protocol, "failed to configure client socket");
            continue;
        }
        let Ok(global_permit) = Arc::clone(&active_connections).try_acquire_owned() else {
            if !global_limit_logged {
                tracing::warn!(%peer, protocol, "audit database_connection_global_limit_reached");
                global_limit_logged = true;
            }
            continue;
        };
        global_limit_logged = false;
        let ip_permit = match limiter.try_acquire(peer.ip()) {
            Ok(permit) => permit,
            Err(GatewayConnectionRejection { reason, should_log }) => {
                let reason = match reason {
                    GatewayConnectionRejectionReason::RateLimited => "rate",
                    GatewayConnectionRejectionReason::TooManyActive => "active",
                    GatewayConnectionRejectionReason::KeyCapacityReached => "key_capacity",
                };
                if should_log {
                    tracing::warn!(%peer, protocol, reason, "audit database_connection_limited");
                }
                continue;
            }
        };
        let resolver = resolver.clone();
        let tls = tls.clone();
        let Some(connection) = connections.try_track() else {
            continue;
        };
        let mut force_shutdown = connections.subscribe_force_shutdown();
        tokio::spawn(async move {
            let _permits = (global_permit, ip_permit, connection);
            tokio::select! {
                result = handler(client, resolver, tls) => {
                    if let Err(error) = result {
                        log_connection_failure(protocol, peer, &error);
                    }
                }
                _ = wait_for_shutdown(&mut force_shutdown) => {
                    tracing::debug!(%peer, protocol, "database connection closed for daemon shutdown");
                }
            }
        });
    }
}

async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

async fn client_handshake<T>(
    protocol: &'static str,
    future: impl Future<Output = Result<T, ListenerError>>,
) -> Result<T, ListenerError> {
    timeout(CLIENT_HANDSHAKE_TIMEOUT, async move {
        let slots = CLIENT_HANDSHAKE_SLOTS
            .get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENT_HANDSHAKES)));
        let _permit = Arc::clone(slots)
            .acquire_owned()
            .await
            .map_err(|_| IoError::other("gateway handshake admission closed"))?;
        future.await
    })
    .await
    .map_err(|_| ListenerError::HandshakeTimeout {
        protocol,
        timeout_secs: CLIENT_HANDSHAKE_TIMEOUT.as_secs(),
    })?
}

fn log_connection_failure(
    protocol: &'static str,
    peer: std::net::SocketAddr,
    error: &ListenerError,
) {
    if expected_client_failure(error) {
        tracing::debug!(%peer, %error, protocol, "database connection rejected");
    } else if let ListenerError::Backend {
        instance_id,
        source,
    } = error
    {
        match backend_log_permit(protocol, instance_id) {
            Some(suppressed) => tracing::warn!(
                event = "database_backend_connection_failed",
                %peer,
                %source,
                protocol,
                instance_id,
                suppressed_since_last_warning = suppressed,
                "managed database backend connection failed; inspect the container lifecycle and logs"
            ),
            None => tracing::debug!(
                %peer,
                %source,
                protocol,
                instance_id,
                "duplicate managed database backend failure suppressed"
            ),
        }
    } else {
        tracing::warn!(%peer, %error, protocol, "database connection failed");
    }
}

fn backend_log_permit(protocol: &str, instance_id: &str) -> Option<u64> {
    let now = StdInstant::now();
    let key = format!("{protocol}\0{instance_id}");
    let mut windows = BACKEND_FAILURE_LOGS
        .get_or_init(|| StdMutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if windows.len() >= MAX_BACKEND_FAILURE_LOG_KEYS && !windows.contains_key(&key) {
        windows.retain(|_, window| {
            now.duration_since(window.last_logged) < BACKEND_FAILURE_WARNING_INTERVAL
        });
        if windows.len() >= MAX_BACKEND_FAILURE_LOG_KEYS {
            return Some(0);
        }
    }

    match windows.get_mut(&key) {
        Some(window)
            if now.duration_since(window.last_logged) < BACKEND_FAILURE_WARNING_INTERVAL =>
        {
            window.suppressed = window.suppressed.saturating_add(1);
            None
        }
        Some(window) => {
            let suppressed = window.suppressed;
            window.last_logged = now;
            window.suppressed = 0;
            Some(suppressed)
        }
        None => {
            windows.insert(
                key,
                BackendFailureLogWindow {
                    last_logged: now,
                    suppressed: 0,
                },
            );
            Some(0)
        }
    }
}

fn expected_client_failure(error: &ListenerError) -> bool {
    match error {
        ListenerError::RouteNotFound
        | ListenerError::HandshakeTimeout { .. }
        | ListenerError::HandshakeMessageLimit { .. }
        | ListenerError::IdentitySwitchRejected { .. } => true,
        ListenerError::Mariadb(mariadb::MariadbProxyError::SharedStorageCommandRejected(_)) => true,
        ListenerError::Io(error) => matches!(
            error.kind(),
            ErrorKind::UnexpectedEof
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
                | ErrorKind::BrokenPipe
        ),
        ListenerError::Mongodb(mongodb::MongodbProxyError::Io(error)) => matches!(
            error.kind(),
            ErrorKind::UnexpectedEof
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
                | ErrorKind::BrokenPipe
        ),
        ListenerError::Clickhouse(clickhouse::ClickhouseParseError::IncompleteNativeHello)
        | ListenerError::Clickhouse(clickhouse::ClickhouseParseError::IncompleteHttpRequest) => {
            true
        }
        ListenerError::Qdrant(error) if error.is_stream_local() => true,
        ListenerError::Backend {
            source: tunnel::TunnelError::Tunnel(error),
            ..
        } => matches!(
            error.kind(),
            ErrorKind::UnexpectedEof
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
                | ErrorKind::BrokenPipe
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clickhouse_incomplete_handshakes_are_expected_client_failures() {
        assert!(expected_client_failure(&ListenerError::Clickhouse(
            clickhouse::ClickhouseParseError::IncompleteNativeHello
        )));
        assert!(expected_client_failure(&ListenerError::Clickhouse(
            clickhouse::ClickhouseParseError::IncompleteHttpRequest
        )));
    }

    #[test]
    fn clickhouse_real_route_errors_remain_warnings() {
        assert!(!expected_client_failure(&ListenerError::Clickhouse(
            clickhouse::ClickhouseParseError::InvalidNativeHello
        )));
    }
}
