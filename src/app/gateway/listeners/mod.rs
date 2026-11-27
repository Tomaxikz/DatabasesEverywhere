use parking_lot::Mutex;
use std::{
    collections::HashMap,
    future::Future,
    io::{Error as IoError, ErrorKind},
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::Instant as StdInstant,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    sync::{Semaphore, watch},
    time::{Duration, timeout},
};

mod admission;
mod clickhouse_listener;
mod client_socket;
mod listener_io;
mod mongodb_listener;
mod mysql_listener;
mod postgres_listener;
mod qdrant_listener;
mod resp_listener;
pub(crate) use admission::{Origin, ProtocolEntry};
use clickhouse_listener::{handle_clickhouse_client, handle_clickhouse_http};
pub(crate) use client_socket::ClientSocket;
use mongodb_listener::handle_mongodb_client;
use mysql_listener::{handle_mariadb_client, handle_mysql_client};
use postgres_listener::handle_postgres_client;
use qdrant_listener::handle_qdrant_client;
use resp_listener::{handle_redis_client, handle_valkey_client};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use super::{
    resolver::RouteResolver,
    security::{GatewayConnectionLimiter, GatewayConnectionRejectionReason},
    supervisor::GatewayConnectionTracker,
    tunnel,
};
use crate::gateway::protocols::{clickhouse, mariadb, mongodb, postgres, qdrant, redis};

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
    Plain(ClientSocket),
    Tls(Box<TlsStream<ClientSocket>>),
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
const MAX_ROUTING_HANDSHAKE_BYTES: usize = 64 * 1024;
const BACKEND_FAILURE_WARNING_INTERVAL: Duration = Duration::from_secs(30);
const MAX_BACKEND_FAILURE_LOG_KEYS: usize = 4_096;

static BACKEND_FAILURE_LOGS: OnceLock<Mutex<HashMap<String, BackendFailureLogWindow>>> =
    OnceLock::new();
static TETHER_FAILURE_LOGS: OnceLock<Mutex<LogWindows>> = OnceLock::new();

#[derive(Debug)]
struct BackendFailureLogWindow {
    last_logged: StdInstant,
    suppressed: u64,
}

pub(crate) fn protocol_entry(
    protocol: &'static str,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
    limiter: GatewayConnectionLimiter,
    connections: GatewayConnectionTracker,
) -> Option<Arc<ProtocolEntry>> {
    macro_rules! entry {
        ($handler:expr) => {
            Some(ProtocolEntry::new(
                protocol,
                $handler,
                resolver,
                tls,
                limiter,
                connections,
            ))
        };
    }
    match protocol {
        "postgres" => entry!(handle_postgres_client),
        "redis" => entry!(handle_redis_client),
        "valkey" => entry!(handle_valkey_client),
        "mariadb" => entry!(handle_mariadb_client),
        "mysql" => entry!(handle_mysql_client),
        "mongodb" => entry!(handle_mongodb_client),
        "clickhouse" => entry!(handle_clickhouse_client),
        "clickhouse_http" => entry!(handle_clickhouse_http),
        "qdrant" => entry!(handle_qdrant_client),
        _ => None,
    }
}

macro_rules! public_listener {
    ($function:ident, $protocol:literal) => {
        pub async fn $function(
            listener: TcpListener,
            bind: &str,
            resolver: RouteResolver,
            tls: Option<TlsAcceptor>,
            limiter: GatewayConnectionLimiter,
            shutdown: watch::Receiver<bool>,
            connections: GatewayConnectionTracker,
        ) -> Result<(), ListenerError> {
            let entry = protocol_entry($protocol, resolver, tls, limiter, connections)
                .ok_or_else(|| IoError::other(concat!("no handler for ", $protocol)))?;
            run_listener(listener, bind, entry, shutdown).await
        }
    };
}

public_listener!(run_postgres_listener, "postgres");
public_listener!(run_redis_listener, "redis");
public_listener!(run_valkey_listener, "valkey");
public_listener!(run_mariadb_listener, "mariadb");
public_listener!(run_mysql_listener, "mysql");
public_listener!(run_mongodb_listener, "mongodb");
public_listener!(run_clickhouse_listener, "clickhouse");
public_listener!(run_clickhouse_http_listener, "clickhouse_http");
public_listener!(run_qdrant_listener, "qdrant");

/// Accepts public TCP clients of one protocol until shutdown.
pub(crate) async fn run_listener(
    listener: TcpListener,
    bind: &str,
    entry: Arc<ProtocolEntry>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ListenerError> {
    let protocol = entry.protocol();
    tracing::info!(
        bind,
        tls = entry.has_tls(),
        protocol,
        max_active_connections = entry.max_active_connections(),
        "database listener started"
    );
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
        // A refused connection is simply dropped; the entry logged why.
        // The handler task owns the slots; a refused connection is simply dropped.
        let _ = entry.admit(ClientSocket::Tcp(client), Origin::public(peer));
    }
}

pub(crate) fn rejection_reason_label(reason: GatewayConnectionRejectionReason) -> &'static str {
    match reason {
        GatewayConnectionRejectionReason::RateLimited => "rate",
        GatewayConnectionRejectionReason::TooManyActive => "active",
        GatewayConnectionRejectionReason::KeyCapacityReached => "key_capacity",
    }
}

pub(super) async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

async fn client_handshake<T>(
    protocol: &'static str,
    slots: Arc<Semaphore>,
    future: impl Future<Output = Result<T, ListenerError>>,
) -> Result<T, ListenerError> {
    timeout(CLIENT_HANDSHAKE_TIMEOUT, async move {
        let _permit = slots
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

pub(super) fn log_connection_failure(
    protocol: &'static str,
    origin: &Origin,
    error: &ListenerError,
) {
    let peer = origin.client;
    let (client, via_node) = (origin.client_field(), origin.via_field());
    if expected_client_failure(error) {
        tracing::debug!(%peer, client, via_node, %error, protocol, "database connection rejected");
    } else if let ListenerError::Backend {
        instance_id,
        source,
    } = error
    {
        // Tunnelled failures are limited by tether's own policy; public ones by the original.
        let permit = if origin.via_node.is_some() {
            tether_log_permit(protocol, instance_id)
        } else {
            backend_log_permit(protocol, instance_id)
        };
        match permit {
            Some(suppressed) => tracing::warn!(
                event = "database_backend_connection_failed",
                %peer,
                client,
                via_node,
                %source,
                protocol,
                instance_id,
                suppressed_since_last_warning = suppressed,
                "managed database backend connection failed; inspect the container lifecycle and logs"
            ),
            None => tracing::debug!(
                %peer,
                client,
                via_node,
                %source,
                protocol,
                instance_id,
                "duplicate managed database backend failure suppressed"
            ),
        }
    } else {
        tracing::warn!(%peer, client, via_node, %error, protocol, "database connection failed");
    }
}

pub(crate) fn backend_log_permit(protocol: &str, instance_id: &str) -> Option<u64> {
    let now = StdInstant::now();
    let key = format!("{protocol}\0{instance_id}");
    let mut windows = BACKEND_FAILURE_LOGS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock();
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

/// The same one-warning-per-key-per-window limit for tether's failures (failed opens on the
/// entry node, tunnelled failures on the data node), with one shared window for the keys
/// that do not fit once the table is full.
pub(crate) fn tether_log_permit(scope: &str, key: &str) -> Option<u64> {
    let key = format!("{scope}\0{key}");
    let mut windows = TETHER_FAILURE_LOGS
        .get_or_init(|| Mutex::new(LogWindows::default()))
        .lock();
    windows.permit(StdInstant::now(), key, MAX_BACKEND_FAILURE_LOG_KEYS)
}

#[derive(Debug, Default)]
struct LogWindows {
    keys: HashMap<String, BackendFailureLogWindow>,
    /// Shared by every key that does not fit in `keys`.
    overflow: Option<BackendFailureLogWindow>,
}

impl LogWindows {
    fn permit(&mut self, now: StdInstant, key: String, max_keys: usize) -> Option<u64> {
        let expired = |window: &BackendFailureLogWindow| {
            now.duration_since(window.last_logged) >= BACKEND_FAILURE_WARNING_INTERVAL
        };
        if self.keys.len() >= max_keys && !self.keys.contains_key(&key) {
            self.keys.retain(|_, window| !expired(window));
            if self.keys.len() >= max_keys {
                // Too many distinct keys to track each: they share one window, so a flood of
                // new keys cannot log on every failure either.
                match &mut self.overflow {
                    Some(window) if !expired(window) => {
                        window.suppressed = window.suppressed.saturating_add(1);
                    }
                    window => {
                        let suppressed = window.as_ref().map_or(0, |window| window.suppressed);
                        tracing::warn!(
                            suppressed_since_last_warning = suppressed,
                            "many distinct failing peers or backends; individual failures are suppressed"
                        );
                        *window = Some(BackendFailureLogWindow {
                            last_logged: now,
                            suppressed: 0,
                        });
                    }
                }
                return None;
            }
        }

        match self.keys.get_mut(&key) {
            Some(window) if !expired(window) => {
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
                self.keys.insert(
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
}

fn expected_client_failure(error: &ListenerError) -> bool {
    match error {
        ListenerError::RouteNotFound
        | ListenerError::HandshakeTimeout { .. }
        | ListenerError::HandshakeMessageLimit { .. }
        | ListenerError::IdentitySwitchRejected { .. } => true,
        ListenerError::Mariadb(mariadb::MariadbProxyError::SharedStorageCommandRejected(_)) => true,
        ListenerError::Io(error) => is_disconnect(error.kind()),
        ListenerError::Mongodb(mongodb::MongodbProxyError::Io(error)) => {
            is_disconnect(error.kind())
        }
        ListenerError::Clickhouse(clickhouse::ClickhouseParseError::IncompleteNativeHello)
        | ListenerError::Clickhouse(clickhouse::ClickhouseParseError::IncompleteHttpRequest) => {
            true
        }
        ListenerError::Qdrant(error) if error.is_stream_local() => true,
        ListenerError::Backend {
            source: tunnel::TunnelError::Tunnel(error),
            ..
        } => is_disconnect(error.kind()),
        _ => false,
    }
}

fn is_disconnect(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::net::TcpStream;

    #[tokio::test]
    async fn listener_applies_configured_connection_capacity() -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut settings = crate::config::Config::default();
        settings.daemon.limits.gateway_connections_per_listener = 2;
        let config = Arc::new(crate::config::RuntimeConfig::new(settings)?);
        let supervisor = crate::gateway::supervisor::GatewaySupervisor::with_config(config);
        supervisor.begin(1);
        supervisor.mark_ready();
        let resolver = RouteResolver::new(
            crate::server::state::InstanceStore::default(),
            crate::subsystems::monitoring::resources::ResourceCache::default(),
            crate::gateway::protocols::qdrant::QdrantRouteKey::new(b"test"),
            supervisor.tenant_sessions(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let entry = ProtocolEntry::new(
            "mysql",
            |mut client, _, _| async move {
                client.write_all(b"x").await?;
                let _ = client.read_u8().await;
                Ok(())
            },
            resolver,
            None,
            GatewayConnectionLimiter::default(),
            supervisor.connection_tracker(),
        );
        let task = tokio::spawn({
            let shutdown = supervisor.subscribe_shutdown();
            async move { run_listener(listener, &address.to_string(), entry, shutdown).await }
        });
        let mut clients = Vec::new();
        for _ in 0..2 {
            let mut client = TcpStream::connect(address).await?;
            assert_eq!(
                timeout(Duration::from_secs(5), client.read_u8()).await??,
                b'x'
            );
            clients.push(client);
        }
        let mut rejected = TcpStream::connect(address).await?;
        assert_eq!(
            timeout(Duration::from_secs(5), rejected.read_u8())
                .await?
                .expect_err("read u8 should return an error")
                .kind(),
            ErrorKind::UnexpectedEof
        );
        assert_eq!(supervisor.active_connections(), 2);
        drop(clients);
        let drained = supervisor
            .drain_connections(Duration::from_secs(5), Duration::from_secs(1))
            .await;
        assert_eq!(drained.remaining, 0);
        supervisor.shutdown();
        timeout(Duration::from_secs(5), task).await???;

        Ok(())
    }

    #[test]
    fn the_backend_failure_log_keeps_its_original_full_table_behaviour() {
        // A full table makes an unseen key log its own warning, as before tether existed.
        for index in 0..MAX_BACKEND_FAILURE_LOG_KEYS {
            let _ = backend_log_permit("full-table-test", &format!("instance-{index}"));
        }
        for _ in 0..3 {
            assert_eq!(backend_log_permit("full-table-test", "never-seen"), Some(0));
        }
    }

    #[test]
    fn log_windows_share_one_overflow_window_when_the_table_is_full() {
        let start = StdInstant::now();
        let mut windows = LogWindows::default();
        let key = |index: usize| format!("tether\0peer-{index}");
        // Normal behaviour: the first failure of a key logs, repeats inside the window don't.
        assert_eq!(windows.permit(start, key(0), 2), Some(0));
        assert_eq!(windows.permit(start, key(0), 2), None);
        assert_eq!(windows.permit(start, key(1), 2), Some(0));
        // Table full: unseen keys no longer log individually, however many there are.
        for index in 2..50 {
            assert_eq!(windows.permit(start, key(index), 2), None, "key {index}");
        }
        assert_eq!(windows.overflow.as_ref().map(|w| w.suppressed), Some(47));
        // Known keys are unaffected.
        assert_eq!(windows.permit(start, key(1), 2), None);
        // After the window, expired keys make room again.
        let later = start + BACKEND_FAILURE_WARNING_INTERVAL + Duration::from_secs(1);
        assert_eq!(windows.permit(later, key(60), 2), Some(0));
    }

    #[tokio::test(start_paused = true)]
    async fn configured_handshake_budget_waits_times_out_and_releases() -> anyhow::Result<()> {
        let mut settings = crate::config::Config::default();
        settings.daemon.limits.gateway_handshakes = 1;
        let config = crate::config::RuntimeConfig::new(settings)?;
        let held = Arc::clone(&config.budgets.gateway_handshakes).try_acquire_owned()?;
        assert!(matches!(
            client_handshake(
                "mysql",
                Arc::clone(&config.budgets.gateway_handshakes),
                async { Ok(()) }
            )
            .await,
            Err(ListenerError::HandshakeTimeout { .. })
        ));
        drop(held);
        assert!(
            client_handshake(
                "postgres",
                Arc::clone(&config.budgets.gateway_handshakes),
                async { Ok(()) }
            )
            .await
            .is_ok()
        );
        assert_eq!(config.budgets.gateway_handshakes.available_permits(), 1);

        Ok(())
    }

    #[test]
    fn only_incomplete_clickhouse_handshakes_are_expected_client_failures() {
        assert!(expected_client_failure(&ListenerError::Clickhouse(
            clickhouse::ClickhouseParseError::IncompleteNativeHello
        )));
        assert!(expected_client_failure(&ListenerError::Clickhouse(
            clickhouse::ClickhouseParseError::IncompleteHttpRequest
        )));
        assert!(!expected_client_failure(&ListenerError::Clickhouse(
            clickhouse::ClickhouseParseError::InvalidNativeHello
        )));
    }
}
