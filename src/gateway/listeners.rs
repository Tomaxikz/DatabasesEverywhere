use std::{
    future::Future,
    io::{Error as IoError, ErrorKind},
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
};
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    time::{Duration, timeout},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use super::{
    resolver::RouteResolver,
    security::{GatewayConnectionLimiter, GatewayConnectionRejection},
    tunnel,
};
use crate::{
    protocols::{clickhouse, mariadb, mongodb, postgres, qdrant, redis},
    shared::backend::BackendEndpoint,
};

#[derive(Debug, thiserror::Error)]
pub enum ListenerError {
    #[error("listener io failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("postgres routing failed: {0}")]
    Postgres(#[from] postgres::PostgresParseError),
    #[error("redis routing failed: {0}")]
    Redis(#[from] redis::RedisParseError),
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
    #[error("clickhouse backend endpoint is invalid")]
    InvalidClickhouseBackend,
    #[error("tunnel failed: {0}")]
    Tunnel(#[from] tunnel::TunnelError),
    #[error("{protocol} client handshake timed out after {timeout_secs}s")]
    HandshakeTimeout {
        protocol: &'static str,
        timeout_secs: u64,
    },
    #[error("{protocol} client exceeded the handshake message limit")]
    HandshakeMessageLimit { protocol: &'static str },
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

const TUNNEL_BUFFER_SIZE: usize = 64 * 1024;
const CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_ACTIVE_CONNECTIONS_PER_LISTENER: usize = 1024;
const MAX_CONCURRENT_CLIENT_HANDSHAKES: usize = 256;
const MAX_ROUTING_HANDSHAKE_BYTES: usize = 64 * 1024;
const MAX_MONGODB_HELLO_MESSAGES: usize = 8;

static CLIENT_HANDSHAKE_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();

struct ListenerRuntime {
    listener: TcpListener,
    bind: String,
    protocol: &'static str,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
    limiter: GatewayConnectionLimiter,
    shutdown: watch::Receiver<bool>,
}

pub async fn run_postgres_listener(
    listener: TcpListener,
    bind: &str,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
    limiter: GatewayConnectionLimiter,
    shutdown: watch::Receiver<bool>,
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
        },
        handle_redis_client,
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
        },
        handle_mariadb_client,
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
        },
        handle_clickhouse_http_client,
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
    } = runtime;
    tracing::info!(
        bind,
        tls = tls.is_some(),
        protocol,
        max_active_connections = MAX_ACTIVE_CONNECTIONS_PER_LISTENER,
        "database listener started"
    );
    let active_connections = Arc::new(Semaphore::new(MAX_ACTIVE_CONNECTIONS_PER_LISTENER));

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
            tracing::warn!(%peer, protocol, "audit database_connection_global_limit_reached");
            continue;
        };
        let ip_permit = match limiter.try_acquire(peer.ip()) {
            Ok(permit) => permit,
            Err(reason) => {
                let reason = match reason {
                    GatewayConnectionRejection::RateLimited => "rate",
                    GatewayConnectionRejection::TooManyActive => "active",
                    GatewayConnectionRejection::KeyCapacityReached => "key_capacity",
                };
                tracing::warn!(%peer, protocol, reason, "audit database_connection_limited");
                continue;
            }
        };
        let resolver = resolver.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _permits = (global_permit, ip_permit);
            if let Err(error) = handler(client, resolver, tls).await {
                log_connection_failure(protocol, peer, &error);
            }
        });
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
    } else {
        tracing::warn!(%peer, %error, protocol, "database connection failed");
    }
}

fn expected_client_failure(error: &ListenerError) -> bool {
    match error {
        ListenerError::RouteNotFound
        | ListenerError::HandshakeTimeout { .. }
        | ListenerError::HandshakeMessageLimit { .. } => true,
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
        _ => false,
    }
}

async fn handle_postgres_client(
    mut client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<(), ListenerError> {
    let (client, endpoint, packet) = client_handshake("postgres", async move {
        let packet = read_postgres_startup_packet(&mut client).await?;

        let (client, packet) = if postgres::is_ssl_request(&packet) {
            if let Some(tls) = tls {
                client.write_all(b"S").await?;
                let mut client = GatewayStream::Tls(Box::new(tls.accept(client).await?));
                let packet = read_postgres_startup_packet(&mut client).await?;
                (client, packet)
            } else {
                client.write_all(b"N").await?;
                let mut client = GatewayStream::Plain(client);
                let packet = read_postgres_startup_packet(&mut client).await?;
                (client, packet)
            }
        } else if tls.is_some() {
            return Err(postgres::PostgresParseError::InvalidLength.into());
        } else {
            (GatewayStream::Plain(client), packet)
        };

        let route = postgres::parse_startup_route(&packet)?;
        let endpoint = resolver
            .resolve_postgres(&route.user, &route.database)
            .await
            .ok_or(ListenerError::RouteNotFound)?;
        tracing::debug!(
            user = %route.user,
            database = %route.database,
            endpoint = ?endpoint,
            "postgres route resolved"
        );
        Ok((client, endpoint, packet))
    })
    .await?;

    tunnel::connect_replay_and_tunnel(client, endpoint, &packet).await?;
    Ok(())
}

async fn read_postgres_startup_packet<S>(client: &mut S) -> Result<Vec<u8>, ListenerError>
where
    S: AsyncRead + Unpin,
{
    let mut len_bytes = [0_u8; 4];
    client.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if !(8..=MAX_ROUTING_HANDSHAKE_BYTES).contains(&len) {
        return Err(postgres::PostgresParseError::InvalidLength.into());
    }

    let mut packet = Vec::with_capacity(len);
    packet.extend_from_slice(&len_bytes);
    packet.resize(len, 0);
    client.read_exact(&mut packet[4..]).await?;
    Ok(packet)
}

async fn handle_redis_client(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<(), ListenerError> {
    let (client, endpoint, initial) = client_handshake("redis", async move {
        let mut client = accept_direct_tls(client, tls).await?;
        let (route, initial) = read_redis_initial_frame(&mut client).await?;
        let endpoint = resolver
            .resolve_redis(&route.username)
            .await
            .ok_or(ListenerError::RouteNotFound)?;
        Ok((client, endpoint, initial))
    })
    .await?;

    tunnel::connect_replay_and_tunnel(client, endpoint, &initial).await?;
    Ok(())
}

async fn handle_mariadb_client(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<(), ListenerError> {
    let Some((mut client, mut backend)) =
        client_handshake("mariadb", prepare_mariadb_tunnel(client, resolver, tls)).await?
    else {
        return Ok(());
    };
    io::copy_bidirectional_with_sizes(
        &mut client,
        &mut backend,
        TUNNEL_BUFFER_SIZE,
        TUNNEL_BUFFER_SIZE,
    )
    .await?;
    Ok(())
}

async fn prepare_mariadb_tunnel(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<Option<(GatewayStream, tunnel::BackendStream)>, ListenerError> {
    let mut client = accept_direct_tls(client, tls).await?;
    let gateway_seed = mariadb::new_gateway_auth_seed();
    mariadb::send_gateway_handshake(&mut client, &gateway_seed).await?;
    let client_response =
        mariadb::read_packet_limited(&mut client, MAX_ROUTING_HANDSHAKE_BYTES).await?;
    let route = match mariadb::parse_client_handshake_response(&client_response.payload) {
        Ok(route) => route,
        Err(error) => {
            let error_message = error.to_string();
            mariadb::write_packet(&mut client, 2, &mariadb::error_packet(&error_message)).await?;
            return Err(error.into());
        }
    };

    let Some(target) = resolver
        .resolve_mariadb(&route.username, &route.database)
        .await
    else {
        mariadb::write_packet(
            &mut client,
            2,
            &mariadb::error_packet("Access denied for requested database"),
        )
        .await?;
        return Err(ListenerError::RouteNotFound);
    };
    let Some(native_password_sha1_stage2) = target.native_password_sha1_stage2.as_deref() else {
        let message = mariadb::MariadbProxyError::MissingNativePasswordVerifier.to_string();
        mariadb::write_packet(&mut client, 2, &mariadb::error_packet(&message)).await?;
        return Err(mariadb::MariadbProxyError::MissingNativePasswordVerifier.into());
    };
    tracing::debug!(
        user = %route.username,
        database = %route.database,
        "mariadb route resolved"
    );
    let mut backend = tunnel::connect_backend(&target.endpoint).await?;
    let backend_handshake_packet = mariadb::read_packet(&mut backend).await?;
    let mut backend_handshake =
        mariadb::parse_backend_handshake(&backend_handshake_packet.payload)?;
    let mut auth_payload = match mariadb::backend_handshake_response(
        &backend_handshake,
        &route,
        &gateway_seed,
        native_password_sha1_stage2,
    ) {
        Ok(payload) => payload,
        Err(error) => {
            let message = error.to_string();
            mariadb::write_packet(&mut client, 2, &mariadb::error_packet(&message)).await?;
            return Err(error.into());
        }
    };
    mariadb::write_packet(&mut backend, 1, &auth_payload).await?;

    let mut backend_response = mariadb::read_packet(&mut backend).await?;
    if let Some(switch) = mariadb::auth_switch_request(&backend_response.payload) {
        backend_handshake = switch;
        auth_payload = match mariadb::backend_auth_switch_response(
            &backend_handshake,
            &route,
            &gateway_seed,
            native_password_sha1_stage2,
        ) {
            Ok(payload) => payload,
            Err(error) => {
                let message = error.to_string();
                mariadb::write_packet(&mut client, 2, &mariadb::error_packet(&message)).await?;
                return Err(error.into());
            }
        };
        mariadb::write_packet(
            &mut backend,
            backend_response.sequence.wrapping_add(1),
            &auth_payload,
        )
        .await?;
        backend_response = mariadb::read_packet(&mut backend).await?;
    }

    if mariadb::packet_is_error(&backend_response.payload) {
        mariadb::write_packet(&mut client, 2, &backend_response.payload).await?;
        return Ok(None);
    }
    if !mariadb::packet_is_ok(&backend_response.payload) {
        let message = "unsupported mariadb backend auth response";
        mariadb::write_packet(&mut client, 2, &mariadb::error_packet(message)).await?;
        return Err(mariadb::MariadbProxyError::MalformedPacket.into());
    }

    mariadb::write_packet(&mut client, 2, &mariadb::ok_packet()).await?;
    Ok(Some((client, backend)))
}

async fn handle_mongodb_client(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<(), ListenerError> {
    let (mut client, mut backend) = client_handshake("mongodb", async move {
        let mut client = accept_direct_tls(client, tls).await?;
        for _ in 0..MAX_MONGODB_HELLO_MESSAGES {
            let message =
                mongodb::read_message_limited(&mut client, MAX_ROUTING_HANDSHAKE_BYTES).await?;
            if mongodb::is_hello(&message) {
                mongodb::write_response(&mut client, &message, mongodb::hello_response()).await?;
                continue;
            }

            let route = match mongodb::parse_sasl_start_route(&message) {
                Ok(route) => route,
                Err(error) => {
                    mongodb::write_response(
                        &mut client,
                        &message,
                        mongodb::command_error(&error.to_string(), 18),
                    )
                    .await?;
                    return Err(error.into());
                }
            };

            let Some(endpoint) = resolver
                .resolve_mongodb(&route.username, &route.database)
                .await
            else {
                mongodb::write_response(
                    &mut client,
                    &message,
                    mongodb::command_error("Authentication failed", 18),
                )
                .await?;
                return Err(ListenerError::RouteNotFound);
            };
            let mut backend = tunnel::connect_backend(&endpoint).await?;
            backend.write_all(&message.raw).await?;
            return Ok((client, backend));
        }

        Err(ListenerError::HandshakeMessageLimit {
            protocol: "mongodb",
        })
    })
    .await?;

    io::copy_bidirectional_with_sizes(
        &mut client,
        &mut backend,
        TUNNEL_BUFFER_SIZE,
        TUNNEL_BUFFER_SIZE,
    )
    .await?;
    Ok(())
}

async fn handle_clickhouse_client(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<(), ListenerError> {
    let (client, endpoint, initial) = client_handshake("clickhouse", async move {
        let mut client = accept_direct_tls(client, tls).await?;
        let initial = read_clickhouse_hello(&mut client).await?;
        let route = clickhouse::parse_native_initial_route(&initial)?;
        let endpoint = resolver
            .resolve_clickhouse(&route.username, &route.database)
            .await
            .ok_or(ListenerError::RouteNotFound)?;
        Ok((client, endpoint, initial))
    })
    .await?;

    tunnel::connect_replay_and_tunnel(client, endpoint, &initial).await?;
    Ok(())
}

async fn handle_clickhouse_http_client(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<(), ListenerError> {
    let (client, endpoint, initial) = client_handshake("clickhouse_http", async move {
        let mut client = accept_direct_tls(client, tls).await?;
        let initial = read_http_headers(&mut client).await?;
        let route = clickhouse::parse_http_initial_route(&initial)?;
        let endpoint = resolver
            .resolve_clickhouse(&route.username, &route.database)
            .await
            .ok_or(ListenerError::RouteNotFound)?;
        let endpoint = clickhouse_http_endpoint(endpoint)?;
        Ok((client, endpoint, initial))
    })
    .await?;

    tunnel::connect_replay_and_tunnel(client, endpoint, &initial).await?;
    Ok(())
}

async fn handle_qdrant_client(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<(), ListenerError> {
    let (mut server, mut backend) = client_handshake("qdrant", async move {
        let client = accept_direct_tls(client, tls).await?;
        let mut server = qdrant::server_handshake(client).await?;
        let Some(first_request) = server.accept().await else {
            return Err(qdrant::QdrantProxyError::MissingApiKey.into());
        };
        let (request, respond) = first_request.map_err(qdrant::QdrantProxyError::from)?;
        let api_key = qdrant::api_key_from_request(&request)?;
        let route_key_sha256 = qdrant::route_key_sha256(&api_key);
        let endpoint = resolver
            .resolve_qdrant(&route_key_sha256)
            .await
            .ok_or(ListenerError::RouteNotFound)?;
        let backend_stream = tunnel::connect_backend(&endpoint).await?;
        let mut backend = qdrant::client_handshake(backend_stream).await?;
        qdrant::proxy_request(request, respond, &mut backend).await?;
        Ok((server, backend))
    })
    .await?;

    while let Some(next_request) = server.accept().await {
        let (request, respond) = next_request.map_err(qdrant::QdrantProxyError::from)?;
        qdrant::proxy_request(request, respond, &mut backend).await?;
    }
    Ok(())
}

fn clickhouse_http_endpoint(endpoint: BackendEndpoint) -> Result<BackendEndpoint, ListenerError> {
    match endpoint {
        BackendEndpoint::UnixSocket { socket_path } => {
            let socket_path = crate::shared::backend::clickhouse_http_socket_path(
                std::path::Path::new(&socket_path),
            )
            .ok_or(ListenerError::InvalidClickhouseBackend)?;
            Ok(BackendEndpoint::UnixSocket {
                socket_path: socket_path.display().to_string(),
            })
        }
        BackendEndpoint::DockerTcp { .. } => Err(ListenerError::InvalidClickhouseBackend),
    }
}

async fn read_clickhouse_hello<S>(client: &mut S) -> Result<Vec<u8>, ListenerError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut buffer = Vec::with_capacity(256);
    let mut chunk = [0_u8; 128];
    loop {
        let read = client.read(&mut chunk).await?;
        if read == 0 {
            return Err(clickhouse::ClickhouseParseError::IncompleteNativeHello.into());
        }
        buffer.extend_from_slice(&chunk[..read]);
        match clickhouse::parse_native_initial_route(&buffer) {
            Ok(_) => return Ok(buffer),
            Err(clickhouse::ClickhouseParseError::IncompleteNativeHello) => {}
            Err(error) => return Err(error.into()),
        }
        if buffer.len() > 64 * 1024 {
            return Err(clickhouse::ClickhouseParseError::InvalidNativeHello.into());
        }
    }
}

async fn read_redis_initial_frame<S>(
    client: &mut S,
) -> Result<(redis::RedisRoute, Vec<u8>), ListenerError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut buffer = Vec::with_capacity(256);
    let mut chunk = [0_u8; 256];
    loop {
        let read = client.read(&mut chunk).await?;
        if read == 0 {
            return Err(redis::RedisParseError::Incomplete.into());
        }
        buffer.extend_from_slice(&chunk[..read]);
        match redis::parse_initial_frame_route(&buffer) {
            Ok(Some((route, _))) => return Ok((route, buffer)),
            Ok(None) => {}
            Err(error) => return Err(error.into()),
        }
        if buffer.len() > 64 * 1024 {
            return Err(redis::RedisParseError::Unsupported.into());
        }
    }
}

async fn read_http_headers<S>(client: &mut S) -> Result<Vec<u8>, ListenerError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut buffer = Vec::with_capacity(2048);
    let mut chunk = [0_u8; 1024];
    let mut scan_from = 0;
    loop {
        let read = client.read(&mut chunk).await?;
        if read == 0 {
            return Err(clickhouse::ClickhouseParseError::IncompleteHttpRequest.into());
        }
        let previous_len = buffer.len();
        buffer.extend_from_slice(&chunk[..read]);
        scan_from = scan_from.min(previous_len.saturating_sub(3));
        if buffer[scan_from..]
            .windows(4)
            .any(|window| window == b"\r\n\r\n")
        {
            return Ok(buffer);
        }
        scan_from = buffer.len().saturating_sub(3);
        if buffer.len() > 64 * 1024 {
            return Err(clickhouse::ClickhouseParseError::InvalidHttpRequest.into());
        }
    }
}

async fn accept_direct_tls(
    client: TcpStream,
    tls: Option<TlsAcceptor>,
) -> Result<GatewayStream, std::io::Error> {
    if let Some(tls) = tls {
        Ok(GatewayStream::Tls(Box::new(tls.accept(client).await?)))
    } else {
        Ok(GatewayStream::Plain(client))
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
            clickhouse::ClickhouseParseError::MissingHttpDatabase
        )));
        assert!(!expected_client_failure(&ListenerError::Clickhouse(
            clickhouse::ClickhouseParseError::InvalidNativeHello
        )));
    }

    #[tokio::test]
    async fn postgres_rejects_declared_startup_packet_over_routing_limit() {
        let (mut client, mut gateway) = tokio::io::duplex(16);
        tokio::spawn(async move {
            client
                .write_all(&((MAX_ROUTING_HANDSHAKE_BYTES + 1) as u32).to_be_bytes())
                .await
                .unwrap();
        });

        assert!(matches!(
            read_postgres_startup_packet(&mut gateway).await,
            Err(ListenerError::Postgres(
                postgres::PostgresParseError::InvalidLength
            ))
        ));
    }
}
