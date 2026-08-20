use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::TcpStream,
    task::JoinSet,
};
use tokio_rustls::TlsAcceptor;

use super::*;
use crate::protocols::qdrant;

impl GatewayStream {
    fn alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            Self::Plain(_) => None,
            Self::Tls(stream) => stream.get_ref().1.alpn_protocol(),
        }
    }
}

struct PrefixedGatewayStream {
    prefix: Bytes,
    inner: GatewayStream,
}

impl PrefixedGatewayStream {
    fn new(prefix: [u8; 4], inner: GatewayStream) -> Self {
        Self {
            prefix: Bytes::copy_from_slice(&prefix),
            inner,
        }
    }
}

impl AsyncRead for PrefixedGatewayStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.prefix.has_remaining() && buffer.remaining() > 0 {
            let count = this.prefix.remaining().min(buffer.remaining());
            buffer.put_slice(&this.prefix[..count]);
            this.prefix.advance(count);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for PrefixedGatewayStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

pub(super) async fn handle_qdrant_client(
    client: TcpStream,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
) -> Result<(), ListenerError> {
    let (client, h2) = client_handshake("qdrant", async move {
        let mut client = accept_direct_tls(client, tls).await?;
        let alpn = client.alpn_protocol().map(<[u8]>::to_vec);
        let mut prefix = [0_u8; 4];
        client.read_exact(&mut prefix).await?;
        let h2 = match alpn.as_deref() {
            Some(b"h2") => true,
            Some(b"http/1.1") => false,
            Some(_) => {
                return Err(qdrant::QdrantProxyError::Http(
                    "unsupported TLS ALPN protocol".to_string(),
                )
                .into());
            }
            None => &prefix == b"PRI ",
        };
        Ok((PrefixedGatewayStream::new(prefix, client), h2))
    })
    .await?;

    if h2 {
        handle_qdrant_h2_client(client, resolver).await
    } else {
        handle_qdrant_http1_client(client, resolver).await
    }
}

async fn handle_qdrant_h2_client(
    client: PrefixedGatewayStream,
    resolver: RouteResolver,
) -> Result<(), ListenerError> {
    let request_verifier = resolver.clone();
    let (mut server, backend, first_request, first_respond, route_key_sha256) =
        client_handshake("qdrant", async move {
            let mut server = qdrant::server_handshake(client).await?;
            let Some(first_request) = server.accept().await else {
                return Err(qdrant::QdrantProxyError::MissingApiKey.into());
            };
            let (request, respond) = first_request.map_err(qdrant::QdrantProxyError::from)?;
            let api_key = qdrant::api_key_from_request(&request)?;
            let route_key_sha256 = resolver.qdrant_route_fingerprint(&api_key);
            let target = resolver
                .resolve_qdrant(&route_key_sha256)
                .await
                .ok_or(ListenerError::RouteNotFound)?;
            let backend_stream =
                tunnel::connect_backend(&target.endpoint)
                    .await
                    .map_err(|source| ListenerError::Backend {
                        instance_id: target.instance_id,
                        source,
                    })?;
            let backend_stream = tunnel::MeteredBackend::new(backend_stream, target.network);
            let backend = qdrant::client_handshake(backend_stream).await?;
            Ok((server, backend, request, respond, route_key_sha256))
        })
        .await?;

    let mut requests = JoinSet::new();
    spawn_qdrant_request(&mut requests, first_request, first_respond, &backend);

    loop {
        tokio::select! {
            next_request = server.accept() => {
                let Some(next_request) = next_request else {
                    requests.abort_all();
                    while requests.join_next().await.is_some() {}
                    return Ok(());
                };
                let (request, mut respond) = match next_request {
                    Ok(request) => request,
                    Err(error) => {
                        let error = qdrant::QdrantProxyError::from(error);
                        if error.is_stream_local() {
                            tracing::debug!(
                                event = "qdrant_rpc_stream_reset_before_dispatch",
                                %error,
                                "qdrant rpc stream reset without closing the multiplexed connection"
                            );
                            continue;
                        }
                        return Err(error.into());
                    }
                };
                if !request_matches_qdrant_route(&request, &route_key_sha256, &request_verifier) {
                    let response = http::Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .version(http::Version::HTTP_2)
                        .body(())
                        .expect("static qdrant h2 authentication response is valid");
                    respond
                        .send_response(response, true)
                        .map_err(qdrant::QdrantProxyError::from)?;
                    continue;
                }
                spawn_qdrant_request(&mut requests, request, respond, &backend);
            }
            completed = requests.join_next(), if !requests.is_empty() => {
                let Some(completed) = completed else {
                    continue;
                };
                let (stream_id, result) = completed
                    .map_err(|error| IoError::other(format!(
                        "qdrant proxy request task failed: {error}"
                    )))?;
                handle_qdrant_stream_result(Some(stream_id), result)?;
            }
        }
    }
}

fn request_matches_qdrant_route<B>(
    request: &http::Request<B>,
    route_key_sha256: &str,
    resolver: &RouteResolver,
) -> bool {
    qdrant::api_key_from_request(request)
        .map(|api_key| resolver.qdrant_route_fingerprint(&api_key) == route_key_sha256)
        .unwrap_or(false)
}

type QdrantHttpError = Box<dyn std::error::Error + Send + Sync>;
type QdrantHttpBody = BoxBody<Bytes, QdrantHttpError>;

async fn handle_qdrant_http1_client(
    client: PrefixedGatewayStream,
    resolver: RouteResolver,
) -> Result<(), ListenerError> {
    let service = service_fn(move |request| {
        let resolver = resolver.clone();
        async move { proxy_qdrant_http1_request(request, resolver).await }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(CLIENT_HANDSHAKE_TIMEOUT)
        .max_buf_size(MAX_ROUTING_HANDSHAKE_BYTES)
        .keep_alive(true);
    builder
        .serve_connection(TokioIo::new(client), service)
        .await
        .map_err(|error| qdrant::QdrantProxyError::Http(error.to_string()))?;
    Ok(())
}

async fn proxy_qdrant_http1_request(
    mut request: http::Request<Incoming>,
    resolver: RouteResolver,
) -> Result<http::Response<QdrantHttpBody>, Infallible> {
    let api_key = match qdrant::api_key_from_request(&request) {
        Ok(api_key) => api_key,
        Err(_) => {
            return Ok(qdrant_http_error(
                http::StatusCode::UNAUTHORIZED,
                "missing or invalid api-key",
            ));
        }
    };
    let route_key_sha256 = resolver.qdrant_route_fingerprint(&api_key);
    let Some(target) = resolver.resolve_qdrant(&route_key_sha256).await else {
        return Ok(qdrant_http_error(
            http::StatusCode::UNAUTHORIZED,
            "authentication failed",
        ));
    };
    let endpoint = match qdrant_http_endpoint(target.endpoint) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            tracing::error!(
                instance_id = %target.instance_id,
                %error,
                "qdrant REST route has no valid private HTTP socket"
            );
            return Ok(qdrant_http_error(
                http::StatusCode::BAD_GATEWAY,
                "qdrant backend is unavailable",
            ));
        }
    };
    let backend = match tunnel::connect_backend(&endpoint).await {
        Ok(backend) => backend,
        Err(error) => {
            tracing::warn!(
                instance_id = %target.instance_id,
                %error,
                "qdrant REST backend connection failed"
            );
            return Ok(qdrant_http_error(
                http::StatusCode::BAD_GATEWAY,
                "qdrant backend is unavailable",
            ));
        }
    };
    let backend = tunnel::MeteredBackend::new(backend, target.network);
    let (mut sender, connection) =
        match hyper::client::conn::http1::handshake(TokioIo::new(backend)).await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!(
                    instance_id = %target.instance_id,
                    %error,
                    "qdrant REST backend HTTP handshake failed"
                );
                return Ok(qdrant_http_error(
                    http::StatusCode::BAD_GATEWAY,
                    "qdrant backend is unavailable",
                ));
            }
        };
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "qdrant REST backend connection stopped");
        }
    });

    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/")
        .parse::<http::Uri>()
        .unwrap_or_else(|_| http::Uri::from_static("/"));
    *request.uri_mut() = path;
    remove_hop_by_hop_headers(request.headers_mut());
    match sender.send_request(request).await {
        Ok(response) => {
            let (mut parts, body) = response.into_parts();
            remove_hop_by_hop_headers(&mut parts.headers);
            Ok(http::Response::from_parts(
                parts,
                body.map_err(|error| -> QdrantHttpError { Box::new(error) })
                    .boxed(),
            ))
        }
        Err(error) => {
            tracing::warn!(
                instance_id = %target.instance_id,
                %error,
                "qdrant REST request failed"
            );
            Ok(qdrant_http_error(
                http::StatusCode::BAD_GATEWAY,
                "qdrant backend request failed",
            ))
        }
    }
}

fn remove_hop_by_hop_headers(headers: &mut http::HeaderMap) {
    let nominated = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| http::HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect::<Vec<_>>();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        http::header::CONNECTION,
        http::header::PROXY_AUTHENTICATE,
        http::header::PROXY_AUTHORIZATION,
        http::header::TE,
        http::header::TRAILER,
        http::header::TRANSFER_ENCODING,
        http::header::UPGRADE,
    ] {
        headers.remove(name);
    }
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
}

fn qdrant_http_error(
    status: http::StatusCode,
    message: &'static str,
) -> http::Response<QdrantHttpBody> {
    let body = Full::new(Bytes::from_static(message.as_bytes()))
        .map_err(|never| -> QdrantHttpError { match never {} })
        .boxed();
    http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body)
        .expect("static qdrant HTTP error response is valid")
}

fn handle_qdrant_stream_result(
    stream_id: Option<h2::StreamId>,
    result: Result<(), qdrant::QdrantProxyError>,
) -> Result<(), ListenerError> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.is_stream_local() => {
            tracing::debug!(
                event = "qdrant_rpc_stream_reset",
                stream_id = ?stream_id,
                %error,
                "qdrant rpc stream ended without closing the multiplexed connection"
            );
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn spawn_qdrant_request(
    requests: &mut JoinSet<(h2::StreamId, Result<(), qdrant::QdrantProxyError>)>,
    request: http::Request<h2::RecvStream>,
    respond: h2::server::SendResponse<bytes::Bytes>,
    backend: &h2::client::SendRequest<bytes::Bytes>,
) {
    let stream_id = request.body().stream_id();
    let mut backend = backend.clone();
    requests.spawn(async move {
        (
            stream_id,
            qdrant::proxy_request(request, respond, &mut backend).await,
        )
    });
}

fn qdrant_http_endpoint(endpoint: BackendEndpoint) -> Result<BackendEndpoint, ListenerError> {
    match endpoint {
        BackendEndpoint::UnixSocket { socket_path } => {
            let socket_path =
                crate::shared::backend::qdrant_http_socket_path(std::path::Path::new(&socket_path))
                    .ok_or(ListenerError::InvalidQdrantBackend)?;
            Ok(BackendEndpoint::UnixSocket {
                socket_path: socket_path.display().to_string(),
            })
        }
        BackendEndpoint::DockerTcp { .. } => Err(ListenerError::InvalidQdrantBackend),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::resources::ResourceCache,
        instances::{
            metadata::{
                DatabaseIdentity, DesiredInstanceState, InstanceStatus, PublicEndpoint,
                RuntimeKind, RuntimeMetadata, SCHEMA_VERSION,
            },
            state::InstanceStore,
        },
        shared::{limits::InstanceLimits, protocol::Protocol},
    };

    #[test]
    fn stream_local_failures_do_not_close_the_multiplexed_connection() {
        assert!(
            handle_qdrant_stream_result(
                None,
                Err(qdrant::QdrantProxyError::InactivityTimeout { timeout_secs: 60 }),
            )
            .is_ok()
        );
        assert!(
            handle_qdrant_stream_result(None, Err(qdrant::QdrantProxyError::OutboundStreamClosed),)
                .is_ok()
        );
        assert!(
            handle_qdrant_stream_result(
                None,
                Err(qdrant::QdrantProxyError::StreamReset {
                    reason: h2::Reason::CANCEL,
                }),
            )
            .is_ok()
        );
        assert!(matches!(
            handle_qdrant_stream_result(None, Err(qdrant::QdrantProxyError::MissingApiKey)),
            Err(ListenerError::Qdrant(
                qdrant::QdrantProxyError::MissingApiKey
            ))
        ));
    }

    #[test]
    fn removes_every_http1_hop_by_hop_header() {
        let mut headers = http::HeaderMap::new();
        for name in [
            "connection",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "keep-alive",
            "proxy-connection",
        ] {
            headers.insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                http::HeaderValue::from_static("x"),
            );
        }
        headers.insert("api-key", http::HeaderValue::from_static("secret"));
        headers.insert("x-hop", http::HeaderValue::from_static("remove-me"));
        headers.insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("keep-alive, x-hop"),
        );
        remove_hop_by_hop_headers(&mut headers);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers.get("api-key").unwrap(), "secret");
    }

    #[test]
    fn every_h2_stream_must_repeat_the_same_route_key() {
        let resolver = RouteResolver::new(
            InstanceStore::default(),
            ResourceCache::default(),
            test_qdrant_route_key(),
        );
        let route = resolver.qdrant_route_fingerprint("secret");
        let valid = http::Request::builder()
            .header("api-key", "secret")
            .body(())
            .unwrap();
        let wrong = http::Request::builder()
            .header("api-key", "other")
            .body(())
            .unwrap();
        let missing = http::Request::new(());
        assert!(request_matches_qdrant_route(&valid, &route, &resolver));
        assert!(!request_matches_qdrant_route(&wrong, &route, &resolver));
        assert!(!request_matches_qdrant_route(&missing, &route, &resolver));
    }

    #[tokio::test]
    async fn rest_authentication_is_checked_on_every_keepalive_request() {
        let directory = tempfile::tempdir().unwrap();
        let grpc_socket = directory.path().join("qdrant-grpc.sock");
        let http_socket = directory.path().join("qdrant-http.sock");
        let backend_listener = tokio::net::UnixListener::bind(&http_socket).unwrap();
        let backend = tokio::spawn(async move {
            let (stream, _) = backend_listener.accept().await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(|request: http::Request<Incoming>| async move {
                        assert_eq!(request.headers().get("api-key").unwrap(), "secret");
                        Ok::<_, Infallible>(http::Response::new(Full::new(Bytes::from_static(
                            b"backend-ok",
                        ))))
                    }),
                )
                .await
                .unwrap();
        });

        let store = InstanceStore::default();
        store.upsert(qdrant_metadata(&grpc_socket)).await;
        let resolver = RouteResolver::new(store, ResourceCache::default(), test_qdrant_route_key());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let gateway = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_qdrant_client(stream, resolver, None).await.unwrap();
        });

        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let (mut client, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        let client_driver = tokio::spawn(connection);
        let response = client
            .send_request(
                http::Request::builder()
                    .uri("/collections")
                    .header("api-key", "secret")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            Bytes::from_static(b"backend-ok")
        );

        let rejected = client
            .send_request(
                http::Request::builder()
                    .uri("/collections")
                    .header("api-key", "wrong")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), http::StatusCode::UNAUTHORIZED);
        drop(client);
        client_driver.await.unwrap().unwrap();
        gateway.await.unwrap();
        backend.await.unwrap();
    }

    fn qdrant_metadata(
        grpc_socket: &std::path::Path,
    ) -> crate::instances::metadata::InstanceMetadata {
        crate::instances::metadata::InstanceMetadata {
            schema_version: SCHEMA_VERSION,
            instance_id: "inst_qdrant_rest".to_string(),
            protocol: Protocol::Qdrant,
            status: InstanceStatus::Running,
            desired_state: DesiredInstanceState::Running,
            disk_limit_blocked: false,
            public: PublicEndpoint {
                host: "db.example.test".to_string(),
                port: 6334,
            },
            backend: BackendEndpoint::UnixSocket {
                socket_path: grpc_socket.display().to_string(),
            },
            runtime: RuntimeMetadata {
                kind: RuntimeKind::Docker,
                container_name: "dbe-qdrant-inst_qdrant_rest".to_string(),
                network_mode: "none".to_string(),
            },
            database: DatabaseIdentity {
                name: "qdrant".to_string(),
                username: "tenant".to_string(),
            },
            route_key_sha256: Some(test_qdrant_route_key().fingerprint("secret")),
            mariadb_native_password_sha1_stage2: None,
            mariadb_root_password: None,
            mysql_native_password_sha1_stage2: None,
            mysql_root_password: None,
            mongodb_root_password: None,
            postgres_admin_password: None,
            tenant_password: Some("secret".to_string()),
            limits: InstanceLimits::default(),
            image: None,
            database_version: None,
            created_at: "2026-08-19T00:00:00Z".to_string(),
            updated_at: "2026-08-19T00:00:00Z".to_string(),
        }
    }

    fn test_qdrant_route_key() -> qdrant::QdrantRouteKey {
        qdrant::QdrantRouteKey::new(b"test-qdrant-route-key")
    }
}
