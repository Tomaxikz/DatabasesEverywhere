use std::{convert::Infallible, time::Duration};

use axum::body::Body;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{Response, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixListener},
};

use super::*;
use crate::{
    databases::protocol::Protocol,
    gateway::protocols::qdrant::QdrantRouteKey,
    gateway::sessions::TenantSessions,
    server::placement::DeploymentMode,
    server::{state::InstanceStore, test_support::metadata},
    subsystems::monitoring::resources::ResourceCache,
    utils::backend::clickhouse_http_socket_path,
};

fn resolver(store: InstanceStore) -> RouteResolver {
    RouteResolver::new(
        store,
        ResourceCache::default(),
        QdrantRouteKey::new(b"http-test"),
        TenantSessions::default(),
    )
}

#[tokio::test]
async fn http_streams_split_chunked_uploads_and_rejects_wrong_tenant_routes() -> anyhow::Result<()>
{
    use anyhow::Context as _;

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let root = tempfile::tempdir()?;
    let native = root.path().join("native.sock");
    let backend = UnixListener::bind(
        clickhouse_http_socket_path(&native)
            .context("expected a value from clickhouse_http_socket_path")?,
    )?;
    let store = InstanceStore::default();
    for suffix in ["a", "b"] {
        let mut instance = metadata(&format!("http-{suffix}"), Protocol::Clickhouse);
        instance.deployment_mode = DeploymentMode::Shared;
        instance.runtime_id = "http-pool".into();
        instance.database.name = format!("db_{suffix}");
        instance.database.username = format!("user_{suffix}");
        instance.backend = BackendEndpoint::UnixSocket {
            socket_path: native.display().to_string(),
        };
        store.upsert(instance).await;
    }
    let backend_task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                socket = backend.accept() => {
                    let (socket, _) = socket.expect("http streams split chunked uploads and rejects wrong tenant routes should succeed");
                    connections.spawn(async move {
                        let service = service_fn(|request: hyper::Request<hyper::body::Incoming>| async move {
                            let user = request.headers()["X-ClickHouse-User"].to_str().expect("to str should succeed").to_string();
                            let database = request.headers()["X-ClickHouse-Database"].to_str().expect("to str should succeed").to_string();
                            assert_eq!(database, user.replace("user_", "db_"));
                            assert!(request.uri().query().expect("query should provide a value").contains(&format!("database={database}")));
                            assert_eq!(request.headers()["Connection"], "close");
                            // Use an independent HTTP parser and wait for the body,
                            // as a real SQL-over-HTTP server is allowed to do.
                            let body = request.into_body().collect().await.expect("collect should succeed").to_bytes();
                            Ok::<_, Infallible>(Response::new(Body::from(body)))
                        });
                        let _ = http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });
    let gateway = TcpListener::bind("127.0.0.1:0").await?;
    let address = gateway.local_addr()?;
    let routes = resolver(store.clone());
    let gateway_task = tokio::spawn(async move {
        let mut clients = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                socket = gateway.accept() => {
                    let (socket, _) = socket.expect("http streams split chunked uploads and rejects wrong tenant routes should succeed");
                    let routes = routes.clone();
                    clients.spawn(async move { handle_clickhouse_http(socket.into(), routes, None).await });
                }
                _ = clients.join_next(), if !clients.is_empty() => {}
            }
        }
    });
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let client = reqwest::Client::builder().no_proxy().build().expect("build should succeed");
        for suffix in ["a", "b"] {
            for chunked in [false, true] {
                let expected = "x".repeat(192 * 1024);
                let request = client.post(format!("http://{address}/?database=db_{suffix}"))
                    .header("X-ClickHouse-User", format!("user_{suffix}"))
                    .header("X-ClickHouse-Key", "test-only-password");
                let request = if chunked {
                    let chunks = futures::stream::unfold(0, |index| async move {
                        if index == 3 { return None; }
                        tokio::time::sleep(Duration::from_millis(15)).await;
                        Some((Ok::<_, Infallible>(Bytes::from(vec![b'x'; 64 * 1024])), index+1))
                    });
                    request.body(reqwest::Body::wrap_stream(chunks))
                } else {
                    request.body(expected.clone())
                };
                let response = request.send().await.expect("send should succeed");
                assert_eq!(response.status(), 200);
                assert_eq!(response.text().await.expect("text should succeed"), expected);
            }
            let peer = if suffix == "a" { "b" } else { "a" };
            let response = client.post(format!("http://{address}/?database=db_{peer}"))
                .header("X-ClickHouse-User", format!("user_{suffix}"))
                .body("SELECT 1").send().await.expect("send should succeed");
            assert_eq!(response.status(), 403);
            assert_eq!(response.text().await.expect("text should succeed"), "Access denied.\n");
        }
        // Explicitly split known-length headers/body across separate writes.
        let mut socket = TcpStream::connect(address).await.expect("connect should succeed");
        socket.write_all(b"POST /?database=db_a HTTP/1.1\r\nHost: localhost\r\nX-ClickHouse-User: user_a\r\nContent-Length: 8\r\n\r\n").await.expect("write all should succeed");
        tokio::time::sleep(Duration::from_millis(25)).await;
        socket.write_all(b"SELECT 1").await.expect("write all should succeed");
        let mut response = String::new();
        socket.read_to_string(&mut response).await.expect("read to string should succeed");
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.ends_with("SELECT 1"));
        store.fence_routes("http-a").await;
        let response = client.post(format!("http://{address}/?database=db_a"))
            .header("X-ClickHouse-User", "user_a").body("SELECT 1").send().await.expect("send should succeed");
        assert_eq!(response.status(), 403);
    }).await;
    gateway_task.abort();
    backend_task.abort();
    let _ = gateway_task.await;
    let _ = backend_task.await;
    result?;

    Ok(())
}

#[tokio::test]
async fn native_route_denials_use_database_errors_instead_of_connection_resets()
-> anyhow::Result<()> {
    for protocol in [Protocol::Clickhouse, Protocol::Postgres] {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept should succeed");
            let routes = resolver(InstanceStore::default());
            match protocol {
                Protocol::Clickhouse => handle_clickhouse_client(socket.into(), routes, None).await,
                Protocol::Postgres => {
                    super::super::postgres_listener::handle_postgres_client(
                        socket.into(),
                        routes,
                        None,
                    )
                    .await
                }
                _ => unreachable!(),
            }
        });
        let mut socket = TcpStream::connect(address).await?;
        let packet = if protocol == Protocol::Clickhouse {
            // Client Hello: empty client name, version 26.4/revision 0,
            // database, user, and an empty password. All strings are <128 bytes.
            b"\x00\x00\x1a\x04\x00\x07missing\x07missing\x00".to_vec()
        } else {
            let fields = b"\x00\x03\x00\x00user\x00missing\x00database\x00missing\x00\x00";
            let mut packet = (fields.len() as u32 + 4).to_be_bytes().to_vec();
            packet.extend_from_slice(fields);
            packet
        };
        socket.write_all(&packet).await?;
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut response)).await??;
        if protocol == Protocol::Clickhouse {
            assert_eq!(response[0], 2);
            assert_eq!(i32::from_le_bytes(response[1..5].try_into()?), 516);
            assert!(response.windows(13).any(|part| part == b"DB::Exception"));
        } else {
            assert_eq!(response[0], b'E');
            assert_eq!(
                u32::from_be_bytes(response[1..5].try_into()?) as usize,
                response.len() - 1
            );
            assert!(response.windows(7).any(|part| part == b"C28000\0"));
        }
        assert!(!response.windows(7).any(|part| part == b"missing"));
        assert!(matches!(server.await?, Err(ListenerError::RouteNotFound)));
    }

    Ok(())
}
