use bson::{Binary, Bson, Document, doc, spec::BinarySubtype};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixListener},
};

use super::*;
use crate::{
    databases::protocol::Protocol,
    gateway::sessions::TenantSessions,
    server::placement::DeploymentMode,
    server::{
        metadata::{InstanceImageStatus, InstanceMetadata},
        state::InstanceStore,
        test_support,
    },
    subsystems::monitoring::resources::{NetworkCounter, ResourceCache},
    utils::backend::BackendEndpoint,
};

#[tokio::test]
async fn normal_sasl_runs_backend_hello_and_opens_accounting_after_auth() {
    run_successful_auth(false).await;
}

#[tokio::test]
async fn speculative_sasl_relays_nested_reply_before_opening_accounting() {
    run_successful_auth(true).await;
}

#[tokio::test]
async fn omitted_speculative_reply_falls_back_without_early_accounting() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let socket = directory.path().join("mongodb.sock");
    let backend_listener = UnixListener::bind(&socket)?;
    let (resolver, sessions, network) = resolver(&socket).await;
    let (mut client, gateway) = tcp_pair().await;
    let handler = tokio::spawn(handle_mongodb_client(gateway.into(), resolver, None));

    send_command(&mut client, speculative_hello()).await;
    let backend = tokio::spawn(async move {
        let (mut backend, _) = backend_listener
            .accept()
            .await
            .expect("accept should succeed");
        let hello = read_message(&mut backend).await;
        mongodb::write_response(
            &mut backend,
            &hello,
            doc! { "ok": 1.0, "maxWireVersion": 25_i32 },
        )
        .await
        .expect("write response should succeed");
        let start = read_message(&mut backend).await;
        assert_eq!(mongodb::command_name(&start).as_deref(), Some("saslStart"));
        mongodb::write_response(
            &mut backend,
            &start,
            doc! {
                "ok": 1.0,
                "conversationId": 9_i32,
                "payload": empty_payload(),
                "done": true,
            },
        )
        .await
        .expect("empty payload should succeed");
        backend.shutdown().await.expect("shutdown should succeed");
    });

    let hello = read_message(&mut client).await;
    assert_eq!(
        mongodb::auth_reply_state(&hello, true)?,
        mongodb::AuthReplyState::SpeculativeFallback
    );
    assert_eq!(sessions.active("tenant-mongo"), 0);
    assert_eq!(network.snapshot(), (0, 0));
    send_command(&mut client, sasl_start()).await;
    let accepted = read_message(&mut client).await;
    assert_eq!(
        mongodb::auth_reply_state(&accepted, false)?,
        mongodb::AuthReplyState::Authenticated
    );
    assert_eq!(sessions.active("tenant-mongo"), 1);
    client.shutdown().await?;
    backend.await?;
    handler.await??;
    assert_eq!(sessions.active("tenant-mongo"), 0);

    Ok(())
}

#[tokio::test]
async fn failed_sasl_never_opens_a_session_or_network_meter() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let directory = tempfile::tempdir()?;
    let socket = directory.path().join("mongodb.sock");
    let backend_listener = UnixListener::bind(&socket)?;
    let (resolver, sessions, network) = resolver(&socket).await;
    let (mut client, gateway) = tcp_pair().await;
    let handler = tokio::spawn(handle_mongodb_client(gateway.into(), resolver, None));

    send_plain_hello(&mut client).await;
    read_message(&mut client).await;
    send_command(&mut client, sasl_start()).await;

    let backend = tokio::spawn(async move {
        let (mut backend, _) = backend_listener
            .accept()
            .await
            .expect("accept should succeed");
        let hello = read_message(&mut backend).await;
        mongodb::write_response(
            &mut backend,
            &hello,
            doc! { "ok": 1.0, "maxWireVersion": 25_i32 },
        )
        .await
        .expect("write response should succeed");
        let auth = read_message(&mut backend).await;
        mongodb::write_response(
            &mut backend,
            &auth,
            doc! { "ok": 0.0, "errmsg": "Authentication failed", "code": 18_i32 },
        )
        .await
        .expect("write response should succeed");
    });

    let rejected = read_message(&mut client).await;
    assert_eq!(
        rejected
            .body
            .context("failed sasl never opens a session or network meter should provide a value")?
            .get_f64("ok")?,
        0.0
    );
    backend.await?;
    handler.await??;
    assert_eq!(sessions.active("tenant-mongo"), 0);
    assert_eq!(network.snapshot(), (0, 0));

    Ok(())
}

async fn run_successful_auth(speculative: bool) {
    let directory = tempfile::tempdir().expect("tempdir should succeed");
    let socket = directory.path().join("mongodb.sock");
    let backend_listener = UnixListener::bind(&socket).expect("bind should succeed");
    let (resolver, sessions, network) = resolver(&socket).await;
    let (mut client, gateway) = tcp_pair().await;
    let handler = tokio::spawn(handle_mongodb_client(gateway.into(), resolver, None));

    if speculative {
        send_command(&mut client, speculative_hello()).await;
    } else {
        send_plain_hello(&mut client).await;
        let hello = read_message(&mut client).await;
        assert!(
            hello
                .body
                .expect("run successful auth should provide a value")
                .contains_key("saslSupportedMechs")
        );
        send_command(&mut client, sasl_start()).await;
    }

    let backend = tokio::spawn(async move {
        let (mut backend, _) = backend_listener
            .accept()
            .await
            .expect("accept should succeed");
        if speculative {
            let hello = read_message(&mut backend).await;
            assert!(mongodb::is_hello(&hello));
            mongodb::write_response(
                &mut backend,
                &hello,
                doc! {
                        "ok": 1.0,
                        "maxWireVersion": 25_i32,
                        "compression": ["zlib"],
                        "speculativeAuthenticate": {
                        "conversationId": 9_i32,
                        "payload": empty_payload(),
                        "done": false,
                    },
                },
            )
            .await
            .expect("empty payload should succeed");
        } else {
            let hello = read_message(&mut backend).await;
            assert!(mongodb::is_hello(&hello));
            mongodb::write_response(
                &mut backend,
                &hello,
                doc! { "ok": 1.0, "maxWireVersion": 25_i32 },
            )
            .await
            .expect("write response should succeed");
            let start = read_message(&mut backend).await;
            assert_eq!(mongodb::command_name(&start).as_deref(), Some("saslStart"));
            mongodb::write_response(
                &mut backend,
                &start,
                doc! {
                    "ok": 1.0,
                    "conversationId": 9_i32,
                    "payload": empty_payload(),
                    "done": false,
                },
            )
            .await
            .expect("empty payload should succeed");
        }

        let continued = read_message(&mut backend).await;
        assert_eq!(
            mongodb::command_name(&continued).as_deref(),
            Some("saslContinue")
        );
        mongodb::write_response(
            &mut backend,
            &continued,
            doc! {
                "ok": 1.0,
                "conversationId": 9_i32,
                "payload": empty_payload(),
                "done": true,
            },
        )
        .await
        .expect("empty payload should succeed");

        let ping = read_message(&mut backend).await;
        assert_eq!(mongodb::command_name(&ping).as_deref(), Some("ping"));
        mongodb::write_response(&mut backend, &ping, doc! { "ok": 1.0 })
            .await
            .expect("write response should succeed");
        backend.shutdown().await.expect("shutdown should succeed");
    });

    let challenge = read_message(&mut client).await;
    if speculative {
        assert_eq!(
            challenge
                .body
                .as_ref()
                .expect("run successful auth should provide a value")
                .get_array("compression")
                .expect("get array should succeed")
                .len(),
            0,
            "DBE must not negotiate a compressed mode its identity fence rejects"
        );
    }
    let state = mongodb::auth_reply_state(&challenge, speculative)
        .expect("auth reply state should succeed");
    assert_eq!(state, mongodb::AuthReplyState::Continue);
    send_command(&mut client, sasl_continue()).await;
    let accepted = read_message(&mut client).await;
    assert_eq!(
        mongodb::auth_reply_state(&accepted, false).expect("auth reply state should succeed"),
        mongodb::AuthReplyState::Authenticated
    );
    assert_eq!(sessions.active("tenant-mongo"), 1);

    send_command(&mut client, doc! { "ping": 1_i32, "$db": "tenant_db" }).await;
    assert_eq!(
        read_message(&mut client)
            .await
            .body
            .expect("read message should provide a value")
            .get_f64("ok")
            .expect("get f64 should succeed"),
        1.0
    );
    client.shutdown().await.expect("shutdown should succeed");
    backend.await.expect("run successful auth should succeed");
    handler
        .await
        .expect("run successful auth should succeed")
        .expect("run successful auth should succeed");
    assert_eq!(sessions.active("tenant-mongo"), 0);
    let (rx, tx) = network.snapshot();
    assert!(rx > 0 && tx > 0);
}

async fn resolver(socket: &std::path::Path) -> (RouteResolver, TenantSessions, NetworkCounter) {
    let store = InstanceStore::default();
    store.upsert(metadata(socket)).await;
    let resources = ResourceCache::default();
    let network = resources.network_counter("tenant-mongo").await;
    let sessions = TenantSessions::default();
    (
        RouteResolver::new(
            store,
            resources,
            crate::gateway::protocols::qdrant::QdrantRouteKey::new(b"mongo-wire-test"),
            sessions.clone(),
        ),
        sessions,
        network,
    )
}

fn metadata(socket: &std::path::Path) -> InstanceMetadata {
    let mut metadata = test_support::metadata("tenant-mongo", Protocol::Mongodb);
    metadata.deployment_mode = DeploymentMode::Shared;
    metadata.runtime_id = "pool-mongo".to_string();
    metadata.backend = BackendEndpoint::UnixSocket {
        socket_path: socket.display().to_string(),
    };
    metadata.runtime.container_name = "pool-mongo".to_string();
    metadata.database.name = "tenant_db".to_string();
    metadata.database.username = "tenant_user".to_string();
    metadata.image = Some(InstanceImageStatus {
        current: Some("mongo:8".to_string()),
        configured: "mongo:8".to_string(),
        update_available: false,
    });
    metadata
}

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind should succeed");
    let address = listener.local_addr().expect("local addr should succeed");
    let connect = tokio::spawn(TcpStream::connect(address));
    let (gateway, _) = listener.accept().await.expect("accept should succeed");
    (
        connect
            .await
            .expect("tcp pair should succeed")
            .expect("tcp pair should succeed"),
        gateway,
    )
}

async fn send_plain_hello(client: &mut TcpStream) {
    send_command(
        client,
        doc! {
            "hello": 1_i32,
            "helloOk": true,
            "saslSupportedMechs": "tenant_db.tenant_user",
            "$db": "admin",
        },
    )
    .await;
}

async fn send_command(stream: &mut (impl AsyncWrite + Unpin), body: Document) {
    stream
        .write_all(&mongodb::encode_command(body).expect("encode command should succeed"))
        .await
        .expect("encode command should succeed");
}

async fn read_message(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> mongodb::MongoMessage {
    mongodb::read_message(stream)
        .await
        .expect("read message should succeed")
}

fn speculative_hello() -> Document {
    doc! {
        "hello": 1_i32,
        "helloOk": true,
        "saslSupportedMechs": "admin.ignored_capability_hint",
        "speculativeAuthenticate": {
            "saslStart": 1_i32,
            "mechanism": "SCRAM-SHA-256",
            "payload": scram_start_payload(),
            "db": "tenant_db",
        },
        "$db": "admin",
    }
}

fn sasl_start() -> Document {
    doc! {
        "saslStart": 1_i32,
        "mechanism": "SCRAM-SHA-256",
        "payload": scram_start_payload(),
        "$db": "tenant_db",
    }
}

fn sasl_continue() -> Document {
    doc! {
        "saslContinue": 1_i32,
        "conversationId": 9_i32,
        "payload": empty_payload(),
        "$db": "tenant_db",
    }
}

fn scram_start_payload() -> Bson {
    Bson::Binary(Binary {
        subtype: BinarySubtype::Generic,
        bytes: b"n,,n=tenant_user,r=nonce".to_vec(),
    })
}

fn empty_payload() -> Bson {
    Bson::Binary(Binary {
        subtype: BinarySubtype::Generic,
        bytes: Vec::new(),
    })
}
