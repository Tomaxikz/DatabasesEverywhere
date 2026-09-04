use bson::{Binary, Bson, Document, doc, spec::BinarySubtype};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixListener},
};

use super::*;
use crate::{
    api::monitoring::resources::{NetworkCounter, ResourceCache},
    gateway::sessions::TenantSessions,
    instances::{
        metadata::{InstanceImageStatus, InstanceMetadata},
        state::InstanceStore,
        test_support,
    },
    placement::DeploymentMode,
    shared::{backend::BackendEndpoint, protocol::Protocol},
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
async fn omitted_speculative_reply_falls_back_without_early_accounting() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("mongodb.sock");
    let backend_listener = UnixListener::bind(&socket).unwrap();
    let (resolver, sessions, network) = resolver(&socket).await;
    let (mut client, gateway) = tcp_pair().await;
    let handler = tokio::spawn(handle_mongodb_client(gateway, resolver, None));

    send_command(&mut client, speculative_hello()).await;
    let backend = tokio::spawn(async move {
        let (mut backend, _) = backend_listener.accept().await.unwrap();
        let hello = read_message(&mut backend).await;
        mongodb::write_response(
            &mut backend,
            &hello,
            doc! { "ok": 1.0, "maxWireVersion": 25_i32 },
        )
        .await
        .unwrap();
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
        .unwrap();
        backend.shutdown().await.unwrap();
    });

    let hello = read_message(&mut client).await;
    assert_eq!(
        mongodb::auth_reply_state(&hello, true).unwrap(),
        mongodb::AuthReplyState::SpeculativeFallback
    );
    assert_eq!(sessions.active("tenant-mongo"), 0);
    assert_eq!(network.snapshot(), (0, 0));
    send_command(&mut client, sasl_start()).await;
    let accepted = read_message(&mut client).await;
    assert_eq!(
        mongodb::auth_reply_state(&accepted, false).unwrap(),
        mongodb::AuthReplyState::Authenticated
    );
    assert_eq!(sessions.active("tenant-mongo"), 1);
    client.shutdown().await.unwrap();
    backend.await.unwrap();
    handler.await.unwrap().unwrap();
    assert_eq!(sessions.active("tenant-mongo"), 0);
}

#[tokio::test]
async fn failed_sasl_never_opens_a_session_or_network_meter() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("mongodb.sock");
    let backend_listener = UnixListener::bind(&socket).unwrap();
    let (resolver, sessions, network) = resolver(&socket).await;
    let (mut client, gateway) = tcp_pair().await;
    let handler = tokio::spawn(handle_mongodb_client(gateway, resolver, None));

    send_plain_hello(&mut client).await;
    read_message(&mut client).await;
    send_command(&mut client, sasl_start()).await;

    let backend = tokio::spawn(async move {
        let (mut backend, _) = backend_listener.accept().await.unwrap();
        let hello = read_message(&mut backend).await;
        mongodb::write_response(
            &mut backend,
            &hello,
            doc! { "ok": 1.0, "maxWireVersion": 25_i32 },
        )
        .await
        .unwrap();
        let auth = read_message(&mut backend).await;
        mongodb::write_response(
            &mut backend,
            &auth,
            doc! { "ok": 0.0, "errmsg": "Authentication failed", "code": 18_i32 },
        )
        .await
        .unwrap();
    });

    let rejected = read_message(&mut client).await;
    assert_eq!(rejected.body.unwrap().get_f64("ok").unwrap(), 0.0);
    backend.await.unwrap();
    handler.await.unwrap().unwrap();
    assert_eq!(sessions.active("tenant-mongo"), 0);
    assert_eq!(network.snapshot(), (0, 0));
}

async fn run_successful_auth(speculative: bool) {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("mongodb.sock");
    let backend_listener = UnixListener::bind(&socket).unwrap();
    let (resolver, sessions, network) = resolver(&socket).await;
    let (mut client, gateway) = tcp_pair().await;
    let handler = tokio::spawn(handle_mongodb_client(gateway, resolver, None));

    if speculative {
        send_command(&mut client, speculative_hello()).await;
    } else {
        send_plain_hello(&mut client).await;
        let hello = read_message(&mut client).await;
        assert!(hello.body.unwrap().contains_key("saslSupportedMechs"));
        send_command(&mut client, sasl_start()).await;
    }

    let backend = tokio::spawn(async move {
        let (mut backend, _) = backend_listener.accept().await.unwrap();
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
            .unwrap();
        } else {
            let hello = read_message(&mut backend).await;
            assert!(mongodb::is_hello(&hello));
            mongodb::write_response(
                &mut backend,
                &hello,
                doc! { "ok": 1.0, "maxWireVersion": 25_i32 },
            )
            .await
            .unwrap();
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
            .unwrap();
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
        .unwrap();

        let ping = read_message(&mut backend).await;
        assert_eq!(mongodb::command_name(&ping).as_deref(), Some("ping"));
        mongodb::write_response(&mut backend, &ping, doc! { "ok": 1.0 })
            .await
            .unwrap();
        backend.shutdown().await.unwrap();
    });

    let challenge = read_message(&mut client).await;
    if speculative {
        assert_eq!(
            challenge
                .body
                .as_ref()
                .unwrap()
                .get_array("compression")
                .unwrap()
                .len(),
            0,
            "DBE must not negotiate a compressed mode its identity fence rejects"
        );
    }
    let state = mongodb::auth_reply_state(&challenge, speculative).unwrap();
    assert_eq!(state, mongodb::AuthReplyState::Continue);
    send_command(&mut client, sasl_continue()).await;
    let accepted = read_message(&mut client).await;
    assert_eq!(
        mongodb::auth_reply_state(&accepted, false).unwrap(),
        mongodb::AuthReplyState::Authenticated
    );
    assert_eq!(sessions.active("tenant-mongo"), 1);

    send_command(&mut client, doc! { "ping": 1_i32, "$db": "tenant_db" }).await;
    assert_eq!(
        read_message(&mut client)
            .await
            .body
            .unwrap()
            .get_f64("ok")
            .unwrap(),
        1.0
    );
    client.shutdown().await.unwrap();
    backend.await.unwrap();
    handler.await.unwrap().unwrap();
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
            crate::protocols::qdrant::QdrantRouteKey::new(b"mongo-wire-test"),
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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let connect = tokio::spawn(TcpStream::connect(address));
    let (gateway, _) = listener.accept().await.unwrap();
    (connect.await.unwrap().unwrap(), gateway)
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
        .write_all(&mongodb::encode_command(body).unwrap())
        .await
        .unwrap();
}

async fn read_message(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> mongodb::MongoMessage {
    mongodb::read_message(stream).await.unwrap()
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
