use std::{net::SocketAddr, sync::atomic::Ordering, time::Duration};

use ::tether::{Peer, TargetId, endpoint::OpenError, wire::Status};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use super::test_support::{Authority, Echo, Node, NodeSpec, authority};
use crate::gateway::{listeners::run_listener, security::GatewayConnectionLimiter};

const WAIT: Duration = Duration::from_secs(15);

async fn within<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, future)
        .await
        .expect("did not finish in time")
}

fn unused_address() -> SocketAddr {
    "127.0.0.1:1".parse().expect("address")
}

fn peer_of(name: &str, node: &Node) -> Peer {
    Peer {
        id: name.parse().expect("node id"),
        address: node.address,
    }
}

async fn open_with(
    node: &Node,
    to: &Peer,
    protocol: &str,
    context: &[u8],
) -> Result<::tether::Stream, OpenError> {
    let target: TargetId = protocol.parse().expect("target id");
    within(node.tether.open(to, &target, context)).await
}

async fn open(node: &Node, to: &Peer, protocol: &str) -> Result<(), OpenError> {
    open_with(node, to, protocol, b"203.0.113.7:51234")
        .await
        .map(drop)
}

struct Data {
    node: Node,
    echo: Echo,
}

/// A data node that lets `node-a` in and serves an echo stand-in as `postgres`.
async fn data_node(authority: &Authority, extra: &[(&str, bool)]) -> Data {
    data_node_with(authority, extra, None, |_| {}).await
}

async fn data_node_with(
    authority: &Authority,
    extra: &[(&str, bool)],
    cap: Option<usize>,
    tweak: impl FnOnce(&mut NodeSpec<'_>),
) -> Data {
    let mut spec = NodeSpec::with_listener_cap("node-b", cap);
    spec.peers.push(("node-a", unused_address(), true));
    for (name, inbound) in extra {
        spec.peers.push((name, unused_address(), *inbound));
    }
    tweak(&mut spec);
    let echo = spec.serve_echo("postgres");
    Data {
        node: authority.start(spec).await,
        echo,
    }
}

async fn client_node(authority: &Authority, name: &str, data: &Data) -> Node {
    let mut spec = NodeSpec::new(name);
    spec.peers.push(("node-b", data.node.address, false));
    authority.start(spec).await
}

async fn entry_node(
    authority: &Authority,
    data: &Data,
    protocol: &str,
    tweak: impl FnOnce(&mut NodeSpec<'_>),
) -> Node {
    let mut spec = NodeSpec::new("node-a");
    spec.peers.push(("node-b", data.node.address, false));
    spec.forwards.push(("node-b", protocol));
    tweak(&mut spec);
    authority.start(spec).await
}

async fn eof(client: &mut TcpStream) -> bool {
    let mut rest = Vec::new();
    within(client.read_to_end(&mut rest)).await.is_err() || rest.is_empty()
}

async fn echoes(client: &mut TcpStream, chunk: &[u8]) {
    client.write_all(chunk).await.expect("write");
    let mut echoed = vec![0u8; chunk.len()];
    within(client.read_exact(&mut echoed)).await.expect("read");
    assert_eq!(echoed, chunk);
}

#[tokio::test]
async fn client_bytes_cross_the_link_and_half_closes_propagate() {
    let authority = authority();
    let data = data_node(&authority, &[]).await;
    let entry = entry_node(&authority, &data, "postgres", |_| {}).await;

    let mut client = within(TcpStream::connect(entry.forwards[0]))
        .await
        .expect("connect to the forward");
    echoes(&mut client, b"one").await;
    echoes(&mut client, b"two").await;
    // The backend only says goodbye after it sees the client's half-close, and the client
    // only sees EOF after the backend closes its side.
    client.shutdown().await.expect("half-close");
    let mut rest = Vec::new();
    within(client.read_to_end(&mut rest)).await.expect("drain");
    assert_eq!(rest, b"bye");

    assert_eq!(data.echo.connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn forward_closes_the_client_when_the_peer_refuses() {
    let authority = authority();
    let data = data_node(&authority, &[]).await;
    // Nothing is behind `redis`, so the data node answers Unavailable.
    let entry = entry_node(&authority, &data, "redis", |_| {}).await;
    let mut client = within(TcpStream::connect(entry.forwards[0]))
        .await
        .expect("connect to the forward");
    assert!(eof(&mut client).await);
}

#[tokio::test]
async fn inbound_peer_opens_a_stream() {
    let authority = authority();
    let data = data_node(&authority, &[]).await;
    let entry = client_node(&authority, "node-a", &data).await;
    open(&entry, &peer_of("node-b", &data.node), "postgres")
        .await
        .expect("an inbound peer may open postgres");
}

#[tokio::test]
async fn peer_without_inbound_is_refused() {
    let authority = authority();
    let data = data_node(&authority, &[("node-c", false)]).await;
    let outsider = client_node(&authority, "node-c", &data).await;
    let result = open(&outsider, &peer_of("node-b", &data.node), "postgres").await;
    assert!(matches!(result, Err(OpenError::Refused(Status::Denied))));
}

#[tokio::test]
async fn unknown_protocol_is_refused() {
    let authority = authority();
    let data = data_node(&authority, &[]).await;
    let entry = client_node(&authority, "node-a", &data).await;
    for target in ["bogus", "postgres2", "Postgres"] {
        let result = open(&entry, &peer_of("node-b", &data.node), target).await;
        assert!(
            matches!(result, Err(OpenError::Refused(Status::Denied))),
            "{target}: {result:?}"
        );
    }
}

#[tokio::test]
async fn protocol_without_an_internal_listener_is_unavailable() {
    let authority = authority();
    let data = data_node(&authority, &[]).await;
    let entry = client_node(&authority, "node-a", &data).await;
    let result = open(&entry, &peer_of("node-b", &data.node), "redis").await;
    assert!(matches!(
        result,
        Err(OpenError::Refused(Status::Unavailable))
    ));
}

#[tokio::test]
async fn node_missing_from_peers_gets_no_stream() {
    let authority = authority();
    let data = data_node(&authority, &[]).await;
    let stranger = client_node(&authority, "node-d", &data).await;
    let result = open(&stranger, &peer_of("node-b", &data.node), "postgres").await;
    assert!(matches!(result, Err(OpenError::Refused(Status::Denied))));
}

#[tokio::test]
async fn data_node_rejects_a_client_certificate_from_another_cluster() {
    let authority = authority();
    let data = data_node(&authority, &[]).await;
    let to = peer_of("node-b", &data.node);
    // Control: a trusted client succeeds against this very endpoint, so a failure below
    // cannot be an unrelated dial problem.
    let trusted = client_node(&authority, "node-a", &data).await;
    open(&trusted, &to, "postgres")
        .await
        .expect("trusted client");

    let foreign = super::test_support::authority();
    // The intruder trusts both clusters, so it accepts the data node's certificate and the
    // only thing that can stop it is the data node refusing the foreign client certificate.
    let bundle = format!("{}{}", foreign.pem(), authority.pem());
    let mut spec = NodeSpec::new("node-a");
    spec.peers.push(("node-b", data.node.address, false));
    let intruder = foreign.start_trusting(spec, &bundle).await;
    let result = open(&intruder, &to, "postgres").await;
    assert!(result.is_err(), "{result:?}");
}

#[tokio::test]
async fn a_stream_without_a_parsable_client_address_is_malformed() {
    let authority = authority();
    let data = data_node(&authority, &[]).await;
    let entry = client_node(&authority, "node-a", &data).await;
    let to = peer_of("node-b", &data.node);
    for context in [&b""[..], b"not-an-address", b"203.0.113.7", b"\xff\xfe"] {
        let result = open_with(&entry, &to, "postgres", context).await;
        assert!(
            matches!(result, Err(OpenError::Refused(Status::Malformed))),
            "{context:?}: {:?}",
            result.err()
        );
    }
    assert_eq!(data.echo.connections.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn each_forward_is_capped_at_the_listener_connection_limit() {
    let authority = authority();
    let data = data_node(&authority, &[]).await;
    let entry = entry_node(&authority, &data, "postgres", |spec| {
        spec.streams_limit = Some(1);
    })
    .await;
    let address = entry.forwards[0];

    let mut first = TcpStream::connect(address).await.expect("connect");
    echoes(&mut first, b"held").await;
    let mut second = TcpStream::connect(address).await.expect("connect");
    assert!(eof(&mut second).await, "the second client is over the cap");

    first.shutdown().await.expect("half-close");
    let mut rest = Vec::new();
    within(first.read_to_end(&mut rest)).await.expect("drain");
    // The slot is free again once the first connection has finished.
    within(async {
        loop {
            let mut third = TcpStream::connect(address).await.expect("connect");
            if third.write_all(b"x").await.is_ok() {
                let mut byte = [0u8; 1];
                if third.read_exact(&mut byte).await.is_ok() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

#[tokio::test]
async fn a_forward_applies_the_same_per_ip_limit_as_the_public_listeners() {
    let authority = authority();
    let data = data_node(&authority, &[]).await;
    // A client already holding its one allowed connection on some public listener.
    let limiter = GatewayConnectionLimiter::with_active_limit(600, 1);
    let public_connection = limiter
        .try_acquire("127.0.0.1".parse().expect("ip"))
        .expect("first connection");
    let shared = limiter.clone();
    let entry = entry_node(&authority, &data, "postgres", move |spec| {
        spec.limiter = shared;
    })
    .await;

    let mut client = TcpStream::connect(entry.forwards[0])
        .await
        .expect("connect");
    assert!(eof(&mut client).await, "limited on the forward as well");
    assert_eq!(data.echo.connections.load(Ordering::SeqCst), 0);

    drop(public_connection);
    within(async {
        loop {
            let mut client = TcpStream::connect(entry.forwards[0])
                .await
                .expect("connect");
            if client.write_all(b"x").await.is_ok() {
                let mut byte = [0u8; 1];
                if client.read_exact(&mut byte).await.is_ok() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

#[tokio::test]
async fn graceful_shutdown_lets_a_live_stream_finish_before_the_endpoint_closes() {
    let authority = authority();
    let data = data_node(&authority, &[]).await;
    let entry = entry_node(&authority, &data, "postgres", |_| {}).await;
    let mut client = TcpStream::connect(entry.forwards[0])
        .await
        .expect("connect");
    echoes(&mut client, b"before").await;

    data.node.supervisor.shutdown();
    // The stream carries on, and new ones are turned away.
    echoes(&mut client, b"during").await;
    let result = open(&entry, &peer_of("node-b", &data.node), "postgres").await;
    assert!(matches!(
        result,
        Err(OpenError::Refused(Status::Unavailable))
    ));
    // The endpoint is still open while the stream lives: accept has not reported closure.
    assert!(
        tokio::time::timeout(Duration::from_millis(400), data.node.tether.accept())
            .await
            .is_err()
    );

    client.shutdown().await.expect("half-close");
    let mut rest = Vec::new();
    within(client.read_to_end(&mut rest)).await.expect("drain");
    assert_eq!(rest, b"bye", "the final payload arrives, then EOF");

    within(data.node.supervisor.wait_background()).await;
    assert!(
        within(data.node.tether.accept()).await.is_none(),
        "the endpoint is closed once the supervisor has waited for it"
    );
    assert!(
        open(&entry, &peer_of("node-b", &data.node), "postgres")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn forced_shutdown_ends_live_streams_and_still_closes_the_endpoint() {
    let authority = authority();
    let data = data_node(&authority, &[]).await;
    let entry = entry_node(&authority, &data, "postgres", |_| {}).await;
    let mut client = TcpStream::connect(entry.forwards[0])
        .await
        .expect("connect");
    echoes(&mut client, b"stuck").await;

    // The client never closes; only the force deadline can end this.
    data.node.supervisor.shutdown();
    let outcome = data
        .node
        .supervisor
        .drain_connections(Duration::from_millis(100), Duration::from_millis(100))
        .await;
    assert!(!outcome.gracefully_drained);
    assert_eq!(outcome.remaining, 0);
    within(data.node.supervisor.wait_background()).await;
    assert!(within(data.node.tether.accept()).await.is_none());
    assert!(eof(&mut client).await, "the stream was cut");
}

#[tokio::test]
async fn tunnelled_and_public_connections_share_the_listener_cap() {
    let authority = authority();
    let data = data_node_with(&authority, &[], Some(1), |_| {}).await;
    let public = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let public_address = public.local_addr().expect("address");
    tokio::spawn({
        let entry = data.echo.entry.clone();
        let shutdown = data.node.supervisor.subscribe_shutdown();
        async move { run_listener(public, "public", entry, shutdown).await }
    });
    let entry = client_node(&authority, "node-a", &data).await;
    let to = peer_of("node-b", &data.node);

    // A public connection takes the only slot; a tunnelled one is refused.
    let mut held = TcpStream::connect(public_address).await.expect("connect");
    echoes(&mut held, b"public").await;
    let result = open(&entry, &to, "postgres").await;
    assert!(matches!(
        result,
        Err(OpenError::Refused(Status::Unavailable))
    ));

    // Once it is gone the tunnelled one gets the slot, and then the public one is refused.
    drop(held);
    let tunnelled = within(async {
        loop {
            match open_with(&entry, &to, "postgres", b"203.0.113.7:1").await {
                Ok(stream) => return stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await;
    let mut second = TcpStream::connect(public_address).await.expect("connect");
    assert!(
        eof(&mut second).await,
        "the public client is over the shared cap"
    );
    drop(tunnelled);
}

#[tokio::test]
async fn a_tunnelled_client_over_its_per_ip_limit_is_refused() {
    let authority = authority();
    let limiter = GatewayConnectionLimiter::with_active_limit(600, 1);
    let held = limiter
        .try_acquire("203.0.113.7".parse().expect("ip"))
        .expect("the client's one connection");
    let data = data_node_with(&authority, &[], None, |spec| spec.limiter = limiter.clone()).await;
    let entry = client_node(&authority, "node-a", &data).await;
    let to = peer_of("node-b", &data.node);

    // The limit follows the client address the entry node asserts, not the entry node.
    let result = open_with(&entry, &to, "postgres", b"203.0.113.7:4000").await;
    assert!(matches!(
        result,
        Err(OpenError::Refused(Status::Unavailable))
    ));
    open_with(&entry, &to, "postgres", b"203.0.113.8:4000")
        .await
        .expect("another client is unaffected");
    drop(held);
    within(async {
        while open_with(&entry, &to, "postgres", b"203.0.113.7:4001")
            .await
            .is_err()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

#[tokio::test]
async fn a_real_protocol_handler_runs_over_a_tunnelled_connection() {
    let authority = authority();
    let mut spec = NodeSpec::new("node-b");
    spec.peers.push(("node-a", unused_address(), true));
    let resolver = spec.resolver();
    let entry = crate::gateway::listeners::protocol_entry(
        "postgres",
        resolver,
        None,
        spec.limiter.clone(),
        spec.supervisor.connection_tracker(),
    )
    .expect("postgres handler");
    spec.dispatch.insert("postgres", entry);
    let data = authority.start(spec).await;
    let mut spec = NodeSpec::new("node-a");
    spec.peers.push(("node-b", data.address, false));
    let entry_node = authority.start(spec).await;

    let mut stream = open_with(
        &entry_node,
        &peer_of("node-b", &data),
        "postgres",
        b"203.0.113.7:51234",
    )
    .await
    .expect("open");
    // A Postgres startup for a tenant that does not exist: the gateway answers with its
    // access-denied error and closes, exactly as it would for a public client.
    let fields = b"user\0nobody\0database\0nodb\0\0";
    let mut startup = Vec::new();
    startup.extend_from_slice(&((fields.len() + 8) as u32).to_be_bytes());
    startup.extend_from_slice(&196_608_u32.to_be_bytes());
    startup.extend_from_slice(fields);
    stream.write_all(&startup).await.expect("write startup");
    let mut first = [0u8; 1];
    within(stream.read_exact(&mut first))
        .await
        .expect("response");
    assert_eq!(first[0], b'E');
    let mut rest = Vec::new();
    within(stream.read_to_end(&mut rest)).await.expect("EOF");
}

#[tokio::test]
async fn a_relay_stuck_on_a_stalled_client_cannot_hold_shutdown() {
    let authority = authority();
    let mut spec = NodeSpec::new("node-b");
    spec.peers.push(("node-a", unused_address(), true));
    // The handler hands its socket to a task and returns; only the relay stays busy, pushing
    // data at a client that never reads.
    spec.entry("postgres", |client, _, _| async move {
        tokio::spawn(async move {
            let mut client = client;
            let _ = client.write_all(&vec![7u8; 128 * 1024 * 1024]).await;
        });
        Ok(())
    });
    let data = authority.start(spec).await;
    let mut spec = NodeSpec::new("node-a");
    spec.peers.push(("node-b", data.address, false));
    spec.forwards.push(("node-b", "postgres"));
    let entry = authority.start(spec).await;
    let _stalled = TcpStream::connect(entry.forwards[0])
        .await
        .expect("connect");

    // Wait until the data side is relaying: the relay, plus the admission lease it shares
    // with the (already returned) handler.
    within(async {
        while data.supervisor.connection_tracker().pending() < 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    for node in [&data, &entry] {
        node.supervisor.shutdown();
        let outcome = within(
            node.supervisor
                .drain_connections(Duration::from_millis(200), Duration::from_secs(3)),
        )
        .await;
        assert!(!outcome.gracefully_drained, "the relay was still busy");
        assert_eq!(outcome.remaining, 0, "force ended the relay");
        within(node.supervisor.wait_background()).await;
        assert!(within(node.tether.accept()).await.is_none());
    }
}

#[tokio::test]
async fn a_relay_that_outlives_its_handler_keeps_the_admission_slot() {
    let authority = authority();
    let mut spec = NodeSpec::with_listener_cap("node-b", Some(1));
    spec.peers.push(("node-a", unused_address(), true));
    // The handler returns at once, leaving its socket to a task that keeps pushing data at a
    // client that never reads, so only the relay is still working.
    spec.entry("postgres", |client, _, _| async move {
        tokio::spawn(async move {
            let mut client = client;
            let _ = client.write_all(&vec![7u8; 128 * 1024 * 1024]).await;
        });
        Ok(())
    });
    let data = authority.start(spec).await;
    let mut spec = NodeSpec::new("node-a");
    spec.peers.push(("node-b", data.address, false));
    spec.forwards.push(("node-b", "postgres"));
    let entry = authority.start(spec).await;
    let stalled = TcpStream::connect(entry.forwards[0])
        .await
        .expect("connect");
    // A second node with an inbound identity is not available (only node-a is inbound), so
    // the direct opener shares node-a's name with the entry node.
    let direct = client_node_to(&authority, "node-a", &data).await;
    let to = peer_of("node-b", &data);

    within(async {
        while data.supervisor.connection_tracker().pending() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The handler is long gone, yet the one slot is still taken by the relay.
    let result = open_with(&direct, &to, "postgres", b"203.0.113.9:1").await;
    assert!(
        matches!(result, Err(OpenError::Refused(Status::Unavailable))),
        "{:?}",
        result.err()
    );

    // Once the relay ends the slot is free again.
    drop(stalled);
    within(async {
        while open_with(&direct, &to, "postgres", b"203.0.113.9:2")
            .await
            .is_err()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

async fn client_node_to(authority: &Authority, name: &str, data: &Node) -> Node {
    let mut spec = NodeSpec::new(name);
    spec.peers.push(("node-b", data.address, false));
    authority.start(spec).await
}
