//! Configuration checks and every limit that protects an endpoint from its peers.

use std::{sync::Arc, time::Duration};

use super::{raw::*, support::*};
use crate::{
    endpoint::{BindError, Config, OpenError, Tether},
    wire::Status,
};

/// The close code a connection over the limits receives (see `CLOSE_LIMIT`).
const LIMIT: u32 = 4;

fn bind_error(tweak: impl FnOnce(&mut Config)) -> BindError {
    let authority = authority();
    let mut config = config(authority.kit("a").identity());
    tweak(&mut config);
    Tether::bind(config, Arc::new(AllowAll))
        .err()
        .expect("rejected")
}

#[tokio::test]
async fn invalid_configuration_is_rejected() {
    type Tweak = Box<dyn FnOnce(&mut Config)>;
    let ms = Duration::from_millis;
    let cases: Vec<(&str, Tweak)> = vec![
        ("streams zero", Box::new(|c| c.max_streams_per_peer = 0)),
        (
            "streams huge",
            Box::new(|c| c.max_streams_per_peer = u32::MAX),
        ),
        ("backlog zero", Box::new(|c| c.accept_backlog = 0)),
        (
            "backlog beyond tokio",
            Box::new(|c| c.accept_backlog = usize::MAX),
        ),
        (
            "backlog beyond the bound",
            Box::new(|c| c.accept_backlog = 65_537),
        ),
        ("header", Box::new(|c| c.header_timeout = Duration::ZERO)),
        (
            "header timeout beyond a day",
            Box::new(|c| c.header_timeout = Duration::MAX),
        ),
        (
            "connect timeout beyond a day",
            Box::new(|c| c.connect_timeout = Duration::from_secs(86_401)),
        ),
        (
            "handshake timeout beyond a day",
            Box::new(|c| c.handshake_timeout = Duration::MAX),
        ),
        (
            "keep-alive beyond a day",
            Box::new(|c| {
                c.idle_timeout = Duration::from_secs(86_400);
                c.keep_alive = Duration::from_secs(86_401);
            }),
        ),
        (
            "idle beyond a day",
            Box::new(|c| c.idle_timeout = Duration::from_secs(86_401)),
        ),
        (
            "keep-alive within the idle timeout's last millisecond",
            Box::new(|c| {
                // Encoded as 1 ms, which the 1.2 ms keep-alive does not undercut.
                c.idle_timeout = Duration::from_micros(1500);
                c.keep_alive = Duration::from_micros(1200);
            }),
        ),
        ("connect", Box::new(|c| c.connect_timeout = Duration::ZERO)),
        ("idle zero", Box::new(|c| c.idle_timeout = Duration::ZERO)),
        (
            "idle below a millisecond",
            Box::new(|c| {
                c.idle_timeout = Duration::from_micros(500);
                c.keep_alive = Duration::from_micros(100);
            }),
        ),
        (
            "idle too large",
            Box::new(|c| c.idle_timeout = Duration::from_secs(u64::MAX / 2)),
        ),
        (
            "keep-alive zero",
            Box::new(|c| c.keep_alive = Duration::ZERO),
        ),
        (
            "keep-alive equal",
            Box::new(|c| c.keep_alive = c.idle_timeout),
        ),
        (
            "keep-alive longer",
            Box::new(move |c| c.keep_alive = c.idle_timeout + ms(1000)),
        ),
        ("connections zero", Box::new(|c| c.max_connections = 0)),
        (
            "connections huge",
            Box::new(|c| c.max_connections = usize::MAX),
        ),
        (
            "per-peer zero",
            Box::new(|c| c.max_connections_per_peer = 0),
        ),
        (
            "per-peer above total",
            Box::new(|c| {
                c.max_connections = 4;
                c.max_connections_per_peer = 5;
            }),
        ),
        ("handshakes zero", Box::new(|c| c.max_handshakes = 0)),
        (
            "handshakes huge",
            Box::new(|c| c.max_handshakes = usize::MAX),
        ),
        (
            "handshake timeout",
            Box::new(|c| c.handshake_timeout = Duration::ZERO),
        ),
        (
            "stream window tiny",
            Box::new(|c| c.stream_receive_window = 1),
        ),
        (
            "stream window huge",
            Box::new(|c| c.stream_receive_window = u32::MAX),
        ),
        (
            "connection window below the stream window",
            Box::new(|c| c.connection_receive_window = c.stream_receive_window - 1),
        ),
        (
            "connection window huge",
            Box::new(|c| c.connection_receive_window = u32::MAX),
        ),
    ];
    for (name, tweak) in cases {
        let error = bind_error(tweak);
        assert!(matches!(error, BindError::Config(_)), "{name}: {error:?}");
    }
}

#[tokio::test]
async fn limits_at_their_bounds_are_accepted() {
    let authority = authority();
    let mut config = config(authority.kit("a").identity());
    config.max_streams_per_peer = 16_384;
    config.accept_backlog = 65_536;
    config.max_connections = 65_536;
    config.max_connections_per_peer = 65_536;
    config.max_handshakes = 65_536;
    config.stream_receive_window = 16 * 1024;
    config.connection_receive_window = 1 << 30;
    config.idle_timeout = Duration::from_millis(2);
    config.keep_alive = Duration::from_millis(1);
    Tether::bind(config, Arc::new(AllowAll)).expect("bounds are valid");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_full_backlog_is_answered_unavailable_instead_of_hanging() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let a = start(&kit_a);
    // Nobody calls `accept` on b.
    let b = start_with(&kit_b, Arc::new(AllowAll), |c| c.accept_backlog = 1);

    // One stream fills the queue and keeps waiting for its answer.
    let first = tokio::spawn({
        let (a, peer) = (a.clone(), peer(&b));
        async move { a.open(&peer, &target("db"), b"").await }
    });
    eventually("the first stream to be queued", || b.queued_incoming() == 1).await;

    // Every further stream is turned away at once, not left waiting.
    for _ in 0..2 {
        let error = within(a.open(&peer(&b), &target("db"), b""))
            .await
            .err()
            .expect("queue is full");
        assert!(
            matches!(error, OpenError::Refused(Status::Unavailable)),
            "{error:?}"
        );
    }
    assert!(!first.is_finished(), "the queued stream is still waiting");

    // Taking it from the queue answers it.
    let incoming = within(b.accept()).await.expect("queued stream");
    let _theirs = incoming.accept().await.expect("accept");
    within(first).await.expect("task").expect("first opens");
}

#[tokio::test(flavor = "multi_thread")]
async fn streams_beyond_the_peer_limit_wait_for_a_free_slot() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let a = start_with(&kit_a, Arc::new(AllowAll), |c| {
        c.header_timeout = Duration::from_millis(400);
    });
    let b = start_with(&kit_b, Arc::new(AllowAll), |c| c.max_streams_per_peer = 2);
    let (mut accepted, _task) = acceptor(&b);
    let (peer, target) = (peer(&b), target("db"));

    let first = a.open(&peer, &target, b"").await.expect("first");
    let _second = a.open(&peer, &target, b"").await.expect("second");
    next(&mut accepted).await;
    next(&mut accepted).await;

    // quinn does not refuse the third stream: `open_bi` waits for credit, so the open
    // runs into the header timeout.
    let error = a.open(&peer, &target, b"").await.err().expect("no slot");
    assert!(matches!(error, OpenError::Timeout), "{error:?}");

    drop(first);
    let mut third = None;
    for _ in 0..20 {
        match a.open(&peer, &target, b"").await {
            Ok(stream) => {
                third = Some(stream);
                break;
            }
            Err(OpenError::Timeout) => {}
            Err(other) => panic!("unexpected {other:?}"),
        }
    }
    assert!(third.is_some(), "no slot freed after closing a stream");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_may_not_hold_more_connections_than_the_per_peer_limit() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let b = start_with(&kit_b, Arc::new(AllowAll), |c| {
        c.max_connections_per_peer = 1;
    });
    let address = b.local_addr().expect("address");

    let first = raw_to(address, &kit_a).await;
    eventually("the first connection to count", || b.live_inbound() == 1).await;

    let second = raw_to(address, &kit_a).await;
    let reason = within(second.connection.closed()).await;
    assert!(
        matches!(&reason, quinn::ConnectionError::ApplicationClosed(c) if c.error_code == LIMIT.into()),
        "{reason:?}"
    );
    assert!(first.connection.close_reason().is_none(), "the first stays");
    assert_eq!(b.live_inbound(), 1);

    // Another node is unaffected by a's usage.
    let other = raw_to(address, &authority.kit("c")).await;
    eventually("the other node to count", || b.live_inbound() == 2).await;
    assert!(other.connection.close_reason().is_none());

    // Closing a's connection frees its slot.
    first.connection.close(0u8.into(), b"done");
    eventually("the slot to be freed", || b.live_inbound() == 1).await;
    let third = raw_to(address, &kit_a).await;
    eventually("the replacement to count", || b.live_inbound() == 2).await;
    assert!(third.connection.close_reason().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn connections_beyond_the_global_limit_are_closed() {
    let authority = authority();
    let b = start_with(&authority.kit("b"), Arc::new(AllowAll), |c| {
        c.max_connections = 2;
    });
    let address = b.local_addr().expect("address");

    let _first = raw_to(address, &authority.kit("a")).await;
    eventually("the first connection to count", || b.live_inbound() == 1).await;
    let _second = raw_to(address, &authority.kit("c")).await;
    eventually("the second connection to count", || b.live_inbound() == 2).await;

    let third = raw_to(address, &authority.kit("d")).await;
    let reason = within(third.connection.closed()).await;
    assert!(
        matches!(&reason, quinn::ConnectionError::ApplicationClosed(c) if c.error_code == LIMIT.into()),
        "{reason:?}"
    );
    assert_eq!(b.live_inbound(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn handshakes_beyond_the_permits_are_refused_and_the_endpoint_recovers() {
    let authority = authority();
    let kit_a = authority.kit("a");
    let b = start_with(&authority.kit("b"), Arc::new(AllowAll), |c| {
        c.max_handshakes = 1;
    });
    let address = b.local_addr().expect("address");

    let gate = Gate::closed();
    let _release = gate.release_on_drop();
    let staller = stalled_client(
        &authority.kit("c"),
        &authority.cert_pem,
        gate.clone(),
        address,
    );
    eventually("the stalled handshake to hold the permit", || {
        b.handshakes_in_use() == 1
    })
    .await;

    let error = raw_client(
        kit_a.identity().client_config().expect("client config"),
        address,
        "b",
    )
    .await
    .err()
    .expect("no permit is free");
    assert!(
        matches!(&error, quinn::ConnectionError::ConnectionClosed(_)),
        "{error:?}"
    );
    assert!(b.refused_attempts() >= 1);
    assert_eq!(b.accepted_connections(), 0);

    gate.release();
    let _stalled = staller
        .finish()
        .await
        .expect("the stalled handshake completes once released");
    eventually("the permit to be returned", || b.handshakes_in_use() == 0).await;
    let _again = raw_to(address, &kit_a).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unvalidated_addresses_are_asked_to_retry_once_half_the_permits_are_taken() {
    let authority = authority();
    let kit_a = authority.kit("a");
    let b = start_with(&authority.kit("b"), Arc::new(AllowAll), |c| {
        c.max_handshakes = 3;
    });
    let address = b.local_addr().expect("address");

    let gate = Gate::closed();
    let _release = gate.release_on_drop();
    let stallers: Vec<_> = ["c", "d"]
        .into_iter()
        .map(|name| {
            stalled_client(
                &authority.kit(name),
                &authority.cert_pem,
                gate.clone(),
                address,
            )
        })
        .collect();
    eventually("both stalled handshakes to hold a permit", || {
        b.handshakes_in_use() == 2
    })
    .await;

    // quinn clients follow a Retry on their own, so this one connects after proving its
    // address, and the counter shows the detour was taken.
    let _client = raw_to(address, &kit_a).await;
    assert!(b.retried_attempts() >= 1, "no Retry was sent");
    assert_eq!(b.refused_attempts(), 0);

    gate.release();
    for staller in stallers {
        staller.finish().await.expect("handshake");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_cannot_open_streams_back_over_a_connection_we_dialed() {
    let authority = authority();
    let a = start(&authority.kit("a"));
    let issued = authority.issue(&[San::Dns("b")]);
    let mut server = raw_server(&issued, None).await;
    let address = server.address;

    // Any dial will do; the raw server never answers the stream, so the open times out.
    let a2 = a.clone();
    let dial = tokio::spawn(async move {
        a2.open(
            &crate::endpoint::Peer {
                id: node("b"),
                address,
            },
            &target("db"),
            b"",
        )
        .await
    });
    let connection = within(server.connections.recv()).await.expect("connection");
    // The dialer advertised no streams, so opening one would wait for credit forever.
    // This can only make the test pass wrongly on a stall, never fail it wrongly.
    let attempt = tokio::time::timeout(Duration::from_millis(300), connection.open_bi()).await;
    assert!(
        attempt.is_err(),
        "the dialer allows the server to open streams"
    );
    dial.abort();
}
