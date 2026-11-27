//! Shutdown, and what it does to pending and open work.

use std::{io::ErrorKind, sync::Arc, time::Duration};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::support::*;
use crate::endpoint::{OpenError, Peer};

/// Opens a stream from `a` to `b`, sends a few bytes each way and returns both ends, so a
/// test starts from a stream that demonstrably works and keeps the opposite end alive.
async fn working_pair(
    a: &crate::endpoint::Tether,
    b: &crate::endpoint::Tether,
) -> (crate::endpoint::Stream, crate::endpoint::Stream) {
    let (mut accepted, _task) = acceptor(b);
    let mut opened = a.open(&peer(b), &target("db"), b"").await.expect("open");
    let mut theirs = next(&mut accepted).await.stream;
    opened.write_all(b"ping").await.expect("write");
    let mut buffer = [0u8; 4];
    within(theirs.read_exact(&mut buffer)).await.expect("read");
    assert_eq!(&buffer, b"ping");
    theirs.write_all(b"pong").await.expect("write");
    within(opened.read_exact(&mut buffer)).await.expect("read");
    assert_eq!(&buffer, b"pong");
    (opened, theirs)
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_stops_accepting_and_opening() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let (a, b) = (start(&kit_a), start(&kit_b));

    // Wait until the accept call is parked, so shutdown has to wake it.
    let waiting = tokio::spawn({
        let a = a.clone();
        async move { a.accept().await.is_none() }
    });
    eventually("accept to be waiting", || a.accept_waiting()).await;
    a.shutdown().await;

    assert!(
        within(waiting).await.expect("task"),
        "accept must return None"
    );
    assert!(a.accept().await.is_none());
    let error = a
        .open(&peer(&b), &target("db"), b"")
        .await
        .err()
        .expect("closed");
    assert!(matches!(error, OpenError::Closed), "{error:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn shutting_down_ends_the_endpoints_own_open_streams() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let (a, b) = (start(&kit_a), start(&kit_b));
    let (mut opened, theirs) = working_pair(&a, &b).await;

    // Only `a` is shut down, and b's end of the stream stays alive throughout: whatever
    // ends the read on `a`'s side is the shutdown, not b dropping its stream.
    a.shutdown().await;
    let mut buffer = [0u8; 8];
    let error = within(opened.read(&mut buffer))
        .await
        .expect_err("the stream must fail when its endpoint closes");
    assert_eq!(error.kind(), ErrorKind::ConnectionAborted);
    assert!(opened.write_all(b"more").await.is_err());
    drop(theirs);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_shutting_down_ends_the_streams_of_its_peers() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let (a, b) = (start(&kit_a), start(&kit_b));
    let (mut opened, theirs) = working_pair(&a, &b).await;

    b.shutdown().await;
    let mut buffer = [0u8; 8];
    let error = within(opened.read(&mut buffer))
        .await
        .expect_err("closed by the peer");
    // Either the close frame or, if it was lost to a race, a stateless reset gets there first.
    assert!(
        matches!(
            error.kind(),
            ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset
        ),
        "{:?}",
        error.kind()
    );
    drop(theirs);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pending_open_returns_closed_when_shutdown_runs() {
    let authority = authority();
    let a = start_with(&authority.kit("a"), Arc::new(AllowAll), |c| {
        c.connect_timeout = Duration::from_secs(60);
    });
    // Bound but silent: the dial can only end by timeout or by shutdown.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("socket");
    let peer = Peer {
        id: node("b"),
        address: silent.local_addr().expect("address"),
    };

    let open = tokio::spawn({
        let a = a.clone();
        async move { a.open(&peer, &target("db"), b"").await }
    });
    eventually("the dial to be in flight", || a.dialing() == 1).await;
    a.shutdown().await;

    let error = within(open).await.expect("task").err().expect("shut down");
    assert!(matches!(error, OpenError::Closed), "{error:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_drops_streams_still_waiting_in_the_accept_queue() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let a = start(&kit_a);
    let b = start(&kit_b);

    // Nobody accepts on b, so the stream waits in its queue.
    let open = tokio::spawn({
        let (a, peer) = (a.clone(), peer(&b));
        async move { a.open(&peer, &target("db"), b"").await }
    });
    eventually("the stream to be queued", || b.queued_incoming() == 1).await;

    b.shutdown().await;
    assert_eq!(b.queued_incoming(), 0, "the queue still holds the stream");
    assert!(b.accept().await.is_none());
    let error = within(open).await.expect("task").err().expect("failed");
    assert!(!matches!(error, OpenError::Closed), "{error:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_abandoned_dial_does_not_keep_the_socket_after_the_last_handle() {
    let authority = authority();
    let a = start_with(&authority.kit("a"), Arc::new(AllowAll), |c| {
        c.connect_timeout = Duration::from_secs(60);
    });
    let address = a.local_addr().expect("address");
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("socket");
    let peer = Peer {
        id: node("b"),
        address: silent.local_addr().expect("address"),
    };

    let open = tokio::spawn({
        let a = a.clone();
        async move { a.open(&peer, &target("db"), b"").await }
    });
    eventually("the dial to be in flight", || a.dialing() == 1).await;
    open.abort();
    assert!(open.await.is_err_and(|error| error.is_cancelled()));
    drop(a);

    // The dial would otherwise hold the socket for the whole connect timeout.
    eventually("the address to be free again", || {
        std::net::UdpSocket::bind(address).is_ok()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_shutdown_nobody_waits_for_still_empties_the_accept_queue() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let a = start(&kit_a);
    let b = start(&kit_b);

    let open = tokio::spawn({
        let (a, peer) = (a.clone(), peer(&b));
        async move { a.open(&peer, &target("db"), b"").await }
    });
    eventually("the stream to be queued", || b.queued_incoming() == 1).await;

    // Polled once and dropped.
    let abandoned = tokio::time::timeout(Duration::ZERO, b.shutdown()).await;
    assert!(
        abandoned.is_err(),
        "shutdown finished within its first poll"
    );
    eventually("the queue to be drained", || b.queued_incoming() == 0).await;
    assert!(within(open).await.expect("task").is_err());
}
