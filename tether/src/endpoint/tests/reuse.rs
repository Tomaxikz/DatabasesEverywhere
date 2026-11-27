//! One connection per peer, however many streams and callers, and what happens when the
//! connection or the peer goes away.

use std::{sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinSet,
};

use super::{raw::*, support::*};
use crate::{
    endpoint::{OpenError, Peer},
    wire::{self, Status},
};

const CLOSE_SUPERSEDED: u32 = 5;

#[tokio::test(flavor = "multi_thread")]
async fn sequential_opens_reuse_one_connection() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let (a, b) = (start(&kit_a), start(&kit_b));
    let (mut accepted, _task) = acceptor(&b);

    let mut streams = Vec::new();
    for _ in 0..20 {
        streams.push(a.open(&peer(&b), &target("db"), b"").await.expect("open"));
        next(&mut accepted).await;
    }
    assert_eq!(a.outbound_connections(), 1);
    assert_eq!(a.dials_started(), 1);
    assert_eq!(b.accepted_connections(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_opens_without_a_connection_share_one_dial() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let a = start_with(&kit_a, Arc::new(AllowAll), |c| {
        c.header_timeout = Duration::from_millis(500);
    });
    let b = start(&kit_b);
    let (mut accepted, _task) = acceptor(&b);

    // The server certificate is held back until every open has looked the peer up, so no
    // open can arrive after the dial finished and start one of its own.
    let gate = Gate::closed();
    let _release = gate.release_on_drop();
    let server = raw_server(&authority.issue(&[San::Dns("b")]), Some(gate.clone())).await;
    let peer = Peer {
        id: node("b"),
        address: server.address,
    };
    let mut opens = JoinSet::new();
    for _ in 0..16 {
        let (a, peer) = (a.clone(), peer.clone());
        opens.spawn(async move { a.open(&peer, &target("db"), b"").await.err() });
    }
    eventually("every open to join the dial", || a.lookups() == 16).await;
    assert_eq!(a.dials_started(), 1);
    gate.release();
    // The raw server never answers a stream, so every open ends in the same way.
    while let Some(result) = opens.join_next().await {
        let error = result.expect("task").expect("raw server never answers");
        assert!(matches!(error, OpenError::Timeout), "{error:?}");
    }
    assert_eq!(a.dials_started(), 1, "opens dialed separately");
    assert_eq!(a.outbound_connections(), 1);

    // And against a real node, the shared connection carries all of them.
    let real = Peer {
        id: node("b"),
        address: b.local_addr().expect("address"),
    };
    let mut streams = Vec::new();
    for _ in 0..16 {
        streams.push(a.open(&real, &target("db"), b"").await.expect("open"));
        next(&mut accepted).await;
    }
    assert_eq!(b.accepted_connections(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_shared_dial_fails_every_waiter_from_one_attempt() {
    let authority = authority();
    let a = start(&authority.kit("a"));
    // This server holds a certificate for "b", so dialing it as "c" must fail.
    let gate = Gate::closed();
    let _release = gate.release_on_drop();
    let server = raw_server(&authority.issue(&[San::Dns("b")]), Some(gate.clone())).await;
    let impostor = Peer {
        id: node("c"),
        address: server.address,
    };

    let mut opens = JoinSet::new();
    for _ in 0..8 {
        let (a, impostor) = (a.clone(), impostor.clone());
        opens.spawn(async move { a.open(&impostor, &target("db"), b"").await.err() });
    }
    // Held until all eight have looked the peer up, so none can start a second dial after
    // the first failed.
    eventually("every open to join the dial", || a.lookups() == 8).await;
    gate.release();
    while let Some(result) = opens.join_next().await {
        let error = result.expect("task").expect("must fail");
        assert!(matches!(error, OpenError::Connect(_)), "{error:?}");
    }
    assert_eq!(a.dials_started(), 1, "waiters dialed separately");
    assert_eq!(a.outbound_connections(), 0);
    assert_eq!(a.dialing(), 0, "the failed entry is gone");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_moved_node_gets_a_new_connection_and_the_old_one_is_released() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let a = start(&kit_a);
    let old = start(&kit_b);
    let new = start(&kit_b);
    let (mut old_accepted, _t1) = acceptor(&old);
    let (mut new_accepted, _t2) = acceptor(&new);

    let first = a
        .open(&peer(&old), &target("db"), b"")
        .await
        .expect("old address");
    next(&mut old_accepted).await;
    let _second = a
        .open(&peer(&new), &target("db"), b"")
        .await
        .expect("new address");
    next(&mut new_accepted).await;

    assert_eq!(a.outbound_connections(), 1);
    assert_eq!(new.accepted_connections(), 1);

    // The retired connection is still in use by its stream, so it must stay up...
    assert_eq!(old.live_inbound(), 1);
    assert_eq!(new.live_inbound(), 1);
    // ...and once that stream ends nothing holds it any more: the watcher must not.
    drop(first);
    eventually("the retired connection to be released", || {
        old.live_inbound() == 0
    })
    .await;
    assert_eq!(new.live_inbound(), 1, "the current connection is untouched");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dial_overtaken_by_a_move_is_closed_when_nobody_waits_for_it() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let a = start(&kit_a);
    let new = start(&kit_b);
    let (mut new_accepted, _task) = acceptor(&new);

    // The first dial stalls inside the old address's handshake.
    let gate = Gate::closed();
    let _release = gate.release_on_drop();
    let mut slow = raw_server(&authority.issue(&[San::Dns("b")]), Some(gate.clone())).await;
    let stale = Peer {
        id: node("b"),
        address: slow.address,
    };
    let pending = tokio::spawn({
        let (a, stale) = (a.clone(), stale.clone());
        async move { a.open(&stale, &target("db"), b"").await }
    });
    eventually("the first dial to start", || a.dialing() == 1).await;

    // The node moves; the new address answers. The pending opener gives up.
    let _stream = a
        .open(&peer(&new), &target("db"), b"")
        .await
        .expect("new address");
    next(&mut new_accepted).await;
    pending.abort();
    let _ = pending.await;

    // Now the stale dial completes. Nobody is waiting, so the connection must be closed.
    gate.release();
    let connection = within(slow.connections.recv()).await.expect("connection");
    let reason = within(connection.closed()).await;
    assert!(
        matches!(&reason, quinn::ConnectionError::ApplicationClosed(c) if c.error_code == CLOSE_SUPERSEDED.into()),
        "{reason:?}"
    );
    assert_eq!(a.outbound_connections(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_restarted_peer_is_reached_again_by_a_fresh_dial() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let a = start(&kit_a);
    let b = start(&kit_b);
    let address = b.local_addr().expect("address");
    let (accepted, task) = acceptor(&b);
    let target = target("db");
    let stream = a.open(&peer(&b), &target, b"").await.expect("first open");
    assert_eq!(a.dials_started(), 1);

    b.shutdown().await;
    task.await.expect("acceptor ends");
    // Streams held anywhere keep the old socket bound, so release all of them.
    drop((b, stream, accepted));

    // The old socket may take a moment to be released after the drop.
    let mut restarted = None;
    for _ in 0..100 {
        let mut config = config(kit_b.identity());
        config.bind = address;
        match crate::endpoint::Tether::bind(config, Arc::new(AllowAll)) {
            Ok(tether) => {
                restarted = Some(tether);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    let b = restarted.expect("rebinding the same address");
    let (mut accepted, _task) = acceptor(&b);

    a.open(
        &Peer {
            id: node("b"),
            address,
        },
        &target,
        b"",
    )
    .await
    .expect("open after restart");
    next(&mut accepted).await;
    assert_eq!(a.outbound_connections(), 1);
    // Whether the old connection had already been noticed as dead or was found out by the
    // open itself, the peer needed exactly one more dial.
    assert_eq!(a.dials_started(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reused_connection_that_turns_out_dead_is_redialed_once() {
    let authority = authority();
    let a = start(&authority.kit("a"));
    let mut server = raw_server(&authority.issue(&[San::Dns("b")]), None).await;
    let peer = Peer {
        id: node("b"),
        address: server.address,
    };

    // Per connection, the responder answers the first stream and kills the connection on
    // the second, after the dialer has already chosen the connection for it.
    let responder = tokio::spawn(async move {
        let mut handled = Vec::new();
        while let Some(connection) = server.connections.recv().await {
            handled.push(tokio::spawn(async move {
                let mut held = None;
                for round in 0..2 {
                    let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                        return;
                    };
                    if wire::read_open(&mut recv).await.is_err() {
                        return;
                    }
                    if round == 0 {
                        wire::write_status(&mut send, Status::Ok)
                            .await
                            .expect("status");
                        // Kept open so the dialer's stream stays healthy.
                        held = Some((send, recv));
                    } else {
                        connection.close(9u8.into(), b"killed");
                    }
                }
                drop(held);
            }));
        }
    });

    let first = a.open(&peer, &target("db"), b"").await.expect("first open");
    assert_eq!(a.dials_started(), 1);
    // Chosen from the table while the connection is still alive, then found dead.
    let second = a.open(&peer, &target("db"), b"").await;
    assert_eq!(a.open_retries(), 1, "the retry branch was not taken");
    assert_eq!(a.dials_started(), 2);
    // The redialed connection is a new one whose first stream the responder answers.
    let _second = second.expect("open on the new connection");
    drop(first);
    responder.abort();
}

/// Runs `work` to completion on a runtime of its own that is gone afterwards.
fn on_temporary_runtime<T: Send + 'static>(
    work: impl std::future::Future<Output = T> + Send + 'static,
) -> T {
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("runtime");
        let result = runtime.block_on(work);
        drop(runtime);
        result
    })
    .join()
    .expect("temporary runtime thread")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_dialed_from_a_short_lived_runtime_keeps_working() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let (a, b) = (start(&kit_a), start(&kit_b));
    let (mut accepted, _task) = acceptor(&b);
    let b_peer = peer(&b);

    // The first open, and so the dial, happens on a runtime that is dropped right after.
    on_temporary_runtime({
        let a = a.clone();
        let b_peer = b_peer.clone();
        async move {
            a.open(&b_peer, &target("db"), b"")
                .await
                .expect("open from the temporary runtime");
        }
    });
    next(&mut accepted).await;

    // The cached connection must still be driven: it carries a new stream and bytes.
    let mut opened = within(a.open(&b_peer, &target("db"), b""))
        .await
        .expect("open after the temporary runtime is gone");
    let mut theirs = next(&mut accepted).await.stream;
    opened.write_all(b"still alive").await.expect("write");
    opened.shutdown().await.expect("shutdown");
    let mut received = Vec::new();
    within(theirs.read_to_end(&mut received))
        .await
        .expect("read");
    assert_eq!(received, b"still alive");
    assert_eq!(a.dials_started(), 1, "the connection was reused");
}

#[tokio::test]
async fn a_dial_dropped_before_its_first_poll_leaves_no_entry() {
    let authority = authority();
    let kit_a = authority.kit("a");
    // An endpoint bound on a runtime nobody drives: whatever it spawns is never polled.
    let idle = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let a = {
        let _entered = idle.enter();
        start(&kit_a)
    };
    let peer = Peer {
        id: node("b"),
        address: "127.0.0.1:9".parse().expect("address"),
    };
    let open = tokio::spawn({
        let a = a.clone();
        async move { a.open(&peer, &target("db"), b"").await }
    });
    eventually("the dial to be registered", || a.dialing() == 1).await;

    // Dropping the runtime drops the spawned dial without it ever having run.
    std::thread::spawn(move || drop(idle))
        .join()
        .expect("runtime dropped");
    assert_eq!(a.dialing(), 0, "the unpolled dial left its entry behind");
    let error = within(open).await.expect("task").err().expect("abandoned");
    assert!(matches!(error, OpenError::Connect(_)), "{error:?}");
}
