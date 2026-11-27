//! Stream setup, the request context and the lifetime of a single stream.

use std::io::ErrorKind;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::support::*;
use crate::{endpoint::OpenError, wire::MAX_CONTEXT_LEN};

#[tokio::test(flavor = "multi_thread")]
async fn incoming_names_the_opener_the_target_and_the_context() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let (a, b) = (start(&kit_a), start(&kit_b));

    let open = tokio::spawn({
        let a = a.clone();
        let peer = peer(&b);
        async move {
            a.open(
                &peer,
                &target("orders.primary"),
                b"tenant=7;client=10.0.0.9",
            )
            .await
        }
    });
    let incoming = within(b.accept()).await.expect("incoming stream");
    assert_eq!(incoming.peer(), &node("a"));
    assert_eq!(incoming.target().as_str(), "orders.primary");
    assert_eq!(incoming.context(), b"tenant=7;client=10.0.0.9");
    let _theirs = incoming.accept().await.expect("accept");
    let _opened = open.await.expect("task").expect("open");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_authorizer_sees_the_context() {
    struct NeedsTenant;
    impl crate::endpoint::Authorizer for NeedsTenant {
        fn allows(&self, _: &crate::NodeId, _: &crate::TargetId, context: &[u8]) -> bool {
            context == b"tenant=7"
        }
    }
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let a = start(&kit_a);
    let b = start_with(&kit_b, std::sync::Arc::new(NeedsTenant), |_| {});
    let (mut accepted, _task) = acceptor(&b);

    let error = a
        .open(&peer(&b), &target("db"), b"tenant=8")
        .await
        .err()
        .expect("denied");
    assert!(
        matches!(error, OpenError::Refused(crate::wire::Status::Denied)),
        "{error:?}"
    );
    a.open(&peer(&b), &target("db"), b"tenant=7")
        .await
        .expect("allowed");
    assert_eq!(next(&mut accepted).await.context, b"tenant=7");
}

#[tokio::test(flavor = "multi_thread")]
async fn context_round_trips_up_to_the_maximum_and_not_beyond() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let (a, b) = (start(&kit_a), start(&kit_b));
    let (mut accepted, _task) = acceptor(&b);

    for context in [Vec::new(), vec![0u8; 1], vec![0xA5; MAX_CONTEXT_LEN]] {
        let _stream = a
            .open(&peer(&b), &target("db"), &context)
            .await
            .expect("open");
        assert_eq!(next(&mut accepted).await.context, context);
    }

    let dials = a.dials_started();
    let error = a
        .open(&peer(&b), &target("db"), &vec![0; MAX_CONTEXT_LEN + 1])
        .await
        .err()
        .expect("one over");
    assert!(matches!(error, OpenError::ContextTooLong), "{error:?}");
    assert_eq!(a.dials_started(), dials, "refused before any dialing");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_overlong_context_is_refused_before_dialing() {
    let authority = authority();
    let a = start(&authority.kit("a"));
    let nowhere = crate::endpoint::Peer {
        id: node("b"),
        address: "127.0.0.1:9".parse().expect("address"),
    };
    let error = a
        .open(&nowhere, &target("db"), &vec![0; MAX_CONTEXT_LEN + 1])
        .await
        .err()
        .expect("refused");
    assert!(matches!(error, OpenError::ContextTooLong), "{error:?}");
    assert_eq!(a.dials_started(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn shutting_down_the_write_side_keeps_the_read_side_open() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let (a, b) = (start(&kit_a), start(&kit_b));
    let (mut accepted, _task) = acceptor(&b);

    let mut opened = a.open(&peer(&b), &target("db"), b"").await.expect("open");
    let mut theirs = next(&mut accepted).await.stream;

    opened.write_all(b"request").await.expect("write");
    opened.shutdown().await.expect("shutdown");
    // Shutting down again is not an error.
    opened.shutdown().await.expect("second shutdown");

    let mut request = Vec::new();
    within(theirs.read_to_end(&mut request))
        .await
        .expect("b reads to EOF");
    assert_eq!(request, b"request");

    theirs
        .write_all(b"response")
        .await
        .expect("b can still write");
    theirs.shutdown().await.expect("shutdown");
    let mut response = Vec::new();
    within(opened.read_to_end(&mut response))
        .await
        .expect("a reads");
    assert_eq!(response, b"response");

    let error = opened
        .write_all(b"more")
        .await
        .expect_err("write after shutdown");
    assert_eq!(error.kind(), ErrorKind::BrokenPipe);
}

#[tokio::test(flavor = "multi_thread")]
async fn shutting_down_a_stream_the_peer_already_reset_reports_it_once() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let (a, b) = (start(&kit_a), start(&kit_b));
    let (mut accepted, _task) = acceptor(&b);

    let mut opened = a.open(&peer(&b), &target("db"), b"").await.expect("open");
    let theirs = next(&mut accepted).await.stream;
    drop(theirs);

    // The reset has to arrive before finishing the send side can fail; reading sees it.
    let mut buffer = [0u8; 1];
    let read = within(opened.read(&mut buffer)).await;
    assert_eq!(read.expect_err("reset").kind(), ErrorKind::ConnectionReset);

    // quinn treats a stopped stream as harmless at finish, so this must not be an error
    // for a stream that is merely stopped...
    opened.shutdown().await.expect("first shutdown");
    // ...and a repeat is always fine.
    opened.shutdown().await.expect("second shutdown");
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_a_stream_resets_the_other_side() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let (a, b) = (start(&kit_a), start(&kit_b));
    let (mut accepted, _task) = acceptor(&b);

    let opened = a.open(&peer(&b), &target("db"), b"").await.expect("open");
    let mut theirs = next(&mut accepted).await.stream;
    drop(opened);

    // A reset is what ends the read; waiting out the idle timeout would be a different
    // error kind.
    let mut buffer = [0u8; 16];
    let read = within(theirs.read(&mut buffer))
        .await
        .expect_err("a reset is an error, not EOF");
    assert_eq!(read.kind(), ErrorKind::ConnectionReset);

    let write: std::io::Result<()> = within(async {
        loop {
            theirs.write_all(b"x").await?;
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert_eq!(
        write.expect_err("peer stopped reading").kind(),
        ErrorKind::ConnectionReset
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn delivered_resolves_once_the_peer_has_all_the_data_and_fails_if_it_stops() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let (a, b) = (start(&kit_a), start(&kit_b));
    let (mut accepted, _task) = acceptor(&b);

    let mut opened = a.open(&peer(&b), &target("db"), b"").await.expect("open");
    let mut theirs = next(&mut accepted).await.stream;
    opened.write_all(b"tail").await.expect("write");
    // Not finished yet, so nothing can be acknowledged to completion.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(200), opened.delivered())
            .await
            .is_err()
    );
    opened.shutdown().await.expect("shutdown");
    within(opened.delivered()).await.expect("delivered");
    let mut received = Vec::new();
    within(theirs.read_to_end(&mut received))
        .await
        .expect("read");
    assert_eq!(received, b"tail");

    // A peer that drops the stream unread stops it instead of acknowledging.
    let mut opened = a.open(&peer(&b), &target("db"), b"").await.expect("open");
    let theirs = next(&mut accepted).await.stream;
    drop(theirs);
    let _ = opened.write_all(b"lost").await;
    let _ = opened.shutdown().await;
    let error = within(opened.delivered()).await.expect_err("stopped");
    assert_eq!(error.kind(), ErrorKind::ConnectionReset);
}
