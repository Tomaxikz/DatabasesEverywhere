//! Deadlines that must hold even when everything is ready, and handshakes that never end.

use std::{io::ErrorKind, sync::Arc, time::Duration};

use super::{raw::*, support::*};

#[tokio::test(flavor = "multi_thread")]
async fn an_answer_after_the_deadline_is_not_sent_even_though_it_could_be() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    // The opener waits far longer than the responder allows, so only the responder's own
    // deadline can stop a late `Ok`.
    let a = start_with(&kit_a, Arc::new(AllowAll), |c| {
        c.header_timeout = Duration::from_secs(20);
    });
    let b = start_with(&kit_b, Arc::new(AllowAll), |c| {
        c.header_timeout = Duration::from_millis(700);
    });
    let open = tokio::spawn({
        let (a, peer) = (a.clone(), peer(&b));
        async move { a.open(&peer, &target("db"), b"").await }
    });
    let incoming = within(b.accept()).await.expect("incoming");

    // Holding it longer can only make the deadline more expired.
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let error = incoming
        .accept()
        .await
        .err()
        .expect("the deadline has passed");
    assert_eq!(error.kind(), ErrorKind::TimedOut);

    let opened = within(open).await.expect("task");
    assert!(opened.is_err(), "the opener was told Ok after the deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn queued_streams_past_their_deadline_are_dropped_instead_of_handed_out() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let a = start_with(&kit_a, Arc::new(AllowAll), |c| {
        c.header_timeout = Duration::from_secs(20);
    });
    let b = start_with(&kit_b, Arc::new(AllowAll), |c| {
        c.header_timeout = Duration::from_millis(300);
    });
    let open = tokio::spawn({
        let (a, peer) = (a.clone(), peer(&b));
        async move { a.open(&peer, &target("db"), b"").await }
    });
    eventually("the request to be queued", || b.queued_incoming() == 1).await;

    // Waiting longer only makes the request more stale.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        next_incoming(&b, Duration::from_millis(500))
            .await
            .is_none(),
        "a stale request reached the application"
    );
    assert_eq!(b.queued_incoming(), 0, "it was dropped from the queue");
    let opened = within(open).await.expect("task");
    assert!(opened.is_err(), "the stale request was answered");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_handshake_that_outlasts_its_timeout_is_abandoned_and_frees_its_permit() {
    let authority = authority();
    let kit_a = authority.kit("a");
    let b = start_with(&authority.kit("b"), Arc::new(AllowAll), |c| {
        c.max_handshakes = 1;
        c.handshake_timeout = Duration::from_secs(1);
    });
    let address = b.local_addr().expect("address");

    // This client never finishes its handshake, as long as the gate stays closed.
    let gate = Gate::closed();
    let _release = gate.release_on_drop();
    let _stalled = stalled_client(
        &authority.kit("c"),
        &authority.cert_pem,
        gate.clone(),
        address,
    );
    eventually("the stalled handshake to take the only permit", || {
        b.handshakes_in_use() == 1
    })
    .await;

    // Only the handshake timeout can return the permit while the gate is closed.
    eventually("the permit to come back", || b.handshakes_in_use() == 0).await;
    assert_eq!(b.accepted_connections(), 0);

    let _legitimate = raw_to(address, &kit_a).await;
    eventually("the legitimate peer to count", || b.live_inbound() == 1).await;
}
