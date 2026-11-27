//! Streams that are turned away, and peers that are not who they must be.

use std::{sync::Arc, time::Duration};

use super::{raw::*, support::*};
use crate::{
    endpoint::OpenError,
    wire::{Status, WireError},
};

#[tokio::test(flavor = "multi_thread")]
async fn authorizer_refusal_is_denied_and_never_reaches_the_application() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let a = start(&kit_a);
    let b = start_with(&kit_b, Arc::new(Deny("secret")), |_| {});

    let error = a
        .open(&peer(&b), &target("secret"), b"")
        .await
        .err()
        .expect("denied");
    assert!(
        matches!(error, OpenError::Refused(Status::Denied)),
        "{error:?}"
    );
    assert!(
        next_incoming(&b, Duration::from_millis(300))
            .await
            .is_none()
    );

    // The refusal is about that target; the connection and other targets are unaffected.
    let (mut accepted, _task) = acceptor(&b);
    a.open(&peer(&b), &target("public"), b"")
        .await
        .expect("allowed target");
    assert_eq!(next(&mut accepted).await.target.as_str(), "public");
}

#[tokio::test(flavor = "multi_thread")]
async fn application_rejection_reaches_the_opener() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let (a, b) = (start(&kit_a), start(&kit_b));

    let rejecter = tokio::spawn({
        let b = b.clone();
        async move {
            b.accept()
                .await
                .expect("incoming")
                .reject(Status::Unavailable)
                .await;
            // `Ok` is not a rejection and goes out as `Unavailable`.
            b.accept().await.expect("incoming").reject(Status::Ok).await;
        }
    });
    let first = a
        .open(&peer(&b), &target("db"), b"")
        .await
        .err()
        .expect("rejected");
    assert!(
        matches!(first, OpenError::Refused(Status::Unavailable)),
        "{first:?}"
    );
    let second = a
        .open(&peer(&b), &target("db"), b"")
        .await
        .err()
        .expect("rejected");
    assert!(
        matches!(second, OpenError::Refused(Status::Unavailable)),
        "{second:?}"
    );
    rejecter.await.expect("task");
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_an_incoming_fails_the_opener_with_a_reset() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    // A long header timeout, so a reset that never arrives shows up as `Timeout`.
    let a = start_with(&kit_a, Arc::new(AllowAll), |c| {
        c.header_timeout = Duration::from_secs(10);
    });
    let b = start(&kit_b);

    let dropper = tokio::spawn({
        let b = b.clone();
        async move { drop(b.accept().await.expect("incoming")) }
    });
    let error = within(a.open(&peer(&b), &target("db"), b""))
        .await
        .err()
        .expect("reset");
    assert!(
        matches!(&error, OpenError::Wire(WireError::Io(e)) if e.kind() == std::io::ErrorKind::ConnectionReset),
        "{error:?}"
    );
    dropper.await.expect("task");
}

#[tokio::test(flavor = "multi_thread")]
async fn dialing_with_the_wrong_expected_node_fails_to_connect() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let (a, b) = (start(&kit_a), start(&kit_b));

    let impostor = crate::endpoint::Peer {
        id: node("c"),
        address: b.local_addr().expect("address"),
    };
    let error = a
        .open(&impostor, &target("db"), b"")
        .await
        .err()
        .expect("wrong node");
    assert!(matches!(error, OpenError::Connect(_)), "{error:?}");
    assert_eq!(a.outbound_connections(), 0);
    assert!(
        next_incoming(&b, Duration::from_millis(200))
            .await
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_from_another_authority_cannot_open_streams() {
    let authority = authority();
    let rogue_authority = self::authority();
    let kit_b = authority.kit("b");
    let rogue = start(&rogue_authority.kit("a"));
    let b = start(&kit_b);

    let error = rogue
        .open(&peer(&b), &target("db"), b"")
        .await
        .err()
        .expect("refused");
    assert!(matches!(error, OpenError::Connect(_)), "{error:?}");
    assert!(
        next_incoming(&b, Duration::from_millis(300))
            .await
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dialer_trusting_us_but_certified_elsewhere_is_closed_out() {
    // This is the server-side check: the rogue trusts b's authority, so only b's client
    // certificate verification can stop it.
    let authority = authority();
    let rogue_authority = self::authority();
    let b = start(&authority.kit("b"));
    let rogue_kit = rogue_authority.kit("a");

    let raw = raw_client(
        rogue_kit.client_trusting(&authority.cert_pem),
        b.local_addr().expect("address"),
        "b",
    )
    .await;
    // TLS 1.3 lets the client finish first, so the refusal may arrive as a close instead
    // of a failed handshake; either way it must not linger.
    if let Ok(raw) = raw {
        let reason = within(raw.connection.closed()).await;
        assert!(
            matches!(reason, quinn::ConnectionError::ConnectionClosed(_)),
            "{reason:?}"
        );
    }
    assert!(
        next_incoming(&b, Duration::from_millis(300))
            .await
            .is_none()
    );
    assert_eq!(b.accepted_connections(), 0);
}
