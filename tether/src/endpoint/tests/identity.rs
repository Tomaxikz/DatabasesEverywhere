//! The dialer's check that whoever answered is exactly the node it asked for.

use std::{sync::Arc, time::Duration};

use super::{raw::*, support::*};
use crate::endpoint::{OpenError, Peer};

const EXPECTED: &str = "does not name exactly the expected node";

async fn dial_server_with(sans: &[San<'_>]) -> (OpenError, crate::endpoint::Tether, RawServer) {
    let authority = authority();
    let a = start_with(&authority.kit("a"), Arc::new(AllowAll), |c| {
        c.header_timeout = Duration::from_millis(500);
    });
    let server = raw_server(&authority.issue(sans), None).await;
    let error = within(a.open(
        &Peer {
            id: node("b"),
            address: server.address,
        },
        &target("db"),
        b"",
    ))
    .await
    .err()
    .expect("the dial must not produce a stream");
    // Handed back so the server, and the connection it holds, outlive the assertions.
    (error, a, server)
}

/// The dial failed because of the certificate, and nothing was published.
async fn assert_refused(sans: &[San<'_>]) {
    let (error, a, _server) = dial_server_with(sans).await;
    assert!(
        matches!(&error, OpenError::Connect(m) if m.contains(EXPECTED)),
        "{error:?}"
    );
    assert_eq!(a.outbound_connections(), 0, "nothing was published");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_certificate_for_two_nodes_is_refused() {
    assert_refused(&[San::Dns("b"), San::Dns("c")]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_certificate_with_other_name_types_is_refused() {
    for extra in [San::Ip("127.0.0.1"), San::Uri("spiffe://cluster/other")] {
        assert_refused(&[San::Dns("b"), extra]).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_certificate_with_an_extra_invalid_name_is_refused() {
    // webpki skips an entry it cannot read as a DNS name, so ordinary verification still
    // accepts this certificate for "b".
    assert_refused(&[San::Dns("b"), San::Dns("Not A Name")]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_check_lets_a_certificate_for_exactly_the_node_through() {
    // Control for the cases above: with a single name the dial is published, and the open
    // only fails later because this raw server never answers the stream.
    let (error, a, _server) = dial_server_with(&[San::Dns("b")]).await;
    assert!(!matches!(error, OpenError::Connect(_)), "{error:?}");
    assert_eq!(a.outbound_connections(), 1);
}
