//! Behaviour toward peers that do not follow the header protocol, driven by a raw client.

use std::{sync::Arc, time::Duration};

use super::{raw::*, support::*};
use crate::{
    PROTOCOL_VERSION,
    endpoint::OpenError,
    wire::{MAX_CONTEXT_LEN, Status},
};

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_that_stalls_in_the_header_is_reset_after_the_timeout() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let b = start_with(&kit_b, Arc::new(AllowAll), |c| {
        c.header_timeout = Duration::from_millis(300);
    });
    let raw = raw_to(b.local_addr().expect("address"), &kit_a).await;

    // A stream only exists for the peer once a frame mentions it, so one byte of the
    // magic goes out and the rest never does. Only the header timeout can end this: a
    // reset is not data, EOF or a connection error.
    let (mut send, mut recv) = raw.connection.open_bi().await.expect("stream");
    send.write_all(b"D").await.expect("write");
    let mut byte = [0u8; 1];
    let error = within(recv.read(&mut byte))
        .await
        .expect_err("a reset, not data or EOF");
    assert!(matches!(error, quinn::ReadError::Reset(_)), "{error:?}");
    assert!(
        next_incoming(&b, Duration::from_millis(200))
            .await
            .is_none()
    );
}

async fn answer_to(raw: &Raw, header: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = raw.connection.open_bi().await.expect("stream");
    send.write_all(header).await.expect("write");
    // The responder finishes its side after a refusal, so EOF ends the answer.
    within(recv.read_to_end(1024)).await.expect("answer")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_without_the_magic_is_answered_malformed() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let b = start(&kit_b);
    let raw = raw_to(b.local_addr().expect("address"), &kit_a).await;

    let answer = answer_to(&raw, b"GET / HTTP/1.1\r\n").await;
    assert_eq!(answer, [Status::Malformed as u8]);
    assert!(
        next_incoming(&b, Duration::from_millis(200))
            .await
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_newer_opener_is_told_the_highest_supported_version() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let b = start(&kit_b);
    let raw = raw_to(b.local_addr().expect("address"), &kit_a).await;

    let answer = answer_to(&raw, b"DBTE\x00\x02\x02db\x00\x00").await;
    assert_eq!(
        answer,
        [Status::UnsupportedVersion as u8, 0, PROTOCOL_VERSION as u8]
    );
    assert!(
        next_incoming(&b, Duration::from_millis(200))
            .await
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_overlong_context_announced_on_the_wire_is_answered_malformed() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let b = start(&kit_b);
    let raw = raw_to(b.local_addr().expect("address"), &kit_a).await;

    let mut header = b"DBTE\x00\x01\x02db".to_vec();
    header.extend_from_slice(&(MAX_CONTEXT_LEN as u16 + 1).to_be_bytes());
    // No context bytes follow: the length alone must be enough to refuse.
    let answer = answer_to(&raw, &header).await;
    assert_eq!(answer, [Status::Malformed as u8]);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_opener_surfaces_the_responders_maximum_version() {
    let authority = authority();
    let a = start(&authority.kit("a"));
    let issued = authority.issue(&[San::Dns("b")]);
    let mut server = raw_server(&issued, None).await;
    let address = server.address;
    let responder = tokio::spawn(async move {
        let connection = server.connections.recv().await.expect("connection");
        let (mut send, mut recv) = connection.accept_bi().await.expect("stream");
        let mut header = [0u8; 4 + 2 + 1 + 2 + 2];
        recv.read_exact(&mut header).await.expect("header");
        // A responder that reports 300 as the highest version it supports.
        send.write_all(&[Status::UnsupportedVersion as u8, 0x01, 0x2C])
            .await
            .expect("answer");
        send.finish().expect("finish");
        // Keep the connection until the opener has read the answer.
        let _ = connection.closed().await;
    });

    let error = a
        .open(
            &crate::endpoint::Peer {
                id: node("b"),
                address,
            },
            &target("db"),
            b"",
        )
        .await
        .err()
        .expect("unsupported");
    assert!(
        matches!(error, OpenError::UnsupportedVersion { peer_max: 300 }),
        "{error:?}"
    );
    // The connection is fine; asking again must not redial.
    assert_eq!(a.dials_started(), 1);
    responder.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_status_the_peer_cannot_receive_is_abandoned_at_the_deadline() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let b = start_with(&kit_b, Arc::new(AllowAll), |c| {
        c.header_timeout = Duration::from_millis(300);
    });
    // The raw client advertises no credit at all for data the responder sends it, so even
    // the one-byte status parks in flow control.
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window(quinn::VarInt::from_u32(0));
    let raw = raw_client_with(
        kit_a.identity().client_config().expect("client config"),
        transport,
        b.local_addr().expect("address"),
        "b",
    )
    .await
    .expect("raw handshake");
    let (mut send, mut recv) = raw.connection.open_bi().await.expect("stream");
    send.write_all(b"DBTE\x00\x01\x02db\x00\x00")
        .await
        .expect("header");

    let incoming = within(b.accept()).await.expect("incoming");
    let error = within(incoming.accept())
        .await
        .err()
        .expect("the status cannot be written");
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    // Giving up resets the stream, which the peer does learn about.
    let read = within(recv.read(&mut [0u8; 1])).await.expect_err("reset");
    assert!(matches!(read, quinn::ReadError::Reset(_)), "{read:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_the_peer_cannot_receive_does_not_linger() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let b = start_with(&kit_b, Arc::new(Deny("secret")), |c| {
        c.header_timeout = Duration::from_millis(300);
    });
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window(quinn::VarInt::from_u32(0));
    let raw = raw_client_with(
        kit_a.identity().client_config().expect("client config"),
        transport,
        b.local_addr().expect("address"),
        "b",
    )
    .await
    .expect("raw handshake");
    let (mut send, mut recv) = raw.connection.open_bi().await.expect("stream");
    send.write_all(b"DBTE\x00\x01\x06secret\x00\x00")
        .await
        .expect("header");

    // The denial cannot be delivered; the stream is reset at the deadline instead of
    // staying parked behind flow control for as long as the connection lives.
    let read = within(recv.read(&mut [0u8; 1])).await.expect_err("reset");
    assert!(matches!(read, quinn::ReadError::Reset(_)), "{read:?}");
}
