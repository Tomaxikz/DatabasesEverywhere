//! Data flow over established streams: integrity, isolation and back-pressure.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::support::*;
use crate::endpoint::Stream;

fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// Sends `outgoing` while reading everything the peer sends, then returns what was read.
async fn exchange(stream: Stream, outgoing: Vec<u8>) -> Vec<u8> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let write = async move {
        writer.write_all(&outgoing).await.expect("write");
        writer.shutdown().await.expect("shutdown");
        writer
    };
    let read = async move {
        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.expect("read");
        received
    };
    let (_writer, received) = tokio::join!(write, read);
    received
}

#[tokio::test(flavor = "multi_thread")]
async fn bytes_flow_both_ways_intact() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let (a, b) = (start(&kit_a), start(&kit_b));
    let (mut accepted, _task) = acceptor(&b);

    let opened = a.open(&peer(&b), &target("db"), b"").await.expect("open");
    let theirs = next(&mut accepted).await;
    assert_eq!(theirs.peer, node("a"));

    let from_a = payload(1, 1024 * 1024);
    let from_b = payload(2, 1024 * 1024);
    let (received_by_b, received_by_a) = within(async {
        tokio::join!(
            exchange(theirs.stream, from_b.clone()),
            exchange(opened, from_a.clone())
        )
    })
    .await;
    assert!(
        received_by_b == from_a,
        "b received different bytes than a sent"
    );
    assert!(
        received_by_a == from_b,
        "a received different bytes than b sent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn simultaneous_streams_do_not_mix() {
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let (a, b) = (start(&kit_a), start(&kit_b));
    let (mut accepted, _task) = acceptor(&b);

    // Distinct lengths and seeds, so mixed-up bytes cannot go unnoticed.
    let one = payload(10, 300_000);
    let two = payload(200, 450_000);
    let (peer, one_target, two_target) = (peer(&b), target("one"), target("two"));
    let opened_one = a.open(&peer, &one_target, b"").await.expect("open one");
    let opened_two = a.open(&peer, &two_target, b"").await.expect("open two");
    let (first, second) = (next(&mut accepted).await, next(&mut accepted).await);
    let (theirs_one, theirs_two) = if first.target == one_target {
        (first.stream, second.stream)
    } else {
        (second.stream, first.stream)
    };
    assert_eq!(a.outbound_connections(), 1, "both share one connection");

    let (at_b_one, at_b_two, at_a_one, at_a_two) = within(async {
        tokio::join!(
            exchange(theirs_one, payload(1, 123_456)),
            exchange(theirs_two, payload(2, 234_567)),
            exchange(opened_one, one.clone()),
            exchange(opened_two, two.clone()),
        )
    })
    .await;
    assert!(at_b_one == one && at_b_two == two, "b got mixed bytes");
    assert!(
        at_a_one == payload(1, 123_456) && at_a_two == payload(2, 234_567),
        "a got mixed bytes"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_reader_stalls_the_writer_instead_of_growing_memory() {
    const WINDOW: u32 = 64 * 1024;
    const TOTAL: usize = 16 * WINDOW as usize;
    let authority = authority();
    let (kit_a, kit_b) = (authority.kit("a"), authority.kit("b"));
    let a = start(&kit_a);
    let b = start_with(&kit_b, Arc::new(AllowAll), |c| {
        c.stream_receive_window = WINDOW;
        c.connection_receive_window = 4 * WINDOW;
    });
    let (mut accepted, _task) = acceptor(&b);

    let opened = a.open(&peer(&b), &target("db"), b"").await.expect("open");
    let mut theirs = next(&mut accepted).await.stream;

    let data = payload(7, TOTAL);
    let written = Arc::new(AtomicUsize::new(0));
    let writer = tokio::spawn({
        let (data, written) = (data.clone(), written.clone());
        async move {
            let mut opened = opened;
            for chunk in data.chunks(4096) {
                opened.write_all(chunk).await.expect("write");
                written.fetch_add(chunk.len(), Ordering::SeqCst);
            }
            opened.shutdown().await.expect("shutdown");
            opened
        }
    });

    // Nobody reads yet. The writer must get as far as the receive window allows and then
    // wait for credit; `written` can only exceed the window by what quinn already holds.
    eventually("the writer to fill the receive window", || {
        written.load(Ordering::SeqCst) >= WINDOW as usize / 2
    })
    .await;
    // A regression shows as the writer racing ahead within these few polls; a slow
    // machine can only make the check weaker, never fail it.
    for _ in 0..10 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert!(!writer.is_finished(), "the writer ran ahead of the reader");
        assert!(
            written.load(Ordering::SeqCst) <= 2 * WINDOW as usize,
            "{} bytes accepted with a {WINDOW} byte window and no reader",
            written.load(Ordering::SeqCst)
        );
    }

    // Reading resumes the flow and everything arrives intact.
    let mut received = Vec::new();
    within(theirs.read_to_end(&mut received))
        .await
        .expect("read");
    assert!(received == data, "bytes were lost or reordered");
    let _opened = within(writer).await.expect("writer task");
}
