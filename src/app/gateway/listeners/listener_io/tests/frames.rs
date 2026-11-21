use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use proptest::prelude::*;
use tokio_util::io::StreamReader;

use super::*;
use crate::gateway::{
    listeners::listener_io::mysql::{INLINE_SQL_BYTES, MAX_SQL_SCANS, SQL_SCAN_SLOTS},
    sessions::TenantSessions,
};

// Record successful transport operations so the small-frame fast path can be
// checked without depending on socket scheduling or wall-clock timings.
struct Burst<'a> {
    bytes: &'a [u8],
    reads: usize,
}

impl AsyncRead for Burst<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let n = buf.remaining().min(self.bytes.len());
        buf.put_slice(&self.bytes[..n]);
        self.bytes = &self.bytes[n..];
        self.reads += usize::from(n != 0);
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct Writes(Vec<Vec<u8>>);

impl AsyncWrite for Writes {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.push(bytes.to_vec());
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn forward_frames(
    protocol: Protocol,
    client: impl AsyncRead + AsyncWrite + Unpin,
    backend: impl AsyncRead + AsyncWrite + Unpin,
    activity: Arc<ActivityCounter>,
) -> Result<(), ListenerError> {
    match protocol {
        Protocol::Postgres => proxy_postgres_session(client, backend, activity).await,
        Protocol::Mongodb => proxy_mongodb_session(client, backend, activity).await,
        Protocol::Mysql | Protocol::Mariadb => {
            proxy_mysql_session(
                client,
                backend,
                protocol,
                protocol == Protocol::Mariadb,
                activity,
                Default::default(),
            )
            .await
        }
        _ => unreachable!("test only exercises framed protocols"),
    }
}

fn read_query_frame(protocol: Protocol, value: u16) -> Vec<u8> {
    match protocol {
        Protocol::Postgres => postgres_frame(b'Q', format!("SELECT {value}\0").as_bytes()),
        Protocol::Mysql | Protocol::Mariadb => {
            mysql_packet(0, format!("\x03SELECT {value}").as_bytes())
        }
        Protocol::Mongodb => {
            mongodb_message(bson::doc! { "find": "items", "limit": i32::from(value) })
        }
        _ => unreachable!("test only exercises framed protocols"),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]
    #[test]
    fn fragmented_frames_preserve_payload_and_order(
        values in prop::collection::vec(any::<u16>(), 1..6),
        chunk_sizes in prop::collection::vec(1usize..32, 1..16),
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        for protocol in [Protocol::Postgres, Protocol::Mysql, Protocol::Mariadb, Protocol::Mongodb] {
            let frames: Vec<u8> = values.iter().flat_map(|&v| read_query_frame(protocol, v)).collect();
            let mut remaining = frames.as_slice();
            let chunks = chunk_sizes.iter().cycle().map_while(|&size| {
                if remaining.is_empty() {
                    return None;
                }
                let (chunk, rest) = remaining.split_at(size.min(remaining.len()));
                remaining = rest;
                Some(Ok::<_, io::Error>(chunk))
            });
            let client = io::join(StreamReader::new(futures::stream::iter(chunks)), io::sink());
            let mut backend = io::join(io::empty(), Vec::new());
            let activity = activity();
            runtime.block_on(forward_frames(protocol, client, &mut backend, activity.clone())).unwrap();
            prop_assert_eq!(backend.writer(), &frames, "protocol {}", protocol);
            prop_assert_eq!(activity.snapshot().accepted.read, values.len() as u64);
        }
    }
}

#[tokio::test]
async fn small_pipelined_frames_share_a_read_and_each_use_one_backend_write() {
    for (protocol, frame) in [
        (Protocol::Postgres, postgres_frame(b'Q', b"SELECT 1\0")),
        (Protocol::Mysql, mysql_packet(0, b"\x03SELECT 1")),
        (Protocol::Mariadb, mysql_packet(0, b"\x16SELECT 1")),
        (
            Protocol::Mongodb,
            mongodb_message(bson::doc! { "find": "items" }),
        ),
    ] {
        let bytes = frame.repeat(2);
        let mut client = io::join(
            Burst {
                bytes: &bytes,
                reads: 0,
            },
            io::sink(),
        );
        let mut backend = io::join(io::empty(), Writes::default());
        let activity = activity();
        forward_frames(protocol, &mut client, &mut backend, activity.clone())
            .await
            .unwrap();
        assert_eq!(client.reader().reads, 1, "{protocol}");
        assert_eq!(backend.writer().0, [frame.clone(), frame], "{protocol}");
        assert_eq!(activity.snapshot().accepted.read, 2);
    }
}

#[tokio::test]
async fn slow_postgres_upload_forwards_header_and_allows_replies_before_body() {
    let (mut client, gateway_client) = io::duplex(32);
    let (gateway_backend, mut backend) = io::duplex(2);
    let activity = activity();
    let proxy = tokio::spawn(proxy_postgres_session(
        gateway_client,
        gateway_backend,
        activity.clone(),
    ));
    let header = [b'Q', 0, 0, 1, 0];
    client.write_all(&header).await.unwrap();
    let mut forwarded = [0; 5];
    tokio::time::timeout(Duration::from_secs(2), backend.read_exact(&mut forwarded))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(forwarded, header);
    backend.write_all(b"!").await.unwrap();
    assert_eq!(client.read_u8().await.unwrap(), b'!');
    client.shutdown().await.unwrap();
    assert!(
        matches!(proxy.await.unwrap(), Err(ListenerError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof)
    );
    assert_eq!(activity.snapshot().accepted.other, 0);
    assert_eq!(activity.snapshot().accepted.read, 0);
}

#[tokio::test]
async fn dedicated_mysql_counts_a_full_size_query_only_after_its_final_packet() {
    let start = b"\xff\xff\xff\x00\x03SELECT ";
    let padding = (MYSQL_MAX_SINGLE_PACKET_PAYLOAD + 4 - start.len()) as u64;
    for (end, expected_reads) in [(&[][..], 0), (&[0, 0, 0, 1][..], 1)] {
        let stream = start
            .as_slice()
            .chain(io::repeat(b' ').take(padding))
            .chain(end);
        let activity = activity();
        proxy_mysql_session(
            io::join(stream, io::sink()),
            io::join(io::empty(), io::sink()),
            Protocol::Mysql,
            false,
            activity.clone(),
            Default::default(),
        )
        .await
        .unwrap();
        assert_eq!(activity.snapshot().accepted.read, expected_reads);
    }
}

#[tokio::test]
async fn large_shared_packets_are_validated_and_forwarded_in_order() {
    let mut payload = vec![MYSQL_COM_QUERY];
    payload.resize(INLINE_SQL_BYTES + 2, b' ');
    payload.extend_from_slice(b"SELECT 1");
    let allowed = mysql_packet(0, &payload);
    payload[0] = MYSQL_COM_STMT_PREPARE;
    payload.extend_from_slice(b"; DROP DATABASE other");
    let mut pipeline = allowed.clone();
    pipeline.extend_from_slice(&mysql_packet(0, &payload));
    let client = io::join(pipeline.as_slice(), io::sink());
    let mut backend = io::join(io::empty(), Vec::new());
    let activity = activity();
    let result = proxy_mysql_session(
        client,
        &mut backend,
        Protocol::Mariadb,
        true,
        activity.clone(),
        Default::default(),
    )
    .await;
    assert!(matches!(
        result,
        Err(ListenerError::Mariadb(
            mariadb::MariadbProxyError::SharedStorageCommandRejected(_)
        ))
    ));
    assert_eq!(backend.writer(), &allowed);
    assert_eq!(activity.snapshot().accepted.read, 1);
    assert_eq!(activity.snapshot().rejected.read, 1);
}

#[tokio::test]
async fn waiting_for_scan_capacity_respects_session_cancellation_and_deadline() {
    let _busy = SQL_SCAN_SLOTS
        .acquire_many(MAX_SQL_SCANS as u32)
        .await
        .unwrap();
    tokio::time::pause();
    for cancel in [true, false] {
        let sessions = TenantSessions::default();
        let (gateway_backend, mut backend) = io::duplex(32);
        let metered = tunnel::MeteredBackend::new(
            gateway_backend,
            Default::default(),
            sessions.open("tenant"),
        );
        let budget = metered.query_budget();
        let mut payload = vec![MYSQL_COM_QUERY];
        payload.resize(INLINE_SQL_BYTES + 2, b' ');
        let packet = mysql_packet(0, &payload);
        let client = io::join(packet.as_slice(), io::sink());
        let proxy = proxy_mysql_session(
            client,
            metered,
            Protocol::Mysql,
            true,
            activity(),
            budget.clone(),
        );
        let mut proxy = Box::pin(proxy);
        assert!(futures::poll!(&mut proxy).is_pending());
        assert!(budget.reserve(32 * 1024 * 1024).is_err());
        let expected = if cancel {
            assert_eq!(sessions.cancel("tenant"), 1);
            io::ErrorKind::ConnectionAborted
        } else {
            tokio::time::advance(QUERY_BODY_TIMEOUT).await;
            io::ErrorKind::TimedOut
        };
        assert!(matches!(proxy.await, Err(ListenerError::Io(e)) if e.kind() == expected));
        assert!(budget.reserve(32 * 1024 * 1024).is_ok());
        assert_eq!(backend.read(&mut [0]).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn mongodb_cstring_terminator_must_fit_inside_both_bounds() {
    for name_len in [MONGODB_MAX_CSTRING_BYTES - 1, MONGODB_MAX_CSTRING_BYTES] {
        let name = "x".repeat(name_len);
        let message = mongodb_message(bson::doc! { name: 1 });
        let mut reader = BufReader::with_capacity(7, message.as_slice());
        let result = read_mongodb_prefix(&mut reader, &mut Vec::new()).await;
        assert_eq!(result.is_ok(), name_len < MONGODB_MAX_CSTRING_BYTES);
    }

    let mut message = mongodb_message(bson::doc! { "find": "items" });
    // End the declared frame in the middle of the key. The following NUL
    // belongs outside this frame even if it has arrived in the same read.
    message[..4].copy_from_slice(&28_i32.to_le_bytes());
    message[21..25].copy_from_slice(&7_i32.to_le_bytes());
    let mut reader = message.as_slice();
    assert!(
        read_mongodb_prefix(&mut reader, &mut Vec::new())
            .await
            .is_err()
    );
    assert_eq!(reader, &message[28..]);
}
