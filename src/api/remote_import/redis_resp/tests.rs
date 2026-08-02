use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const TEST_TIMEOUT: Duration = Duration::from_secs(1);
const TEST_MAX_STREAMED_BULK_LEN: usize = 1024 * 1024;

fn connection(stream: DuplexStream) -> RespConnection {
    RespConnection::from_stream(stream, RespLimits::default(), TEST_TIMEOUT, TEST_TIMEOUT)
}

fn connection_with_limits(stream: DuplexStream, limits: RespLimits) -> RespConnection {
    RespConnection::from_stream(stream, limits, TEST_TIMEOUT, TEST_TIMEOUT)
}

fn encode_command(arguments: &[&[u8]]) -> Vec<u8> {
    let mut encoded = format!("*{}\r\n", arguments.len()).into_bytes();
    for argument in arguments {
        encoded.extend_from_slice(format!("${}\r\n", argument.len()).as_bytes());
        encoded.extend_from_slice(argument);
        encoded.extend_from_slice(b"\r\n");
    }
    encoded
}

async fn read_exact_command(server: &mut DuplexStream, expected: &[u8]) {
    let mut actual = vec![0_u8; expected.len()];
    server.read_exact(&mut actual).await.unwrap();
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn dump_restore_relay_preserves_binary_keys_and_payloads() {
    let key = b"line\r\nnul\0tail";
    let payload = b"\x00\r\n\xff\n\r\0tail";
    let expected_dump = encode_command(&[b"DUMP", key]);
    let expected_restore = encode_command(&[b"RESTORE", key, b"0", payload, b"REPLACE"]);
    let (source_client, mut source_server) = tokio::io::duplex(4096);
    let (target_client, mut target_server) = tokio::io::duplex(4096);

    let source_task = tokio::spawn(async move {
        read_exact_command(&mut source_server, &expected_dump).await;
        source_server
            .write_all(format!("${}\r\n", payload.len()).as_bytes())
            .await
            .unwrap();
        source_server.write_all(payload).await.unwrap();
        source_server.write_all(b"\r\n").await.unwrap();
    });
    let target_task = tokio::spawn(async move {
        read_exact_command(&mut target_server, &expected_restore).await;
        target_server.write_all(b"+OK\r\n").await.unwrap();
    });
    let mut source = connection(source_client);
    let mut target = connection(target_client);

    let restored = source
        .relay_dump_to_restore_replace(
            &mut target,
            key,
            RedisRestoreExpiration::Persistent,
            TEST_MAX_STREAMED_BULK_LEN,
        )
        .await
        .unwrap();

    assert!(restored);
    source_task.await.unwrap();
    target_task.await.unwrap();
}

#[tokio::test]
async fn dump_restore_relay_streams_payload_larger_than_its_buffer_exactly() {
    let key = b"large-key";
    let payload = (0..(RELAY_BUFFER_BYTES * 3 + 137))
        .map(|index| ((index * 131 + 17) % 256) as u8)
        .collect::<Vec<_>>();
    let source_payload = payload.clone();
    let expected_payload = payload;
    let absolute_deadline = 1_900_000_000_123_u64;
    let absolute_deadline = absolute_deadline.to_string();
    let expected_dump = encode_command(&[b"DUMP", key]);
    let mut restore_prefix = format!(
        "*6\r\n$7\r\nRESTORE\r\n$9\r\nlarge-key\r\n${}\r\n",
        absolute_deadline.len()
    )
    .into_bytes();
    restore_prefix.extend_from_slice(absolute_deadline.as_bytes());
    restore_prefix.extend_from_slice(format!("\r\n${}\r\n", expected_payload.len()).as_bytes());
    let (source_client, mut source_server) = tokio::io::duplex(4096);
    let (target_client, mut target_server) = tokio::io::duplex(4096);

    let source_task = tokio::spawn(async move {
        read_exact_command(&mut source_server, &expected_dump).await;
        source_server
            .write_all(format!("${}\r\n", source_payload.len()).as_bytes())
            .await
            .unwrap();
        let split = RELAY_BUFFER_BYTES / 2;
        source_server
            .write_all(&source_payload[..split])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        source_server
            .write_all(&source_payload[split..])
            .await
            .unwrap();
        source_server.write_all(b"\r\n").await.unwrap();
    });
    let target_task = tokio::spawn(async move {
        read_exact_command(&mut target_server, &restore_prefix).await;
        let mut offset = 0;
        let mut buffer = [0_u8; 8191];
        while offset < expected_payload.len() {
            let length = (expected_payload.len() - offset).min(buffer.len());
            target_server
                .read_exact(&mut buffer[..length])
                .await
                .unwrap();
            assert_eq!(
                &buffer[..length],
                &expected_payload[offset..offset + length]
            );
            offset += length;
        }
        read_exact_command(&mut target_server, b"\r\n$7\r\nREPLACE\r\n$6\r\nABSTTL\r\n").await;
        target_server.write_all(b"+OK\r\n").await.unwrap();
    });
    let mut source = connection(source_client);
    let mut target = connection(target_client);

    let restored = source
        .relay_dump_to_restore_replace(
            &mut target,
            key,
            RedisRestoreExpiration::AbsoluteUnixMilliseconds(1_900_000_000_123),
            TEST_MAX_STREAMED_BULK_LEN,
        )
        .await
        .unwrap();

    assert!(restored);
    source_task.await.unwrap();
    target_task.await.unwrap();
}

#[tokio::test]
async fn dump_restore_relay_skips_null_dump_without_touching_target() {
    let key = b"expired";
    let expected_dump = encode_command(&[b"DUMP", key]);
    let (source_client, mut source_server) = tokio::io::duplex(1024);
    let (target_client, mut target_server) = tokio::io::duplex(1024);
    let source_task = tokio::spawn(async move {
        read_exact_command(&mut source_server, &expected_dump).await;
        source_server.write_all(b"$-1\r\n").await.unwrap();
    });
    let mut source = connection(source_client);
    let mut target = connection(target_client);

    let restored = source
        .relay_dump_to_restore_replace(
            &mut target,
            key,
            RedisRestoreExpiration::Persistent,
            TEST_MAX_STREAMED_BULK_LEN,
        )
        .await
        .unwrap();

    assert!(!restored);
    assert!(
        tokio::time::timeout(Duration::from_millis(25), target_server.read_u8())
            .await
            .is_err()
    );
    source_task.await.unwrap();
}

#[tokio::test]
async fn dump_restore_relay_requires_restore_ok() {
    let key = b"key";
    let payload = b"value";
    let expected_dump = encode_command(&[b"DUMP", key]);
    let expected_restore = encode_command(&[b"RESTORE", key, b"0", payload, b"REPLACE"]);
    let (source_client, mut source_server) = tokio::io::duplex(1024);
    let (target_client, mut target_server) = tokio::io::duplex(1024);
    let source_task = tokio::spawn(async move {
        read_exact_command(&mut source_server, &expected_dump).await;
        source_server.write_all(b"$5\r\nvalue\r\n").await.unwrap();
    });
    let target_task = tokio::spawn(async move {
        read_exact_command(&mut target_server, &expected_restore).await;
        target_server.write_all(b"+NOPE\r\n").await.unwrap();
    });
    let mut source = connection(source_client);
    let mut target = connection(target_client);

    let error = source
        .relay_dump_to_restore_replace(
            &mut target,
            key,
            RedisRestoreExpiration::Persistent,
            TEST_MAX_STREAMED_BULK_LEN,
        )
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        RedisRelayError::Target(RedisRespError::UnexpectedResponse {
            operation: "RESTORE",
            ..
        })
    ));
    source_task.await.unwrap();
    target_task.await.unwrap();
}

#[tokio::test]
async fn dump_restore_relay_decouples_streamed_and_control_bulk_limits() {
    let key = b"key";
    let payload = b"123456789";
    let expected_dump = encode_command(&[b"DUMP", key]);
    let expected_restore = encode_command(&[b"RESTORE", key, b"0", payload, b"REPLACE"]);
    let (source_client, mut source_server) = tokio::io::duplex(1024);
    let (target_client, mut target_server) = tokio::io::duplex(1024);
    let source_task = tokio::spawn(async move {
        read_exact_command(&mut source_server, &expected_dump).await;
        source_server
            .write_all(b"$9\r\n123456789\r\n")
            .await
            .unwrap();
    });
    let target_task = tokio::spawn(async move {
        read_exact_command(&mut target_server, &expected_restore).await;
        target_server.write_all(b"+OK\r\n").await.unwrap();
    });
    let control_limits = RespLimits {
        max_bulk_len: 8,
        ..RespLimits::default()
    };
    let mut source = connection_with_limits(source_client, control_limits);
    let mut target = connection_with_limits(target_client, control_limits);

    let restored = source
        .relay_dump_to_restore_replace(
            &mut target,
            key,
            RedisRestoreExpiration::Persistent,
            payload.len(),
        )
        .await
        .unwrap();

    assert!(restored);
    source_task.await.unwrap();
    target_task.await.unwrap();
}

#[tokio::test]
async fn dump_restore_relay_enforces_source_and_target_bulk_limits_before_copying() {
    let key = b"key";
    let expected_dump = encode_command(&[b"DUMP", key]);
    let (source_client, mut source_server) = tokio::io::duplex(1024);
    let (target_client, mut target_server) = tokio::io::duplex(1024);
    let source_task = tokio::spawn(async move {
        read_exact_command(&mut source_server, &expected_dump).await;
        source_server.write_all(b"$9\r\n").await.unwrap();
    });
    let mut source = connection_with_limits(
        source_client,
        RespLimits {
            max_bulk_len: 8,
            ..RespLimits::default()
        },
    );
    let mut target = connection(target_client);

    let error = source
        .relay_dump_to_restore_replace(&mut target, key, RedisRestoreExpiration::Persistent, 8)
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        RedisRelayError::Source(RedisRespError::LimitExceeded {
            limit_name: "streaming bulk length",
            limit: 8
        })
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(25), target_server.read_u8())
            .await
            .is_err()
    );
    source_task.await.unwrap();

    let key = b"nine-byte";
    let expected_dump = encode_command(&[b"DUMP", key]);
    let (source_client, mut source_server) = tokio::io::duplex(1024);
    let (target_client, mut target_server) = tokio::io::duplex(1024);
    let source_task = tokio::spawn(async move {
        read_exact_command(&mut source_server, &expected_dump).await;
        source_server.write_all(b"$1\r\n").await.unwrap();
    });
    let mut source = connection(source_client);
    let mut target = connection_with_limits(
        target_client,
        RespLimits {
            max_bulk_len: 8,
            ..RespLimits::default()
        },
    );

    let error = source
        .relay_dump_to_restore_replace(
            &mut target,
            key,
            RedisRestoreExpiration::Persistent,
            TEST_MAX_STREAMED_BULK_LEN,
        )
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        RedisRelayError::Target(RedisRespError::LimitExceeded {
            limit_name: "outbound bulk length",
            limit: 8
        })
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(25), target_server.read_u8())
            .await
            .is_err()
    );
    source_task.await.unwrap();
}

#[tokio::test]
async fn scan_preserves_binary_keys_and_parses_cursor() {
    let (client, mut server) = tokio::io::duplex(4096);
    let server_task = tokio::spawn(async move {
        let expected = b"*4\r\n$4\r\nSCAN\r\n$1\r\n0\r\n$5\r\nCOUNT\r\n$2\r\n25\r\n";
        read_exact_command(&mut server, expected).await;
        server
            .write_all(b"*2\r\n$2\r\n42\r\n*2\r\n$3\r\na\nb\r\n$3\r\nx\0y\r\n")
            .await
            .unwrap();
    });
    let mut client = connection(client);

    let page = client.scan(0, 25).await.unwrap();

    assert_eq!(page.next_cursor, 42);
    assert_eq!(page.keys, vec![b"a\nb".to_vec(), b"x\0y".to_vec()]);
    server_task.await.unwrap();
}

#[tokio::test]
async fn command_turns_resp_error_into_typed_server_error() {
    let (client, mut server) = tokio::io::duplex(1024);
    let server_task = tokio::spawn(async move {
        read_exact_command(&mut server, b"*1\r\n$4\r\nPING\r\n").await;
        server
            .write_all(b"-WRONGPASS invalid credentials\r\n")
            .await
            .unwrap();
    });
    let mut client = connection(client);

    let error = client.ping().await.unwrap_err();

    assert!(matches!(
        error,
        RedisRespError::Server(message) if message == "WRONGPASS invalid credentials"
    ));
    server_task.await.unwrap();
}

#[tokio::test]
async fn rejects_bulk_array_line_and_nesting_over_limits() {
    assert_limit_error(
        b"$5\r\n",
        RespLimits {
            max_bulk_len: 4,
            ..RespLimits::default()
        },
    )
    .await;
    assert_limit_error(
        b"*2\r\n",
        RespLimits {
            max_array_len: 1,
            ..RespLimits::default()
        },
    )
    .await;
    assert_limit_error(
        b"+abcde\r\n",
        RespLimits {
            max_line_len: 4,
            ..RespLimits::default()
        },
    )
    .await;
    assert_limit_error(
        b"*1\r\n*1\r\n+OK\r\n",
        RespLimits {
            max_nesting: 1,
            ..RespLimits::default()
        },
    )
    .await;
}

async fn assert_limit_error(response: &'static [u8], limits: RespLimits) {
    let (client, mut server) = tokio::io::duplex(1024);
    let server_task = tokio::spawn(async move {
        server.write_all(response).await.unwrap();
    });
    let mut client = RespConnection::from_stream(client, limits, TEST_TIMEOUT, TEST_TIMEOUT);

    let error = client.read_response().await.unwrap_err();

    assert!(matches!(error, RedisRespError::LimitExceeded { .. }));
    server_task.await.unwrap();
}

#[tokio::test]
async fn rejects_bad_bulk_delimiter_and_negative_lengths() {
    let (client, mut server) = tokio::io::duplex(1024);
    let server_task = tokio::spawn(async move {
        server.write_all(b"$3\r\nabcxx").await.unwrap();
    });
    let mut client = connection(client);

    assert!(matches!(
        client.read_response().await.unwrap_err(),
        RedisRespError::Protocol(_)
    ));
    server_task.await.unwrap();

    let (client, mut server) = tokio::io::duplex(1024);
    let server_task = tokio::spawn(async move {
        server.write_all(b"*-2\r\n").await.unwrap();
    });
    let mut client = connection(client);

    assert!(matches!(
        client.read_response().await.unwrap_err(),
        RedisRespError::Protocol(_)
    ));
    server_task.await.unwrap();
}

#[tokio::test]
async fn enforces_total_value_and_response_byte_budgets() {
    assert_limit_error(
        b"*2\r\n+1\r\n+2\r\n",
        RespLimits {
            max_total_values: 2,
            ..RespLimits::default()
        },
    )
    .await;
    assert_limit_error(
        b"$4\r\ndata\r\n",
        RespLimits {
            max_response_bytes: 8,
            ..RespLimits::default()
        },
    )
    .await;
}
