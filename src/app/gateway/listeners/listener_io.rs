use std::sync::Arc;
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsAcceptor;

const MYSQL_COM_CHANGE_USER: u8 = 0x11;
const MYSQL_COM_CREATE_DB: u8 = 0x05;
const MYSQL_COM_DROP_DB: u8 = 0x06;
const MYSQL_COM_QUERY: u8 = 0x03;
const MYSQL_COM_STMT_PREPARE: u8 = 0x16;
const MYSQL_COM_STMT_EXECUTE: u8 = 0x17;
const MYSQL_MAX_SINGLE_PACKET_PAYLOAD: usize = 0x00ff_ffff;
const MONGODB_OP_QUERY: i32 = 2004;
const MONGODB_OP_COMPRESSED: i32 = 2012;
const MONGODB_OP_MSG: i32 = 2013;
const MONGODB_MAX_CSTRING_BYTES: usize = 1024;

use super::{GatewayStream, ListenerError};
use crate::{
    api::import_export::inspection::validate_shared_mysql_command,
    gateway::tunnel,
    monitoring::{ActivityCounter, OperationKind},
    protocols::{clickhouse, mariadb, redis},
    shared::protocol::Protocol,
};

const MAX_HANDSHAKE_BYTES: usize = 64 * 1024;
const SQL_PREFIX_BYTES: usize = 512;
const QUERY_BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub(super) type MysqlTunnel = (
    GatewayStream,
    tunnel::MeteredBackend<tunnel::BackendStream>,
    bool,
    Arc<ActivityCounter>,
);
pub(super) type MongodbTunnel = (
    GatewayStream,
    tunnel::MeteredBackend<tunnel::BackendStream>,
    Arc<ActivityCounter>,
);

struct ActivitySession(Arc<ActivityCounter>);

impl ActivitySession {
    fn open(counter: Arc<ActivityCounter>) -> Self {
        counter.connection_opened();
        Self(counter)
    }
}

impl Drop for ActivitySession {
    fn drop(&mut self) {
        self.0.connection_closed();
    }
}

pub(super) async fn read_clickhouse_hello<S>(client: &mut S) -> Result<Vec<u8>, ListenerError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut buffer = Vec::with_capacity(256);
    let mut chunk = [0_u8; 128];
    loop {
        let read = client.read(&mut chunk).await?;
        if read == 0 {
            return Err(clickhouse::ClickhouseParseError::IncompleteNativeHello.into());
        }
        buffer.extend_from_slice(&chunk[..read]);
        match clickhouse::parse_native_initial_route(&buffer) {
            Ok(_) => return Ok(buffer),
            Err(clickhouse::ClickhouseParseError::IncompleteNativeHello) => {}
            Err(error) => return Err(error.into()),
        }
        if buffer.len() > MAX_HANDSHAKE_BYTES {
            return Err(clickhouse::ClickhouseParseError::InvalidNativeHello.into());
        }
    }
}

pub(super) async fn read_resp_initial_frame<S>(
    client: &mut S,
) -> Result<(redis::RedisRoute, Vec<u8>, usize), ListenerError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut buffer = Vec::with_capacity(256);
    let mut chunk = [0_u8; 256];
    loop {
        let read = client.read(&mut chunk).await?;
        if read == 0 {
            return Err(redis::RedisParseError::Incomplete.into());
        }
        buffer.extend_from_slice(&chunk[..read]);
        match redis::parse_initial_frame_route(&buffer) {
            Ok(Some((route, consumed))) => return Ok((route, buffer, consumed)),
            Ok(None) => {}
            Err(error) => return Err(error.into()),
        }
        if buffer.len() > MAX_HANDSHAKE_BYTES {
            return Err(redis::RedisParseError::Unsupported.into());
        }
    }
}

pub(super) async fn read_http_headers<S>(client: &mut S) -> Result<Vec<u8>, ListenerError>
where
    S: AsyncRead + Unpin + ?Sized,
{
    let mut buffer = Vec::with_capacity(2048);
    let mut chunk = [0_u8; 1024];
    let mut scan_from = 0;
    loop {
        let read = client.read(&mut chunk).await?;
        if read == 0 {
            return Err(clickhouse::ClickhouseParseError::IncompleteHttpRequest.into());
        }
        let previous_len = buffer.len();
        buffer.extend_from_slice(&chunk[..read]);
        scan_from = scan_from.min(previous_len.saturating_sub(3));
        if buffer[scan_from..]
            .windows(4)
            .any(|window| window == b"\r\n\r\n")
        {
            return Ok(buffer);
        }
        scan_from = buffer.len().saturating_sub(3);
        if buffer.len() > MAX_HANDSHAKE_BYTES {
            return Err(clickhouse::ClickhouseParseError::InvalidHttpRequest.into());
        }
    }
}

pub(super) async fn accept_direct_tls(
    client: TcpStream,
    tls: Option<TlsAcceptor>,
) -> Result<GatewayStream, std::io::Error> {
    if let Some(tls) = tls {
        Ok(GatewayStream::Tls(Box::new(tls.accept(client).await?)))
    } else {
        Ok(GatewayStream::Plain(client))
    }
}

/// Proxies an authenticated MySQL-family session while retaining the routed
/// tenant identity. Shared tenants additionally validate complete text-query
/// and prepared-statement packets before any byte reaches the backend.
pub(super) async fn proxy_mysql_session<C, B>(
    client: C,
    backend: B,
    protocol: Protocol,
    shared: bool,
    activity: Arc<ActivityCounter>,
    buffers: crate::gateway::buffers::QueryBudget,
) -> Result<(), ListenerError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let _activity_session = ActivitySession::open(Arc::clone(&activity));
    let (mut client_read, mut client_write) = io::split(client);
    let (mut backend_read, mut backend_write) = io::split(backend);
    let upload = async {
        let mut continued_command = None;
        loop {
            let mut header = [0_u8; 4];
            let read = client_read.read(&mut header[..1]).await?;
            if read == 0 {
                backend_write.shutdown().await?;
                return Ok::<(), ListenerError>(());
            }
            client_read.read_exact(&mut header[1..]).await?;
            let payload_len = usize::from(header[0])
                | (usize::from(header[1]) << 8)
                | (usize::from(header[2]) << 16);
            if header[3] == 0 {
                continued_command = None;
            }
            if payload_len == 0 {
                backend_write.write_all(&header).await?;
                if header[3] != 0
                    && let Some(kind) = continued_command.take()
                {
                    activity.accept(kind);
                }
                continue;
            }
            let mut first = [0_u8; 1];
            client_read.read_exact(&mut first).await?;
            if header[3] == 0 && first[0] == MYSQL_COM_CHANGE_USER {
                activity.reject_kind(OperationKind::Other);
                return Err(ListenerError::IdentitySwitchRejected {
                    protocol: protocol.as_str(),
                });
            }
            // A command-phase packet always resets the sequence id to zero.
            // Nonzero packets can contain arbitrary continuation or LOCAL
            // INFILE bytes, so their first payload byte is not a command.
            if shared
                && header[3] == 0
                && matches!(first[0], MYSQL_COM_CREATE_DB | MYSQL_COM_DROP_DB)
            {
                activity.reject_kind(OperationKind::Ddl);
                return Err(mariadb::MariadbProxyError::SharedStorageCommandRejected(
                    "raw database create/drop commands are unavailable to shared tenants"
                        .to_string(),
                )
                .into());
            }
            if shared
                && header[3] == 0
                && matches!(first[0], MYSQL_COM_QUERY | MYSQL_COM_STMT_PREPARE)
            {
                if payload_len == MYSQL_MAX_SINGLE_PACKET_PAYLOAD {
                    activity.reject_kind(OperationKind::Other);
                    return Err(mariadb::MariadbProxyError::SharedStorageCommandRejected(
                        "SQL command exceeds the bounded single-packet policy".to_string(),
                    )
                    .into());
                }
                let _reservation = buffers.reserve(payload_len)?;
                tokio::time::timeout(QUERY_BODY_TIMEOUT, async {
                    let mut payload = Vec::with_capacity(payload_len);
                    payload.push(first[0]);
                    payload.resize(payload_len, 0);
                    client_read.read_exact(&mut payload[1..]).await?;
                    if let Err(error) = validate_shared_mysql_command(&payload[1..], protocol) {
                        activity.reject_kind(classify_sql(&payload[1..]));
                        return Err(ListenerError::Mariadb(
                            mariadb::MariadbProxyError::SharedStorageCommandRejected(
                                error.to_string(),
                            ),
                        ));
                    }
                    backend_write.write_all(&header).await?;
                    backend_write.write_all(&payload).await?;
                    activity.accept(classify_sql(&payload[1..]));
                    Ok::<(), ListenerError>(())
                })
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "shared SQL command transfer timed out",
                    )
                })??;
                continue;
            }
            backend_write.write_all(&header).await?;
            backend_write.write_all(&first).await?;
            let command = (header[3] == 0).then_some(first[0]);
            let remaining = payload_len - 1;
            let prefix_len = remaining.min(SQL_PREFIX_BYTES);
            let mut prefix = [0_u8; SQL_PREFIX_BYTES];
            client_read.read_exact(&mut prefix[..prefix_len]).await?;
            backend_write.write_all(&prefix[..prefix_len]).await?;
            copy_exact(
                &mut client_read,
                &mut backend_write,
                remaining - prefix_len,
                "mysql client packet ended before its declared length",
            )
            .await?;

            let kind = match command {
                Some(MYSQL_COM_QUERY | MYSQL_COM_STMT_PREPARE) => {
                    Some(classify_sql(&prefix[..prefix_len]))
                }
                Some(MYSQL_COM_STMT_EXECUTE) => Some(OperationKind::Other),
                _ => None,
            };
            if let Some(kind) = kind {
                if payload_len == MYSQL_MAX_SINGLE_PACKET_PAYLOAD {
                    continued_command = Some(kind);
                } else {
                    activity.accept(kind);
                }
            } else if header[3] != 0
                && payload_len < MYSQL_MAX_SINGLE_PACKET_PAYLOAD
                && let Some(kind) = continued_command.take()
            {
                activity.accept(kind);
            }
        }
    };
    let download = async {
        io::copy(&mut backend_read, &mut client_write).await?;
        client_write.shutdown().await?;
        Ok::<(), ListenerError>(())
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

/// Keeps a successfully authenticated MongoDB socket bound to the identity
/// that acquired its tenant session. Messages are streamed after inspecting
/// only the bounded command prefix, so normal 16 MiB writes are not buffered.
pub(super) async fn proxy_mongodb_session<C, B>(
    client: C,
    backend: B,
    activity: Arc<ActivityCounter>,
) -> Result<(), ListenerError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let _activity_session = ActivitySession::open(Arc::clone(&activity));
    let (mut client_read, mut client_write) = io::split(client);
    let (mut backend_read, mut backend_write) = io::split(backend);
    let upload = async {
        loop {
            let parsed = read_mongodb_prefix(&mut client_read).await;
            let Some((prefix, message_len, command)) = (match parsed {
                Ok(parsed) => parsed,
                Err(error @ ListenerError::IdentitySwitchRejected { .. }) => {
                    activity.reject_kind(OperationKind::Other);
                    return Err(error);
                }
                Err(error) => return Err(error),
            }) else {
                backend_write.shutdown().await?;
                return Ok::<(), ListenerError>(());
            };
            backend_write.write_all(&prefix).await?;
            copy_exact(
                &mut client_read,
                &mut backend_write,
                message_len - prefix.len(),
                "mongodb client message ended before its declared length",
            )
            .await?;
            if let Some(command) = command {
                activity.accept(classify_mongodb(&command));
            }
        }
    };
    let download = async {
        io::copy(&mut backend_read, &mut client_write).await?;
        client_write.shutdown().await?;
        Ok::<(), ListenerError>(())
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

async fn read_mongodb_prefix(
    reader: &mut (impl AsyncRead + Unpin),
) -> Result<Option<(Vec<u8>, usize, Option<Vec<u8>>)>, ListenerError> {
    let mut header = [0_u8; 16];
    if reader.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..]).await?;
    let message_len = i32::from_le_bytes(header[..4].try_into().unwrap());
    if !(16..=crate::protocols::mongodb::MAX_WIRE_MESSAGE_BYTES as i32).contains(&message_len) {
        return Err(crate::protocols::mongodb::MongodbProxyError::MalformedMessage.into());
    }
    let message_len = message_len as usize;
    let opcode = i32::from_le_bytes(header[12..16].try_into().unwrap());
    if opcode == MONGODB_OP_COMPRESSED {
        return Err(ListenerError::IdentitySwitchRejected {
            protocol: "mongodb",
        });
    }

    let mut prefix = header.to_vec();
    let command = match opcode {
        MONGODB_OP_MSG => {
            append_exact(reader, &mut prefix, 5, message_len).await?;
            if prefix[20] != 0 {
                return Err(crate::protocols::mongodb::MongodbProxyError::MalformedMessage.into());
            }
            Some(read_mongodb_command_key(reader, &mut prefix, message_len).await?)
        }
        MONGODB_OP_QUERY => {
            append_exact(reader, &mut prefix, 4, message_len).await?;
            let collection = append_cstring(reader, &mut prefix, message_len).await?;
            append_exact(reader, &mut prefix, 8, message_len).await?;
            let command = read_mongodb_command_key(reader, &mut prefix, message_len).await?;
            collection.ends_with(b".$cmd").then_some(command)
        }
        _ => None,
    };
    if command.as_deref().is_some_and(is_mongodb_identity_command) {
        return Err(ListenerError::IdentitySwitchRejected {
            protocol: "mongodb",
        });
    }
    Ok(Some((prefix, message_len, command)))
}

/// Proxies authenticated PostgreSQL frontend frames without buffering query
/// bodies. Only complete Query and Execute messages affect activity counters.
pub(super) async fn proxy_postgres_session<C, B>(
    client: C,
    backend: B,
    activity: Arc<ActivityCounter>,
) -> Result<(), ListenerError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let _activity_session = ActivitySession::open(Arc::clone(&activity));
    let (mut client_read, mut client_write) = io::split(client);
    let (mut backend_read, mut backend_write) = io::split(backend);
    let upload = async {
        loop {
            let mut header = [0_u8; 5];
            if client_read.read(&mut header[..1]).await? == 0 {
                backend_write.shutdown().await?;
                return Ok::<(), ListenerError>(());
            }
            client_read.read_exact(&mut header[1..]).await?;
            let len = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
            if len < 4 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "postgres frontend message length is smaller than its header",
                )
                .into());
            }
            backend_write.write_all(&header).await?;
            let remaining = len - 4;
            let prefix_len = remaining.min(SQL_PREFIX_BYTES);
            let mut prefix = [0_u8; SQL_PREFIX_BYTES];
            client_read.read_exact(&mut prefix[..prefix_len]).await?;
            backend_write.write_all(&prefix[..prefix_len]).await?;
            copy_exact(
                &mut client_read,
                &mut backend_write,
                remaining - prefix_len,
                "postgres frontend message ended before its declared length",
            )
            .await?;
            match header[0] {
                b'Q' => activity.accept(classify_sql(&prefix[..prefix_len])),
                b'E' => activity.accept(OperationKind::Other),
                _ => {}
            }
        }
    };
    let download = async {
        io::copy(&mut backend_read, &mut client_write).await?;
        client_write.shutdown().await?;
        Ok::<(), ListenerError>(())
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

async fn copy_exact(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    bytes: usize,
    eof: &'static str,
) -> Result<(), ListenerError> {
    let mut payload = reader.take(bytes as u64);
    if io::copy(&mut payload, writer).await? != bytes as u64 {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, eof).into());
    }
    Ok(())
}

fn classify_sql(sql: &[u8]) -> OperationKind {
    let Some(keyword) = sql_keyword(sql) else {
        return OperationKind::Other;
    };
    if [
        b"SELECT".as_slice(),
        b"SHOW",
        b"DESCRIBE",
        b"DESC",
        b"EXPLAIN",
    ]
    .iter()
    .any(|candidate| keyword.eq_ignore_ascii_case(candidate))
    {
        OperationKind::Read
    } else if [
        b"INSERT".as_slice(),
        b"UPDATE",
        b"DELETE",
        b"REPLACE",
        b"MERGE",
        b"LOAD",
    ]
    .iter()
    .any(|candidate| keyword.eq_ignore_ascii_case(candidate))
    {
        OperationKind::Write
    } else if [
        b"CREATE".as_slice(),
        b"ALTER",
        b"DROP",
        b"TRUNCATE",
        b"RENAME",
        b"GRANT",
        b"REVOKE",
    ]
    .iter()
    .any(|candidate| keyword.eq_ignore_ascii_case(candidate))
    {
        OperationKind::Ddl
    } else {
        OperationKind::Other
    }
}

fn sql_keyword(mut sql: &[u8]) -> Option<&[u8]> {
    loop {
        let start = sql
            .iter()
            .position(|byte| !byte.is_ascii_whitespace() && *byte != b';')
            .unwrap_or(sql.len());
        sql = &sql[start..];
        if sql.is_empty() {
            return None;
        }
        if sql.starts_with(b"--") || sql.starts_with(b"#") {
            let end = sql.iter().position(|byte| *byte == b'\n')?;
            sql = &sql[end + 1..];
        } else if let Some(comment) = sql.strip_prefix(b"/*") {
            let end = comment.windows(2).position(|window| window == b"*/")?;
            sql = &comment[end + 2..];
        } else {
            let end = sql
                .iter()
                .position(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
                .unwrap_or(sql.len());
            return (end > 0).then_some(&sql[..end]);
        }
    }
}

fn classify_mongodb(command: &[u8]) -> OperationKind {
    if [
        b"find".as_slice(),
        b"getMore",
        b"aggregate",
        b"count",
        b"distinct",
    ]
    .iter()
    .any(|candidate| command.eq_ignore_ascii_case(candidate))
    {
        OperationKind::Read
    } else if [
        b"insert".as_slice(),
        b"update",
        b"delete",
        b"findAndModify",
        b"bulkWrite",
    ]
    .iter()
    .any(|candidate| command.eq_ignore_ascii_case(candidate))
    {
        OperationKind::Write
    } else if [
        b"create".as_slice(),
        b"drop",
        b"renameCollection",
        b"createIndexes",
        b"dropIndexes",
    ]
    .iter()
    .any(|candidate| command.eq_ignore_ascii_case(candidate))
    {
        OperationKind::Ddl
    } else {
        OperationKind::Other
    }
}

async fn read_mongodb_command_key(
    reader: &mut (impl AsyncRead + Unpin),
    prefix: &mut Vec<u8>,
    message_len: usize,
) -> Result<Vec<u8>, ListenerError> {
    let start = prefix.len();
    append_exact(reader, prefix, 5, message_len).await?;
    let document_len = i32::from_le_bytes(prefix[start..start + 4].try_into().unwrap());
    if document_len < 5 || document_len as usize > message_len - start {
        return Err(crate::protocols::mongodb::MongodbProxyError::MalformedMessage.into());
    }
    if prefix[start + 4] == 0 {
        return Err(crate::protocols::mongodb::MongodbProxyError::MalformedMessage.into());
    }
    append_cstring(reader, prefix, message_len).await
}

async fn append_cstring(
    reader: &mut (impl AsyncRead + Unpin),
    prefix: &mut Vec<u8>,
    message_len: usize,
) -> Result<Vec<u8>, ListenerError> {
    let mut value = Vec::new();
    loop {
        if value.len() >= MONGODB_MAX_CSTRING_BYTES || prefix.len() >= message_len {
            return Err(crate::protocols::mongodb::MongodbProxyError::MalformedMessage.into());
        }
        let mut byte = [0_u8; 1];
        reader.read_exact(&mut byte).await?;
        prefix.push(byte[0]);
        if byte[0] == 0 {
            return Ok(value);
        }
        value.push(byte[0]);
    }
}

async fn append_exact(
    reader: &mut (impl AsyncRead + Unpin),
    prefix: &mut Vec<u8>,
    bytes: usize,
    message_len: usize,
) -> Result<(), ListenerError> {
    if prefix
        .len()
        .checked_add(bytes)
        .is_none_or(|end| end > message_len)
    {
        return Err(crate::protocols::mongodb::MongodbProxyError::MalformedMessage.into());
    }
    let start = prefix.len();
    prefix.resize(start + bytes, 0);
    reader.read_exact(&mut prefix[start..]).await?;
    Ok(())
}

fn is_mongodb_identity_command(command: &[u8]) -> bool {
    [
        b"saslStart".as_slice(),
        b"saslContinue".as_slice(),
        b"authenticate".as_slice(),
        b"logout".as_slice(),
        b"getnonce".as_slice(),
        b"hello".as_slice(),
        b"isMaster".as_slice(),
        b"ismaster".as_slice(),
        b"$query".as_slice(),
    ]
    .iter()
    .any(|blocked| command.eq_ignore_ascii_case(blocked))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn shared_query_deadline_releases_buffer_without_timing_out_idle_clients() {
        let (mut client, gateway_client) = tokio::io::duplex(64);
        let (gateway_backend, mut backend) = tokio::io::duplex(64);
        let budget = crate::gateway::buffers::QueryBudget::default();
        let proxy = tokio::spawn(proxy_mysql_session(
            gateway_client,
            gateway_backend,
            Protocol::Mysql,
            true,
            activity(),
            budget.clone(),
        ));
        tokio::task::yield_now().await;
        tokio::time::advance(QUERY_BODY_TIMEOUT * 2).await;
        assert!(!proxy.is_finished(), "an idle pooled connection is valid");
        let packet = mysql_packet(0, b"\x03SELECT 1");
        client.write_all(&packet[..6]).await.unwrap();
        tokio::task::yield_now().await;
        assert!(budget.reserve(32 * 1024 * 1024).is_err());
        tokio::time::advance(QUERY_BODY_TIMEOUT).await;
        assert!(
            matches!(proxy.await.unwrap(), Err(ListenerError::Io(error)) if error.kind() == io::ErrorKind::TimedOut)
        );
        assert!(budget.reserve(32 * 1024 * 1024).is_ok());
        assert_eq!(
            backend.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn mongodb_wire_limit_matches_advertised_limit_without_large_allocations() {
        let mut message = mongodb_message(bson::doc! { "insert": "items", "$db": "tenant" });
        let limit = crate::protocols::mongodb::MAX_WIRE_MESSAGE_BYTES;
        for size in [16 * 1024 * 1024 + 128, limit] {
            message[..4].copy_from_slice(&(size as i32).to_le_bytes());
            let (prefix, declared, command) = read_mongodb_prefix(&mut message.as_slice())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(declared, size);
            assert!(prefix.len() < 64);
            assert_eq!(command.as_deref(), Some(b"insert".as_slice()));
        }
        message[..4].copy_from_slice(&((limit + 1) as i32).to_le_bytes());
        assert!(read_mongodb_prefix(&mut message.as_slice()).await.is_err());
    }

    fn activity() -> Arc<ActivityCounter> {
        Arc::new(ActivityCounter::default())
    }

    #[test]
    fn sql_kind_uses_the_first_real_keyword() {
        assert_eq!(
            classify_sql(b" ; /* trace */ -- note\n SELECT 1"),
            OperationKind::Read
        );
        assert_eq!(
            classify_sql(b"INSERT INTO items VALUES (1)"),
            OperationKind::Write
        );
        assert_eq!(classify_sql(b"DROP TABLE items"), OperationKind::Ddl);
        assert_eq!(
            classify_sql(b"WITH rows AS (SELECT 1) SELECT * FROM rows"),
            OperationKind::Other
        );
    }

    #[test]
    fn mongodb_kind_is_case_insensitive_and_conservative() {
        assert_eq!(classify_mongodb(b"FiNd"), OperationKind::Read);
        assert_eq!(classify_mongodb(b"bulkWrite"), OperationKind::Write);
        assert_eq!(classify_mongodb(b"createIndexes"), OperationKind::Ddl);
        assert_eq!(classify_mongodb(b"serverStatus"), OperationKind::Other);
    }

    #[tokio::test]
    async fn postgres_proxy_forwards_complete_frontend_frames() {
        let (mut client, gateway_client) = tokio::io::duplex(128);
        let (gateway_backend, mut backend) = tokio::io::duplex(128);
        let activity = activity();
        let proxy = tokio::spawn(proxy_postgres_session(
            gateway_client,
            gateway_backend,
            Arc::clone(&activity),
        ));
        let mut frames = postgres_frame(b'Q', b"SELECT 1\0");
        frames.extend_from_slice(&postgres_frame(b'E', b"\0\0\0\0\0"));
        client.write_all(&frames).await.unwrap();
        client.shutdown().await.unwrap();

        let mut forwarded = vec![0_u8; frames.len()];
        backend.read_exact(&mut forwarded).await.unwrap();
        backend.shutdown().await.unwrap();
        proxy.await.unwrap().unwrap();
        assert_eq!(forwarded, frames);
        let snapshot = activity.snapshot();
        assert_eq!(snapshot.accepted.read, 1);
        assert_eq!(snapshot.accepted.other, 1);
        assert_eq!(snapshot.gateway.opened_connections, 1);
        assert_eq!(snapshot.gateway.active_connections, 0);
    }

    #[tokio::test]
    async fn postgres_proxy_rejects_invalid_frame_lengths() {
        let (mut client, gateway_client) = tokio::io::duplex(32);
        let (gateway_backend, mut backend) = tokio::io::duplex(32);
        let proxy = tokio::spawn(proxy_postgres_session(
            gateway_client,
            gateway_backend,
            activity(),
        ));
        client.write_all(&[b'Q', 0, 0, 0, 3]).await.unwrap();
        let error = proxy.await.unwrap().unwrap_err();
        assert!(
            matches!(error, ListenerError::Io(error) if error.kind() == std::io::ErrorKind::InvalidData)
        );
        let mut byte = [0_u8; 1];
        assert_eq!(backend.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn mysql_proxy_forwards_commands_but_rejects_change_user() {
        let (mut client, gateway_client) = tokio::io::duplex(256);
        let (gateway_backend, mut backend) = tokio::io::duplex(256);
        let activity = activity();
        let proxy = tokio::spawn(proxy_mysql_session(
            gateway_client,
            gateway_backend,
            Protocol::Mysql,
            false,
            Arc::clone(&activity),
            Default::default(),
        ));

        let query = mysql_packet(
            0,
            &[
                MYSQL_COM_QUERY,
                b'S',
                b'E',
                b'L',
                b'E',
                b'C',
                b'T',
                b' ',
                b'1',
            ],
        );
        client.write_all(&query).await.unwrap();
        let mut forwarded = vec![0_u8; query.len()];
        backend.read_exact(&mut forwarded).await.unwrap();
        assert_eq!(forwarded, query);

        client
            .write_all(&mysql_packet(0, &[MYSQL_COM_CHANGE_USER, b'x']))
            .await
            .unwrap();
        let error = proxy.await.unwrap().unwrap_err();
        assert!(matches!(
            error,
            ListenerError::IdentitySwitchRejected { protocol: "mysql" }
        ));
        let snapshot = activity.snapshot();
        assert_eq!(snapshot.accepted.read, 1);
        assert_eq!(snapshot.rejected.other, 1);
        assert_eq!(snapshot.gateway.opened_connections, 1);
        assert_eq!(snapshot.gateway.active_connections, 0);
    }

    #[tokio::test]
    async fn mysql_continuation_payload_cannot_be_misread_as_change_user() {
        let (mut client, gateway_client) = tokio::io::duplex(256);
        let (gateway_backend, mut backend) = tokio::io::duplex(256);
        let proxy = tokio::spawn(proxy_mysql_session(
            gateway_client,
            gateway_backend,
            Protocol::Mariadb,
            false,
            activity(),
            Default::default(),
        ));
        let continuation = mysql_packet(1, &[MYSQL_COM_CHANGE_USER, b'x']);
        client.write_all(&continuation).await.unwrap();
        client.shutdown().await.unwrap();
        let mut forwarded = vec![0_u8; continuation.len()];
        backend.read_exact(&mut forwarded).await.unwrap();
        backend.shutdown().await.unwrap();
        proxy.await.unwrap().unwrap();
        assert_eq!(forwarded, continuation);
    }

    #[tokio::test]
    async fn shared_mysql_nonzero_payload_is_not_misread_as_a_database_command() {
        for protocol in [Protocol::Mysql, Protocol::Mariadb] {
            for command in [MYSQL_COM_CREATE_DB, MYSQL_COM_DROP_DB] {
                let (mut client, gateway_client) = tokio::io::duplex(128);
                let (gateway_backend, mut backend) = tokio::io::duplex(128);
                let proxy = tokio::spawn(proxy_mysql_session(
                    gateway_client,
                    gateway_backend,
                    protocol,
                    true,
                    activity(),
                    Default::default(),
                ));
                let continuation = mysql_packet(1, &[command, b'x']);

                client.write_all(&continuation).await.unwrap();
                client.shutdown().await.unwrap();
                let mut forwarded = vec![0_u8; continuation.len()];
                backend.read_exact(&mut forwarded).await.unwrap();
                backend.shutdown().await.unwrap();
                proxy.await.unwrap().unwrap();
                assert_eq!(forwarded, continuation);
            }
        }
    }

    #[tokio::test]
    async fn shared_mysql_rejects_raw_database_commands_before_forwarding() {
        for protocol in [Protocol::Mysql, Protocol::Mariadb] {
            for command in [MYSQL_COM_CREATE_DB, MYSQL_COM_DROP_DB] {
                let (mut client, gateway_client) = tokio::io::duplex(128);
                let (gateway_backend, mut backend) = tokio::io::duplex(128);
                let proxy = tokio::spawn(proxy_mysql_session(
                    gateway_client,
                    gateway_backend,
                    protocol,
                    true,
                    activity(),
                    Default::default(),
                ));
                let packet = mysql_packet(0, &[command, b't', b'e', b'n', b'a', b'n', b't']);

                client.write_all(&packet).await.unwrap();

                let error = proxy.await.unwrap().unwrap_err();
                assert!(matches!(
                    error,
                    ListenerError::Mariadb(
                        mariadb::MariadbProxyError::SharedStorageCommandRejected(_)
                    )
                ));
                let mut byte = [0_u8; 1];
                assert_eq!(backend.read(&mut byte).await.unwrap(), 0);
            }
        }
    }

    #[tokio::test]
    async fn fragmented_shared_mysql_raw_database_commands_are_rejected() {
        for protocol in [Protocol::Mysql, Protocol::Mariadb] {
            for command in [MYSQL_COM_CREATE_DB, MYSQL_COM_DROP_DB] {
                let (mut client, gateway_client) = tokio::io::duplex(32);
                let (gateway_backend, mut backend) = tokio::io::duplex(32);
                let proxy = tokio::spawn(proxy_mysql_session(
                    gateway_client,
                    gateway_backend,
                    protocol,
                    true,
                    activity(),
                    Default::default(),
                ));
                // The command is the last byte so the proxy cannot close the
                // in-memory client while the test still has bytes to write.
                let packet = mysql_packet(0, &[command]);

                for byte in packet {
                    client.write_all(&[byte]).await.unwrap();
                    tokio::task::yield_now().await;
                }

                let error = proxy.await.unwrap().unwrap_err();
                assert!(matches!(
                    error,
                    ListenerError::Mariadb(
                        mariadb::MariadbProxyError::SharedStorageCommandRejected(_)
                    )
                ));
                let mut byte = [0_u8; 1];
                assert_eq!(backend.read(&mut byte).await.unwrap(), 0);
            }
        }
    }

    #[tokio::test]
    async fn dedicated_mysql_forwards_raw_database_commands() {
        for protocol in [Protocol::Mysql, Protocol::Mariadb] {
            for command in [MYSQL_COM_CREATE_DB, MYSQL_COM_DROP_DB] {
                let (mut client, gateway_client) = tokio::io::duplex(128);
                let (gateway_backend, mut backend) = tokio::io::duplex(128);
                let proxy = tokio::spawn(proxy_mysql_session(
                    gateway_client,
                    gateway_backend,
                    protocol,
                    false,
                    activity(),
                    Default::default(),
                ));
                let packet = mysql_packet(0, &[command, b't', b'e', b'n', b'a', b'n', b't']);

                client.write_all(&packet).await.unwrap();
                client.shutdown().await.unwrap();
                let mut forwarded = vec![0_u8; packet.len()];
                backend.read_exact(&mut forwarded).await.unwrap();
                assert_eq!(forwarded, packet);
                backend.shutdown().await.unwrap();
                proxy.await.unwrap().unwrap();
            }
        }
    }

    #[tokio::test]
    async fn shared_mysql_proxy_blocks_storage_escape_before_backend_forwarding() {
        for (protocol, command) in [
            (Protocol::Mysql, MYSQL_COM_QUERY),
            (Protocol::Mariadb, MYSQL_COM_STMT_PREPARE),
        ] {
            let (mut client, gateway_client) = tokio::io::duplex(512);
            let (gateway_backend, mut backend) = tokio::io::duplex(512);
            let proxy = tokio::spawn(proxy_mysql_session(
                gateway_client,
                gateway_backend,
                protocol,
                true,
                activity(),
                Default::default(),
            ));
            let mut payload = vec![command];
            payload.extend_from_slice(b"CREATE TABLE items(id BIGINT) TABLESPACE=innodb_system");
            client.write_all(&mysql_packet(0, &payload)).await.unwrap();

            let error = proxy.await.unwrap().unwrap_err();
            assert!(matches!(
                error,
                ListenerError::Mariadb(mariadb::MariadbProxyError::SharedStorageCommandRejected(_))
            ));
            let mut byte = [0_u8; 1];
            assert_eq!(backend.read(&mut byte).await.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn fragmented_shared_mysql_commands_are_checked_before_forwarding() {
        for (protocol, command) in [
            (Protocol::Mysql, MYSQL_COM_QUERY),
            (Protocol::Mariadb, MYSQL_COM_STMT_PREPARE),
        ] {
            let (mut client, gateway_client) = tokio::io::duplex(64);
            let (gateway_backend, mut backend) = tokio::io::duplex(64);
            let proxy = tokio::spawn(proxy_mysql_session(
                gateway_client,
                gateway_backend,
                protocol,
                true,
                activity(),
                Default::default(),
            ));
            let mut payload = vec![command];
            payload.extend_from_slice(b"DROP DATABASE tenant_db");
            let packet = mysql_packet(0, &payload);

            for byte in packet {
                client.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }

            let error = proxy.await.unwrap().unwrap_err();
            assert!(matches!(
                error,
                ListenerError::Mariadb(mariadb::MariadbProxyError::SharedStorageCommandRejected(_))
            ));
            let mut byte = [0_u8; 1];
            assert_eq!(backend.read(&mut byte).await.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn shared_mysql_rejects_multi_packet_text_before_forwarding() {
        for command in [MYSQL_COM_QUERY, MYSQL_COM_STMT_PREPARE] {
            let (mut client, gateway_client) = tokio::io::duplex(64);
            let (gateway_backend, mut backend) = tokio::io::duplex(64);
            let proxy = tokio::spawn(proxy_mysql_session(
                gateway_client,
                gateway_backend,
                Protocol::Mysql,
                true,
                activity(),
                Default::default(),
            ));

            client
                .write_all(&[0xff, 0xff, 0xff, 0, command])
                .await
                .unwrap();

            let error = proxy.await.unwrap().unwrap_err();
            assert!(matches!(
                error,
                ListenerError::Mariadb(mariadb::MariadbProxyError::SharedStorageCommandRejected(_))
            ));
            let mut byte = [0_u8; 1];
            assert_eq!(backend.read(&mut byte).await.unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn mysql_storage_policy_is_shared_only_and_preserves_table_ddl() {
        for (shared, sql) in [
            (true, "CREATE TABLE items(id BIGINT) ENGINE=InnoDB"),
            (true, "ALTER TABLE items ADD COLUMN note TEXT"),
            (true, "DROP TABLE items"),
            (false, "DROP DATABASE tenant_db"),
        ] {
            let (mut client, gateway_client) = tokio::io::duplex(512);
            let (gateway_backend, mut backend) = tokio::io::duplex(512);
            let proxy = tokio::spawn(proxy_mysql_session(
                gateway_client,
                gateway_backend,
                Protocol::Mysql,
                shared,
                activity(),
                Default::default(),
            ));
            let mut payload = vec![MYSQL_COM_QUERY];
            payload.extend_from_slice(sql.as_bytes());
            let packet = mysql_packet(0, &payload);
            client.write_all(&packet).await.unwrap();
            client.shutdown().await.unwrap();

            let mut forwarded = vec![0_u8; packet.len()];
            backend.read_exact(&mut forwarded).await.unwrap();
            assert_eq!(forwarded, packet);
            backend.shutdown().await.unwrap();
            proxy.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn binary_execute_payload_is_not_treated_as_sql_text() {
        let (mut client, gateway_client) = tokio::io::duplex(512);
        let (gateway_backend, mut backend) = tokio::io::duplex(512);
        let proxy = tokio::spawn(proxy_mysql_session(
            gateway_client,
            gateway_backend,
            Protocol::Mysql,
            true,
            activity(),
            Default::default(),
        ));
        let mut payload = vec![MYSQL_COM_STMT_EXECUTE];
        payload.extend_from_slice(b"DROP DATABASE tenant_db\0TABLESPACE innodb_system");
        let packet = mysql_packet(0, &payload);
        client.write_all(&packet).await.unwrap();
        client.shutdown().await.unwrap();

        let mut forwarded = vec![0_u8; packet.len()];
        backend.read_exact(&mut forwarded).await.unwrap();
        assert_eq!(forwarded, packet);
        backend.shutdown().await.unwrap();
        proxy.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn mongodb_proxy_streams_data_but_rejects_post_auth_identity_commands() {
        let (mut client, gateway_client) = tokio::io::duplex(1024);
        let (gateway_backend, mut backend) = tokio::io::duplex(1024);
        let activity = activity();
        let proxy = tokio::spawn(proxy_mongodb_session(
            gateway_client,
            gateway_backend,
            Arc::clone(&activity),
        ));

        let ping = mongodb_message(bson::doc! { "ping": 1_i32, "$db": "tenant_db" });
        client.write_all(&ping).await.unwrap();
        let mut forwarded = vec![0_u8; ping.len()];
        backend.read_exact(&mut forwarded).await.unwrap();
        assert_eq!(forwarded, ping);

        let reauth = mongodb_message(bson::doc! {
            "saslStart": 1_i32,
            "mechanism": "SCRAM-SHA-256",
            "$db": "victim_db",
        });
        client.write_all(&reauth).await.unwrap();
        let error = proxy.await.unwrap().unwrap_err();
        assert!(matches!(
            error,
            ListenerError::IdentitySwitchRejected {
                protocol: "mongodb"
            }
        ));
        let snapshot = activity.snapshot();
        assert_eq!(snapshot.accepted.other, 1);
        assert_eq!(snapshot.rejected.other, 1);
        assert_eq!(snapshot.gateway.opened_connections, 1);
        assert_eq!(snapshot.gateway.active_connections, 0);
    }

    #[tokio::test]
    async fn mongodb_proxy_streams_large_non_auth_messages_without_handshake_cap() {
        let (mut client, gateway_client) = tokio::io::duplex(4096);
        let (gateway_backend, mut backend) = tokio::io::duplex(4096);
        let proxy = tokio::spawn(proxy_mongodb_session(
            gateway_client,
            gateway_backend,
            activity(),
        ));
        let message = mongodb_message(bson::doc! {
            "insert": "tenant_collection",
            "payload": bson::Binary {
                subtype: bson::spec::BinarySubtype::Generic,
                bytes: vec![7_u8; 128 * 1024],
            },
            "$db": "tenant_db",
        });
        let expected = message.clone();
        let send = tokio::spawn(async move {
            client.write_all(&message).await.unwrap();
            client.shutdown().await.unwrap();
        });
        let mut forwarded = vec![0_u8; expected.len()];
        backend.read_exact(&mut forwarded).await.unwrap();
        backend.shutdown().await.unwrap();
        send.await.unwrap();
        proxy.await.unwrap().unwrap();
        assert_eq!(forwarded, expected);
    }

    fn mysql_packet(sequence: u8, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut packet = vec![len as u8, (len >> 8) as u8, (len >> 16) as u8, sequence];
        packet.extend_from_slice(payload);
        packet
    }

    fn postgres_frame(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(payload.len() + 5);
        frame.push(kind);
        frame.extend_from_slice(&((payload.len() + 4) as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn mongodb_message(body: bson::Document) -> Vec<u8> {
        let body = bson::to_vec(&body).unwrap();
        let len = 16 + 5 + body.len();
        let mut message = Vec::with_capacity(len);
        message.extend_from_slice(&(len as i32).to_le_bytes());
        message.extend_from_slice(&7_i32.to_le_bytes());
        message.extend_from_slice(&0_i32.to_le_bytes());
        message.extend_from_slice(&MONGODB_OP_MSG.to_le_bytes());
        message.extend_from_slice(&0_i32.to_le_bytes());
        message.push(0);
        message.extend_from_slice(&body);
        message
    }
}
