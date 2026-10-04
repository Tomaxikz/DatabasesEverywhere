/// Proxies an authenticated MySQL-family session while retaining the routed
/// tenant identity. Shared tenants additionally validate complete text-query
/// and prepared-statement packets before any byte reaches the backend.
use std::sync::Arc;

use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    databases::protocol::Protocol,
    gateway::{
        listeners::{
            ListenerError,
            listener_io::{
                ActivitySession, MYSQL_COM_CHANGE_USER, MYSQL_COM_CREATE_DB, MYSQL_COM_DROP_DB,
                MYSQL_COM_QUERY, MYSQL_COM_STMT_EXECUTE, MYSQL_COM_STMT_PREPARE,
                MYSQL_MAX_SINGLE_PACKET_PAYLOAD, QUERY_BODY_TIMEOUT, SQL_PREFIX_BYTES,
                classify::classify_sql, copy_exact,
            },
        },
        protocols::mariadb,
    },
    server::monitoring::{ActivityCounter, OperationKind},
    subsystems::import_export::inspection::validate_shared_mysql_command,
};

pub(in super::super) async fn proxy_mysql_session<C, B>(
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
            let payload_len = mysql_payload_len(&header);
            let is_command_packet = header[3] == 0;
            if is_command_packet {
                continued_command = None;
            }
            if payload_len == 0 {
                backend_write.write_all(&header).await?;
                if !is_command_packet && let Some(kind) = continued_command.take() {
                    activity.accept(kind);
                }
                continue;
            }
            let mut first = [0_u8; 1];
            client_read.read_exact(&mut first).await?;
            if is_command_packet && first[0] == MYSQL_COM_CHANGE_USER {
                activity.reject_kind(OperationKind::Other);
                return Err(ListenerError::IdentitySwitchRejected {
                    protocol: protocol.as_str(),
                });
            }
            // A command-phase packet always resets the sequence id to zero.
            // Nonzero packets can contain arbitrary continuation or LOCAL
            // INFILE bytes, so their first payload byte is not a command.
            if shared
                && is_command_packet
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
                && is_command_packet
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
            let command = is_command_packet.then_some(first[0]);
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
            } else if !is_command_packet
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

pub(super) fn mysql_payload_len(header: &[u8; 4]) -> usize {
    usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16)
}
