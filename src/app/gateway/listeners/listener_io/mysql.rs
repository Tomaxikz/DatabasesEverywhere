/// Proxies an authenticated MySQL-family session while retaining the routed
/// tenant identity. Shared tenants additionally validate complete text-query
/// and prepared-statement packets before any byte reaches the backend.
use std::sync::Arc;

use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    sync::Semaphore,
    time::{Instant, timeout_at},
};
use tokio_util::task::AbortOnDropHandle;

use crate::{
    databases::protocol::Protocol,
    gateway::{
        buffers::{QueryBudget, QueryReservation},
        listeners::{
            ListenerError,
            listener_io::{
                ActivitySession, FRAME_READ_AHEAD, FrameBuffers, MYSQL_COM_CHANGE_USER,
                MYSQL_COM_CREATE_DB, MYSQL_COM_DROP_DB, MYSQL_COM_QUERY, MYSQL_COM_STMT_EXECUTE,
                MYSQL_COM_STMT_PREPARE, MYSQL_MAX_SINGLE_PACKET_PAYLOAD, QUERY_BODY_TIMEOUT,
                SQL_PREFIX_BYTES, classify::classify_sql,
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
    buffers: QueryBudget,
) -> Result<(), ListenerError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let _activity_session = ActivitySession::open(Arc::clone(&activity));
    let (client_read, mut client_write) = io::split(client);
    let (mut backend_read, mut backend_write) = io::split(backend);
    let mut client_read = BufReader::with_capacity(FRAME_READ_AHEAD, client_read);
    let upload = async {
        let mut frame = FrameBuffers::default();
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
                let reservation = buffers.reserve(payload_len)?;
                let deadline = Instant::now() + QUERY_BODY_TIMEOUT;
                timeout_at(deadline, async {
                    let mut payload = vec![0; payload_len];
                    payload[0] = first[0];
                    client_read.read_exact(&mut payload[1..]).await?;
                    let (payload, _reservation, kind) =
                        inspect_shared_payload(payload, reservation, protocol, &activity).await?;
                    // The join and the timer can become ready in the same poll.
                    // MeteredBackend also checks session cancellation on every write.
                    if Instant::now() >= deadline {
                        return Err(query_timeout().into());
                    }
                    if payload_len <= FRAME_READ_AHEAD {
                        frame.prefix.clear();
                        frame.prefix.extend_from_slice(&header);
                        frame.prefix.extend_from_slice(&payload);
                        backend_write.write_all(&frame.prefix).await?;
                    } else {
                        backend_write.write_all(&header).await?;
                        backend_write.write_all(&payload).await?;
                    }
                    activity.accept(kind);
                    Ok::<(), ListenerError>(())
                })
                .await
                .map_err(|_| query_timeout())??;
                continue;
            }
            let command = is_command_packet.then_some(first[0]);
            let remaining = payload_len - 1;
            frame.prefix.clear();
            frame.prefix.extend_from_slice(&header);
            frame.prefix.push(first[0]);
            let prefix = frame
                .forward(
                    &mut client_read,
                    &mut backend_write,
                    remaining,
                    SQL_PREFIX_BYTES,
                    "mysql client packet ended before its declared length",
                )
                .await?;

            let kind = match command {
                Some(MYSQL_COM_QUERY | MYSQL_COM_STMT_PREPARE) => Some(classify_sql(prefix)),
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

fn query_timeout() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "shared SQL command transfer timed out",
    )
}

pub(super) const INLINE_SQL_BYTES: usize = 64 * 1024;
// Limit CPU work across all tenants, independently of the query byte budget.
pub(super) const MAX_SQL_SCANS: usize = 4;
pub(super) static SQL_SCAN_SLOTS: Semaphore = Semaphore::const_new(MAX_SQL_SCANS);

async fn inspect_shared_payload(
    payload: Vec<u8>,
    reservation: QueryReservation,
    protocol: Protocol,
    activity: &ActivityCounter,
) -> Result<(Vec<u8>, QueryReservation, OperationKind), ListenerError> {
    let large = payload.len() - 1 > INLINE_SQL_BYTES;
    let inspect = move || {
        let sql = &payload[1..];
        let verdict = validate_shared_mysql_command(sql, protocol);
        let kind = classify_sql(sql);
        (payload, reservation, kind, verdict)
    };
    let (payload, reservation, kind, verdict) = if large {
        let slot = SQL_SCAN_SLOTS
            .acquire()
            .await
            .expect("SQL scan semaphore stays open");
        // A started blocking task may outlive a disconnected session. Keep both
        // the byte reservation and the CPU slot with the work until it finishes.
        AbortOnDropHandle::new(tokio::task::spawn_blocking(move || {
            let _slot = slot;
            inspect()
        }))
        .await
        .map_err(io::Error::other)?
    } else {
        inspect()
    };
    if let Err(error) = verdict {
        activity.reject_kind(kind);
        return Err(
            mariadb::MariadbProxyError::SharedStorageCommandRejected(error.to_string()).into(),
        );
    }
    Ok((payload, reservation, kind))
}

pub(super) fn mysql_payload_len(header: &[u8; 4]) -> usize {
    usize::from(header[0]) | (usize::from(header[1]) << 8) | (usize::from(header[2]) << 16)
}
