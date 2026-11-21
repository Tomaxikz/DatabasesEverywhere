/// Keeps a successfully authenticated MongoDB socket bound to the identity
/// that acquired its tenant session. Messages are streamed after inspecting
/// only the bounded command prefix, so normal 16 MiB writes are not buffered.
use std::{ops::Range, sync::Arc};

use tokio::io::{
    self, AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
    BufReader,
};

use crate::{
    gateway::listeners::{
        ListenerError,
        listener_io::{
            ActivitySession, FRAME_READ_AHEAD, FrameBuffers, MONGODB_MAX_CSTRING_BYTES,
            MONGODB_OP_COMPRESSED, MONGODB_OP_MSG, MONGODB_OP_QUERY,
            classify::{MONGODB_IDENTITY_COMMANDS, classify_mongodb, matches_any_ignore_case},
        },
    },
    server::monitoring::{ActivityCounter, OperationKind},
};

pub(in super::super) async fn proxy_mongodb_session<C, B>(
    client: C,
    backend: B,
    activity: Arc<ActivityCounter>,
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
        loop {
            let parsed = read_mongodb_prefix(&mut client_read, &mut frame.prefix).await;
            let Some((message_len, kind)) = (match parsed {
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
            frame
                .forward(
                    &mut client_read,
                    &mut backend_write,
                    message_len - frame.prefix.len(),
                    0,
                    "mongodb client message ended before its declared length",
                )
                .await?;
            if let Some(kind) = kind {
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

pub(super) async fn read_mongodb_prefix(
    reader: &mut (impl AsyncBufRead + Unpin),
    prefix: &mut Vec<u8>,
) -> Result<Option<(usize, Option<OperationKind>)>, ListenerError> {
    let mut header = [0_u8; 16];
    if reader.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..]).await?;
    let message_len = i32::from_le_bytes(header[..4].try_into().unwrap());
    if !(16..=crate::gateway::protocols::mongodb::MAX_WIRE_MESSAGE_BYTES as i32)
        .contains(&message_len)
    {
        return Err(malformed_mongodb_message());
    }
    let message_len = message_len as usize;
    let opcode = i32::from_le_bytes(header[12..16].try_into().unwrap());
    if opcode == MONGODB_OP_COMPRESSED {
        return Err(ListenerError::IdentitySwitchRejected {
            protocol: "mongodb",
        });
    }

    prefix.clear();
    prefix.extend_from_slice(&header);
    let command = match opcode {
        MONGODB_OP_MSG => {
            append_exact(reader, prefix, 5, message_len).await?;
            if prefix[20] != 0 {
                return Err(malformed_mongodb_message());
            }
            Some(read_mongodb_command_key(reader, prefix, message_len).await?)
        }
        MONGODB_OP_QUERY => {
            append_exact(reader, prefix, 4, message_len).await?;
            let collection = append_cstring(reader, prefix, message_len).await?;
            append_exact(reader, prefix, 8, message_len).await?;
            let command = read_mongodb_command_key(reader, prefix, message_len).await?;
            prefix[collection].ends_with(b".$cmd").then_some(command)
        }
        _ => None,
    };
    let command = command.map(|range| &prefix[range]);
    if command.is_some_and(is_mongodb_identity_command) {
        return Err(ListenerError::IdentitySwitchRejected {
            protocol: "mongodb",
        });
    }
    Ok(Some((message_len, command.map(classify_mongodb))))
}

async fn read_mongodb_command_key(
    reader: &mut (impl AsyncBufRead + Unpin),
    prefix: &mut Vec<u8>,
    message_len: usize,
) -> Result<Range<usize>, ListenerError> {
    let start = prefix.len();
    append_exact(reader, prefix, 5, message_len).await?;
    let document_len = i32::from_le_bytes(prefix[start..start + 4].try_into().unwrap());
    if document_len < 5 || document_len as usize > message_len - start {
        return Err(malformed_mongodb_message());
    }
    if prefix[start + 4] == 0 {
        return Err(malformed_mongodb_message());
    }
    append_cstring(reader, prefix, message_len).await
}

async fn append_cstring(
    reader: &mut (impl AsyncBufRead + Unpin),
    prefix: &mut Vec<u8>,
    message_len: usize,
) -> Result<Range<usize>, ListenerError> {
    let start = prefix.len();
    let end = message_len.min(start + MONGODB_MAX_CSTRING_BYTES);
    while prefix.len() < end {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        let chunk = &available[..available.len().min(end - prefix.len())];
        let nul = chunk.iter().position(|byte| *byte == 0);
        let n = nul.map_or(chunk.len(), |i| i + 1);
        prefix.extend_from_slice(&chunk[..n]);
        reader.consume(n);
        if nul.is_some() {
            return Ok(start..prefix.len() - 1);
        }
    }
    Err(malformed_mongodb_message())
}

pub(super) async fn append_exact(
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
        return Err(malformed_mongodb_message());
    }
    let start = prefix.len();
    prefix.resize(start + bytes, 0);
    reader.read_exact(&mut prefix[start..]).await?;
    Ok(())
}

pub(super) fn malformed_mongodb_message() -> ListenerError {
    crate::gateway::protocols::mongodb::MongodbProxyError::MalformedMessage.into()
}

pub(super) fn is_mongodb_identity_command(command: &[u8]) -> bool {
    matches_any_ignore_case(command, MONGODB_IDENTITY_COMMANDS)
}
