/// Keeps a successfully authenticated MongoDB socket bound to the identity
/// that acquired its tenant session. Messages are streamed after inspecting
/// only the bounded command prefix, so normal 16 MiB writes are not buffered.
use std::sync::Arc;

use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    gateway::listeners::{
        ListenerError,
        listener_io::{
            ActivitySession, MONGODB_MAX_CSTRING_BYTES, MONGODB_OP_COMPRESSED, MONGODB_OP_MSG,
            MONGODB_OP_QUERY,
            classify::{MONGODB_IDENTITY_COMMANDS, classify_mongodb, matches_any_ignore_case},
            copy_exact,
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

pub(super) async fn read_mongodb_prefix(
    reader: &mut (impl AsyncRead + Unpin),
) -> Result<Option<(Vec<u8>, usize, Option<Vec<u8>>)>, ListenerError> {
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

    let mut prefix = header.to_vec();
    let command = match opcode {
        MONGODB_OP_MSG => {
            append_exact(reader, &mut prefix, 5, message_len).await?;
            if prefix[20] != 0 {
                return Err(malformed_mongodb_message());
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

pub(super) async fn read_mongodb_command_key(
    reader: &mut (impl AsyncRead + Unpin),
    prefix: &mut Vec<u8>,
    message_len: usize,
) -> Result<Vec<u8>, ListenerError> {
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

pub(super) async fn append_cstring(
    reader: &mut (impl AsyncRead + Unpin),
    prefix: &mut Vec<u8>,
    message_len: usize,
) -> Result<Vec<u8>, ListenerError> {
    let mut value = Vec::new();
    loop {
        if value.len() >= MONGODB_MAX_CSTRING_BYTES || prefix.len() >= message_len {
            return Err(malformed_mongodb_message());
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
