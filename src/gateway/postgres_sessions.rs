use std::{
    collections::HashMap,
    sync::{OnceLock, RwLock},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    api::resources::NetworkCounter,
    gateway::{resolver::ResolvedRoute, tunnel},
    shared::backend::BackendEndpoint,
};

const MAX_ACTIVE_POSTGRES_CANCEL_KEYS: usize = 65_536;
const MAX_POSTGRES_STARTUP_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CancelKey {
    process_id: i32,
    secret_key: i32,
}

impl From<(i32, i32)> for CancelKey {
    fn from((process_id, secret_key): (i32, i32)) -> Self {
        Self {
            process_id,
            secret_key,
        }
    }
}

#[derive(Debug, Clone)]
struct CancelTarget {
    instance_id: String,
    endpoint: BackendEndpoint,
    network: NetworkCounter,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PostgresSessionError {
    #[error("PostgreSQL startup message io failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("PostgreSQL startup message is malformed or exceeds the bounded proxy limit")]
    Malformed,
    #[error("PostgreSQL cancellation registry is at capacity")]
    RegistryFull,
    #[error("PostgreSQL backend cancellation key collided with an active session")]
    RegistryCollision,
    #[error("PostgreSQL cancellation backend failed: {0}")]
    Backend(#[from] tunnel::TunnelError),
}

static CANCEL_TARGETS: OnceLock<RwLock<HashMap<CancelKey, CancelTarget>>> = OnceLock::new();

fn cancel_targets() -> &'static RwLock<HashMap<CancelKey, CancelTarget>> {
    CANCEL_TARGETS.get_or_init(|| RwLock::new(HashMap::new()))
}

pub(crate) struct CancelRegistration {
    key: Option<CancelKey>,
}

impl Drop for CancelRegistration {
    fn drop(&mut self) {
        if let Some(key) = self.key {
            cancel_targets()
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&key);
        }
    }
}

pub(crate) async fn proxy_startup_and_register<C, B>(
    client: &mut C,
    backend: &mut B,
    target: &ResolvedRoute,
) -> Result<CancelRegistration, PostgresSessionError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut cancel_key = None;
    loop {
        let backend_message = read_message(backend).await?;
        let message_type = backend_message[0];
        if message_type == b'K' {
            if backend_message.len() != 13 {
                return Err(PostgresSessionError::Malformed);
            }
            cancel_key = Some(CancelKey {
                process_id: i32::from_be_bytes(
                    backend_message[5..9]
                        .try_into()
                        .map_err(|_| PostgresSessionError::Malformed)?,
                ),
                secret_key: i32::from_be_bytes(
                    backend_message[9..13]
                        .try_into()
                        .map_err(|_| PostgresSessionError::Malformed)?,
                ),
            });
        }
        client.write_all(&backend_message).await?;

        if message_type == b'E' {
            return Ok(CancelRegistration { key: None });
        }

        if authentication_requires_frontend_response(&backend_message)? {
            let frontend_message = read_message(client).await?;
            backend.write_all(&frontend_message).await?;
        }
        if message_type == b'Z' {
            break;
        }
    }

    if let Some(key) = cancel_key {
        let mut targets = cancel_targets()
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if targets.len() >= MAX_ACTIVE_POSTGRES_CANCEL_KEYS && !targets.contains_key(&key) {
            return Err(PostgresSessionError::RegistryFull);
        }
        if targets.contains_key(&key) {
            return Err(PostgresSessionError::RegistryCollision);
        }
        targets.insert(
            key,
            CancelTarget {
                instance_id: target.instance_id.clone(),
                endpoint: target.endpoint.clone(),
                network: target.network.clone(),
            },
        );
    }
    Ok(CancelRegistration { key: cancel_key })
}

/// PostgreSQL intentionally sends no reply for cancellation, including an
/// unknown key. Returning `false` therefore only informs internal tests/logs.
pub(crate) async fn forward_cancel(
    key: CancelKey,
    packet: &[u8],
) -> Result<bool, PostgresSessionError> {
    let target = cancel_targets()
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
        .cloned();
    let Some(target) = target else {
        return Ok(false);
    };
    let backend = tunnel::connect_backend(&target.endpoint).await?;
    let mut backend = tunnel::MeteredBackend::new(backend, target.network);
    backend.write_all(packet).await?;
    backend.shutdown().await?;
    tracing::debug!(
        instance_id = %target.instance_id,
        "forwarded a PostgreSQL CancelRequest to its exact active backend session"
    );
    Ok(true)
}

async fn read_message(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<Vec<u8>, PostgresSessionError> {
    let mut header = [0_u8; 5];
    stream.read_exact(&mut header).await?;
    let length = u32::from_be_bytes(header[1..5].try_into().unwrap()) as usize;
    if !(4..=MAX_POSTGRES_STARTUP_MESSAGE_BYTES).contains(&length) {
        return Err(PostgresSessionError::Malformed);
    }
    let total = length
        .checked_add(1)
        .ok_or(PostgresSessionError::Malformed)?;
    let mut message = Vec::with_capacity(total);
    message.extend_from_slice(&header);
    message.resize(total, 0);
    stream.read_exact(&mut message[5..]).await?;
    Ok(message)
}

fn authentication_requires_frontend_response(message: &[u8]) -> Result<bool, PostgresSessionError> {
    if message.first() != Some(&b'R') {
        return Ok(false);
    }
    if message.len() < 9 {
        return Err(PostgresSessionError::Malformed);
    }
    let code = i32::from_be_bytes(
        message[5..9]
            .try_into()
            .map_err(|_| PostgresSessionError::Malformed)?,
    );
    Ok(matches!(code, 3 | 5 | 7 | 8 | 9 | 10 | 11))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_authentication_messages_that_require_a_frontend_reply() {
        for code in [3_i32, 5, 7, 8, 9, 10, 11] {
            let mut message = vec![b'R'];
            message.extend_from_slice(&8_u32.to_be_bytes());
            message.extend_from_slice(&code.to_be_bytes());
            assert!(authentication_requires_frontend_response(&message).unwrap());
        }
        for code in [0_i32, 2, 6, 12] {
            let mut message = vec![b'R'];
            message.extend_from_slice(&8_u32.to_be_bytes());
            message.extend_from_slice(&code.to_be_bytes());
            assert!(!authentication_requires_frontend_response(&message).unwrap());
        }
    }

    #[tokio::test]
    async fn backend_key_is_registered_only_for_the_live_session_and_forwards_exact_cancel() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("postgres.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let target = ResolvedRoute {
            instance_id: "inst_postgres_cancel".to_string(),
            endpoint: BackendEndpoint::UnixSocket {
                socket_path: socket.display().to_string(),
            },
            network: NetworkCounter::default(),
        };
        let (mut proxy_client, mut client) = tokio::io::duplex(1024);
        let (mut proxy_backend, mut backend) = tokio::io::duplex(1024);
        let backend_startup = tokio::spawn(async move {
            backend
                .write_all(&postgres_message(b'R', &0_i32.to_be_bytes()))
                .await
                .unwrap();
            let mut key_body = Vec::new();
            key_body.extend_from_slice(&123_i32.to_be_bytes());
            key_body.extend_from_slice(&456_i32.to_be_bytes());
            backend
                .write_all(&postgres_message(b'K', &key_body))
                .await
                .unwrap();
            backend
                .write_all(&postgres_message(b'Z', b"I"))
                .await
                .unwrap();
        });
        let registration =
            proxy_startup_and_register(&mut proxy_client, &mut proxy_backend, &target)
                .await
                .unwrap();
        backend_startup.await.unwrap();
        let mut forwarded_startup = vec![0_u8; 9 + 13 + 6];
        client.read_exact(&mut forwarded_startup).await.unwrap();
        assert!(
            forwarded_startup
                .windows(5)
                .any(|value| value == b"K\0\0\0\x0c")
        );

        let cancel = {
            let mut packet = Vec::new();
            packet.extend_from_slice(&16_u32.to_be_bytes());
            packet
                .extend_from_slice(&crate::protocols::postgres::CANCEL_REQUEST_CODE.to_be_bytes());
            packet.extend_from_slice(&123_i32.to_be_bytes());
            packet.extend_from_slice(&456_i32.to_be_bytes());
            packet
        };
        let received_cancel = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut packet = [0_u8; 16];
            stream.read_exact(&mut packet).await.unwrap();
            packet
        });
        assert!(
            forward_cancel(CancelKey::from((123, 456)), &cancel)
                .await
                .unwrap()
        );
        assert_eq!(received_cancel.await.unwrap().as_slice(), cancel);

        drop(registration);
        assert!(
            !forward_cancel(CancelKey::from((123, 456)), &cancel)
                .await
                .unwrap()
        );
    }

    fn postgres_message(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut message = vec![kind];
        message.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        message.extend_from_slice(body);
        message
    }
}
