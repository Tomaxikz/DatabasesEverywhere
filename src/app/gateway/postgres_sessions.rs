use std::{
    collections::HashMap,
    sync::{OnceLock, RwLock},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocols::postgres::CancelKey;
use crate::{
    api::monitoring::resources::NetworkCounter, gateway::tunnel, shared::backend::BackendEndpoint,
};

const MAX_ACTIVE_POSTGRES_CANCEL_KEYS: usize = 65_536;
const MAX_POSTGRES_STARTUP_MESSAGE_BYTES: usize = 1024 * 1024;

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
        if let Some(key) = self.key.take() {
            cancel_targets()
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&key);
        }
    }
}

pub(crate) struct Startup {
    key: Option<CancelKey>,
    ready: Vec<u8>,
}

pub(crate) async fn proxy_startup<C, B>(
    client: &mut C,
    backend: &mut B,
) -> Result<Option<Startup>, PostgresSessionError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut cancel_key = None;
    loop {
        let backend_message = read_message(backend).await?;
        let message_type = backend_message[0];
        if message_type == b'K' {
            cancel_key = Some(
                CancelKey::from_backend_data(&backend_message[5..])
                    .ok_or(PostgresSessionError::Malformed)?,
            );
        }
        if message_type == b'Z' {
            // Do not tell the client it can send queries until the caller has
            // rechecked the route and acquired an authenticated tenant slot.
            return Ok(Some(Startup {
                key: cancel_key,
                ready: backend_message,
            }));
        }
        client.write_all(&backend_message).await?;

        if message_type == b'E' {
            return Ok(None);
        }

        if auth_needs_frontend_reply(&backend_message)? {
            let frontend_message = read_message(client).await?;
            backend.write_all(&frontend_message).await?;
        }
    }
}

impl Startup {
    pub(crate) async fn finish(
        self,
        client: &mut (impl AsyncWrite + Unpin),
        instance_id: &str,
        endpoint: &BackendEndpoint,
        network: &NetworkCounter,
    ) -> Result<CancelRegistration, PostgresSessionError> {
        if let Some(key) = &self.key {
            let mut targets = cancel_targets()
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if targets.len() >= MAX_ACTIVE_POSTGRES_CANCEL_KEYS && !targets.contains_key(key) {
                return Err(PostgresSessionError::RegistryFull);
            }
            if targets.contains_key(key) {
                return Err(PostgresSessionError::RegistryCollision);
            }
            targets.insert(
                key.clone(),
                CancelTarget {
                    instance_id: instance_id.to_string(),
                    endpoint: endpoint.clone(),
                    network: network.clone(),
                },
            );
        }
        let registration = CancelRegistration { key: self.key };
        client.write_all(&self.ready).await?;
        Ok(registration)
    }
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
    let mut backend = tunnel::MeteredBackend::untracked(backend, target.network);
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
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
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

fn auth_needs_frontend_reply(message: &[u8]) -> Result<bool, PostgresSessionError> {
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

    async fn proxy_startup_and_register<C, B>(
        client: &mut C,
        backend: &mut B,
        instance: &str,
        endpoint: &BackendEndpoint,
        network: &NetworkCounter,
    ) -> Result<Option<CancelRegistration>, PostgresSessionError>
    where
        C: AsyncRead + AsyncWrite + Unpin,
        B: AsyncRead + AsyncWrite + Unpin,
    {
        match proxy_startup(client, backend).await? {
            Some(startup) => startup
                .finish(client, instance, endpoint, network)
                .await
                .map(Some),
            None => Ok(None),
        }
    }

    #[test]
    fn recognizes_only_authentication_messages_that_require_a_frontend_reply() {
        for code in [3_i32, 5, 7, 8, 9, 10, 11] {
            let mut message = vec![b'R'];
            message.extend_from_slice(&8_u32.to_be_bytes());
            message.extend_from_slice(&code.to_be_bytes());
            assert!(auth_needs_frontend_reply(&message).unwrap());
        }
        for code in [0_i32, 2, 6, 12] {
            let mut message = vec![b'R'];
            message.extend_from_slice(&8_u32.to_be_bytes());
            message.extend_from_slice(&code.to_be_bytes());
            assert!(!auth_needs_frontend_reply(&message).unwrap());
        }
    }

    #[tokio::test]
    async fn backend_key_is_registered_only_for_the_live_session_and_forwards_exact_cancel() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("postgres.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let instance_id = "inst_postgres_cancel";
        let endpoint = BackendEndpoint::UnixSocket {
            socket_path: socket.display().to_string(),
        };
        let network = NetworkCounter::default();
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
        let registration = proxy_startup_and_register(
            &mut proxy_client,
            &mut proxy_backend,
            instance_id,
            &endpoint,
            &network,
        )
        .await
        .unwrap();
        assert!(registration.is_some());
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

    #[tokio::test]
    async fn backend_error_is_not_an_authenticated_session() {
        let endpoint = BackendEndpoint::UnixSocket {
            socket_path: "/tmp/not-used.sock".to_string(),
        };
        let network = NetworkCounter::default();
        let (mut proxy_client, mut client) = tokio::io::duplex(256);
        let (mut proxy_backend, mut backend) = tokio::io::duplex(256);
        let backend_startup = tokio::spawn(async move {
            backend
                .write_all(&postgres_message(b'E', b"SERROR\0\0"))
                .await
                .unwrap();
        });

        let registration = proxy_startup_and_register(
            &mut proxy_client,
            &mut proxy_backend,
            "tenant-rejected",
            &endpoint,
            &network,
        )
        .await
        .unwrap();
        backend_startup.await.unwrap();

        assert!(registration.is_none());
        let mut forwarded = vec![0_u8; 13];
        client.read_exact(&mut forwarded).await.unwrap();
        assert_eq!(forwarded[0], b'E');
    }

    fn postgres_message(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut message = vec![kind];
        message.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        message.extend_from_slice(body);
        message
    }

    #[tokio::test]
    async fn variable_cancel_keys_wait_for_admission_and_forward_unchanged() {
        for key_size in [32, 256] {
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("postgres.sock");
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            let endpoint = BackendEndpoint::UnixSocket {
                socket_path: socket.display().to_string(),
            };
            let mut body = 789_i32.to_be_bytes().to_vec();
            body.extend(vec![7_u8; key_size]);
            let key = CancelKey::from_backend_data(&body).unwrap();
            let mut startup_bytes = postgres_message(b'R', &0_i32.to_be_bytes());
            startup_bytes.extend(postgres_message(b'K', &body));
            let forwarded_len = startup_bytes.len();
            startup_bytes.extend(postgres_message(b'Z', b"I"));
            let (mut backend, mut engine) = tokio::io::duplex(1024);
            engine.write_all(&startup_bytes).await.unwrap();
            let (mut proxy, mut client) = tokio::io::duplex(1024);
            let startup = proxy_startup(&mut proxy, &mut backend)
                .await
                .unwrap()
                .unwrap();
            let mut forwarded = vec![0; forwarded_len];
            client.read_exact(&mut forwarded).await.unwrap();
            assert_eq!(forwarded, startup_bytes[..forwarded_len]);
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(1), client.read_u8())
                    .await
                    .is_err()
            );
            assert!(!cancel_targets().read().unwrap().contains_key(&key));
            let registration = startup
                .finish(
                    &mut proxy,
                    "tenant-variable-key",
                    &endpoint,
                    &NetworkCounter::default(),
                )
                .await
                .unwrap();
            let mut ready = [0; 6];
            client.read_exact(&mut ready).await.unwrap();
            assert_eq!(ready.as_slice(), postgres_message(b'Z', b"I"));

            let mut packet = ((8 + body.len()) as u32).to_be_bytes().to_vec();
            packet.extend(crate::protocols::postgres::CANCEL_REQUEST_CODE.to_be_bytes());
            packet.extend(body);
            assert_eq!(
                crate::protocols::postgres::cancel_request_key(&packet),
                Some(key.clone())
            );
            assert!(forward_cancel(key.clone(), &packet).await.unwrap());
            let (mut received, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            received.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, packet);
            drop(registration);
            assert!(!cancel_targets().read().unwrap().contains_key(&key));
        }
    }
}
