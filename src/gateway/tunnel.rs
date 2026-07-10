use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UnixStream,
    time::{Duration, timeout},
};

use crate::shared::backend::BackendEndpoint;

const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const BACKEND_REPLAY_TIMEOUT: Duration = Duration::from_secs(5);
const BACKEND_FIRST_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const TUNNEL_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("backend connection failed: {0}")]
    Connect(std::io::Error),
    #[error("backend connection timed out after {timeout_secs}s to {endpoint}")]
    ConnectTimeout { endpoint: String, timeout_secs: u64 },
    #[error("backend replay failed: {0}")]
    Replay(std::io::Error),
    #[error("backend replay timed out after {timeout_secs}s to {endpoint}")]
    ReplayTimeout { endpoint: String, timeout_secs: u64 },
    #[error("backend first response failed: {0}")]
    FirstResponse(std::io::Error),
    #[error("backend first response timed out after {timeout_secs}s from {endpoint}")]
    FirstResponseTimeout { endpoint: String, timeout_secs: u64 },
    #[error("tunnel io failed: {0}")]
    Tunnel(std::io::Error),
    #[error("legacy Docker TCP backend endpoints are quarantined and cannot be opened")]
    LegacyDockerTcp,
}

#[derive(Debug)]
pub enum BackendStream {
    Unix(UnixStream),
}

impl AsyncRead for BackendStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Unix(stream) => Pin::new(stream).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for BackendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Unix(stream) => Pin::new(stream).poll_write(context, bytes),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Unix(stream) => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(context),
        }
    }
}

pub async fn connect_backend(endpoint: &BackendEndpoint) -> Result<BackendStream, TunnelError> {
    let description = endpoint_description(endpoint);
    let stream = match endpoint {
        BackendEndpoint::UnixSocket { socket_path } => {
            let stream = timeout(BACKEND_CONNECT_TIMEOUT, UnixStream::connect(socket_path))
                .await
                .map_err(|_| TunnelError::ConnectTimeout {
                    endpoint: description,
                    timeout_secs: BACKEND_CONNECT_TIMEOUT.as_secs(),
                })?
                .map_err(TunnelError::Connect)?;
            BackendStream::Unix(stream)
        }
        BackendEndpoint::DockerTcp { .. } => return Err(TunnelError::LegacyDockerTcp),
    };
    Ok(stream)
}

fn endpoint_description(endpoint: &BackendEndpoint) -> String {
    match endpoint {
        BackendEndpoint::UnixSocket { socket_path } => socket_path.clone(),
        BackendEndpoint::DockerTcp { host, port } => format!("{host}:{port}"),
    }
}

pub async fn connect_replay_and_tunnel<S>(
    mut client: S,
    endpoint: BackendEndpoint,
    replay: &[u8],
) -> Result<(), TunnelError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let endpoint_description = endpoint_description(&endpoint);
    let mut backend = connect_backend(&endpoint).await?;
    timeout(BACKEND_REPLAY_TIMEOUT, backend.write_all(replay))
        .await
        .map_err(|_| TunnelError::ReplayTimeout {
            endpoint: endpoint_description.clone(),
            timeout_secs: BACKEND_REPLAY_TIMEOUT.as_secs(),
        })?
        .map_err(TunnelError::Replay)?;
    tunnel_after_first_backend_response(&mut client, &mut backend, endpoint_description).await?;
    Ok(())
}

async fn tunnel_after_first_backend_response<C, B>(
    client: &mut C,
    backend: &mut B,
    endpoint: String,
) -> Result<(), TunnelError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut first = [0_u8; 1];
    timeout(
        BACKEND_FIRST_RESPONSE_TIMEOUT,
        backend.read_exact(&mut first),
    )
    .await
    .map_err(|_| TunnelError::FirstResponseTimeout {
        endpoint,
        timeout_secs: BACKEND_FIRST_RESPONSE_TIMEOUT.as_secs(),
    })?
    .map_err(TunnelError::FirstResponse)?;
    client
        .write_all(&first)
        .await
        .map_err(TunnelError::Tunnel)?;
    io::copy_bidirectional_with_sizes(client, backend, TUNNEL_BUFFER_SIZE, TUNNEL_BUFFER_SIZE)
        .await
        .map_err(TunnelError::Tunnel)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn legacy_tcp_backends_fail_closed() {
        let error = connect_backend(&BackendEndpoint::DockerTcp {
            host: "127.0.0.1".to_string(),
            port: 5432,
        })
        .await
        .unwrap_err();

        assert!(matches!(error, TunnelError::LegacyDockerTcp));
    }
}
