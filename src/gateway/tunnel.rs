use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UnixStream},
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
}

pub async fn connect_replay_and_tunnel<S>(
    mut client: S,
    endpoint: BackendEndpoint,
    replay: &[u8],
) -> Result<(), TunnelError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match endpoint {
        BackendEndpoint::UnixSocket { socket_path } => {
            let endpoint = socket_path.clone();
            let mut backend = timeout(BACKEND_CONNECT_TIMEOUT, UnixStream::connect(socket_path))
                .await
                .map_err(|_| TunnelError::ConnectTimeout {
                    endpoint: endpoint.clone(),
                    timeout_secs: BACKEND_CONNECT_TIMEOUT.as_secs(),
                })?
                .map_err(TunnelError::Connect)?;
            timeout(BACKEND_REPLAY_TIMEOUT, backend.write_all(replay))
                .await
                .map_err(|_| TunnelError::ReplayTimeout {
                    endpoint: endpoint.clone(),
                    timeout_secs: BACKEND_REPLAY_TIMEOUT.as_secs(),
                })?
                .map_err(TunnelError::Replay)?;
            tunnel_after_first_backend_response(&mut client, &mut backend, endpoint).await?;
        }
        BackendEndpoint::DockerTcp { host, port } => {
            let endpoint = format!("{host}:{port}");
            let mut backend = timeout(
                BACKEND_CONNECT_TIMEOUT,
                TcpStream::connect((host.as_str(), port)),
            )
            .await
            .map_err(|_| TunnelError::ConnectTimeout {
                endpoint: endpoint.clone(),
                timeout_secs: BACKEND_CONNECT_TIMEOUT.as_secs(),
            })?
            .map_err(TunnelError::Connect)?;
            backend.set_nodelay(true).map_err(TunnelError::Connect)?;
            timeout(BACKEND_REPLAY_TIMEOUT, backend.write_all(replay))
                .await
                .map_err(|_| TunnelError::ReplayTimeout {
                    endpoint: endpoint.clone(),
                    timeout_secs: BACKEND_REPLAY_TIMEOUT.as_secs(),
                })?
                .map_err(TunnelError::Replay)?;
            tunnel_after_first_backend_response(&mut client, &mut backend, endpoint).await?;
        }
    }
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
