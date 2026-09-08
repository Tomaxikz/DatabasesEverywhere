use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UnixStream,
    time::{Duration, timeout},
};

use crate::{api::monitoring::resources::NetworkCounter, shared::backend::BackendEndpoint};

const BACKEND_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const BACKEND_REPLAY_TIMEOUT: Duration = Duration::from_secs(5);
const FIRST_REPLY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
// Two buffers are retained for the lifetime of every idle tunnel. Stream
// larger transfers in 16 KiB chunks instead of reserving 128 KiB per client.
const TUNNEL_BUFFER_SIZE: usize = 16 * 1024;

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
    #[error(
        "backend first response stalled for {timeout_secs}s without upload progress: {endpoint}"
    )]
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

/// Counts bytes at the backend boundary. Writes are bytes received by the
/// database instance (RX); reads are bytes sent by it (TX). Measuring here
/// covers plain and TLS clients uniformly and works with network-none
/// containers connected through Unix sockets.
#[derive(Debug)]
pub(crate) struct MeteredBackend<S> {
    inner: S,
    network: NetworkCounter,
    session: Option<crate::gateway::sessions::TenantSession>,
}

impl<S> MeteredBackend<S> {
    pub(crate) fn authenticate_session(&self, limit: Option<usize>) -> std::io::Result<()> {
        self.session
            .as_ref()
            .ok_or_else(|| std::io::Error::other("missing tenant session"))?
            .authenticate(limit)
    }

    pub(crate) fn query_budget(&self) -> super::buffers::QueryBudget {
        self.session
            .as_ref()
            .expect("SQL tunnels always own a tenant session")
            .query_budget()
    }

    pub(crate) fn new(
        inner: S,
        network: NetworkCounter,
        session: crate::gateway::sessions::TenantSession,
    ) -> Self {
        Self {
            inner,
            network,
            session: Some(session),
        }
    }

    /// Internal control traffic such as PostgreSQL CancelRequest forwarding is
    /// not a tenant session and therefore has no lifecycle lease.
    pub(crate) fn untracked(inner: S, network: NetworkCounter) -> Self {
        Self {
            inner,
            network,
            session: None,
        }
    }

    fn cancelled(&self, context: &Context<'_>) -> std::io::Result<()> {
        if self
            .session
            .as_ref()
            .is_some_and(|session| session.poll_cancelled(context))
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "tenant session was closed by a lifecycle operation",
            ))
        } else {
            Ok(())
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MeteredBackend<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.cancelled(context) {
            return Poll::Ready(Err(error));
        }
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(context, buffer);
        if let Poll::Ready(Ok(())) = &result {
            this.network
                .add_tx(buffer.filled().len().saturating_sub(before) as u64);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MeteredBackend<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if let Err(error) = this.cancelled(context) {
            return Poll::Ready(Err(error));
        }
        let result = Pin::new(&mut this.inner).poll_write(context, bytes);
        if let Poll::Ready(Ok(written)) = result {
            this.network.add_rx(written as u64);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.cancelled(context) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
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

pub(crate) async fn connect_replay_and_tunnel<S>(
    mut client: S,
    endpoint: BackendEndpoint,
    replay: &[u8],
    network: NetworkCounter,
    session: crate::gateway::sessions::TenantSession,
) -> Result<(), TunnelError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let endpoint_description = endpoint_description(&endpoint);
    let backend = connect_backend(&endpoint).await?;
    let mut backend = MeteredBackend::new(backend, network, session);
    timeout(BACKEND_REPLAY_TIMEOUT, backend.write_all(replay))
        .await
        .map_err(|_| TunnelError::ReplayTimeout {
            endpoint: endpoint_description.clone(),
            timeout_secs: BACKEND_REPLAY_TIMEOUT.as_secs(),
        })?
        .map_err(TunnelError::Replay)?;
    tunnel_streams(&mut client, &mut backend, endpoint_description).await?;
    Ok(())
}

async fn tunnel_streams<C, B>(
    client: &mut C,
    backend: &mut B,
    endpoint: String,
) -> Result<(), TunnelError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = io::split(client);
    let (mut backend_read, mut backend_write) = io::split(backend);
    let (progress, mut uploaded) = tokio::sync::watch::channel(());
    let upstream = async {
        let mut buffer = vec![0_u8; TUNNEL_BUFFER_SIZE];
        loop {
            let count = client_read.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            // HTTP may not reply until it receives the complete body. Forward
            // it immediately, and count actual upload progress as activity.
            // The receiver is dropped after the first backend byte.
            let mut pending = &buffer[..count];
            while !pending.is_empty() {
                let written = backend_write.write(pending).await?;
                if written == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
                }
                pending = &pending[written..];
                let _ = progress.send(());
            }
        }
        drop(progress);
        backend_write.shutdown().await
    };
    let downstream = async {
        let mut first = [0_u8; 1];
        let mut uploading = true;
        loop {
            tokio::select! {
                result = backend_read.read_exact(&mut first) => {
                    result.map_err(TunnelError::FirstResponse)?;
                    break;
                }
                changed = uploaded.changed(), if uploading => {
                    uploading = changed.is_ok();
                }
                _ = tokio::time::sleep(FIRST_REPLY_IDLE_TIMEOUT) => {
                    return Err(TunnelError::FirstResponseTimeout {
                        endpoint,
                        timeout_secs: FIRST_REPLY_IDLE_TIMEOUT.as_secs(),
                    });
                }
            }
        }
        drop(uploaded);
        client_write
            .write_all(&first)
            .await
            .map_err(TunnelError::Tunnel)?;
        let mut reader = io::BufReader::with_capacity(TUNNEL_BUFFER_SIZE, backend_read);
        io::copy_buf(&mut reader, &mut client_write)
            .await
            .map_err(TunnelError::Tunnel)?;
        client_write.shutdown().await.map_err(TunnelError::Tunnel)
    };
    // A failure in either direction cancels the other; a clean half-close
    // still lets its peer finish. Tenant-session cancellation remains metered.
    tokio::try_join!(
        async { upstream.await.map_err(TunnelError::Tunnel) },
        downstream
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn small_buffers_preserve_large_transfers_and_half_closes() {
        let (client, mut client_proxy) = io::duplex(1024);
        let (backend_proxy, database) = io::duplex(1024);
        let network = NetworkCounter::default();
        let sessions = crate::gateway::sessions::TenantSessions::default();
        let mut backend =
            MeteredBackend::new(backend_proxy, network.clone(), sessions.open("tenant"));
        let request = vec![0x51; 256 * 1024 + 7];
        let response = vec![0x52; 256 * 1024 + 13];
        let client_exchange = async {
            let (mut read, mut write) = io::split(client);
            let mut received = Vec::new();
            let send = async {
                write.write_all(&request).await?;
                write.shutdown().await
            };
            tokio::try_join!(send, read.read_to_end(&mut received)).unwrap();
            received
        };
        let database_exchange = async {
            let (mut read, mut write) = io::split(database);
            let mut received = Vec::new();
            // HTTP servers may need the entire POST body before producing
            // even their first response byte. The gateway must not hold it.
            read.read_to_end(&mut received).await.unwrap();
            write.write_all(b"!").await.unwrap();
            write.write_all(&response).await.unwrap();
            write.shutdown().await.unwrap();
            received
        };
        let (forwarded, reply, query) = timeout(Duration::from_secs(5), async {
            tokio::join!(
                tunnel_streams(&mut client_proxy, &mut backend, "test".into()),
                client_exchange,
                database_exchange,
            )
        })
        .await
        .unwrap();
        forwarded.unwrap();
        assert_eq!(query, request);
        assert_eq!(reply[0], b'!');
        assert_eq!(reply[1..], response);
        assert_eq!(
            network.snapshot(),
            (request.len() as u64, response.len() as u64 + 1)
        );
    }

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

    #[tokio::test(start_paused = true)]
    async fn first_reply_timeout_tracks_upload_progress_not_total_request_time() {
        let (mut client, mut client_proxy) = io::duplex(64);
        let (mut backend, mut database) = io::duplex(1);
        let forward = tunnel_streams(&mut client_proxy, &mut backend, "test".into());
        let upload = async {
            client.write_all(b"bodybodybodybody").await.unwrap();
            client.shutdown().await.unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"OK");
        };
        let response = async {
            let mut body = Vec::new();
            for _ in 0..16 {
                tokio::time::sleep(Duration::from_secs(20)).await;
                body.push(database.read_u8().await.unwrap());
            }
            assert_eq!(body, b"bodybodybodybody");
            database.write_all(b"OK").await.unwrap();
            database.shutdown().await.unwrap();
        };
        let (result, (), ()) = tokio::join!(forward, upload, response);
        result.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn silent_backends_still_time_out_with_and_without_a_client_half_close() {
        for half_close in [false, true] {
            let (mut client, mut client_proxy) = io::duplex(64);
            let (mut backend, _database) = io::duplex(64);
            if half_close {
                client.shutdown().await.unwrap();
            }
            assert!(matches!(
                tunnel_streams(&mut client_proxy, &mut backend, "test".into()).await,
                Err(TunnelError::FirstResponseTimeout { .. })
            ));
        }
    }

    #[tokio::test]
    async fn metered_backend_reports_live_rx_and_tx_bytes() {
        let network = NetworkCounter::default();
        let (stream, mut peer) = tokio::io::duplex(64);
        let sessions = crate::gateway::sessions::TenantSessions::default();
        let mut metered = MeteredBackend::new(stream, network.clone(), sessions.open("tenant"));

        metered.write_all(b"request").await.unwrap();
        let mut request = [0_u8; 7];
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");

        peer.write_all(b"response").await.unwrap();
        let mut response = [0_u8; 8];
        metered.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");

        assert_eq!(network.snapshot(), (7, 8));
    }

    #[tokio::test]
    async fn tenant_cancellation_wakes_and_closes_a_blocked_backend_read() {
        let sessions = crate::gateway::sessions::TenantSessions::default();
        let (stream, _peer) = tokio::io::duplex(64);
        let mut metered =
            MeteredBackend::new(stream, NetworkCounter::default(), sessions.open("tenant"));
        let read = tokio::spawn(async move {
            let mut byte = [0_u8; 1];
            metered.read_exact(&mut byte).await
        });
        tokio::task::yield_now().await;

        assert_eq!(sessions.cancel("tenant"), 1);
        let error = read.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
    }
}
