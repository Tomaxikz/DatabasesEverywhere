use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use quinn::{
    ClientConfig, Connection, Endpoint, VarInt,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use rustls_pki_types::CertificateDer;
use tokio::sync::{mpsc, watch};

use crate::{
    id::{NodeId, TargetId},
    identity::{IdentityError, peer_node_id},
    wire::{Status, WireError},
};

mod admission;
mod config;
mod dial;
mod inbound;
mod incoming;
mod outbound;
mod stream;
#[cfg(test)]
mod tests;

pub use config::{
    Config, MAX_ACCEPT_BACKLOG_LIMIT, MAX_CONNECTIONS_LIMIT, MAX_DURATION,
    MAX_STREAMS_PER_PEER_LIMIT, MAX_WINDOW, MIN_STREAM_WINDOW,
};
pub use incoming::Incoming;
pub use stream::Stream;

/// Application close code for an orderly [`Tether::shutdown`].
const CLOSE_SHUTDOWN: VarInt = VarInt::from_u32(1);
/// Application close code for a peer whose certificate does not name exactly one node.
const CLOSE_IDENTITY: VarInt = VarInt::from_u32(2);
/// Application close code when the last [`Tether`] handle is dropped.
const CLOSE_DROPPED: VarInt = VarInt::from_u32(3);
/// Application close code for a connection over the connection limits.
const CLOSE_LIMIT: VarInt = VarInt::from_u32(4);
/// Application close code for a connection the dialer no longer wants because the peer moved.
const CLOSE_SUPERSEDED: VarInt = VarInt::from_u32(5);

/// How long `shutdown` waits for peers to acknowledge the close. A peer that has vanished
/// must not hold shutdown up.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Decides whether a peer node may open a stream to a target on this node. Called for every
/// inbound stream, so it must be cheap and must not block.
///
/// `context` is what the peer node sent with the request. It is the peer's own assertion,
/// not something tether verifies: base a decision on it only as far as `peer` is trusted to
/// make that claim.
pub trait Authorizer: Send + Sync + 'static {
    fn allows(&self, peer: &NodeId, target: &TargetId, context: &[u8]) -> bool;
}

/// Where to reach a peer and who must answer there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub id: NodeId,
    pub address: SocketAddr,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BindError {
    #[error("invalid configuration: {0}")]
    Config(&'static str),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("TLS configuration cannot be used for QUIC: {0}")]
    Quic(String),
    #[error("could not bind the tether socket: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OpenError {
    /// The peer could not be reached, or whoever answered is not the expected node.
    #[error("could not connect to the peer: {0}")]
    Connect(String),
    /// The peer answered the stream with a status other than `Ok` and
    /// `UnsupportedVersion`.
    #[error("the peer refused the stream: {0:?}")]
    Refused(Status),
    /// The peer does not speak this build's protocol version; `peer_max` is the highest
    /// version it supports.
    #[error("the peer speaks protocol versions up to {peer_max} only")]
    UnsupportedVersion { peer_max: u16 },
    /// The request context is longer than [`MAX_CONTEXT_LEN`](crate::wire::MAX_CONTEXT_LEN).
    #[error("the request context is too long")]
    ContextTooLong,
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("timed out")]
    Timeout,
    /// This endpoint has been shut down.
    #[error("the endpoint is closed")]
    Closed,
}

/// This node's endpoint. Cheap to clone; all clones share the same socket and connections.
#[derive(Clone)]
pub struct Tether {
    inner: Arc<Inner>,
}

struct Inner {
    /// The runtime `bind` ran on. Dials and their watchers run here, so the connections
    /// outlive whichever runtime a caller happens to use.
    runtime: tokio::runtime::Handle,
    endpoint: Endpoint,
    node_id: NodeId,
    client_config: ClientConfig,
    header_timeout: Duration,
    connect_timeout: Duration,
    outbound: outbound::Table,
    // Behind an async mutex so concurrent `accept` calls queue up instead of each
    // needing its own receiver.
    accept_rx: tokio::sync::Mutex<mpsc::Receiver<Incoming>>,
    closed: watch::Sender<bool>,
    // Background tasks hold this instead of `Inner`, so dropping every `Tether` handle
    // ends them rather than keeping the socket alive. Only tests read it back.
    #[cfg_attr(not(test), allow(dead_code))]
    inbound: Arc<inbound::Context>,
}

impl Inner {
    fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.endpoint.close(CLOSE_DROPPED, b"dropped");
    }
}

/// The node a verified connection's peer certificate names, if it names exactly one.
fn peer_of(connection: &Connection) -> Option<NodeId> {
    let identity = connection.peer_identity()?;
    let chain = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    peer_node_id(&chain).ok()
}

impl Tether {
    /// Binds the socket and starts accepting peers. Must be called inside a Tokio runtime,
    /// which then runs every connection of this endpoint and so must outlive it.
    pub fn bind(config: Config, authorizer: Arc<dyn Authorizer>) -> Result<Self, BindError> {
        config::validate(&config)?;
        let listening = config::transport(&config, config::Role::Listening)?;
        let dialing = config::transport(&config, config::Role::Dialing)?;

        let server_crypto = QuicServerConfig::try_from(config.identity.server_config()?)
            .map_err(|error| BindError::Quic(error.to_string()))?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
        server_config.transport_config(listening);
        // Attempts still waiting to be looked at are bounded like the handshakes behind them.
        server_config.max_incoming(config.max_handshakes);

        let client_crypto = QuicClientConfig::try_from(config.identity.client_config()?)
            .map_err(|error| BindError::Quic(error.to_string()))?;
        let mut client_config = ClientConfig::new(Arc::new(client_crypto));
        client_config.transport_config(dialing);

        let endpoint = Endpoint::server(server_config, config.bind)?;

        let (accept_tx, accept_rx) = mpsc::channel(config.accept_backlog);
        let admission = admission::Admission::new(
            config.max_handshakes,
            config.max_connections,
            config.max_connections_per_peer,
        );
        let inbound = Arc::new(inbound::Context::new(
            authorizer,
            accept_tx,
            config.header_timeout,
            config.handshake_timeout,
            admission,
        ));
        let runtime = tokio::runtime::Handle::current();
        runtime.spawn(inbound::accept_loop(endpoint.clone(), inbound.clone()));

        Ok(Self {
            inner: Arc::new(Inner {
                runtime,
                endpoint,
                node_id: config.identity.node_id().clone(),
                client_config,
                header_timeout: config.header_timeout,
                connect_timeout: config.connect_timeout,
                outbound: outbound::Table::default(),
                accept_rx: tokio::sync::Mutex::new(accept_rx),
                closed: watch::Sender::new(false),
                inbound,
            }),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.endpoint.local_addr()
    }

    pub fn node_id(&self) -> &NodeId {
        &self.inner.node_id
    }

    /// Opens a stream to `target` on `peer`, connecting first if there is no live connection.
    /// Returns once the peer has answered `Ok`.
    ///
    /// `context` travels with the request (at most
    /// [`MAX_CONTEXT_LEN`](crate::wire::MAX_CONTEXT_LEN) bytes). The peer's authorizer and
    /// application see it as this node's assertion; tether does not verify it for them.
    ///
    /// A failed open may already have reached the peer. If a reused connection turns out to
    /// be dead, the open is repeated once on a new connection, so the peer can see the same
    /// request twice and may admit it twice. Its answer is what counts: only an `Ok` result
    /// means a stream exists.
    pub async fn open(
        &self,
        peer: &Peer,
        target: &TargetId,
        context: &[u8],
    ) -> Result<Stream, OpenError> {
        outbound::open(&self.inner, peer, target, context).await
    }

    /// The next authorized inbound stream, or `None` once the endpoint is shut down.
    pub async fn accept(&self) -> Option<Incoming> {
        let mut closed = self.inner.closed.subscribe();
        tokio::select! {
            biased;
            () = async { let _ = closed.wait_for(|closed| *closed).await; } => None,
            incoming = async {
                let mut queue = self.inner.accept_rx.lock().await;
                loop {
                    let incoming = queue.recv().await?;
                    // Past its deadline the opener has given up or is about to; dropping
                    // it resets the stream instead of handing stale work to the application.
                    if !incoming.expired() {
                        return Some(incoming);
                    }
                }
            } => incoming,
        }
    }

    /// Number of live outbound connections. For metrics and tests.
    pub fn outbound_connections(&self) -> usize {
        self.inner.outbound.live()
    }

    /// Closes every connection and stops accepting. Pending and later `open` calls fail with
    /// [`OpenError::Closed`] and `accept` returns `None`.
    pub async fn shutdown(&self) {
        self.inner.closed.send_replace(true);
        self.inner.endpoint.close(CLOSE_SHUTDOWN, b"shutdown");
        self.inner.outbound.clear();
        // Streams still queued would otherwise sit unanswered until the endpoint is
        // dropped; closing the queue drops them, which resets their streams. A concurrent
        // `accept` gives up the receiver at once because `closed` is already set.
        // In a task of its own, so a caller that stops waiting for `shutdown` cannot leave
        // the queue half drained.
        let inner = self.inner.clone();
        let drained = self.inner.runtime.spawn(async move {
            let mut queue = inner.accept_rx.lock().await;
            queue.close();
            // `recv` also accounts for sends that reserved capacity but have not published
            // yet, which `try_recv` would report as empty.
            while queue.recv().await.is_some() {}
        });
        // It only fails when the runtime is going away, which drops the queue anyway.
        let _ = drained.await;
        if tokio::time::timeout(SHUTDOWN_GRACE, self.inner.endpoint.wait_idle())
            .await
            .is_err()
        {
            tracing::debug!("shutdown: peers did not acknowledge the close in time");
        }
    }

    #[cfg(test)]
    fn accepted_connections(&self) -> usize {
        self.inner.inbound.accepted_connections()
    }

    /// Inbound connections currently counted against the limits.
    #[cfg(test)]
    fn live_inbound(&self) -> usize {
        self.inner.inbound.live_connections()
    }

    #[cfg(test)]
    fn refused_attempts(&self) -> usize {
        self.inner.inbound.refused_attempts()
    }

    #[cfg(test)]
    fn retried_attempts(&self) -> usize {
        self.inner.inbound.retried_attempts()
    }

    #[cfg(test)]
    fn handshakes_in_use(&self) -> usize {
        self.inner.inbound.handshakes_in_use()
    }

    /// Streams waiting in the accept queue.
    #[cfg(test)]
    fn queued_incoming(&self) -> usize {
        self.inner.inbound.queued()
    }

    /// Whether an `accept` call is parked on the queue.
    #[cfg(test)]
    fn accept_waiting(&self) -> bool {
        self.inner.accept_rx.try_lock().is_err()
    }

    #[cfg(test)]
    fn dials_started(&self) -> usize {
        self.inner.outbound.dials_started()
    }

    #[cfg(test)]
    fn lookups(&self) -> usize {
        self.inner.outbound.lookups()
    }

    #[cfg(test)]
    fn open_retries(&self) -> usize {
        self.inner.outbound.retries()
    }

    #[cfg(test)]
    fn dialing(&self) -> usize {
        self.inner.outbound.dialing()
    }
}
