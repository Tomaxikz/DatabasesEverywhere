//! Node-to-node links: lets a client of this node reach a database held by another node.
//!
//! The node that holds the database authenticates the tenant with its own gateway; the entry
//! node is a plain byte forwarder that parses nothing. A stream arriving over tether is
//! therefore handed to an internal loopback copy of the protocol listener it names (see
//! [`handoff`]), and the entry side ([`forward`]) only relays a client's TCP connection into
//! a stream.

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use ::tether::{Authorizer, Config as EndpointConfig, Identity, NodeId, Peer, TargetId, Tether};
use anyhow::Context;
use tokio::{net::TcpListener, sync::watch, task::JoinSet, time::Duration};

use super::{
    listeners::{ListenerError, ProtocolEntry},
    security::GatewayConnectionLimiter,
    supervisor::{GatewayConnectionTracker, GatewaySupervisor},
};
use crate::config::{Config, TETHER_PROTOCOLS};

mod forward;
mod pem;
mod receive;
mod relay;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

/// The gateway entry of every enabled protocol, by protocol name: where an authorized
/// tunnelled connection is handed to the protocol's handler.
pub(crate) type Dispatch = HashMap<&'static str, Arc<ProtocolEntry>>;

/// What the supervisor's monitored task set holds: a label and how the task ended.
pub(crate) type MonitoredTasks = JoinSet<(String, Result<(), ListenerError>)>;

/// How long the closer waits for relay tasks that were told to stop.
const FORCED_EXIT_WAIT: Duration = Duration::from_secs(3);

/// Tether stream targets are protocol names; a peer may open a stream only when it is a
/// configured inbound peer and names one of them.
struct InboundPolicy {
    inbound: Vec<NodeId>,
}

impl Authorizer for InboundPolicy {
    fn allows(&self, peer: &NodeId, target: &TargetId, _context: &[u8]) -> bool {
        self.inbound.contains(peer) && TETHER_PROTOCOLS.contains(&target.as_str())
    }
}

/// A bound tether endpoint with its forward listeners, not yet serving.
pub(crate) struct TetherRuntime {
    tether: Tether,
    dispatch: Arc<Dispatch>,
    /// Whether any peer may open streams to this node.
    receives: bool,
    streams_limit: usize,
    forwards: Vec<forward::Forward>,
    limiter: GatewayConnectionLimiter,
}

/// Binds the forward listeners and the endpoint. Nothing is accepted until
/// [`spawn`](TetherRuntime::spawn); if anything fails, nothing stays bound.
pub(crate) async fn bind(
    config: &Config,
    dispatch: Dispatch,
    limiter: GatewayConnectionLimiter,
) -> anyhow::Result<TetherRuntime> {
    let settings = &config.tether;
    let node: NodeId = settings
        .node
        .parse()
        .with_context(|| format!("tether.node {:?} is not a valid node id", settings.node))?;

    let mut peers = HashMap::new();
    let mut inbound = Vec::new();
    for peer in &settings.peers {
        let id: NodeId = peer
            .node
            .parse()
            .with_context(|| format!("tether peer {:?} is not a valid node id", peer.node))?;
        let address: SocketAddr = peer
            .address
            .parse()
            .with_context(|| format!("tether peer {id} address {:?} is invalid", peer.address))?;
        if peer.inbound {
            inbound.push(id.clone());
        }
        peers.insert(id.clone(), Peer { id, address });
    }

    let (ca, cert, key) = (
        pem::read("ca", &settings.ca).await?,
        pem::read("cert", &settings.cert).await?,
        pem::read("key", &settings.key).await?,
    );
    let identity = Identity::from_pem(node.clone(), &cert, &key, &ca)
        .context("failed to load the tether identity")?;
    let bind_addr: SocketAddr = settings
        .bind
        .parse()
        .with_context(|| format!("tether.bind {:?} is invalid", settings.bind))?;

    let mut forwards = Vec::new();
    for entry in &settings.forwards {
        let id: NodeId = entry.node.parse().with_context(|| {
            format!(
                "tether forward node {:?} is not a valid node id",
                entry.node
            )
        })?;
        let peer = peers
            .get(&id)
            .with_context(|| format!("tether forward names {id}, which is not a peer"))?
            .clone();
        let target: TargetId = entry
            .protocol
            .parse()
            .with_context(|| format!("tether forward protocol {:?} is invalid", entry.protocol))?;
        let listener = TcpListener::bind(&entry.bind)
            .await
            .with_context(|| format!("failed to bind tether forward on {}", entry.bind))?;
        forwards.push(forward::Forward {
            listener,
            peer,
            target,
        });
    }

    // Last, so a failure above leaves no UDP socket behind.
    let tether = Tether::bind(
        EndpointConfig::new(bind_addr, identity),
        Arc::new(InboundPolicy { inbound }),
    )
    .with_context(|| format!("failed to bind tether endpoint on {bind_addr}"))?;

    tracing::info!(
        bind = %tether.local_addr().map_or_else(|_| bind_addr.to_string(), |a| a.to_string()),
        node = %node,
        peers = settings.peers.len(),
        forwards = forwards.len(),
        "tether started"
    );
    Ok(TetherRuntime {
        tether,
        dispatch: Arc::new(dispatch),
        receives: settings.peers.iter().any(|peer| peer.inbound),
        streams_limit: config.daemon.limits.gateway_connections_per_listener,
        forwards,
        limiter,
    })
}

impl TetherRuntime {
    #[cfg(test)]
    fn tether(&self) -> Tether {
        self.tether.clone()
    }

    /// Where each forward accepts clients, in configuration order.
    #[cfg(test)]
    fn forward_addrs(&self) -> Vec<SocketAddr> {
        self.forwards
            .iter()
            .filter_map(|forward| forward.listener.local_addr().ok())
            .collect()
    }

    /// Starts serving: one monitored task per forward and one for the stream receiver (only
    /// when some peer may open streams here), matching what `begin` was told to expect. The
    /// endpoint is closed by a task the supervisor waits for at shutdown.
    pub(crate) async fn spawn(self, supervisor: &GatewaySupervisor, tasks: &mut MonitoredTasks) {
        let Self {
            tether,
            dispatch,
            receives,
            streams_limit,
            forwards,
            limiter,
        } = self;
        if receives {
            let receiver = receive::Receiver {
                tether: tether.clone(),
                dispatch,
                connections: supervisor.connection_tracker(),
                shutdown: supervisor.subscribe_shutdown(),
            };
            tasks.spawn(async move {
                receive::run(receiver).await;
                ("tether receiver".to_string(), Ok(()))
            });
        }
        for forward in forwards {
            let label = format!("tether forward to {} ({})", forward.peer.id, forward.target);
            let (tether, limiter) = (tether.clone(), limiter.clone());
            let (connections, shutdown) = (
                supervisor.connection_tracker(),
                supervisor.subscribe_shutdown(),
            );
            tasks.spawn(async move {
                forward::run(
                    forward,
                    tether,
                    limiter,
                    connections,
                    shutdown,
                    streams_limit,
                )
                .await;
                (label, Ok(()))
            });
        }
        let closer = tokio::spawn(close_after_drain(
            tether.clone(),
            supervisor.connection_tracker(),
            supervisor.subscribe_shutdown(),
        ));
        // Shutdown may already have finished waiting; then nobody would wait for the closer,
        // so the endpoint is closed here, before returning.
        if let Err(closer) = supervisor.track_background(closer) {
            closer.abort();
            tether.shutdown().await;
        }
    }
}

/// Closes the endpoint once the supervisor has drained or force-closed the connections and
/// relays it carries: closing earlier would cut streams that shutdown is still letting
/// finish. The supervisor waits for this task, so the daemon does not exit before the close
/// completes.
async fn close_after_drain(
    tether: Tether,
    connections: GatewayConnectionTracker,
    mut shutdown: watch::Receiver<bool>,
) {
    wait_for(&mut shutdown).await;
    let mut force = connections.subscribe_force_shutdown();
    let idle = || connections.pending() == 0;
    while !idle() {
        tokio::select! {
            () = wait_for(&mut force) => {
                // Forced: the tasks are being cancelled; give them a moment to actually exit.
                let exited = async {
                    while !idle() {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                };
                let _ = tokio::time::timeout(FORCED_EXIT_WAIT, exited).await;
                break;
            }
            () = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
    tether.shutdown().await;
    tracing::info!("tether stopped");
}

/// Resolves once the flag is true, or immediately if its sender is gone.
async fn wait_for(flag: &mut watch::Receiver<bool>) {
    let _ = flag.wait_for(|value| *value).await;
}
