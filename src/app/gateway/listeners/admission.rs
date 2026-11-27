use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use ::tether::NodeId;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;

use super::{
    ClientSocket, ListenerError, log_connection_failure, rejection_reason_label, wait_for_shutdown,
};
use crate::gateway::{
    resolver::RouteResolver,
    security::{GatewayConnectionLimiter, GatewayConnectionPermit, GatewayConnectionRejection},
    supervisor::{GatewayConnectionGuard, GatewayConnectionTracker},
};

type HandlerFuture = Pin<Box<dyn Future<Output = Result<(), ListenerError>> + Send>>;
type Handler =
    Box<dyn Fn(ClientSocket, RouteResolver, Option<TlsAcceptor>) -> HandlerFuture + Send + Sync>;

/// Where a connection came from, for log lines. Public connections show their own address;
/// tunnelled ones show the client address the entry node asserted (it is not verified) and
/// that node, as direct fields so quiet logging keeps them.
#[derive(Debug, Clone)]
pub(crate) struct Origin {
    pub(crate) client: SocketAddr,
    pub(crate) via_node: Option<NodeId>,
}

impl Origin {
    pub(crate) fn public(client: SocketAddr) -> Self {
        Self {
            client,
            via_node: None,
        }
    }

    pub(crate) fn tunnelled(client: SocketAddr, via_node: NodeId) -> Self {
        Self {
            client,
            via_node: Some(via_node),
        }
    }

    /// Present only for tunnelled connections, so public log lines keep their shape.
    pub(crate) fn client_field(&self) -> Option<tracing::field::DisplayValue<SocketAddr>> {
        self.via_node
            .as_ref()
            .map(|_| tracing::field::display(self.client))
    }

    pub(crate) fn via_field(&self) -> Option<tracing::field::DisplayValue<&NodeId>> {
        self.via_node.as_ref().map(tracing::field::display)
    }
}

/// Why a connection was not handed to its handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The protocol's listener already carries its configured number of connections.
    Capacity,
    /// The client is over its per-IP limit.
    ClientLimit,
    /// The gateway is not accepting connections.
    NotAccepting,
}

/// The slots one admitted connection holds: the protocol's connection cap, the client's
/// per-IP permit and the connection tracker.
struct Permits {
    _global: OwnedSemaphorePermit,
    _client: GatewayConnectionPermit,
    _tracked: GatewayConnectionGuard,
}

/// Shared ownership of an admitted connection's slots. The handler task holds one; a caller
/// that keeps relaying after the handler is done holds another, and the slots are released
/// only when the last one is dropped.
#[must_use]
pub(crate) struct Lease {
    _permits: Arc<Permits>,
}

/// One protocol's gateway: its handler and everything a connection needs to be admitted to
/// it. A public listener and tether's dispatch hand connections over through the same
/// [`admit`](Self::admit), so the same limits apply in the same order to both.
pub(crate) struct ProtocolEntry {
    protocol: &'static str,
    handler: Handler,
    resolver: RouteResolver,
    tls: Option<TlsAcceptor>,
    slots: Arc<Semaphore>,
    capacity_logged: AtomicBool,
    limiter: GatewayConnectionLimiter,
    connections: GatewayConnectionTracker,
}

impl ProtocolEntry {
    pub(crate) fn new<H, F>(
        protocol: &'static str,
        handler: H,
        resolver: RouteResolver,
        tls: Option<TlsAcceptor>,
        limiter: GatewayConnectionLimiter,
        connections: GatewayConnectionTracker,
    ) -> Arc<Self>
    where
        H: Fn(ClientSocket, RouteResolver, Option<TlsAcceptor>) -> F + Send + Sync + 'static,
        F: Future<Output = Result<(), ListenerError>> + Send + 'static,
    {
        let max_active = resolver
            .config()
            .daemon
            .limits
            .gateway_connections_per_listener;
        Arc::new(Self {
            protocol,
            handler: Box::new(move |socket, resolver, tls| {
                Box::pin(handler(socket, resolver, tls))
            }),
            resolver,
            tls,
            slots: Arc::new(Semaphore::new(max_active)),
            capacity_logged: AtomicBool::new(false),
            limiter,
            connections,
        })
    }

    pub(super) fn has_tls(&self) -> bool {
        self.tls.is_some()
    }

    pub(crate) fn protocol(&self) -> &'static str {
        self.protocol
    }

    pub(crate) fn max_active_connections(&self) -> usize {
        self.resolver
            .config()
            .daemon
            .limits
            .gateway_connections_per_listener
    }

    /// Admits `socket` in a fixed order: the listener's connection cap, the client's per-IP
    /// limit, the connection tracker. On success the handler runs in its own task, tracked
    /// and cancelled on forced shutdown, and nothing more is required of the caller.
    pub(crate) fn admit(
        self: &Arc<Self>,
        socket: ClientSocket,
        origin: Origin,
    ) -> Result<Lease, Refusal> {
        let protocol = self.protocol;
        let peer = origin.client;
        let Ok(global_permit) = Arc::clone(&self.slots).try_acquire_owned() else {
            if !self.capacity_logged.swap(true, Ordering::Relaxed) {
                tracing::warn!(%peer, client = origin.client_field(), via_node = origin.via_field(), protocol, "audit database_connection_global_limit_reached");
            }
            return Err(Refusal::Capacity);
        };
        self.capacity_logged.store(false, Ordering::Relaxed);
        let ip_permit = match self.limiter.try_acquire(peer.ip()) {
            Ok(permit) => permit,
            Err(GatewayConnectionRejection { reason, should_log }) => {
                if should_log {
                    let reason = rejection_reason_label(reason);
                    tracing::warn!(%peer, client = origin.client_field(), via_node = origin.via_field(), protocol, reason, "audit database_connection_limited");
                }
                return Err(Refusal::ClientLimit);
            }
        };
        let Some(connection) = self.connections.try_track() else {
            return Err(Refusal::NotAccepting);
        };
        let permits = Arc::new(Permits {
            _global: global_permit,
            _client: ip_permit,
            _tracked: connection,
        });
        let lease = Lease {
            _permits: Arc::clone(&permits),
        };
        let mut force_shutdown = self.connections.subscribe_force_shutdown();
        let entry = Arc::clone(self);
        tokio::spawn(async move {
            let _permits = permits;
            let handled = (entry.handler)(socket, entry.resolver.clone(), entry.tls.clone());
            tokio::select! {
                result = handled => {
                    if let Err(error) = result {
                        log_connection_failure(protocol, &origin, &error);
                    }
                }
                _ = wait_for_shutdown(&mut force_shutdown) => {
                    tracing::debug!(%peer, client = origin.client_field(), via_node = origin.via_field(), protocol, "database connection closed for daemon shutdown");
                }
            }
        });
        Ok(lease)
    }
}
