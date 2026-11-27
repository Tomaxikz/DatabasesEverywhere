//! Entry side: relays a client's TCP connection into a tether stream, parsing nothing.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use ::tether::{Peer, TargetId, Tether};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
};

use super::{
    relay::{self, Outcome, relay},
    wait_for,
};
use crate::gateway::{
    listeners::{rejection_reason_label, tether_log_permit},
    security::{GatewayConnectionLimiter, GatewayConnectionRejection},
    supervisor::GatewayConnectionTracker,
};

/// Pause after a failed `accept`, so a persistent error (such as running out of file
/// descriptors) does not spin.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

pub(super) struct Forward {
    pub(super) listener: TcpListener,
    pub(super) peer: Peer,
    pub(super) target: TargetId,
}

pub(super) async fn run(
    forward: Forward,
    tether: Tether,
    limiter: GatewayConnectionLimiter,
    connections: GatewayConnectionTracker,
    mut shutdown: watch::Receiver<bool>,
    max_connections: usize,
) {
    let Forward {
        listener,
        peer,
        target,
    } = forward;
    let bind = listener
        .local_addr()
        .map(|address| address.to_string())
        .unwrap_or_default();
    tracing::info!(bind, node = %peer.id, protocol = %target, max_active_connections = max_connections, "tether forward started");
    let slots = Arc::new(Semaphore::new(max_connections));
    let mut limit_logged = false;
    loop {
        let accepted = tokio::select! {
            () = wait_for(&mut shutdown) => {
                tracing::info!(bind, node = %peer.id, protocol = %target, "tether forward stopping");
                return;
            }
            accepted = listener.accept() => accepted,
        };
        let (client, client_addr) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(bind, %error, "tether forward accept failed");
                tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                continue;
            }
        };
        if let Err(error) = client.set_nodelay(true) {
            tracing::debug!(%client_addr, %error, "failed to configure client socket");
            continue;
        }
        let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
            if !limit_logged {
                tracing::warn!(%client_addr, protocol = %target, "audit database_connection_global_limit_reached");
                limit_logged = true;
            }
            continue;
        };
        limit_logged = false;
        let ip_permit = match limiter.try_acquire(client_addr.ip()) {
            Ok(permit) => permit,
            Err(GatewayConnectionRejection { reason, should_log }) => {
                if should_log {
                    let reason = rejection_reason_label(reason);
                    tracing::warn!(
                        %client_addr, protocol = %target, reason, "audit database_connection_limited"
                    );
                }
                continue;
            }
        };
        let Some(connection) = connections.try_track() else {
            continue;
        };
        let mut force_shutdown = connections.subscribe_force_shutdown();
        let (tether, peer, target) = (tether.clone(), peer.clone(), target.clone());
        tokio::spawn(async move {
            let _permits = (slot, ip_permit, connection);
            tokio::select! {
                () = forward_connection(client, client_addr, &tether, &peer, &target) => {}
                () = wait_for(&mut force_shutdown) => {
                    tracing::debug!(%client_addr, protocol = %target, "tether connection closed for daemon shutdown");
                }
            }
        });
    }
}

async fn forward_connection(
    client: TcpStream,
    client_addr: SocketAddr,
    tether: &Tether,
    peer: &Peer,
    target: &TargetId,
) {
    // The data node limits and logs by this address, so it is sent as strict text.
    let context = client_addr.to_string();
    let stream = match tether.open(peer, target, context.as_bytes()).await {
        Ok(stream) => stream,
        Err(error) => {
            let window = format!("{}/{target}", peer.id);
            match tether_log_permit("open", &window) {
                Some(suppressed) => tracing::warn!(
                    node = %peer.id, protocol = %target, %error,
                    suppressed_since_last_warning = suppressed,
                    "tether could not open a stream"
                ),
                None => {
                    tracing::debug!(node = %peer.id, protocol = %target, %error, "tether open failure suppressed")
                }
            }
            return;
        }
    };
    match relay(client, stream, relay::GRACE).await {
        Ok(Outcome::Delivered) => {}
        Ok(Outcome::Undelivered(reason)) => {
            tracing::debug!(%client_addr, node = %peer.id, protocol = %target, %reason, "tether stream tail was not delivered");
        }
        Err(error) => {
            tracing::debug!(%client_addr, node = %peer.id, protocol = %target, %error, "tether connection ended with an error");
        }
    }
}
