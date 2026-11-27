//! Data side: hands each inbound tether stream to the gateway handler of the protocol it
//! names, in process.

use std::{net::SocketAddr, sync::Arc};

use ::tether::{Tether, wire::Status};
use tokio::{net::UnixStream, sync::watch};

use super::{
    Dispatch,
    relay::{self, Outcome, relay},
    wait_for,
};
use crate::gateway::{
    listeners::{ClientSocket, Origin},
    supervisor::GatewayConnectionTracker,
};

pub(super) struct Receiver {
    pub(super) tether: Tether,
    pub(super) dispatch: Arc<Dispatch>,
    pub(super) connections: GatewayConnectionTracker,
    pub(super) shutdown: watch::Receiver<bool>,
}

/// Accepts streams until the endpoint is shut down.
pub(super) async fn run(receiver: Receiver) {
    let Receiver {
        tether,
        dispatch,
        connections,
        shutdown,
    } = receiver;
    while let Some(incoming) = tether.accept().await {
        // The context is the client address the entry node asserts; admission limits and
        // logs by it, so a stream without one is turned away first.
        let Some(client) = std::str::from_utf8(incoming.context())
            .ok()
            .and_then(|text| text.parse::<SocketAddr>().ok())
        else {
            tokio::spawn(incoming.reject(Status::Malformed));
            continue;
        };
        let Some(entry) = dispatch.get(incoming.target().as_str()).cloned() else {
            tokio::spawn(incoming.reject(Status::Unavailable));
            continue;
        };
        // The relay is counted before shutdown is checked, so the closer can never see zero
        // while a stream is being admitted.
        let relay_guard = connections.track_relay();
        if *shutdown.borrow() || !connections.is_accepting() {
            drop(relay_guard);
            tokio::spawn(incoming.reject(Status::Unavailable));
            continue;
        }
        let Ok((handler_end, relay_end)) = UnixStream::pair() else {
            drop(relay_guard);
            tokio::spawn(incoming.reject(Status::Unavailable));
            continue;
        };
        let origin = Origin::tunnelled(client, incoming.peer().clone());
        // The same admission as a public connection; the stream is accepted only once the
        // handler is running, so a refused stream costs the peer nothing it could not retry.
        let Ok(lease) = entry.admit(
            ClientSocket::Local(handler_end, origin.clone()),
            origin.clone(),
        ) else {
            drop(relay_guard);
            tokio::spawn(incoming.reject(Status::Unavailable));
            continue;
        };
        let mut force_shutdown = connections.subscribe_force_shutdown();
        tokio::spawn(async move {
            // Held until the relay has ended, delivery included. The admission slots are
            // shared with the handler task, so a relay that outlives its handler still
            // occupies the slot and the client's per-IP permit.
            let _held = (relay_guard, lease);
            tokio::select! {
                () = serve(incoming, relay_end, origin) => {}
                () = wait_for(&mut force_shutdown) => {}
            }
        });
    }
}

async fn serve(incoming: ::tether::Incoming, handler: UnixStream, origin: Origin) {
    let protocol = incoming.target().clone();
    let (client, via_node) = (origin.client_field(), origin.via_field());
    // Dropping `handler` when this fails ends the handler's connection.
    let Ok(stream) = incoming.accept().await else {
        return;
    };
    match relay(stream, handler, relay::GRACE).await {
        Ok(Outcome::Delivered) => {}
        Ok(Outcome::Undelivered(reason)) => {
            tracing::debug!(client, via_node, %protocol, %reason, "tether stream tail was not delivered");
        }
        Err(error) => {
            tracing::debug!(client, via_node, %protocol, %error, "tether connection ended with an error");
        }
    }
}
