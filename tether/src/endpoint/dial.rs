//! The dial task: connects, checks who answered, publishes the connection and watches it.

use std::{
    sync::{Arc, Weak},
    time::Duration,
};

use quinn::Connection;
use tokio::sync::{oneshot, watch};

use super::{
    CLOSE_IDENTITY, CLOSE_SUPERSEDED, Inner, Peer,
    outbound::{DialResult, State},
    peer_of,
};
use crate::id::NodeId;

/// Removes the entry of a dial that is dropped or unwinds before publishing, so a later
/// caller for the same peer starts afresh instead of waiting on a dial that no longer exists.
pub(super) struct Guard {
    // Weak, like everything a dial holds: a dial nobody waits for must not keep the socket
    // open after the last `Tether` handle is gone.
    inner: Weak<Inner>,
    node: NodeId,
    generation: u64,
    armed: bool,
}

impl Guard {
    /// Built by whoever spawns the dial, not inside it, so a dial that is dropped before it
    /// is ever polled still cleans up.
    pub(super) fn new(inner: Weak<Inner>, node: NodeId, generation: u64) -> Self {
        Self {
            inner,
            node,
            generation,
            armed: true,
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let removed = {
            let mut entries = inner.outbound.lock();
            let ours = entries.by_node.get(&self.node).is_some_and(|entry| {
                entry.generation == self.generation && matches!(entry.state, State::Dialing(_))
            });
            if ours {
                entries.by_node.remove(&self.node)
            } else {
                None
            }
        };
        drop(removed);
    }
}

pub(super) async fn dial(
    inner: Weak<Inner>,
    peer: Peer,
    generation: u64,
    sender: watch::Sender<Option<DialResult>>,
    mut guard: Guard,
) {
    // The endpoint is only borrowed to start the attempt and again to publish it. Dropping
    // the last handle in between closes the socket, which ends the attempt at once.
    let result = match inner.upgrade() {
        Some(strong) => {
            let attempt = begin(&strong, &peer);
            let limit = strong.connect_timeout;
            drop(strong);
            match attempt {
                Ok(connecting) => finish(connecting, limit, &peer).await,
                Err(error) => Err(error),
            }
        }
        None => Err(GONE.into()),
    };
    let Some(inner) = inner.upgrade() else {
        // Dropping the endpoint already closed every connection.
        sender.send_replace(Some(Err(GONE.into())));
        return;
    };

    // `Some` when this dial's entry is still the one in the table and now holds the
    // connection; the receiver ends when that entry is replaced or removed.
    let retire = {
        let mut entries = inner.outbound.lock();
        let current = entries
            .by_node
            .get(&peer.id)
            .is_some_and(|entry| entry.generation == generation);
        let mut retire = None;
        if current {
            match &result {
                Ok(connection) => {
                    if let Some(entry) = entries.by_node.get_mut(&peer.id) {
                        let (sender, retired) = oneshot::channel();
                        entry.state = State::Live {
                            connection: connection.clone(),
                            _retire: sender,
                        };
                        retire = Some(retired);
                    }
                }
                Err(_) => {
                    entries.by_node.remove(&peer.id);
                }
            }
        }
        guard.armed = false;
        retire
    };

    if let Ok(connection) = &result {
        match retire {
            Some(retired) => {
                inner.runtime.spawn(watch_closed(
                    Arc::downgrade(&inner),
                    peer.id.clone(),
                    connection.clone(),
                    retired,
                ));
            }
            // The peer moved while this dial ran. Whoever still waits may use the
            // connection; if nobody does, nothing else would ever close it.
            None if sender.receiver_count() == 0 => {
                connection.close(CLOSE_SUPERSEDED, b"superseded");
            }
            None => {}
        }
    }
    // `send` would discard the value when no waiter is left.
    sender.send_replace(Some(result));
}

/// Forgets the entry when the connection dies, and lets go of the connection when the entry
/// is replaced so an unused retired connection is not kept alive by this task.
async fn watch_closed(
    inner: Weak<Inner>,
    node: NodeId,
    connection: Connection,
    retired: oneshot::Receiver<()>,
) {
    tokio::select! {
        _ = connection.closed() => {
            if let Some(inner) = inner.upgrade() {
                inner.outbound.forget(&node, connection.stable_id());
            }
        }
        // Nothing is ever sent: the sender dropping is the signal.
        _ = retired => {}
    }
}

const GONE: &str = "the endpoint was dropped";

fn begin(inner: &Inner, peer: &Peer) -> Result<quinn::Connecting, String> {
    // The certificate must be valid for the node id, so that is the only server name used.
    inner
        .endpoint
        .connect_with(inner.client_config.clone(), peer.address, peer.id.as_str())
        .map_err(|error| error.to_string())
}

async fn finish(connecting: quinn::Connecting, limit: Duration, peer: &Peer) -> DialResult {
    let connection = match tokio::time::timeout(limit, connecting).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => return Err(error.to_string()),
        Err(_) => return Err("timed out".into()),
    };
    // Ordinary verification accepts a certificate that merely lists the node among several
    // names; the node must be the only one, or this peer could answer for others too.
    if peer_of(&connection).as_ref() != Some(&peer.id) {
        connection.close(CLOSE_IDENTITY, b"identity");
        return Err("the peer's certificate does not name exactly the expected node".into());
    }
    Ok(connection)
}
