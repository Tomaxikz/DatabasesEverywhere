//! Dialing peers: one shared connection per node and the opening handshake on each stream.

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard},
};

use quinn::Connection;
use tokio::sync::{oneshot, watch};

use super::{Inner, OpenError, Peer, Stream, dial};
use crate::{
    id::{NodeId, TargetId},
    wire::{self, MAX_CONTEXT_LEN, OpenRequest, Status},
};

pub(super) type DialResult = Result<Connection, String>;
pub(super) type DialWatch = watch::Receiver<Option<DialResult>>;

pub(super) enum State {
    /// A dial task is running; everyone who needs the peer waits on its result.
    Dialing(DialWatch),
    Live {
        connection: Connection,
        // Dropped with the entry, which tells the close watcher to let go of its handle:
        // a connection no entry names is then held only by the streams still using it.
        _retire: oneshot::Sender<()>,
    },
}

pub(super) struct Entry {
    pub(super) address: SocketAddr,
    /// Tells a dial task whether the entry it started is still the one in the table.
    pub(super) generation: u64,
    pub(super) state: State,
}

#[derive(Default)]
pub(super) struct Entries {
    pub(super) by_node: HashMap<NodeId, Entry>,
    next_generation: u64,
}

/// At most one entry per node id, so it cannot grow beyond the peers the application names.
#[derive(Default)]
pub(super) struct Table {
    entries: Mutex<Entries>,
    #[cfg(test)]
    stats: Stats,
}

#[cfg(test)]
#[derive(Default)]
struct Stats {
    dials: AtomicUsize,
    lookups: AtomicUsize,
    retries: AtomicUsize,
}

impl Table {
    // Nothing under this lock can panic or await, so a poisoned lock holds valid data.
    pub(super) fn lock(&self) -> MutexGuard<'_, Entries> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn live(&self) -> usize {
        self.lock()
            .by_node
            .values()
            .filter(|entry| {
                matches!(&entry.state, State::Live { connection, .. } if connection.close_reason().is_none())
            })
            .count()
    }

    pub(super) fn clear(&self) {
        // Taken out first so the connections drop after the lock is released.
        let entries = std::mem::take(&mut self.lock().by_node);
        drop(entries);
    }

    /// Drops the entry for `node` if it still holds the connection with this id.
    pub(super) fn forget(&self, node: &NodeId, connection_id: usize) {
        let removed = {
            let mut entries = self.lock();
            let same = matches!(
                entries.by_node.get(node),
                Some(Entry { state: State::Live { connection, .. }, .. })
                    if connection.stable_id() == connection_id
            );
            if same {
                entries.by_node.remove(node)
            } else {
                None
            }
        };
        drop(removed);
    }

    #[cfg(test)]
    pub(super) fn dials_started(&self) -> usize {
        self.stats.dials.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn lookups(&self) -> usize {
        self.stats.lookups.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn retries(&self) -> usize {
        self.stats.retries.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn dialing(&self) -> usize {
        self.lock()
            .by_node
            .values()
            .filter(|entry| matches!(entry.state, State::Dialing(_)))
            .count()
    }
}

pub(super) async fn open(
    inner: &Arc<Inner>,
    peer: &Peer,
    target: &TargetId,
    context: &[u8],
) -> Result<Stream, OpenError> {
    // Checked before any dialing so a bad request costs nothing.
    if context.len() > MAX_CONTEXT_LEN {
        return Err(OpenError::ContextTooLong);
    }
    let mut retried = false;
    loop {
        if inner.is_closed() {
            return Err(OpenError::Closed);
        }
        let (connection, fresh) = match connection(inner, peer).await {
            Ok(found) => found,
            // Shutdown closes the endpoint under a pending dial, which then fails; the
            // caller needs to hear that the endpoint is closed, not about the dial.
            Err(_) if inner.is_closed() => return Err(OpenError::Closed),
            Err(error) => return Err(error),
        };
        let error = match exchange(inner, &connection, target, context).await {
            Ok(stream) => return Ok(stream),
            Err(error) => error,
        };
        if inner.is_closed() {
            return Err(OpenError::Closed);
        }
        let Some(reason) = connection.close_reason() else {
            return Err(error);
        };
        if matches!(
            error,
            OpenError::Refused(_) | OpenError::UnsupportedVersion { .. }
        ) {
            return Err(error);
        }
        inner.outbound.forget(&peer.id, connection.stable_id());
        // A connection this call just dialed that dies at once was refused by the peer, for
        // instance for a certificate from another authority; TLS 1.3 only tells the dialer
        // after its handshake looks complete. Redialing would repeat the refusal.
        if fresh || retried {
            return Err(OpenError::Connect(reason.to_string()));
        }
        retried = true;
        #[cfg(test)]
        inner.outbound.stats.retries.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(peer = %peer.id, "reusing a closed connection failed, redialing");
    }
}

/// Returns a live connection to the peer and whether this call waited on a new dial for it.
async fn connection(inner: &Arc<Inner>, peer: &Peer) -> Result<(Connection, bool), OpenError> {
    let mut result = match lookup(inner, peer) {
        Lookup::Live(connection) => return Ok((connection, false)),
        Lookup::Wait(result) => result,
    };
    let abandoned = || OpenError::Connect("the connection attempt was abandoned".into());
    let outcome = result
        .wait_for(Option::is_some)
        .await
        .map_err(|_| abandoned())?
        .clone();
    match outcome {
        Some(Ok(connection)) => Ok((connection, true)),
        Some(Err(message)) => Err(OpenError::Connect(message)),
        None => Err(abandoned()),
    }
}

pub(super) enum Lookup {
    Live(Connection),
    Wait(DialWatch),
}

/// What an existing entry offers a caller who wants `address`, if anything.
pub(super) fn reusable(entry: &Entry, address: SocketAddr) -> Option<Lookup> {
    // The same id at another address is a node that moved; its old entry is replaced.
    if entry.address != address {
        return None;
    }
    match &entry.state {
        State::Live { connection, .. } if connection.close_reason().is_none() => {
            Some(Lookup::Live(connection.clone()))
        }
        // A dial whose task is gone without publishing would never answer: treat it as absent.
        State::Dialing(result) if result.has_changed().is_ok() => {
            Some(Lookup::Wait(result.clone()))
        }
        State::Dialing(_) | State::Live { .. } => None,
    }
}

fn lookup(inner: &Arc<Inner>, peer: &Peer) -> Lookup {
    #[cfg(test)]
    inner.outbound.stats.lookups.fetch_add(1, Ordering::Relaxed);
    let mut entries = inner.outbound.lock();
    if let Some(found) = entries
        .by_node
        .get(&peer.id)
        .and_then(|entry| reusable(entry, peer.address))
    {
        return found;
    }

    let generation = entries.next_generation;
    entries.next_generation += 1;
    let (sender, receiver) = watch::channel(None);
    let replaced = entries.by_node.insert(
        peer.id.clone(),
        Entry {
            address: peer.address,
            generation,
            state: State::Dialing(receiver.clone()),
        },
    );
    drop(entries);
    // Dropped outside the lock; for a retired live entry this releases its watcher.
    drop(replaced);
    #[cfg(test)]
    inner.outbound.stats.dials.fetch_add(1, Ordering::Relaxed);
    // A task of its own, so an opener that gives up does not abort the dial the others
    // are waiting on.
    // On the endpoint's own runtime, never the caller's: quinn starts the connection driver
    // on whichever runtime builds the connection, and a caller's runtime may end first.
    let guard = dial::Guard::new(Arc::downgrade(inner), peer.id.clone(), generation);
    inner.runtime.spawn(dial::dial(
        Arc::downgrade(inner),
        peer.clone(),
        generation,
        sender,
        guard,
    ));
    Lookup::Wait(receiver)
}

async fn exchange(
    inner: &Inner,
    connection: &Connection,
    target: &TargetId,
    context: &[u8],
) -> Result<Stream, OpenError> {
    let attempt = async {
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|error| OpenError::Connect(error.to_string()))?;
        // Wrapped at once so any failure below resets the stream instead of finishing it.
        let mut stream = Stream::new(send, recv);
        let request = OpenRequest {
            target: target.clone(),
            context: context.to_vec(),
        };
        wire::write_open(&mut stream, &request)
            .await
            .map_err(|error| OpenError::Wire(error.into()))?;
        let answer = wire::read_status(&mut stream).await?;
        match answer.status {
            Status::Ok => Ok(stream),
            Status::UnsupportedVersion => Err(OpenError::UnsupportedVersion {
                peer_max: answer.peer_max.unwrap_or(0),
            }),
            status => Err(OpenError::Refused(status)),
        }
    };
    let deadline = tokio::time::Instant::now() + inner.header_timeout;
    let stream = tokio::time::timeout_at(deadline, attempt)
        .await
        .map_err(|_| OpenError::Timeout)??;
    // `timeout_at` polls the attempt before the clock, so an answer that arrived while
    // this task was not running would otherwise be taken after the deadline. Dropping the
    // stream resets it, which tells the peer nobody is there.
    if tokio::time::Instant::now() >= deadline {
        return Err(OpenError::Timeout);
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(state: State) -> Entry {
        Entry {
            address: "127.0.0.1:1".parse().expect("address"),
            generation: 0,
            state,
        }
    }

    #[test]
    fn a_dialing_entry_whose_task_is_gone_is_absent() {
        let address = "127.0.0.1:1".parse().expect("address");
        let (sender, receiver) = watch::channel(None);
        let waiting = entry(State::Dialing(receiver.clone()));
        assert!(matches!(reusable(&waiting, address), Some(Lookup::Wait(_))));

        drop(sender);
        assert!(reusable(&waiting, address).is_none());
    }

    #[test]
    fn an_entry_for_another_address_is_not_reused() {
        let (_sender, receiver) = watch::channel(None);
        let waiting = entry(State::Dialing(receiver));
        let other = "127.0.0.1:2".parse().expect("address");
        assert!(reusable(&waiting, other).is_none());
    }
}
