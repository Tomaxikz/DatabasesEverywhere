//! Budgets for inbound connections: how many handshakes may run, and how many authenticated
//! connections may be live in total and per node.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::id::NodeId;

/// What to do with a connection attempt that has not been looked at yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Decision {
    /// Spend a handshake permit on it.
    Proceed,
    /// Ask the peer to prove its address first; costs this side no state.
    Retry,
    /// Turn it away.
    Refuse,
}

/// `in_use` of `max` handshake permits are taken. Once more than half are, an attempt that
/// has not proven its address is sent a Retry, so spoofed sources cannot fill the rest.
pub(super) fn decide(address_validated: bool, in_use: usize, max: usize) -> Decision {
    if in_use >= max {
        Decision::Refuse
    } else if !address_validated && in_use * 2 > max {
        Decision::Retry
    } else {
        Decision::Proceed
    }
}

pub(super) struct Admission {
    handshakes: Arc<Semaphore>,
    max_handshakes: usize,
    max_connections: usize,
    max_per_peer: usize,
    live: Mutex<Live>,
}

/// Bounded by `max_connections`: an entry exists only while one of its connections does.
#[derive(Default)]
struct Live {
    total: usize,
    per_peer: HashMap<NodeId, usize>,
}

/// A live inbound connection counted against the limits. Dropping it frees the slot.
pub(super) struct Slot {
    admission: Arc<Admission>,
    peer: NodeId,
}

impl Admission {
    pub(super) fn new(
        max_handshakes: usize,
        max_connections: usize,
        max_per_peer: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            handshakes: Arc::new(Semaphore::new(max_handshakes)),
            max_handshakes,
            max_connections,
            max_per_peer,
            live: Mutex::new(Live::default()),
        })
    }

    // Nothing under this lock can panic or await, so a poisoned lock holds valid data.
    fn lock(&self) -> MutexGuard<'_, Live> {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn handshakes_in_use(&self) -> usize {
        self.max_handshakes
            .saturating_sub(self.handshakes.available_permits())
    }

    pub(super) fn max_handshakes(&self) -> usize {
        self.max_handshakes
    }

    /// Takes a handshake permit without waiting.
    pub(super) fn try_handshake(&self) -> Option<OwnedSemaphorePermit> {
        self.handshakes.clone().try_acquire_owned().ok()
    }

    /// Counts a connection from `peer`, or returns `None` when either limit is reached.
    pub(super) fn admit(self: &Arc<Self>, peer: &NodeId) -> Option<Slot> {
        let mut guard = self.lock();
        let live = &mut *guard;
        if live.total >= self.max_connections {
            return None;
        }
        let count = live.per_peer.entry(peer.clone()).or_default();
        if *count >= self.max_per_peer {
            // `or_default` inserted a zero only if the peer was new, and a zero count cannot
            // be at the limit, so nothing is left behind here.
            return None;
        }
        *count += 1;
        live.total += 1;
        Some(Slot {
            admission: self.clone(),
            peer: peer.clone(),
        })
    }

    #[cfg(test)]
    pub(super) fn live_connections(&self) -> usize {
        self.lock().total
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut live = self.admission.lock();
        live.total = live.total.saturating_sub(1);
        if let Some(count) = live.per_peer.get_mut(&self.peer) {
            *count -= 1;
            if *count == 0 {
                live.per_peer.remove(&self.peer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str) -> NodeId {
        name.parse().expect("valid node id")
    }

    #[test]
    fn decisions_follow_the_permit_and_validation_state() {
        // (validated, in_use, max)
        assert_eq!(decide(false, 0, 4), Decision::Proceed);
        assert_eq!(decide(false, 2, 4), Decision::Proceed, "exactly half");
        assert_eq!(decide(false, 3, 4), Decision::Retry);
        assert_eq!(decide(true, 3, 4), Decision::Proceed);
        assert_eq!(decide(true, 4, 4), Decision::Refuse);
        assert_eq!(decide(false, 4, 4), Decision::Refuse);
    }

    #[test]
    fn handshake_permits_run_out_without_waiting() {
        let admission = Admission::new(2, 8, 8);
        let first = admission.try_handshake().expect("first");
        let _second = admission.try_handshake().expect("second");
        assert!(admission.try_handshake().is_none());
        assert_eq!(admission.handshakes_in_use(), 2);
        drop(first);
        assert!(admission.try_handshake().is_some());
    }

    #[test]
    fn slots_enforce_both_limits_and_free_on_drop() {
        let admission = Admission::new(1, 3, 2);
        let a1 = admission.admit(&node("a")).expect("a first");
        let _a2 = admission.admit(&node("a")).expect("a second");
        assert!(admission.admit(&node("a")).is_none(), "per-peer limit");
        let _b = admission.admit(&node("b")).expect("b");
        assert!(admission.admit(&node("c")).is_none(), "global limit");
        assert_eq!(admission.live_connections(), 3);
        drop(a1);
        assert!(admission.admit(&node("c")).is_some(), "slot freed");
    }

    #[test]
    fn a_refused_peer_leaves_no_entry_behind() {
        let admission = Admission::new(1, 1, 1);
        let _a = admission.admit(&node("a")).expect("a");
        assert!(admission.admit(&node("b")).is_none());
        assert_eq!(admission.lock().per_peer.len(), 1);
    }
}
