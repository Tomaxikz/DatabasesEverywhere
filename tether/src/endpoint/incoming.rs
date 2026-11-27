//! The pending inbound stream that precedes a [`Stream`](super::Stream).

use std::io;

use tokio::time::Instant;

use super::{Stream, stream::write_status_by};
use crate::{
    id::{NodeId, TargetId},
    wire::Status,
};

/// An inbound stream whose header was valid and whose peer is authorized for the target. The
/// peer is still waiting for its status: answer with [`Incoming::accept`] or
/// [`Incoming::reject`]. Dropping it unanswered resets the stream.
///
/// The answer must be written before the deadline of the header exchange, which began when
/// the stream arrived. A peer that grants no flow-control credit therefore cannot hold the
/// application up: past the deadline `accept` fails and the stream is reset.
pub struct Incoming {
    peer: NodeId,
    target: TargetId,
    context: Vec<u8>,
    deadline: Instant,
    // Dropping the stream resets it, which is exactly what an unanswered `Incoming` needs.
    stream: Stream,
}

impl Incoming {
    pub(super) fn new(
        peer: NodeId,
        target: TargetId,
        context: Vec<u8>,
        stream: Stream,
        deadline: Instant,
    ) -> Self {
        Self {
            peer,
            target,
            context,
            deadline,
            stream,
        }
    }

    /// Whether the answer's deadline has already passed.
    pub(super) fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    /// The authenticated node that opened the stream.
    pub fn peer(&self) -> &NodeId {
        &self.peer
    }

    pub fn target(&self) -> &TargetId {
        &self.target
    }

    /// The opaque request context. It is an assertion made by the peer node named by
    /// [`Incoming::peer`]: tether delivers it but does not verify it, so trust it only as far
    /// as that node is trusted to make such claims.
    pub fn context(&self) -> &[u8] {
        &self.context
    }

    /// Answers `Ok` and hands over the stream. Fails with `TimedOut` if the answer cannot
    /// be written before the header exchange's deadline; the stream is then reset.
    pub async fn accept(mut self) -> io::Result<Stream> {
        match write_status_by(&mut self.stream, Status::Ok, self.deadline).await {
            Ok(()) => Ok(self.stream),
            Err(error) => {
                tracing::debug!(peer = %self.peer, "could not answer an inbound stream: {error}");
                Err(error)
            }
        }
    }

    /// Answers with `status` and closes the stream. `Status::Ok` is not a rejection and is
    /// sent as `Status::Unavailable`. Gives up at the same deadline as [`Incoming::accept`].
    pub async fn reject(self, status: Status) {
        self.stream.refuse(status, self.deadline).await;
    }
}
