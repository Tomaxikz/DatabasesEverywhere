//! Accepting peers: admission, handshake, identity, and the per-stream header check.

use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use quinn::{Connection, RecvStream, SendStream};
use rustls_pki_types::CertificateDer;
use tokio::{
    sync::{OwnedSemaphorePermit, mpsc},
    time::{Instant, timeout, timeout_at},
};

use super::{
    Authorizer, CLOSE_IDENTITY, CLOSE_LIMIT, Incoming, Stream,
    admission::{Admission, Decision, decide},
};
use crate::wire::Status;
use crate::{id::NodeId, identity::peer_node_id, wire};

/// What every background task of the accept side needs. Kept apart from `Inner` so these
/// tasks do not keep the endpoint alive.
pub(super) struct Context {
    authorizer: Arc<dyn Authorizer>,
    queue: mpsc::Sender<Incoming>,
    header_timeout: Duration,
    handshake_timeout: Duration,
    admission: Arc<Admission>,
    #[cfg(test)]
    stats: Stats,
}

#[cfg(test)]
#[derive(Default)]
struct Stats {
    accepted: AtomicUsize,
    retried: AtomicUsize,
    refused: AtomicUsize,
}

impl Context {
    pub(super) fn new(
        authorizer: Arc<dyn Authorizer>,
        queue: mpsc::Sender<Incoming>,
        header_timeout: Duration,
        handshake_timeout: Duration,
        admission: Arc<Admission>,
    ) -> Self {
        Self {
            authorizer,
            queue,
            header_timeout,
            handshake_timeout,
            admission,
            #[cfg(test)]
            stats: Stats::default(),
        }
    }

    #[cfg(test)]
    pub(super) fn accepted_connections(&self) -> usize {
        self.stats.accepted.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn retried_attempts(&self) -> usize {
        self.stats.retried.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn refused_attempts(&self) -> usize {
        self.stats.refused.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(super) fn live_connections(&self) -> usize {
        self.admission.live_connections()
    }

    #[cfg(test)]
    pub(super) fn handshakes_in_use(&self) -> usize {
        self.admission.handshakes_in_use()
    }

    #[cfg(test)]
    pub(super) fn queued(&self) -> usize {
        self.queue.max_capacity() - self.queue.capacity()
    }
}

pub(super) async fn accept_loop(endpoint: quinn::Endpoint, context: Arc<Context>) {
    while let Some(incoming) = endpoint.accept().await {
        let admission = &context.admission;
        let decision = decide(
            incoming.remote_address_validated(),
            admission.handshakes_in_use(),
            admission.max_handshakes(),
        );
        match decision {
            // The permit is taken here, before anything is spawned, so a flood of attempts
            // cannot create tasks faster than handshakes finish.
            Decision::Proceed => match admission.try_handshake() {
                // Its own task, so one slow peer cannot hold up the rest.
                Some(permit) => {
                    tokio::spawn(serve(incoming, context.clone(), permit));
                }
                None => refuse(&context, incoming),
            },
            Decision::Retry => match incoming.retry() {
                Ok(()) => {
                    #[cfg(test)]
                    context.stats.retried.fetch_add(1, Ordering::Relaxed);
                }
                // Cannot happen for an unvalidated address, but refusing is always safe.
                Err(error) => refuse(&context, error.into_incoming()),
            },
            Decision::Refuse => refuse(&context, incoming),
        }
    }
}

fn refuse(context: &Context, incoming: quinn::Incoming) {
    #[cfg(test)]
    context.stats.refused.fetch_add(1, Ordering::Relaxed);
    #[cfg(not(test))]
    let _ = context;
    incoming.refuse();
}

fn identify(connection: &Connection) -> Option<NodeId> {
    let identity = connection.peer_identity()?;
    let chain = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    peer_node_id(&chain).ok()
}

async fn serve(incoming: quinn::Incoming, context: Arc<Context>, handshake: OwnedSemaphorePermit) {
    let connection = match timeout(context.handshake_timeout, incoming).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => {
            tracing::debug!("inbound handshake failed: {error}");
            return;
        }
        Err(_) => {
            tracing::debug!("inbound handshake timed out");
            return;
        }
    };
    let Some(peer) = identify(&connection) else {
        tracing::debug!("closing a peer whose certificate names no single node");
        connection.close(CLOSE_IDENTITY, b"identity");
        return;
    };
    let Some(_slot) = context.admission.admit(&peer) else {
        tracing::debug!(%peer, "closing a connection over the connection limits");
        connection.close(CLOSE_LIMIT, b"limit");
        return;
    };
    // The handshake is over; the connection now counts against the live limits instead.
    drop(handshake);
    #[cfg(test)]
    context.stats.accepted.fetch_add(1, Ordering::Relaxed);
    tracing::debug!(%peer, "peer connected");

    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                // The exchange's deadline starts now, not when the handler task first runs.
                let Some(deadline) = Instant::now().checked_add(context.header_timeout) else {
                    continue;
                };
                tokio::spawn(serve_stream(
                    context.clone(),
                    peer.clone(),
                    send,
                    recv,
                    deadline,
                ));
            }
            Err(error) => {
                tracing::debug!(%peer, "peer connection ended: {error}");
                return;
            }
        }
    }
}

/// Dropping the stream on any early return resets it, which is the answer for headers
/// that time out or fail to arrive.
async fn serve_stream(
    context: Arc<Context>,
    peer: NodeId,
    send: SendStream,
    recv: RecvStream,
    deadline: Instant,
) {
    let mut stream = Stream::new(send, recv);
    let request = match timeout_at(deadline, wire::read_open(&mut stream)).await {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => {
            tracing::debug!(%peer, "bad stream header: {error}");
            if let Some(status) = error.status() {
                stream.refuse(status, deadline).await;
            }
            return;
        }
        Err(_) => {
            tracing::debug!(%peer, "stream header timed out");
            return;
        }
    };

    if !context
        .authorizer
        .allows(&peer, &request.target, &request.context)
    {
        tracing::debug!(%peer, target = %request.target, "stream denied");
        stream.refuse(Status::Denied, deadline).await;
        return;
    }

    match context.queue.try_send(Incoming::new(
        peer,
        request.target,
        request.context,
        stream,
        deadline,
    )) {
        Ok(()) => {}
        // A full queue or a closed one: answer instead of waiting, so a slow application
        // cannot make peers pile up streams here.
        Err(
            mpsc::error::TrySendError::Full(incoming) | mpsc::error::TrySendError::Closed(incoming),
        ) => {
            incoming.reject(Status::Unavailable).await;
        }
    }
}
