//! The byte stream handed to the application.

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use quinn::{ConnectionError, ReadError, RecvStream, SendStream, VarInt, WriteError};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use tokio::time::{Instant, sleep_until};

use crate::wire::{self, Status};

/// Error code carried by the reset and stop frames when a stream is dropped or refused.
const ABORT: VarInt = VarInt::from_u32(1);

impl Drop for Stream {
    fn drop(&mut self) {
        // quinn's own drop would finish the send side gracefully and leave the peer
        // waiting for data that will never come. A stream that was shut down is already
        // finished and must still deliver what it queued, so only unfinished ones reset.
        if !self.finished {
            let _ = self.send.reset(ABORT);
        }
        let _ = self.recv.stop(ABORT);
    }
}

/// One proxied connection. Reads and writes raw bytes. Dropping it resets both directions.
///
/// Shutting down the write half queues the end of the stream behind the data already
/// written and returns; it is not an acknowledgment that the peer received anything. The
/// peer's reads continue and so do this stream's. A stream dropped without being shut down
/// discards data it has not yet sent, so shut it down first when the tail matters.
pub struct Stream {
    send: SendStream,
    recv: RecvStream,
    finished: bool,
}

impl Stream {
    pub(super) fn new(send: SendStream, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            finished: false,
        }
    }

    /// Sends a final status, delivers it by finishing the send side and refuses further
    /// input. Used for every stream that is turned away. A peer that grants no
    /// flow-control credit can stall even a tiny write, so it is bounded by `deadline`;
    /// when it is missed the stream is dropped, which resets it.
    pub(super) async fn refuse(mut self, status: Status, deadline: Instant) {
        let status = if status == Status::Ok {
            Status::Unavailable
        } else {
            status
        };
        if write_status_by(&mut self.send, status, deadline)
            .await
            .is_ok()
        {
            let _ = self.finish();
        }
        let _ = self.recv.stop(ABORT);
    }

    fn finish(&mut self) -> Result<(), quinn::ClosedStream> {
        // Set first: whatever finish reports, the send side is done and must not be reset.
        self.finished = true;
        self.send.finish()
    }
}

/// Writes a status so that it never completes after `deadline`: the clock is checked
/// before every poll of the write, so a write that happens to be ready late still loses to
/// the deadline. (`tokio::time::timeout` polls the inner future first and would let it win.)
pub(super) async fn write_status_by<W>(
    writer: &mut W,
    status: Status,
    deadline: Instant,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let expired = || io::Error::new(io::ErrorKind::TimedOut, "the answer missed its deadline");
    let write = wire::write_status(writer, status);
    let sleep = sleep_until(deadline);
    tokio::pin!(write, sleep);
    std::future::poll_fn(|cx| {
        if Instant::now() >= deadline {
            return Poll::Ready(Err(expired()));
        }
        if let Poll::Ready(result) = write.as_mut().poll(cx) {
            return Poll::Ready(result);
        }
        // Registers the wake-up for the deadline itself.
        if sleep.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(expired()));
        }
        Poll::Pending
    })
    .await
}

fn connection_kind(error: &ConnectionError) -> io::ErrorKind {
    match error {
        ConnectionError::TimedOut => io::ErrorKind::TimedOut,
        ConnectionError::Reset => io::ErrorKind::ConnectionReset,
        _ => io::ErrorKind::ConnectionAborted,
    }
}

fn read_error(error: io::Error) -> io::Error {
    let kind = match error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<ReadError>())
    {
        Some(ReadError::Reset(_) | ReadError::ZeroRttRejected) => io::ErrorKind::ConnectionReset,
        Some(ReadError::ConnectionLost(lost)) => connection_kind(lost),
        Some(ReadError::ClosedStream) => io::ErrorKind::NotConnected,
        _ => return error,
    };
    io::Error::new(kind, error)
}

fn write_error(error: io::Error) -> io::Error {
    let kind = match error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<WriteError>())
    {
        Some(WriteError::Stopped(_) | WriteError::ZeroRttRejected) => {
            io::ErrorKind::ConnectionReset
        }
        Some(WriteError::ConnectionLost(lost)) => connection_kind(lost),
        Some(WriteError::ClosedStream) => io::ErrorKind::BrokenPipe,
        _ => return error,
    };
    io::Error::new(kind, error)
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buffer).map_err(read_error)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, bytes).map_err(write_error)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // quinn sends buffered data on its own; there is nothing to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.finished {
            return Poll::Ready(Ok(()));
        }
        // The first call reports what quinn says (a send side that was already reset or
        // finished); later calls find it finished and succeed.
        Poll::Ready(
            self.finish()
                .map_err(|error| io::Error::new(io::ErrorKind::BrokenPipe, error)),
        )
    }
}
