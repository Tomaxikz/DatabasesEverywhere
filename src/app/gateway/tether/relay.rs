//! Moves bytes between a client's connection and the database side of a tether hop.

use std::{future::Future, io, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy, split},
    net::{TcpStream, UnixStream},
    time::timeout,
};

/// How long the client's direction may keep going once the database side has finished. A
/// client that never closes its side must not hold a connection slot forever.
pub(super) const GRACE: Duration = Duration::from_secs(5);
/// How long to wait for the peer to acknowledge the tail of a tether stream.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(5);

/// How a relay that ended without an error ended.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    /// Both directions finished and the tether tail was acknowledged.
    Delivered,
    /// Both directions finished but the peer did not acknowledge the tail of a tether stream.
    Undelivered(String),
}

/// A connection the relay can move bytes through.
pub(super) trait Endpoint: AsyncRead + AsyncWrite + Unpin + Send {
    /// Resolves once everything written has reached the other end, as far as that can be
    /// known. Plain sockets have nothing to wait for.
    fn await_delivery(&self) -> impl Future<Output = Result<(), String>> + Send {
        async { Ok(()) }
    }
}

impl Endpoint for TcpStream {}
impl Endpoint for UnixStream {}

impl Endpoint for ::tether::Stream {
    async fn await_delivery(&self) -> Result<(), String> {
        match timeout(DELIVERY_TIMEOUT, self.delivered()).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error.to_string()),
            Err(_) => Err("timed out waiting for the acknowledgment".to_string()),
        }
    }
}

/// Copies both directions at once and half-closes each when its source ends.
///
/// When the database side finishes first, the client direction gets `grace` to finish and is
/// reported as cut (`Outcome::Undelivered`) if it does not; when the client half-closes
/// first, the reply is relayed in full however long it takes. On a
/// clean end both write halves are shut down and tether's tail is awaited (up to
/// [`DELIVERY_TIMEOUT`]) before the streams are dropped, because dropping an unfinished
/// tether stream resets it. A tail that was not acknowledged is reported, not hidden.
pub(super) async fn relay<C: Endpoint, D: Endpoint>(
    client: C,
    database: D,
    grace: Duration,
) -> io::Result<Outcome> {
    let (mut client_read, mut client_write) = split(client);
    let (mut database_read, mut database_write) = split(database);
    let mut cut = None;
    let result = {
        let up = half(&mut client_read, &mut database_write);
        let down = half(&mut database_read, &mut client_write);
        tokio::pin!(up, down);
        tokio::select! {
            finished = &mut up => match finished {
                Ok(()) => down.await,
                Err(error) => Err(error),
            },
            finished = &mut down => match finished {
                Ok(()) => match timeout(grace, up).await {
                    Ok(finished) => finished,
                    Err(_) => {
                        // Bytes the client had sent or was about to send may be dropped with
                        // the copy; the caller is told rather than left to assume.
                        cut = Some("the client direction was cut when the grace expired".to_string());
                        Ok(())
                    }
                },
                Err(error) => Err(error),
            },
        }
    };
    result?;
    let _ = client_write.shutdown().await;
    let _ = database_write.shutdown().await;
    let client = client_read.unsplit(client_write);
    let database = database_read.unsplit(database_write);
    let (client, database) = tokio::join!(client.await_delivery(), database.await_delivery());
    Ok(match (cut, client.and(database)) {
        (Some(reason), _) | (None, Err(reason)) => Outcome::Undelivered(reason),
        (None, Ok(())) => Outcome::Delivered,
    })
}

async fn half<R, W>(from: &mut R, to: &mut W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    copy(from, to).await?;
    to.shutdown().await
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, DuplexStream, duplex};

    use super::*;

    impl Endpoint for DuplexStream {}

    const TEST_GRACE: Duration = Duration::from_millis(150);

    #[tokio::test]
    async fn a_silent_client_is_released_after_the_database_finishes() -> anyhow::Result<()> {
        let (mut client, relayed_client) = duplex(1024);
        let (mut database, relayed_database) = duplex(1024);
        let relaying = tokio::spawn(relay(relayed_client, relayed_database, TEST_GRACE));

        database.write_all(b"reply").await?;
        database.shutdown().await?;
        let mut reply = [0u8; 5];
        client.read_exact(&mut reply).await?;
        assert_eq!(&reply, b"reply");
        // The client stays open and silent: only the grace ends the relay, and the outcome
        // says the client direction was cut.
        let outcome = timeout(Duration::from_secs(5), relaying).await???;
        assert!(
            matches!(&outcome, Outcome::Undelivered(reason) if reason.contains("cut")),
            "{outcome:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_client_that_half_closes_first_still_gets_the_whole_reply() -> anyhow::Result<()> {
        let (mut client, relayed_client) = duplex(1024);
        let (mut database, relayed_database) = duplex(1024);
        let relaying = tokio::spawn(relay(relayed_client, relayed_database, TEST_GRACE));

        client.write_all(b"request").await?;
        client.shutdown().await?;
        let mut request = Vec::new();
        database.read_to_end(&mut request).await?;
        assert_eq!(request, b"request");
        // Longer than the grace: the grace must not apply to this order of closing.
        tokio::time::sleep(TEST_GRACE * 3).await;
        database.write_all(b"full reply").await?;
        database.shutdown().await?;
        let mut reply = Vec::new();
        timeout(Duration::from_secs(5), client.read_to_end(&mut reply)).await??;
        assert_eq!(reply, b"full reply");
        let outcome = timeout(Duration::from_secs(5), relaying).await???;
        assert_eq!(outcome, Outcome::Delivered);
        Ok(())
    }

    #[tokio::test]
    async fn pending_client_bytes_behind_a_backpressured_database_are_reported_cut()
    -> anyhow::Result<()> {
        let (mut client, relayed_client) = duplex(1024);
        // A tiny pipe that nobody reads: the client's bytes cannot be written onward.
        let (mut database, relayed_database) = duplex(16);
        let relaying = tokio::spawn(relay(relayed_client, relayed_database, TEST_GRACE));

        client.write_all(&[1u8; 512]).await?;
        database.write_all(b"reply").await?;
        database.shutdown().await?;
        let mut reply = [0u8; 5];
        client.read_exact(&mut reply).await?;
        let outcome = timeout(Duration::from_secs(5), relaying).await???;
        assert!(
            matches!(&outcome, Outcome::Undelivered(reason) if reason.contains("cut")),
            "{outcome:?}"
        );
        Ok(())
    }
}
