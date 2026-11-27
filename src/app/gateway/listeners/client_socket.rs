use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use rustix::net::RecvFlags;

use super::Origin;
use tokio::{
    io::{AsyncRead, AsyncWrite, Interest, ReadBuf},
    net::{TcpStream, UnixStream},
};

/// A client connection as the protocol handlers see it: a TCP client of a public listener,
/// or the local end of an in-process pair that carries a connection tunnelled over tether,
/// together with where that connection came from.
pub(crate) enum ClientSocket {
    Tcp(TcpStream),
    Local(UnixStream, Origin),
}

impl From<TcpStream> for ClientSocket {
    fn from(stream: TcpStream) -> Self {
        Self::Tcp(stream)
    }
}

impl ClientSocket {
    /// Where a tunnelled connection came from, for events a handler logs itself. `None` for
    /// public connections, whose events carry no such fields.
    pub(crate) fn origin(&self) -> Option<Origin> {
        match self {
            Self::Tcp(_) => None,
            Self::Local(_, origin) => Some(origin.clone()),
        }
    }

    /// Reads without consuming, like `TcpStream::peek`.
    pub(crate) async fn peek(&self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.peek(buffer).await,
            Self::Local(stream, _) => loop {
                stream.readable().await?;
                let peeked = stream.try_io(Interest::READABLE, || {
                    rustix::net::recv(stream, &mut *buffer, RecvFlags::PEEK)
                        .map(|(read, _)| read)
                        .map_err(io::Error::from)
                });
                match peeked {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    result => return result,
                }
            },
        }
    }
}

impl AsyncRead for ClientSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buffer),
            Self::Local(stream, _) => Pin::new(stream).poll_read(cx, buffer),
        }
    }
}

impl AsyncWrite for ClientSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, bytes),
            Self::Local(stream, _) => Pin::new(stream).poll_write(cx, bytes),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Local(stream, _) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Local(stream, _) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn peeking_a_local_socket_does_not_consume() -> anyhow::Result<()> {
        let (mut far, near) = UnixStream::pair()?;
        let origin = Origin::tunnelled("203.0.113.7:1".parse()?, "node-a".parse()?);
        let mut socket = ClientSocket::Local(near, origin);
        far.write_all(&[0x16, 1, 2]).await?;
        let mut first = [0u8; 1];
        assert_eq!(socket.peek(&mut first).await?, 1);
        assert_eq!(first, [0x16]);
        assert_eq!(socket.peek(&mut first).await?, 1);
        let mut all = [0u8; 3];
        socket.read_exact(&mut all).await?;
        assert_eq!(all, [0x16, 1, 2]);
        // A peek on an idle socket waits for data instead of reporting none.
        let waiting = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            socket.peek(&mut first),
        )
        .await;
        assert!(waiting.is_err());
        drop(far);
        assert_eq!(socket.peek(&mut first).await?, 0);
        Ok(())
    }
}
