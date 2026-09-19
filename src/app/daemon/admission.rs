use std::{
    collections::HashMap,
    future::Future,
    io::{self, ErrorKind},
    net::IpAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
};

use axum_server::accept::Accept;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
};

#[derive(Debug, Clone)]
pub(super) struct ApiConnectionAcceptor<A> {
    inner: A,
    limiter: Arc<ApiConnectionLimiter>,
}

impl<A> ApiConnectionAcceptor<A> {
    pub(super) fn new(inner: A, limits: &crate::config::RuntimeLimits) -> Self {
        Self {
            inner,
            limiter: Arc::new(ApiConnectionLimiter::new(
                limits.api_connections,
                limits.api_connections_per_peer,
            )),
        }
    }
}

impl<S, A> Accept<TcpStream, S> for ApiConnectionAcceptor<A>
where
    S: Send + 'static,
    A: Accept<TcpStream, S> + Send + Sync,
    A::Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    A::Service: Send + 'static,
    A::Future: Send + 'static,
{
    type Stream = AdmittedApiStream<A::Stream>;
    type Service = A::Service;
    type Future =
        Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send + 'static>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let peer_ip = match stream.peer_addr() {
            Ok(peer) => peer.ip(),
            Err(error) => return Box::pin(async move { Err(error) }),
        };
        let permit = match self.limiter.try_acquire(peer_ip) {
            Some(permit) => permit,
            None => {
                return Box::pin(async {
                    Err(io::Error::new(
                        ErrorKind::WouldBlock,
                        "API connection admission capacity reached",
                    ))
                });
            }
        };
        let accepted = self.inner.accept(stream, service);
        Box::pin(async move {
            let (stream, service) = accepted.await?;
            Ok((
                AdmittedApiStream {
                    inner: stream,
                    _permit: permit,
                },
                service,
            ))
        })
    }
}

#[derive(Debug)]
pub(super) struct AdmittedApiStream<S> {
    inner: S,
    _permit: ApiConnectionPermit,
}

#[derive(Debug)]
struct ApiConnectionLimiter {
    global: Arc<Semaphore>,
    active: Mutex<HashMap<IpAddr, usize>>,
    max_active_per_peer: usize,
}

impl ApiConnectionLimiter {
    fn new(max_active: usize, max_active_per_peer: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(max_active.max(1))),
            active: Mutex::new(HashMap::new()),
            max_active_per_peer: max_active_per_peer.max(1),
        }
    }

    fn try_acquire(self: &Arc<Self>, peer_ip: IpAddr) -> Option<ApiConnectionPermit> {
        // Acquire global capacity before entering the per-peer map. The owned
        // permit is released automatically if the peer bucket is already full.
        let global = Arc::clone(&self.global).try_acquire_owned().ok()?;
        let peer_ip = canonical_peer_ip(peer_ip);
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = active.entry(peer_ip).or_default();
        if *count >= self.max_active_per_peer {
            return None;
        }
        *count += 1;
        Some(ApiConnectionPermit {
            _global: global,
            limiter: Arc::clone(self),
            peer_ip,
        })
    }
}

#[derive(Debug)]
struct ApiConnectionPermit {
    _global: OwnedSemaphorePermit,
    limiter: Arc<ApiConnectionLimiter>,
    peer_ip: IpAddr,
}

impl Drop for ApiConnectionPermit {
    fn drop(&mut self) {
        let mut active = self
            .limiter
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(count) = active.get_mut(&self.peer_ip) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            active.remove(&self.peer_ip);
        }
    }
}

fn canonical_peer_ip(peer_ip: IpAddr) -> IpAddr {
    match peer_ip {
        IpAddr::V6(ipv6) => ipv6.to_ipv4_mapped().map_or_else(
            || {
                let mut prefix = ipv6.octets();
                prefix[8..].fill(0);
                IpAddr::V6(prefix.into())
            },
            IpAddr::V4,
        ),
        ipv4 => ipv4,
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for AdmittedApiStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for AdmittedApiStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, sync::Arc};

    use super::ApiConnectionLimiter;

    #[test]
    fn acceptor_uses_configured_limits() {
        let limits = crate::config::RuntimeLimits {
            api_connections: 2,
            api_connections_per_peer: 1,
            ..Default::default()
        };
        let acceptor = super::ApiConnectionAcceptor::new((), &limits);
        let first_ip = "192.0.2.10".parse().unwrap();
        let first = acceptor.limiter.try_acquire(first_ip).unwrap();
        assert!(acceptor.limiter.try_acquire(first_ip).is_none());
        let _second = acceptor
            .limiter
            .try_acquire("192.0.2.11".parse().unwrap())
            .unwrap();
        assert!(
            acceptor
                .limiter
                .try_acquire("192.0.2.12".parse().unwrap())
                .is_none()
        );
        drop(first);
        assert!(acceptor.limiter.try_acquire(first_ip).is_some());
    }

    #[test]
    fn enforces_and_releases_peer_and_global_capacity() {
        let limiter = Arc::new(ApiConnectionLimiter::new(3, 2));
        let first_ip: IpAddr = "192.0.2.10".parse().unwrap();
        let second_ip: IpAddr = "192.0.2.11".parse().unwrap();

        let first = limiter.try_acquire(first_ip).unwrap();
        let second = limiter.try_acquire(first_ip).unwrap();
        assert!(limiter.try_acquire(first_ip).is_none());
        let other_peer = limiter.try_acquire(second_ip).unwrap();

        drop(first);
        assert!(limiter.try_acquire(first_ip).is_some());
        drop(second);
        drop(other_peer);

        let limiter = Arc::new(ApiConnectionLimiter::new(2, 2));
        let first = limiter.try_acquire("192.0.2.10".parse().unwrap()).unwrap();
        let _second = limiter.try_acquire("192.0.2.11".parse().unwrap()).unwrap();

        assert!(limiter.try_acquire("192.0.2.12".parse().unwrap()).is_none());
        drop(first);
        assert!(limiter.try_acquire("192.0.2.12".parse().unwrap()).is_some());
    }

    #[test]
    fn normalizes_ipv4_and_ipv6_peer_buckets() {
        let limiter = Arc::new(ApiConnectionLimiter::new(2, 1));
        let ipv4: IpAddr = "192.0.2.10".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.10".parse().unwrap();
        let _permit = limiter.try_acquire(ipv4).unwrap();
        assert!(limiter.try_acquire(mapped).is_none());

        let limiter = Arc::new(ApiConnectionLimiter::new(3, 1));
        let first: IpAddr = "2001:db8:1234:5678::1".parse().unwrap();
        let same_prefix: IpAddr = "2001:db8:1234:5678:ffff::2".parse().unwrap();
        let other_prefix: IpAddr = "2001:db8:1234:5679::1".parse().unwrap();
        let _first = limiter.try_acquire(first).unwrap();
        assert!(limiter.try_acquire(same_prefix).is_none());
        assert!(limiter.try_acquire(other_prefix).is_some());
    }
}
