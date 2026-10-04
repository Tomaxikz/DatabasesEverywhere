use super::{MAX_ACTIVE_DOWNLOADS, MAX_ACTIVE_DOWNLOADS_PER_PEER, MAX_CONSUMED_DOWNLOAD_TICKETS};
use crate::routes::http::response::ApiError;
use crate::utils::time::now_unix;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

#[derive(Debug, Clone)]
pub struct ArtifactDownloadTickets {
    pub(super) consumed: Arc<Mutex<HashMap<String, i64>>>,
    pub(super) active_downloads: Arc<Semaphore>,
    pub(super) active_by_peer: Arc<StdMutex<HashMap<DownloadPeer, usize>>>,
}

impl Default for ArtifactDownloadTickets {
    fn default() -> Self {
        Self {
            consumed: Arc::default(),
            active_downloads: Arc::new(Semaphore::new(MAX_ACTIVE_DOWNLOADS)),
            active_by_peer: Arc::default(),
        }
    }
}

impl ArtifactDownloadTickets {
    pub(super) async fn consume(&self, jti: &str, exp: i64) -> bool {
        let now = now_unix();
        let mut consumed = self.consumed.lock().await;
        consumed.retain(|_, expires_at| *expires_at > now);
        if consumed.contains_key(jti) {
            return false;
        }
        if consumed.len() >= MAX_CONSUMED_DOWNLOAD_TICKETS {
            tracing::warn!("audit artifact_download_ticket_capacity_reached");
            return false;
        }
        consumed.insert(jti.to_string(), exp);
        true
    }

    pub(super) fn admit_download(
        &self,
        peer: Option<SocketAddr>,
    ) -> Result<ArtifactDownloadPermit, ApiError> {
        let global = Arc::clone(&self.active_downloads)
            .try_acquire_owned()
            .map_err(|_| ApiError::RateLimited)?;
        let peer = DownloadPeer::from_socket(peer);
        let mut active = self
            .active_by_peer
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let count = active.entry(peer).or_default();
        if *count >= MAX_ACTIVE_DOWNLOADS_PER_PEER {
            return Err(ApiError::RateLimited);
        }
        *count += 1;
        drop(active);
        Ok(ArtifactDownloadPermit {
            _global: global,
            peer,
            active_by_peer: Arc::clone(&self.active_by_peer),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum DownloadPeer {
    V4([u8; 4]),
    V6Prefix64([u8; 8]),
    Unknown,
}

impl DownloadPeer {
    pub(super) fn from_socket(peer: Option<SocketAddr>) -> Self {
        match peer.map(|address| address.ip()) {
            Some(IpAddr::V4(address)) => Self::V4(address.octets()),
            Some(IpAddr::V6(address)) => address.to_ipv4_mapped().map_or_else(
                || {
                    let mut prefix = [0_u8; 8];
                    prefix.copy_from_slice(&address.octets()[..8]);
                    Self::V6Prefix64(prefix)
                },
                |address| Self::V4(address.octets()),
            ),
            None => Self::Unknown,
        }
    }
}

#[derive(Debug)]
pub(super) struct ArtifactDownloadPermit {
    pub(super) _global: OwnedSemaphorePermit,
    pub(super) peer: DownloadPeer,
    pub(super) active_by_peer: Arc<StdMutex<HashMap<DownloadPeer, usize>>>,
}

impl Drop for ArtifactDownloadPermit {
    fn drop(&mut self) {
        let mut active = self
            .active_by_peer
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(count) = active.get_mut(&self.peer) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            active.remove(&self.peer);
        }
    }
}
