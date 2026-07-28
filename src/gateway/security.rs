use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const DB_CONNECTION_WINDOW: Duration = Duration::from_secs(60);
const MAX_GATEWAY_RATE_LIMIT_KEYS: usize = 8192;
const MAX_ACTIVE_CONNECTIONS_PER_IP: u32 = 64;

#[derive(Debug, Clone)]
pub struct GatewayConnectionLimiter {
    inner: Arc<Mutex<LimiterState>>,
    max_connections: u32,
    max_active_per_ip: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayConnectionRejectionReason {
    RateLimited,
    TooManyActive,
    KeyCapacityReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayConnectionRejection {
    pub reason: GatewayConnectionRejectionReason,
    pub should_log: bool,
}

#[derive(Debug)]
pub struct GatewayConnectionPermit {
    inner: Arc<Mutex<LimiterState>>,
    peer: GatewayPeer,
}

impl Drop for GatewayConnectionPermit {
    fn drop(&mut self) {
        let mut state = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let Some(active) = state.active.get_mut(&self.peer) else {
            return;
        };
        *active = active.saturating_sub(1);
        if *active == 0 {
            state.active.remove(&self.peer);
            if let Some(window) = state.windows.get_mut(&self.peer) {
                window.active_rejection_logged = false;
            }
        }
    }
}

impl Default for GatewayConnectionLimiter {
    fn default() -> Self {
        Self::new(240)
    }
}

impl GatewayConnectionLimiter {
    pub fn new(max_connections: u32) -> Self {
        let max_connections = max_connections.max(1);
        Self {
            inner: Arc::default(),
            max_connections,
            max_active_per_ip: max_connections.min(MAX_ACTIVE_CONNECTIONS_PER_IP),
        }
    }

    pub fn try_acquire(
        &self,
        ip: IpAddr,
    ) -> Result<GatewayConnectionPermit, GatewayConnectionRejection> {
        let now = Instant::now();
        let peer = GatewayPeer::from_ip(ip);
        let mut state = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        evict_expired_windows(&mut state, now);

        if state.windows.len() >= MAX_GATEWAY_RATE_LIMIT_KEYS && !state.windows.contains_key(&peer)
        {
            let should_log = !state.capacity_rejection_logged;
            state.capacity_rejection_logged = true;
            return Err(GatewayConnectionRejection {
                reason: GatewayConnectionRejectionReason::KeyCapacityReached,
                should_log,
            });
        }

        if state.active.get(&peer).copied().unwrap_or_default() >= self.max_active_per_ip {
            let window = state.windows.entry(peer).or_insert(ConnectionWindow {
                started_at: now,
                count: 0,
                rate_rejection_logged: false,
                active_rejection_logged: false,
            });
            let should_log = !window.active_rejection_logged;
            window.active_rejection_logged = true;
            return Err(GatewayConnectionRejection {
                reason: GatewayConnectionRejectionReason::TooManyActive,
                should_log,
            });
        }

        let window = state.windows.entry(peer).or_insert(ConnectionWindow {
            started_at: now,
            count: 0,
            rate_rejection_logged: false,
            active_rejection_logged: false,
        });
        if now.duration_since(window.started_at) >= DB_CONNECTION_WINDOW {
            window.started_at = now;
            window.count = 0;
            window.rate_rejection_logged = false;
        }
        if window.count >= self.max_connections {
            let should_log = !window.rate_rejection_logged;
            window.rate_rejection_logged = true;
            return Err(GatewayConnectionRejection {
                reason: GatewayConnectionRejectionReason::RateLimited,
                should_log,
            });
        }
        window.active_rejection_logged = false;
        window.count += 1;
        *state.active.entry(peer).or_default() += 1;

        Ok(GatewayConnectionPermit {
            inner: Arc::clone(&self.inner),
            peer,
        })
    }
}

#[derive(Debug, Default)]
struct LimiterState {
    windows: HashMap<GatewayPeer, ConnectionWindow>,
    active: HashMap<GatewayPeer, u32>,
    capacity_rejection_logged: bool,
}

#[derive(Debug, Clone)]
struct ConnectionWindow {
    started_at: Instant,
    count: u32,
    rate_rejection_logged: bool,
    active_rejection_logged: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum GatewayPeer {
    V4([u8; 4]),
    V6Prefix64([u8; 8]),
}

impl GatewayPeer {
    fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(address) => Self::V4(address.octets()),
            IpAddr::V6(address) => {
                let mut prefix = [0_u8; 8];
                prefix.copy_from_slice(&address.octets()[..8]);
                Self::V6Prefix64(prefix)
            }
        }
    }
}

fn evict_expired_windows(state: &mut LimiterState, now: Instant) {
    if state.windows.len() < MAX_GATEWAY_RATE_LIMIT_KEYS {
        return;
    }
    state.windows.retain(|ip, window| {
        state.active.contains_key(ip)
            || now.duration_since(window.started_at) < DB_CONNECTION_WINDOW
    });
    if state.windows.len() < MAX_GATEWAY_RATE_LIMIT_KEYS {
        state.capacity_rejection_logged = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_excess_active_connections_and_releases_permit() {
        let limiter = GatewayConnectionLimiter::new(2);
        let ip = "203.0.113.10".parse().unwrap();
        let first = limiter.try_acquire(ip).unwrap();
        let second = limiter.try_acquire(ip).unwrap();

        assert!(matches!(
            limiter.try_acquire(ip),
            Err(GatewayConnectionRejection {
                reason: GatewayConnectionRejectionReason::TooManyActive,
                should_log: true,
            })
        ));

        drop(first);
        assert!(limiter.try_acquire(ip).is_err(), "rate limit still applies");
        drop(second);
    }

    #[test]
    fn tracks_active_connections_independently_per_ip() {
        let limiter = GatewayConnectionLimiter::new(1);
        let first_ip = "203.0.113.10".parse().unwrap();
        let second_ip = "203.0.113.11".parse().unwrap();

        let _first = limiter.try_acquire(first_ip).unwrap();
        assert!(limiter.try_acquire(second_ip).is_ok());
    }

    #[test]
    fn groups_ipv6_addresses_by_64_bit_prefix() {
        let limiter = GatewayConnectionLimiter::new(2);
        let first = "2001:db8:1234:5678::1".parse().unwrap();
        let second = "2001:db8:1234:5678::2".parse().unwrap();

        let _first = limiter.try_acquire(first).unwrap();
        let _second = limiter.try_acquire(second).unwrap();
        assert!(matches!(
            limiter.try_acquire(first),
            Err(GatewayConnectionRejection {
                reason: GatewayConnectionRejectionReason::TooManyActive,
                ..
            })
        ));
    }

    #[test]
    fn repeated_rejections_are_logged_once_until_recovery() {
        let limiter = GatewayConnectionLimiter::new(1);
        let ip = "203.0.113.10".parse().unwrap();
        let permit = limiter.try_acquire(ip).unwrap();
        let first = limiter.try_acquire(ip).unwrap_err();
        let repeated = limiter.try_acquire(ip).unwrap_err();

        assert!(first.should_log);
        assert!(!repeated.should_log);
        drop(permit);
    }
}
