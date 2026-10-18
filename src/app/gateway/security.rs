use std::{
    collections::HashMap,
    net::IpAddr,
    num::NonZeroU32,
    sync::{Arc, Mutex},
    time::Duration,
};

use governor::{
    Quota, RateLimiter,
    clock::{Clock, DefaultClock, Reference},
    middleware::NoOpMiddleware,
    nanos::Nanos,
    state::keyed::HashMapStateStore,
};

/// A peer idle for this long has a fully replenished per-minute quota, so its
/// bookkeeping can be dropped without changing any rate decision.
const DB_CONNECTION_WINDOW: Duration = Duration::from_secs(60);
const MAX_GATEWAY_RATE_LIMIT_KEYS: usize = 8192;
const DEFAULT_MAX_CONNECTIONS_PER_WINDOW: u32 = 240;

type KeyedRateLimiter<C> = RateLimiter<
    GatewayPeer,
    HashMapStateStore<GatewayPeer>,
    C,
    NoOpMiddleware<<C as Clock>::Instant>,
>;

#[derive(Debug, Clone)]
pub struct GatewayConnectionLimiter<C: Clock = DefaultClock> {
    inner: Arc<Mutex<LimiterState<C>>>,
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
pub struct GatewayConnectionPermit<C: Clock = DefaultClock> {
    inner: Arc<Mutex<LimiterState<C>>>,
    peer: GatewayPeer,
}

impl<C: Clock> Drop for GatewayConnectionPermit<C> {
    fn drop(&mut self) {
        let mut state = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let Some(active) = state.active.get_mut(&self.peer) else {
            return;
        };
        *active = active.saturating_sub(1);
        if *active == 0 {
            state.active.remove(&self.peer);
            if let Some(peer) = state.peers.get_mut(&self.peer) {
                peer.active_rejection_logged = false;
            }
        }
    }
}

impl Default for GatewayConnectionLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_CONNECTIONS_PER_WINDOW)
    }
}

impl GatewayConnectionLimiter {
    pub fn new(max_connections: u32) -> Self {
        Self::with_active_limit(
            max_connections,
            crate::config::RuntimeLimits::default().gateway_connections_per_peer,
        )
    }

    pub(crate) fn with_active_limit(max_connections: u32, max_active: usize) -> Self {
        Self::with_clock(max_connections, max_active, DefaultClock::default())
    }
}

impl<C: Clock> GatewayConnectionLimiter<C> {
    fn with_clock(max_connections: u32, max_active: usize, clock: C) -> Self {
        let max_connections = NonZeroU32::new(max_connections).unwrap_or(NonZeroU32::MIN);
        Self {
            inner: Arc::new(Mutex::new(LimiterState::new(
                Quota::per_minute(max_connections),
                clock,
            ))),
            max_active_per_ip: max_active.max(1).min(max_connections.get() as usize) as u32,
        }
    }

    pub fn try_acquire(
        &self,
        ip: IpAddr,
    ) -> Result<GatewayConnectionPermit<C>, GatewayConnectionRejection> {
        let peer = GatewayPeer::from_ip(ip);
        let mut state = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let now = state.limiter.clock().now();
        state.evict_idle_peers(now);

        if state.peers.len() >= MAX_GATEWAY_RATE_LIMIT_KEYS && !state.peers.contains_key(&peer) {
            let should_log = !state.capacity_rejection_logged;
            state.capacity_rejection_logged = true;
            return Err(GatewayConnectionRejection {
                reason: GatewayConnectionRejectionReason::KeyCapacityReached,
                should_log,
            });
        }

        if state.active.get(&peer).copied().unwrap_or_default() >= self.max_active_per_ip {
            let peer_state = state.touch(peer, now);
            let should_log = !peer_state.active_rejection_logged;
            peer_state.active_rejection_logged = true;
            return Err(GatewayConnectionRejection {
                reason: GatewayConnectionRejectionReason::TooManyActive,
                should_log,
            });
        }

        let allowed = state.limiter.check_key(&peer).is_ok();
        let peer_state = state.touch(peer, now);
        if !allowed {
            let should_log = !peer_state.rate_rejection_logged;
            peer_state.rate_rejection_logged = true;
            return Err(GatewayConnectionRejection {
                reason: GatewayConnectionRejectionReason::RateLimited,
                should_log,
            });
        }
        peer_state.rate_rejection_logged = false;
        peer_state.active_rejection_logged = false;
        *state.active.entry(peer).or_default() += 1;

        Ok(GatewayConnectionPermit {
            inner: Arc::clone(&self.inner),
            peer,
        })
    }
}

/// `limiter` holds the GCRA state that decides admission; `peers` mirrors the
/// tracked peers so the limiter can cap their number and log rejections once.
#[derive(Debug)]
struct LimiterState<C: Clock> {
    limiter: KeyedRateLimiter<C>,
    peers: HashMap<GatewayPeer, PeerState<C::Instant>>,
    active: HashMap<GatewayPeer, u32>,
    last_sweep: C::Instant,
    capacity_rejection_logged: bool,
}

impl<C: Clock> LimiterState<C> {
    fn new(quota: Quota, clock: C) -> Self {
        let limiter = RateLimiter::hashmap_with_clock(quota, clock);
        let last_sweep = limiter.clock().now();
        Self {
            limiter,
            peers: HashMap::new(),
            active: HashMap::new(),
            last_sweep,
            capacity_rejection_logged: false,
        }
    }

    fn touch(&mut self, peer: GatewayPeer, now: C::Instant) -> &mut PeerState<C::Instant> {
        let peer_state = self.peers.entry(peer).or_insert(PeerState {
            last_seen: now,
            rate_rejection_logged: false,
            active_rejection_logged: false,
        });
        peer_state.last_seen = now;
        peer_state
    }

    /// Drops peers with no active connection that have been idle for a full
    /// window, both from the bookkeeping map and (via `retain_recent`) from
    /// governor's store. Runs once per window, or on every call while full.
    fn evict_idle_peers(&mut self, now: C::Instant) {
        let window = Nanos::from(DB_CONNECTION_WINDOW);
        let full = self.peers.len() >= MAX_GATEWAY_RATE_LIMIT_KEYS;
        let sweep_due = now.duration_since(self.last_sweep) >= window;
        if sweep_due || full {
            let active = &self.active;
            self.peers.retain(|peer, state| {
                active.contains_key(peer) || now.duration_since(state.last_seen) < window
            });
            self.limiter.retain_recent();
        }
        if sweep_due {
            self.limiter.shrink_to_fit();
            self.last_sweep = now;
        }
        if self.peers.len() < MAX_GATEWAY_RATE_LIMIT_KEYS {
            self.capacity_rejection_logged = false;
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PeerState<I> {
    last_seen: I,
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
                if let Some(address) = address.to_ipv4_mapped() {
                    return Self::V4(address.octets());
                }
                let mut prefix = [0_u8; 8];
                prefix.copy_from_slice(&address.octets()[..8]);
                Self::V6Prefix64(prefix)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_does_not_double_across_a_minute_boundary() {
        let clock = governor::clock::FakeRelativeClock::default();
        let limiter = GatewayConnectionLimiter::with_clock(60, 1000, clock.clone());
        let ip = "192.0.2.30".parse().unwrap();
        let allowed_until_rejected = || {
            let mut allowed = 0;
            while limiter.try_acquire(ip).is_ok() {
                allowed += 1;
            }
            allowed
        };

        // A fixed window opened at t=0 would admit 60 at t=59s and another 60
        // at t=61s. GCRA only refills one connection per second.
        drop(limiter.try_acquire(ip).unwrap());
        clock.advance(Duration::from_secs(59));
        assert_eq!(allowed_until_rejected(), 60);
        clock.advance(Duration::from_secs(2));
        assert_eq!(allowed_until_rejected(), 2);
        assert!(matches!(
            limiter.try_acquire(ip),
            Err(GatewayConnectionRejection {
                reason: GatewayConnectionRejectionReason::RateLimited,
                should_log: false,
            })
        ));
    }

    #[test]
    fn idle_peers_are_evicted_but_active_peers_are_kept() {
        let clock = governor::clock::FakeRelativeClock::default();
        let limiter = GatewayConnectionLimiter::with_clock(2, 2, clock.clone());
        let idle = "192.0.2.40".parse().unwrap();
        let busy = "192.0.2.41".parse().unwrap();
        drop(limiter.try_acquire(idle).unwrap());
        let _permit = limiter.try_acquire(busy).unwrap();

        clock.advance(DB_CONNECTION_WINDOW);
        drop(limiter.try_acquire("192.0.2.42".parse().unwrap()).unwrap());
        let state = limiter.inner.lock().unwrap();
        assert!(!state.peers.contains_key(&GatewayPeer::from_ip(idle)));
        assert!(state.peers.contains_key(&GatewayPeer::from_ip(busy)));
        assert_eq!(state.limiter.len(), 1);
    }

    #[test]
    fn active_peer_limit_is_configurable_and_releases_capacity() {
        let limiter = GatewayConnectionLimiter::with_active_limit(1000, 80);
        let ip = "192.0.2.20".parse().unwrap();
        let mut permits = Vec::new();
        for _ in 0..80 {
            permits.push(limiter.try_acquire(ip).unwrap());
        }
        assert!(matches!(
            limiter.try_acquire(ip),
            Err(GatewayConnectionRejection {
                reason: GatewayConnectionRejectionReason::TooManyActive,
                ..
            })
        ));
        permits.pop();
        assert!(limiter.try_acquire(ip).is_ok());
    }

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
    fn cloned_limiters_share_per_ip_accounting_across_listeners() {
        let first_listener = GatewayConnectionLimiter::new(1);
        let second_listener = first_listener.clone();
        let ip = "203.0.113.10".parse().unwrap();

        let _permit = first_listener.try_acquire(ip).unwrap();

        assert!(matches!(
            second_listener.try_acquire(ip),
            Err(GatewayConnectionRejection {
                reason: GatewayConnectionRejectionReason::TooManyActive,
                ..
            })
        ));
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
    fn ipv4_mapped_ipv6_uses_distinct_native_ipv4_identities() {
        let native = GatewayPeer::from_ip("203.0.113.10".parse().unwrap());
        let mapped = GatewayPeer::from_ip("::ffff:203.0.113.10".parse().unwrap());
        assert_eq!(native, mapped);

        let first = GatewayPeer::from_ip("::ffff:203.0.113.10".parse().unwrap());
        let second = GatewayPeer::from_ip("::ffff:203.0.113.11".parse().unwrap());

        assert_ne!(first, second);
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
