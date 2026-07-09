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
pub enum GatewayConnectionRejection {
    RateLimited,
    TooManyActive,
    KeyCapacityReached,
}

#[derive(Debug)]
pub struct GatewayConnectionPermit {
    inner: Arc<Mutex<LimiterState>>,
    ip: IpAddr,
}

impl Drop for GatewayConnectionPermit {
    fn drop(&mut self) {
        let mut state = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let Some(active) = state.active.get_mut(&self.ip) else {
            return;
        };
        *active = active.saturating_sub(1);
        if *active == 0 {
            state.active.remove(&self.ip);
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
        let mut state = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        evict_expired_windows(&mut state, now);

        if state.windows.len() >= MAX_GATEWAY_RATE_LIMIT_KEYS && !state.windows.contains_key(&ip) {
            return Err(GatewayConnectionRejection::KeyCapacityReached);
        }

        if state.active.get(&ip).copied().unwrap_or_default() >= self.max_active_per_ip {
            return Err(GatewayConnectionRejection::TooManyActive);
        }

        let window = state.windows.entry(ip).or_insert(ConnectionWindow {
            started_at: now,
            count: 0,
        });
        if now.duration_since(window.started_at) >= DB_CONNECTION_WINDOW {
            window.started_at = now;
            window.count = 0;
        }
        if window.count >= self.max_connections {
            return Err(GatewayConnectionRejection::RateLimited);
        }
        window.count += 1;
        *state.active.entry(ip).or_default() += 1;

        Ok(GatewayConnectionPermit {
            inner: Arc::clone(&self.inner),
            ip,
        })
    }
}

#[derive(Debug, Default)]
struct LimiterState {
    windows: HashMap<IpAddr, ConnectionWindow>,
    active: HashMap<IpAddr, u32>,
}

#[derive(Debug, Clone)]
struct ConnectionWindow {
    started_at: Instant,
    count: u32,
}

fn evict_expired_windows(state: &mut LimiterState, now: Instant) {
    if state.windows.len() < MAX_GATEWAY_RATE_LIMIT_KEYS {
        return;
    }
    state.windows.retain(|ip, window| {
        state.active.contains_key(ip)
            || now.duration_since(window.started_at) < DB_CONNECTION_WINDOW
    });
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
            Err(GatewayConnectionRejection::TooManyActive)
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
}
