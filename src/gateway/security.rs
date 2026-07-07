use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::Mutex;

const DB_CONNECTION_WINDOW: Duration = Duration::from_secs(60);
const MAX_GATEWAY_RATE_LIMIT_KEYS: usize = 8192;

#[derive(Debug, Clone)]
pub struct GatewayConnectionLimiter {
    inner: Arc<Mutex<HashMap<IpAddr, ConnectionWindow>>>,
    max_connections: u32,
}

impl Default for GatewayConnectionLimiter {
    fn default() -> Self {
        Self::new(240)
    }
}

impl GatewayConnectionLimiter {
    pub fn new(max_connections: u32) -> Self {
        Self {
            inner: Arc::default(),
            max_connections: max_connections.max(1),
        }
    }

    pub async fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut inner = self.inner.lock().await;
        evict_expired_windows(&mut inner, now);
        if inner.len() >= MAX_GATEWAY_RATE_LIMIT_KEYS && !inner.contains_key(&ip) {
            tracing::warn!(
                keys = inner.len(),
                "audit gateway_rate_limit_key_capacity_reached"
            );
            return false;
        }
        let window = inner.entry(ip).or_insert(ConnectionWindow {
            started_at: now,
            count: 0,
        });
        if now.duration_since(window.started_at) >= DB_CONNECTION_WINDOW {
            window.started_at = now;
            window.count = 0;
        }
        window.count += 1;
        window.count <= self.max_connections
    }
}

#[derive(Debug, Clone)]
struct ConnectionWindow {
    started_at: Instant,
    count: u32,
}

fn evict_expired_windows(inner: &mut HashMap<IpAddr, ConnectionWindow>, now: Instant) {
    if inner.len() < MAX_GATEWAY_RATE_LIMIT_KEYS {
        return;
    }
    inner.retain(|_, window| now.duration_since(window.started_at) < DB_CONNECTION_WINDOW);
}
