use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

#[derive(Debug, Clone, Default)]
pub(crate) struct NetworkCounter {
    rx_bytes: Arc<AtomicU64>,
    tx_bytes: Arc<AtomicU64>,
}

impl NetworkCounter {
    pub(crate) fn add_rx(&self, bytes: u64) {
        add(&self.rx_bytes, bytes);
    }

    pub(crate) fn add_tx(&self, bytes: u64) {
        add(&self.tx_bytes, bytes);
    }

    pub(crate) fn snapshot(&self) -> (u64, u64) {
        (
            self.rx_bytes.load(Ordering::Relaxed),
            self.tx_bytes.load(Ordering::Relaxed),
        )
    }
}

fn add(counter: &AtomicU64, bytes: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(bytes))
    });
}
