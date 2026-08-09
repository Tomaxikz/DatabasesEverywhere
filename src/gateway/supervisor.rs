use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use serde::Serialize;
use tokio::sync::{Notify, watch};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GatewayPhase {
    Starting,
    Ready,
    Failed,
    Stopping,
}

impl GatewayPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Stopping => "stopping",
        }
    }
}

#[derive(Debug)]
struct GatewayState {
    phase: GatewayPhase,
    expected_listeners: usize,
    ready_listeners: usize,
    failure: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GatewayReadinessSnapshot {
    pub status: &'static str,
    pub expected_listeners: usize,
    pub ready_listeners: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
}

#[derive(Debug)]
struct GatewayConnections {
    accepting: AtomicBool,
    active: AtomicUsize,
    drain_notify: Notify,
    force_shutdown: watch::Sender<bool>,
}

#[derive(Debug, Clone)]
pub struct GatewayConnectionTracker {
    inner: Arc<GatewayConnections>,
}

#[derive(Debug)]
pub struct GatewayConnectionGuard {
    inner: Arc<GatewayConnections>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayDrainOutcome {
    pub active_at_start: usize,
    pub gracefully_drained: bool,
    pub remaining: usize,
}

impl GatewayConnectionTracker {
    fn new() -> Self {
        let (force_shutdown, _) = watch::channel(false);
        Self {
            inner: Arc::new(GatewayConnections {
                accepting: AtomicBool::new(false),
                active: AtomicUsize::new(0),
                drain_notify: Notify::new(),
                force_shutdown,
            }),
        }
    }

    fn start_accepting(&self) {
        self.inner.force_shutdown.send_replace(false);
        self.inner.accepting.store(true, Ordering::Release);
    }

    fn stop_accepting(&self) {
        self.inner.accepting.store(false, Ordering::Release);
    }

    pub fn try_track(&self) -> Option<GatewayConnectionGuard> {
        if !self.inner.accepting.load(Ordering::Acquire) {
            return None;
        }
        self.inner.active.fetch_add(1, Ordering::AcqRel);
        if !self.inner.accepting.load(Ordering::Acquire) {
            release_connection(&self.inner);
            return None;
        }
        Some(GatewayConnectionGuard {
            inner: Arc::clone(&self.inner),
        })
    }

    pub fn subscribe_force_shutdown(&self) -> watch::Receiver<bool> {
        self.inner.force_shutdown.subscribe()
    }

    pub fn active_connections(&self) -> usize {
        self.inner.active.load(Ordering::Acquire)
    }

    async fn wait_for_drain(&self, deadline: Duration) -> bool {
        let drained = async {
            loop {
                let notified = self.inner.drain_notify.notified();
                if self.active_connections() == 0 {
                    return;
                }
                notified.await;
            }
        };
        tokio::time::timeout(deadline, drained).await.is_ok()
    }

    fn force_close(&self) {
        self.inner.force_shutdown.send_replace(true);
    }
}

impl Drop for GatewayConnectionGuard {
    fn drop(&mut self) {
        release_connection(&self.inner);
    }
}

fn release_connection(connections: &GatewayConnections) {
    let previous = connections.active.fetch_sub(1, Ordering::AcqRel);
    debug_assert!(previous > 0, "gateway connection count underflow");
    if previous == 1 {
        connections.drain_notify.notify_waiters();
    }
}

#[derive(Debug, Clone)]
pub struct GatewaySupervisor {
    state: Arc<RwLock<GatewayState>>,
    shutdown: watch::Sender<bool>,
    connections: GatewayConnectionTracker,
}

impl Default for GatewaySupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewaySupervisor {
    pub fn new() -> Self {
        let (shutdown, _) = watch::channel(false);
        Self {
            state: Arc::new(RwLock::new(GatewayState {
                phase: GatewayPhase::Starting,
                expected_listeners: 0,
                ready_listeners: 0,
                failure: None,
            })),
            shutdown,
            connections: GatewayConnectionTracker::new(),
        }
    }

    pub fn begin(&self, expected_listeners: usize) -> bool {
        let mut state = self.write_state();
        if state.phase == GatewayPhase::Stopping {
            return false;
        }
        state.phase = GatewayPhase::Starting;
        state.expected_listeners = expected_listeners;
        state.ready_listeners = 0;
        state.failure = None;
        self.connections.start_accepting();
        self.shutdown.send_replace(false);
        true
    }

    pub fn mark_ready(&self) {
        let mut state = self.write_state();
        if state.phase == GatewayPhase::Stopping {
            return;
        }
        state.phase = GatewayPhase::Ready;
        state.ready_listeners = state.expected_listeners;
        state.failure = None;
    }

    pub fn mark_failed(&self, failure: impl Into<String>) {
        let mut state = self.write_state();
        if state.phase == GatewayPhase::Stopping {
            return;
        }
        state.phase = GatewayPhase::Failed;
        state.ready_listeners = 0;
        state.failure = Some(failure.into());
    }

    pub fn fail_and_stop(&self, failure: impl Into<String>) {
        self.mark_failed(failure);
        self.connections.stop_accepting();
        self.connections.force_close();
        self.shutdown.send_replace(true);
    }

    pub fn shutdown(&self) {
        {
            let mut state = self.write_state();
            state.phase = GatewayPhase::Stopping;
            state.ready_listeners = 0;
            state.failure = None;
        }
        self.connections.stop_accepting();
        self.shutdown.send_replace(true);
    }

    pub fn subscribe_shutdown(&self) -> watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    pub fn connection_tracker(&self) -> GatewayConnectionTracker {
        self.connections.clone()
    }

    pub fn active_connections(&self) -> usize {
        self.connections.active_connections()
    }

    pub async fn drain_connections(
        &self,
        graceful_timeout: Duration,
        force_close_timeout: Duration,
    ) -> GatewayDrainOutcome {
        self.connections.stop_accepting();
        let active_at_start = self.connections.active_connections();
        if self.connections.wait_for_drain(graceful_timeout).await {
            return GatewayDrainOutcome {
                active_at_start,
                gracefully_drained: true,
                remaining: 0,
            };
        }

        self.connections.force_close();
        let _ = self.connections.wait_for_drain(force_close_timeout).await;
        GatewayDrainOutcome {
            active_at_start,
            gracefully_drained: false,
            remaining: self.connections.active_connections(),
        }
    }

    pub fn is_stopping(&self) -> bool {
        self.read_state().phase == GatewayPhase::Stopping
    }

    pub fn is_ready(&self) -> bool {
        self.read_state().phase == GatewayPhase::Ready
    }

    pub fn snapshot(&self) -> GatewayReadinessSnapshot {
        let state = self.read_state();
        GatewayReadinessSnapshot {
            status: state.phase.as_str(),
            expected_listeners: state.expected_listeners,
            ready_listeners: state.ready_listeners,
            failure: state.failure.clone(),
        }
    }

    fn read_state(&self) -> std::sync::RwLockReadGuard<'_, GatewayState> {
        self.state.read().unwrap_or_else(|error| error.into_inner())
    }

    fn write_state(&self) -> std::sync::RwLockWriteGuard<'_, GatewayState> {
        self.state
            .write()
            .unwrap_or_else(|error| error.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_tracks_start_failure_and_shutdown() {
        let supervisor = GatewaySupervisor::new();
        assert!(supervisor.begin(3));
        assert!(!supervisor.is_ready());

        supervisor.mark_ready();
        assert!(supervisor.is_ready());
        assert_eq!(supervisor.snapshot().ready_listeners, 3);

        supervisor.mark_failed("postgres listener stopped");
        assert_eq!(supervisor.snapshot().status, "failed");

        supervisor.shutdown();
        assert!(supervisor.is_stopping());
        assert_eq!(supervisor.snapshot().status, "stopping");
    }

    #[tokio::test]
    async fn connections_drain_naturally_after_listener_admission_closes() {
        let supervisor = GatewaySupervisor::new();
        assert!(supervisor.begin(1));
        let tracker = supervisor.connection_tracker();
        let connection = tracker.try_track().unwrap();
        supervisor.shutdown();
        assert!(tracker.try_track().is_none());

        tokio::spawn(async move {
            tokio::task::yield_now().await;
            drop(connection);
        });
        let outcome = supervisor
            .drain_connections(Duration::from_secs(1), Duration::from_secs(1))
            .await;
        assert_eq!(
            outcome,
            GatewayDrainOutcome {
                active_at_start: 1,
                gracefully_drained: true,
                remaining: 0,
            }
        );
    }

    #[tokio::test]
    async fn remaining_connections_receive_a_forced_shutdown_signal() {
        let supervisor = GatewaySupervisor::new();
        assert!(supervisor.begin(1));
        let tracker = supervisor.connection_tracker();
        let connection = tracker.try_track().unwrap();
        let mut forced = tracker.subscribe_force_shutdown();
        supervisor.shutdown();

        tokio::spawn(async move {
            while !*forced.borrow() {
                if forced.changed().await.is_err() {
                    return;
                }
            }
            drop(connection);
        });
        let outcome = supervisor
            .drain_connections(Duration::from_millis(1), Duration::from_secs(1))
            .await;
        assert_eq!(outcome.active_at_start, 1);
        assert!(!outcome.gracefully_drained);
        assert_eq!(outcome.remaining, 0);
    }
}
