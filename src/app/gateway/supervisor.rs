use parking_lot::RwLock;
use std::{
    sync::{
        Arc,
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

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[schema(as = GatewayReadiness)]
pub struct GatewayReadinessSnapshot {
    #[schema(schema_with = crate::routes::openapi::literals::gateway_status)]
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
    /// Tether relay tasks. They are not gateway connections, but shutdown must drain and
    /// force them like connections: a relay stuck on a stalled peer cannot hold it forever.
    relays: AtomicUsize,
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

/// Held while a tether relay task runs; see [`GatewayConnectionTracker::track_relay`].
#[derive(Debug)]
pub struct GatewayRelayGuard {
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
                relays: AtomicUsize::new(0),
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

    pub fn is_accepting(&self) -> bool {
        self.inner.accepting.load(Ordering::Acquire)
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

    /// Counts a tether relay task. Unlike [`try_track`](Self::try_track) this never refuses:
    /// callers take the guard first and then check whether the gateway is still accepting, so
    /// shutdown can never see zero relays while one is being admitted.
    pub fn track_relay(&self) -> GatewayRelayGuard {
        self.inner.relays.fetch_add(1, Ordering::AcqRel);
        GatewayRelayGuard {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Gateway connections plus tether relay tasks.
    pub fn pending(&self) -> usize {
        self.inner.active.load(Ordering::Acquire) + self.inner.relays.load(Ordering::Acquire)
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
                if self.pending() == 0 {
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

impl Drop for GatewayRelayGuard {
    fn drop(&mut self) {
        let previous = self.inner.relays.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "tether relay count underflow");
        self.inner.drain_notify.notify_waiters();
    }
}

fn release_connection(connections: &GatewayConnections) {
    let previous = connections.active.fetch_sub(1, Ordering::AcqRel);
    debug_assert!(previous > 0, "gateway connection count underflow");
    if previous == 1 {
        connections.drain_notify.notify_waiters();
    }
}

#[derive(Debug, Default)]
struct Background {
    tasks: Vec<tokio::task::JoinHandle<()>>,
    /// Set once `wait_background` has found nothing left to wait for.
    sealed: bool,
}

#[derive(Debug, Clone)]
pub struct GatewaySupervisor {
    state: Arc<RwLock<GatewayState>>,
    shutdown: watch::Sender<bool>,
    connections: GatewayConnectionTracker,
    tenant_sessions: crate::gateway::sessions::TenantSessions,
    /// Tasks the daemon must wait for before exiting, such as the tether endpoint's close.
    background: Arc<parking_lot::Mutex<Background>>,
}

impl Default for GatewaySupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewaySupervisor {
    pub fn new() -> Self {
        Self::with_config(Arc::new(crate::config::RuntimeConfig::default()))
    }

    pub(crate) fn with_config(config: Arc<crate::config::RuntimeConfig>) -> Self {
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
            tenant_sessions: crate::gateway::sessions::TenantSessions::with_config(config),
            background: Arc::default(),
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
        self.connections.stop_accepting();
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
        self.connections.start_accepting();
    }

    pub fn mark_failed(&self, failure: impl Into<String>) {
        let mut state = self.write_state();
        if state.phase == GatewayPhase::Stopping {
            return;
        }
        state.phase = GatewayPhase::Failed;
        state.ready_listeners = 0;
        state.failure = Some(failure.into());
        self.connections.stop_accepting();
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

    pub fn tenant_sessions(&self) -> crate::gateway::sessions::TenantSessions {
        self.tenant_sessions.clone()
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
        let active_at_start = self.connections.pending();
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
            remaining: self.connections.pending(),
        }
    }

    /// Registers a task that [`wait_background`](Self::wait_background) will wait for.
    /// Returns the task back if shutdown has already finished waiting; the caller must then
    /// do the task's work itself.
    pub fn track_background(
        &self,
        task: tokio::task::JoinHandle<()>,
    ) -> Result<(), tokio::task::JoinHandle<()>> {
        let mut background = self.background.lock();
        if background.sealed {
            return Err(task);
        }
        background.tasks.push(task);
        Ok(())
    }

    /// Waits for every registered background task, including ones registered while it
    /// waits, such as closing the tether endpoint. Later registrations are refused.
    pub async fn wait_background(&self) {
        loop {
            let tasks = {
                let mut background = self.background.lock();
                if background.tasks.is_empty() {
                    background.sealed = true;
                    return;
                }
                std::mem::take(&mut background.tasks)
            };
            for task in tasks {
                let _ = task.await;
            }
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

    fn read_state(&self) -> parking_lot::RwLockReadGuard<'_, GatewayState> {
        self.state.read()
    }

    fn write_state(&self) -> parking_lot::RwLockWriteGuard<'_, GatewayState> {
        self.state.write()
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context as _;

    use super::*;

    #[tokio::test]
    async fn background_tasks_registered_during_the_wait_are_awaited_and_late_ones_refused() {
        let supervisor = GatewaySupervisor::new();
        let finished = Arc::new(AtomicBool::new(false));
        supervisor
            .track_background(tokio::spawn(async {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }))
            .expect("registered");
        let waiting = tokio::spawn({
            let supervisor = supervisor.clone();
            async move { supervisor.wait_background().await }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        // Registered while the wait is already under way.
        let flag = finished.clone();
        supervisor
            .track_background(tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(150)).await;
                flag.store(true, Ordering::SeqCst);
            }))
            .expect("registered during the wait");
        waiting.await.expect("wait");
        assert!(finished.load(Ordering::SeqCst));
        // After the wait has completed nobody would await a new task.
        assert!(supervisor.track_background(tokio::spawn(async {})).is_err());
    }

    #[tokio::test]
    async fn relays_hold_the_drain_open_and_are_forced_like_connections() {
        let supervisor = GatewaySupervisor::new();
        supervisor.begin(0);
        supervisor.mark_ready();
        let tracker = supervisor.connection_tracker();
        let relay = tracker.track_relay();
        assert_eq!((tracker.active_connections(), tracker.pending()), (0, 1));
        let outcome = supervisor
            .drain_connections(Duration::from_millis(50), Duration::from_millis(50))
            .await;
        assert!(!outcome.gracefully_drained);
        assert_eq!(outcome.remaining, 1);
        assert!(*tracker.subscribe_force_shutdown().borrow());
        drop(relay);
        assert_eq!(tracker.pending(), 0);
    }

    #[test]
    fn readiness_tracks_start_failure_and_shutdown() {
        let supervisor = GatewaySupervisor::new();
        let tracker = supervisor.connection_tracker();
        assert_eq!(supervisor.snapshot().status, "starting");
        assert!(!supervisor.is_ready());
        assert!(tracker.try_track().is_none());

        assert!(supervisor.begin(3));
        assert!(!supervisor.is_ready());
        assert!(tracker.try_track().is_none());

        supervisor.mark_ready();
        assert!(supervisor.is_ready());
        assert_eq!(supervisor.snapshot().ready_listeners, 3);
        assert!(tracker.try_track().is_some());

        supervisor.mark_failed("postgres listener stopped");
        assert_eq!(supervisor.snapshot().status, "failed");
        assert!(tracker.try_track().is_none());

        supervisor.shutdown();
        assert!(supervisor.is_stopping());
        assert_eq!(supervisor.snapshot().status, "stopping");
    }

    #[tokio::test]
    async fn connections_drain_naturally_after_listener_admission_closes() -> anyhow::Result<()> {
        let supervisor = GatewaySupervisor::new();
        assert!(supervisor.begin(1));
        supervisor.mark_ready();
        let tracker = supervisor.connection_tracker();
        let connection = tracker
            .try_track()
            .context("expected a value from try_track")?;
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

        Ok(())
    }

    #[tokio::test]
    async fn remaining_connections_receive_a_forced_shutdown_signal() {
        let supervisor = GatewaySupervisor::new();
        assert!(supervisor.begin(1));
        supervisor.mark_ready();
        let tracker = supervisor.connection_tracker();
        let connection = tracker
            .try_track()
            .expect("expected a value from try_track");
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
