use std::sync::{Arc, RwLock};

use serde::Serialize;
use tokio::sync::watch;

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

#[derive(Debug, Clone)]
pub struct GatewaySupervisor {
    state: Arc<RwLock<GatewayState>>,
    shutdown: watch::Sender<bool>,
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
        let _ = self.shutdown.send(true);
    }

    pub fn shutdown(&self) {
        {
            let mut state = self.write_state();
            state.phase = GatewayPhase::Stopping;
            state.ready_listeners = 0;
            state.failure = None;
        }
        let _ = self.shutdown.send(true);
    }

    pub fn subscribe_shutdown(&self) -> watch::Receiver<bool> {
        self.shutdown.subscribe()
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
}
