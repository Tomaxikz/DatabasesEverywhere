use crate::daemon::container_events::monitor_container_events;
use tokio::task::JoinHandle;

use super::{DaemonService, ServiceKind};
use crate::state::AppState;

pub(super) const NAME: &str = "managed container event monitor";

pub(super) struct ManagedContainerEvents;

impl DaemonService for ManagedContainerEvents {
    fn name(&self) -> &'static str {
        NAME
    }

    fn kind(&self) -> ServiceKind {
        ServiceKind::Lifecycle
    }

    fn spawn(&self, state: AppState) -> JoinHandle<()> {
        tokio::spawn(monitor_container_events(state))
    }
}
