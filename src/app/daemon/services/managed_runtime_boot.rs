use tokio::task::JoinHandle;

use super::{DaemonService, ServiceKind};
use crate::state::AppState;

pub(super) const NAME: &str = "managed runtime boot";

pub(super) struct ManagedRuntimeBoot;

impl DaemonService for ManagedRuntimeBoot {
    fn name(&self) -> &'static str {
        NAME
    }

    fn kind(&self) -> ServiceKind {
        ServiceKind::Lifecycle
    }

    fn spawn(&self, state: AppState) -> JoinHandle<()> {
        tokio::spawn(super::super::finish_runtime_boot(state))
    }
}
