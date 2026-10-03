use tokio::task::JoinHandle;

use super::{DaemonService, ServiceKind};
use crate::state::AppState;

pub(super) struct OneUseExportSweeper;

impl DaemonService for OneUseExportSweeper {
    fn name(&self) -> &'static str {
        "one use export sweeper"
    }

    fn kind(&self) -> ServiceKind {
        ServiceKind::Maintenance
    }

    fn spawn(&self, state: AppState) -> JoinHandle<()> {
        tokio::spawn(crate::subsystems::artifacts::run_export_sweeper(state))
    }
}
