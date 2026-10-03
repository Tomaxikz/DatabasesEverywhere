use tokio::task::JoinHandle;

use super::{DaemonService, ServiceKind};
use crate::state::AppState;

pub(super) struct ImportUploadSweeper;

impl DaemonService for ImportUploadSweeper {
    fn name(&self) -> &'static str {
        "import upload sweeper"
    }

    fn kind(&self) -> ServiceKind {
        ServiceKind::Maintenance
    }

    fn spawn(&self, state: AppState) -> JoinHandle<()> {
        tokio::spawn(crate::subsystems::import_export::run_upload_sweeper(state))
    }
}
