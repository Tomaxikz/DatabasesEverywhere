use tokio::task::JoinHandle;

use super::{DaemonService, ServiceKind};
use crate::state::AppState;

pub(super) struct SoftDiskLimits;

impl DaemonService for SoftDiskLimits {
    fn name(&self) -> &'static str {
        "soft disk limits"
    }

    fn kind(&self) -> ServiceKind {
        ServiceKind::Maintenance
    }

    fn spawn(&self, state: AppState) -> JoinHandle<()> {
        tokio::spawn(super::super::monitor_soft_disk_limits(state))
    }
}
