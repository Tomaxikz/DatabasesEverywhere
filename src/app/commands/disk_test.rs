use std::path::PathBuf;

use crate::{commands::CliCommand, daemon::maintenance::disk_test};

pub(crate) struct DiskTestCommand {
    pub(crate) quota_mib: u64,
    pub(crate) write_mib: u64,
}

impl CliCommand for DiskTestCommand {
    async fn execute(self, config_path: PathBuf) -> anyhow::Result<()> {
        disk_test(config_path, self.quota_mib, self.write_mib).await
    }
}
