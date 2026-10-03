use std::path::PathBuf;

use crate::{commands::CliCommand, daemon::run_daemon};

pub(crate) struct DaemonCommand;

impl CliCommand for DaemonCommand {
    async fn execute(self, config_path: PathBuf) -> anyhow::Result<()> {
        run_daemon(config_path).await
    }
}
