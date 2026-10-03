use std::path::PathBuf;

use crate::{commands::CliCommand, daemon::maintenance::dev_clean};

pub(crate) struct DevCleanCommand;

impl CliCommand for DevCleanCommand {
    async fn execute(self, config_path: PathBuf) -> anyhow::Result<()> {
        dev_clean(config_path).await
    }
}
