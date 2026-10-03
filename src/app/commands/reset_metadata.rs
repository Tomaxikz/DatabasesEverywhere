use std::path::PathBuf;

use crate::{commands::CliCommand, daemon::maintenance::reset_metadata};

pub(crate) struct ResetMetadataCommand;

impl CliCommand for ResetMetadataCommand {
    async fn execute(self, config_path: PathBuf) -> anyhow::Result<()> {
        reset_metadata(config_path).await
    }
}
