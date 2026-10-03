use std::path::PathBuf;

use crate::{commands::CliCommand, daemon::maintenance::migrate_metadata};

pub(crate) struct MigrateCommand;

impl CliCommand for MigrateCommand {
    async fn execute(self, config_path: PathBuf) -> anyhow::Result<()> {
        migrate_metadata(config_path).await
    }
}
