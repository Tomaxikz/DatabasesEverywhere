use std::path::PathBuf;

use crate::{commands::CliCommand, daemon::maintenance::migrate_paths};

pub(crate) struct MigratePathsCommand {
    pub(crate) dry_run: bool,
    pub(crate) force: bool,
}

impl CliCommand for MigratePathsCommand {
    async fn execute(self, config_path: PathBuf) -> anyhow::Result<()> {
        migrate_paths(config_path, self.dry_run, self.force).await
    }
}
