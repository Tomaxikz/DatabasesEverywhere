use std::path::PathBuf;

use crate::commands::CliCommand;

pub(crate) struct QuarantineCommand {
    pub(crate) entity_id: Option<String>,
    pub(crate) history: bool,
    pub(crate) before: Option<i64>,
    pub(crate) limit: u32,
    pub(crate) json: bool,
}

impl CliCommand for QuarantineCommand {
    async fn execute(self, config_path: PathBuf) -> anyhow::Result<()> {
        crate::daemon::quarantine::show(
            config_path,
            self.entity_id,
            self.history,
            self.before,
            self.limit,
            self.json,
        )
        .await
    }
}
