use std::path::PathBuf;

use crate::{
    commands::CliCommand, daemon::maintenance::repair_protected_secret,
    storage::repositories::ProtectedSecretField,
};

pub(crate) struct RepairProtectedSecretCommand {
    pub(crate) instance_id: String,
    pub(crate) field: ProtectedSecretField,
    pub(crate) confirm_legacy_plaintext: bool,
}

impl CliCommand for RepairProtectedSecretCommand {
    async fn execute(self, config_path: PathBuf) -> anyhow::Result<()> {
        repair_protected_secret(
            config_path,
            self.instance_id,
            self.field,
            self.confirm_legacy_plaintext,
        )
        .await
    }
}
