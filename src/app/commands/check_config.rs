use std::path::PathBuf;

use crate::{
    commands::CliCommand,
    config::load::load_config,
    daemon::runtime_paths::{log_disk_mode, validate_runtime_support},
};

pub(crate) struct CheckConfigCommand;

impl CliCommand for CheckConfigCommand {
    async fn execute(self, config_path: PathBuf) -> anyhow::Result<()> {
        let mut config = load_config(&config_path)?;
        log_disk_mode(&mut config)?;
        validate_runtime_support(&config).await?;
        println!("config ok");
        Ok(())
    }
}
