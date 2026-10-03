use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::{
    daemon::{logging::init_stdout_logging, setup::setup_system},
    storage::repositories::ProtectedSecretField,
    utils::constants::defaults,
};

use check_config::CheckConfigCommand;
use daemon::DaemonCommand;
use dev_clean::DevCleanCommand;
use disk_test::DiskTestCommand;
use migrate::MigrateCommand;
use migrate_paths::MigratePathsCommand;
use quarantine::QuarantineCommand;
use repair_protected_secret::RepairProtectedSecretCommand;
use reset_metadata::ResetMetadataCommand;

pub mod bench;
mod check_config;
mod daemon;
mod dev_clean;
mod disk_test;
mod migrate;
mod migrate_paths;
mod quarantine;
mod repair_protected_secret;
mod reset_metadata;

pub(crate) trait CliCommand {
    fn execute(
        self,
        config_path: PathBuf,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
}

#[cfg(test)]
mod tests;

#[derive(Debug, Parser)]
#[command(name = "dbev")]
#[command(about = "Container-backed database hosting daemon")]
#[command(version)]
pub struct Cli {
    #[arg(short, long, default_value = defaults::CONFIG_PATH)]
    config: PathBuf,
    #[command(flatten)]
    bench: crate::commands::bench::BenchArgs,
    #[arg(long)]
    setup: bool,
    #[arg(long)]
    move_new_config: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Read durable quarantine causes without modifying the daemon or its data.
    Quarantine {
        #[arg(long)]
        entity_id: Option<String>,
        #[arg(long)]
        history: bool,
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        before: Option<i64>,
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=1000))]
        limit: u32,
    },
    Daemon,
    CheckConfig,
    DiskTest {
        #[arg(long, default_value_t = 16)]
        quota_mib: u64,
        #[arg(long, default_value_t = 64)]
        write_mib: u64,
    },
    Migrate,
    MigratePaths {
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        force: bool,
    },
    DevClean,
    ResetMetadata,
    RepairProtectedSecret {
        #[arg(long)]
        instance_id: String,
        #[arg(long)]
        field: ProtectedSecretField,
        #[arg(long)]
        confirm_legacy_plaintext: bool,
    },
}

pub async fn run() -> anyhow::Result<()> {
    // Keep this call for library consumers that invoke the CLI without using
    // the bundled binary entry point. Setting the same mask twice is harmless.
    set_safe_umask();
    let cli = Cli::parse();
    if cli.bench.bench {
        if cli.setup || cli.move_new_config || cli.command.is_some() {
            anyhow::bail!("--bench cannot be combined with setup, migration, or daemon commands");
        }
        init_stdout_logging();
        return crate::commands::bench::run(cli.config, cli.bench).await;
    }
    if cli.setup {
        init_stdout_logging();
        return setup_system(cli.config).await;
    }
    if cli.move_new_config {
        return MigratePathsCommand {
            dry_run: false,
            force: false,
        }
        .execute(cli.config)
        .await;
    }
    cli.command
        .unwrap_or(Command::Daemon)
        .execute(cli.config)
        .await
}

impl Command {
    async fn execute(self, config_path: PathBuf) -> anyhow::Result<()> {
        match self {
            Command::Quarantine {
                entity_id,
                history,
                before,
                limit,
            } => {
                QuarantineCommand {
                    entity_id,
                    history,
                    before,
                    limit,
                }
                .execute(config_path)
                .await
            }
            Command::Daemon => DaemonCommand.execute(config_path).await,
            Command::CheckConfig => CheckConfigCommand.execute(config_path).await,
            Command::DiskTest {
                quota_mib,
                write_mib,
            } => {
                DiskTestCommand {
                    quota_mib,
                    write_mib,
                }
                .execute(config_path)
                .await
            }
            Command::Migrate => MigrateCommand.execute(config_path).await,
            Command::MigratePaths { dry_run, force } => {
                MigratePathsCommand { dry_run, force }
                    .execute(config_path)
                    .await
            }
            Command::DevClean => DevCleanCommand.execute(config_path).await,
            Command::ResetMetadata => ResetMetadataCommand.execute(config_path).await,
            Command::RepairProtectedSecret {
                instance_id,
                field,
                confirm_legacy_plaintext,
            } => {
                RepairProtectedSecretCommand {
                    instance_id,
                    field,
                    confirm_legacy_plaintext,
                }
                .execute(config_path)
                .await
            }
        }
    }
}

/// Restrict default permissions before the process creates logs, state, or
/// runtime files. Explicitly requested modes can still be tightened further.
pub fn set_safe_umask() {
    use rustix::fs::Mode;

    rustix::process::umask(Mode::RWXG | Mode::RWXO);
}
