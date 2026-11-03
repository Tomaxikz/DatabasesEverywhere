use std::path::PathBuf;

use clap::{
    ArgAction, ColorChoice, Parser, Subcommand,
    builder::styling::{AnsiColor, Styles},
};

use crate::{
    daemon::{logging::init_stdout_logging, setup::setup_system},
    storage::repositories::ProtectedSecretField,
    utils::{constants::defaults, term},
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
mod console;
mod daemon;
mod dev_clean;
mod disk_test;
mod migrate;
mod migrate_paths;
mod quarantine;
mod repair_protected_secret;
mod reset_metadata;

pub fn report_error(error: &anyhow::Error) {
    term::error(error);
}

pub(crate) trait CliCommand {
    fn execute(
        self,
        config_path: PathBuf,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
}

#[cfg(test)]
mod tests;

const HELP_STYLES: Styles = Styles::styled()
    .header(AnsiColor::Green.on_default().bold())
    .usage(AnsiColor::Green.on_default().bold())
    .literal(AnsiColor::Cyan.on_default().bold())
    .placeholder(AnsiColor::Cyan.on_default())
    .valid(AnsiColor::Cyan.on_default().bold())
    .invalid(AnsiColor::Yellow.on_default().bold())
    .error(AnsiColor::Red.on_default().bold());

#[derive(Debug, Parser)]
#[command(name = "dbev")]
#[command(about = "Container-backed database hosting daemon")]
#[command(
    long_about = "Container-backed database hosting daemon.\n\nWith no command, dbev runs the daemon in the foreground."
)]
#[command(version, styles = HELP_STYLES)]
pub struct Cli {
    /// Configuration file.
    #[arg(short, long, global = true, env = "DBEV_CONFIG", default_value = defaults::CONFIG_PATH)]
    config: PathBuf,
    /// When to colour output. NO_COLOR and CLICOLOR_FORCE are respected under auto.
    #[arg(long, global = true, value_enum, default_value_t = ColorChoice::Auto, help_heading = "Output")]
    color: ColorChoice,
    /// Print only warnings and errors.
    #[arg(
        short,
        long,
        global = true,
        conflicts_with = "verbose",
        help_heading = "Output"
    )]
    quiet: bool,
    /// Log more detail; repeat for trace logs. RUST_LOG takes precedence.
    #[arg(short, long, global = true, action = ArgAction::Count, help_heading = "Output")]
    verbose: u8,
    #[command(flatten, next_help_heading = "Benchmark")]
    bench: crate::commands::bench::BenchArgs,
    /// Open the interactive admin console (talks to the local daemon API).
    #[arg(long, help_heading = "Modes")]
    cli: bool,
    /// Install dbev as a system service using the existing configuration. Requires root.
    #[arg(long, help_heading = "Modes")]
    setup: bool,
    /// Move data from legacy paths to the configured ones; same as `dbev migrate-paths`.
    #[arg(long, help_heading = "Modes")]
    move_new_config: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the daemon in the foreground (the default).
    Daemon,
    /// Validate the configuration and host support, then summarise it.
    CheckConfig {
        /// Print the summary as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Read durable quarantine causes without modifying the daemon or its data.
    Quarantine {
        /// Only show causes for this pool or instance.
        #[arg(long)]
        entity_id: Option<String>,
        /// Include closed causes.
        #[arg(long)]
        history: bool,
        /// Only show events older than this event ID, for paging.
        #[arg(long, value_parser = clap::value_parser!(i64).range(1..))]
        before: Option<i64>,
        /// Maximum number of events to show (1-1000).
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=1000))]
        limit: u32,
        /// Print JSON even on a terminal; piped output is always JSON.
        #[arg(long)]
        json: bool,
    },
    /// Apply pending metadata database migrations.
    Migrate,
    /// Move data from legacy paths to the configured ones.
    MigratePaths {
        /// Show the planned moves without changing anything.
        #[arg(long)]
        dry_run: bool,
        /// Migrate even while managed containers are running.
        #[arg(long)]
        force: bool,
        /// Print the plan as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Check that disk quotas are enforced by writing past a test quota.
    DiskTest {
        /// Quota for the test volume, in MiB.
        #[arg(long, default_value_t = 16)]
        quota_mib: u64,
        /// Data to write, in MiB; must exceed --quota-mib.
        #[arg(long, default_value_t = 64)]
        write_mib: u64,
    },
    /// Re-encrypt a known legacy plaintext secret piped on stdin.
    RepairProtectedSecret {
        /// Instance that owns the secret.
        #[arg(long)]
        instance_id: String,
        /// Secret field to repair.
        #[arg(long)]
        field: ProtectedSecretField,
        /// Confirm the stored value is legacy plaintext beginning with dbev1:.
        #[arg(long)]
        confirm_legacy_plaintext: bool,
    },
    /// Delete the SQLite metadata databases. Destructive.
    ResetMetadata,
    /// Remove every container managed by this node. For development hosts.
    DevClean,
}

pub async fn run() -> anyhow::Result<()> {
    // Keep this call for library consumers that invoke the CLI without using
    // the bundled binary entry point. Setting the same mask twice is harmless.
    set_safe_umask();
    let cli = Cli::parse();
    term::configure(
        match cli.color {
            ColorChoice::Auto => anstream::ColorChoice::Auto,
            ColorChoice::Always => anstream::ColorChoice::Always,
            ColorChoice::Never => anstream::ColorChoice::Never,
        },
        cli.quiet,
        cli.verbose,
    );
    if cli.bench.bench {
        if cli.setup || cli.move_new_config || cli.command.is_some() {
            anyhow::bail!("--bench cannot be combined with setup, migration, or daemon commands");
        }
        init_stdout_logging();
        return crate::commands::bench::run(cli.config, cli.bench).await;
    }
    if cli.cli {
        if cli.setup || cli.move_new_config || cli.command.is_some() {
            anyhow::bail!("--cli cannot be combined with setup, migration, or daemon commands");
        }
        return console::run(cli.config).await;
    }
    if cli.setup {
        init_stdout_logging();
        return setup_system(cli.config).await;
    }
    if cli.move_new_config {
        term::send_logs_to_stderr();
        return MigratePathsCommand {
            dry_run: false,
            force: false,
            json: false,
        }
        .execute(cli.config)
        .await;
    }
    let command = cli.command.unwrap_or(Command::Daemon);
    if !matches!(command, Command::Daemon) {
        term::send_logs_to_stderr();
    }
    command.execute(cli.config).await
}

impl Command {
    async fn execute(self, config_path: PathBuf) -> anyhow::Result<()> {
        match self {
            Command::Quarantine {
                entity_id,
                history,
                before,
                limit,
                json,
            } => {
                QuarantineCommand {
                    entity_id,
                    history,
                    before,
                    limit,
                    json,
                }
                .execute(config_path)
                .await
            }
            Command::Daemon => DaemonCommand.execute(config_path).await,
            Command::CheckConfig { json } => CheckConfigCommand { json }.execute(config_path).await,
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
            Command::MigratePaths {
                dry_run,
                force,
                json,
            } => {
                MigratePathsCommand {
                    dry_run,
                    force,
                    json,
                }
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

pub fn set_safe_umask() {
    use rustix::fs::Mode;

    rustix::process::umask(Mode::RWXG | Mode::RWXO);
}
