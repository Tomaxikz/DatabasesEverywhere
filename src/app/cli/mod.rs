use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::{
    config::load::load_config,
    constants::defaults,
    daemon::{
        logging::init_stdout_logging,
        maintenance::{
            dev_clean, disk_test, migrate_metadata, migrate_paths, repair_protected_secret,
            reset_metadata,
        },
        run_daemon,
        runtime_paths::{log_disk_mode, validate_runtime_support},
        setup::setup_system,
    },
    storage::repositories::ProtectedSecretField,
};

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
    bench: crate::bench::BenchArgs,
    #[arg(long)]
    setup: bool,
    #[arg(long)]
    move_new_config: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
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
        return crate::bench::run(cli.config, cli.bench).await;
    }
    if cli.setup {
        init_stdout_logging();
        return setup_system(cli.config).await;
    }
    if cli.move_new_config {
        return migrate_paths(cli.config, false, false).await;
    }
    match cli.command.unwrap_or(Command::Daemon) {
        Command::Daemon => run_daemon(cli.config).await,
        Command::CheckConfig => {
            let mut config = load_config(&cli.config)?;
            log_disk_mode(&mut config)?;
            validate_runtime_support(&config).await?;
            println!("config ok");
            Ok(())
        }
        Command::DiskTest {
            quota_mib,
            write_mib,
        } => disk_test(cli.config, quota_mib, write_mib).await,
        Command::Migrate => migrate_metadata(cli.config).await,
        Command::MigratePaths { dry_run, force } => migrate_paths(cli.config, dry_run, force).await,
        Command::DevClean => dev_clean(cli.config).await,
        Command::ResetMetadata => reset_metadata(cli.config).await,
        Command::RepairProtectedSecret {
            instance_id,
            field,
            confirm_legacy_plaintext,
        } => {
            repair_protected_secret(cli.config, instance_id, field, confirm_legacy_plaintext).await
        }
    }
}

/// Restrict default permissions before the process creates logs, state, or
/// runtime files. Explicitly requested modes can still be tightened further.
pub fn set_safe_umask() {
    {
        use rustix::fs::Mode;

        rustix::process::umask(Mode::RWXG | Mode::RWXO);
    }
}
