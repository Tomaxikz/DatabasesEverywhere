use std::{
    fs,
    future::IntoFuture,
    io::{ErrorKind, Read, Write},
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    process::Command as StdCommand,
    sync::Arc,
    sync::OnceLock,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use axum::Router;
use axum_server::{Handle, tls_rustls::RustlsConfig};
use clap::{Parser, Subcommand};
use futures::StreamExt;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio::{io::AsyncWriteExt, net::TcpListener};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    api::{
        progress::InstallProgressStore,
        routes::{AppState, build_router},
    },
    auth::api_token::ApiToken,
    config::{Config, DaemonEngine, DiskLimitMode, load::load_config},
    constants::{self, defaults},
    disk::DiskLimiter,
    gateway::{
        listeners, resolver::RouteResolver, security::GatewayConnectionLimiter,
        supervisor::GatewaySupervisor,
    },
    instances::{
        manager::InstanceManager, metadata::InstanceStatus, paths::InstancePaths, reconcile,
        state::InstanceStore,
    },
    jobs::import_export::ImportExportJobs,
    runtime::docker::DockerRuntime,
    shared::{images::has_sha256_digest, logs::truncate_log_tail, protocol::Protocol},
    storage::{
        import_export_jobs::ImportExportJobRepository, repositories::InstanceRepository, sqlite,
    },
};

const IMPORT_EXPORT_DRAIN_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const API_CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY: usize = 8;

#[derive(Debug, Parser)]
#[command(name = "dbev")]
#[command(about = "Container-backed database hosting daemon")]
pub struct Cli {
    #[arg(short, long, default_value = defaults::CONFIG_PATH)]
    config: PathBuf,
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
}

pub async fn run() -> anyhow::Result<()> {
    // Keep this call for library consumers that invoke the CLI without using
    // the bundled binary entry point. Setting the same mask twice is harmless.
    harden_process_file_creation();
    let cli = Cli::parse();
    if cli.setup {
        init_stdout_logging();
        return setup_system(cli.config).await;
    }
    if cli.move_new_config {
        init_stdout_logging();
        return migrate_paths(cli.config, false, false).await;
    }
    match cli.command.unwrap_or(Command::Daemon) {
        Command::Daemon => run_daemon(cli.config).await,
        Command::CheckConfig => {
            let mut config = load_config(&cli.config)?;
            detect_and_log_disk_mode(&mut config)?;
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
    }
}

/// Restrict default permissions before the process creates logs, state, or
/// runtime files. Explicitly requested modes can still be tightened further.
pub fn harden_process_file_creation() {
    #[cfg(unix)]
    {
        use rustix::fs::Mode;

        rustix::process::umask(Mode::RWXG | Mode::RWXO);
    }
}

const SERVICE_PATH: &str = "/etc/systemd/system/databases-everywhere.service";
const SUDOERS_PATH: &str = "/etc/sudoers.d/databases-everywhere";
const INSTALL_PATH: &str = "/usr/local/bin/dbev";

async fn setup_system(config_path: PathBuf) -> anyhow::Result<()> {
    ensure_root()?;
    validate_setup_config_path(&config_path)?;
    require_existing_config(&config_path)?;
    let mut config = load_config(&config_path)?;
    ensure_required_setup_commands()?;
    install_current_binary(Path::new(INSTALL_PATH))?;
    secure_config_permissions(&config_path)?;
    ensure_system_directories(&config_path)?;
    detect_and_log_disk_mode(&mut config)?;
    ensure_fuse_quota_host_config(&config)?;
    remove_obsolete_managed_sudoers()?;
    validate_runtime_support(&config).await?;
    write_systemd_service(&config_path, config.daemon.engine)?;
    reload_systemd()?;
    println!("system setup complete");
    println!("config read from: {}", config_path.display());
    println!("node uuid: {}", config.uuid);
    println!("token id: {}", config.token_id);
    println!("remote panel: {}", config.remote);
    println!("api listener: {}", config.api.bind_addr());
    if config.api.host == "0.0.0.0" {
        println!(
            "panel api url: use the node domain or server IP with port {}",
            config.api.port
        );
    }
    println!("start with: systemctl enable --now databases-everywhere");
    Ok(())
}

fn validate_setup_config_path(config_path: &Path) -> anyhow::Result<()> {
    if !config_path.is_absolute()
        || config_path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        anyhow::bail!("setup requires an absolute config path without parent traversal");
    }
    let value = config_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("setup config path must be valid UTF-8"))?;
    if value
        .bytes()
        .any(|byte| !(byte.is_ascii_alphanumeric() || b"/._-".contains(&byte)))
    {
        anyhow::bail!(
            "setup config path may contain only ASCII letters, digits, '/', '.', '_', and '-'"
        );
    }
    Ok(())
}

fn ensure_required_setup_commands() -> anyhow::Result<()> {
    for command in ["chown"] {
        if !command_exists(command)? {
            anyhow::bail!("required setup command {command} was not found");
        }
    }
    Ok(())
}

fn ensure_fuse_quota_host_config(config: &Config) -> anyhow::Result<()> {
    if config.disk.mode != DiskLimitMode::FuseQuota {
        return Ok(());
    }

    ensure_fuse_device_supported()?;
    warn_if_fuse_not_listed_in_proc_filesystems();

    let path = Path::new("/etc/fuse.conf");
    let mut contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        }
    };

    match ensure_fuse_conf_allow_other(&contents) {
        FuseConfUpdate::AlreadyEnabled => {
            println!("fuse quota host config ok: /etc/fuse.conf has user_allow_other");
            return Ok(());
        }
        FuseConfUpdate::Updated(updated) => contents = updated,
    }

    atomic_replace_setup_file(path, 0o644, "fuse configuration", |file| {
        file.write_all(contents.as_bytes())
    })
    .with_context(|| {
        format!(
            "failed to write {}; for Docker installs, do not mount this file read-only, or add user_allow_other on the host before starting dbev",
            path.display()
        )
    })?;
    println!("enabled fuse allow_other support in /etc/fuse.conf");
    Ok(())
}

enum FuseConfUpdate {
    AlreadyEnabled,
    Updated(String),
}

fn ensure_fuse_conf_allow_other(contents: &str) -> FuseConfUpdate {
    if contents.lines().any(is_active_user_allow_other_line) {
        return FuseConfUpdate::AlreadyEnabled;
    }

    let mut uncommented = false;
    let mut updated = String::new();
    for line in contents.lines() {
        if !uncommented && is_commented_user_allow_other_line(line) {
            let indent = line
                .chars()
                .take_while(|character| character.is_whitespace())
                .collect::<String>();
            updated.push_str(&indent);
            updated.push_str("user_allow_other\n");
            uncommented = true;
        } else {
            updated.push_str(line);
            updated.push('\n');
        }
    }

    if uncommented {
        return FuseConfUpdate::Updated(updated);
    }

    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str("user_allow_other\n");
    FuseConfUpdate::Updated(updated)
}

fn is_active_user_allow_other_line(line: &str) -> bool {
    let line = line.trim();
    !line.starts_with('#') && line == "user_allow_other"
}

fn is_commented_user_allow_other_line(line: &str) -> bool {
    let line = line.trim_start();
    let Some(line) = line.strip_prefix('#') else {
        return false;
    };
    line.trim() == "user_allow_other"
}

fn ensure_fuse_device_supported() -> anyhow::Result<()> {
    let path = Path::new("/dev/fuse");
    let metadata = fs::metadata(path).with_context(|| {
        "automatic disk-limit detection selected FuseQuota, but /dev/fuse is unavailable; install/enable host FUSE support, then rerun dbev --setup"
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_char_device() {
            anyhow::bail!(
                "automatic disk-limit detection selected FuseQuota, but /dev/fuse is not a character device"
            );
        }
    }

    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(
            || "automatic disk-limit detection selected FuseQuota, but /dev/fuse is not openable read/write by setup",
        )?;
    println!("fuse quota host support ok: /dev/fuse is available");
    Ok(())
}

fn warn_if_fuse_not_listed_in_proc_filesystems() {
    let mut contents = String::new();
    let Ok(mut file) = fs::File::open("/proc/filesystems") else {
        return;
    };
    if file.read_to_string(&mut contents).is_err() {
        return;
    }
    let has_fuse = contents.lines().any(|line| {
        line.split_whitespace()
            .last()
            .is_some_and(|name| name == "fuse")
    });
    if !has_fuse {
        eprintln!(
            "warning: /proc/filesystems does not list fuse; setup will continue because /dev/fuse is available"
        );
    }
}

fn ensure_root() -> anyhow::Result<()> {
    let output = StdCommand::new("id")
        .arg("-u")
        .output()
        .context("failed to check current uid")?;
    let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if uid == "0" {
        Ok(())
    } else {
        anyhow::bail!("--setup must be run as root")
    }
}

fn install_current_binary(destination: &Path) -> anyhow::Result<()> {
    let current = std::env::current_exe().context("failed to resolve current executable")?;
    if current != destination {
        use rustix::fs::{FileType, Mode, OFlags};

        let source_fd = rustix::fs::open(
            &current,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)
        .with_context(|| format!("failed to open current executable {}", current.display()))?;
        let source_stat = rustix::fs::fstat(&source_fd)
            .map_err(std::io::Error::from)
            .with_context(|| {
                format!("failed to inspect current executable {}", current.display())
            })?;
        if FileType::from_raw_mode(source_stat.st_mode) != FileType::RegularFile {
            anyhow::bail!(
                "current executable {} must be a real regular file",
                current.display()
            );
        }
        let mut source = fs::File::from(source_fd);
        atomic_replace_setup_file(destination, 0o755, "installed daemon binary", |target| {
            std::io::copy(&mut source, target).map(|_| ())
        })
        .with_context(|| {
            format!(
                "failed to install {} to {}",
                current.display(),
                destination.display()
            )
        })?;
    } else {
        use std::os::unix::fs::MetadataExt;

        validate_setup_replace_target(destination, "installed daemon binary")?;
        validate_setup_parent_directory(
            destination
                .parent()
                .ok_or_else(|| anyhow::anyhow!("installed daemon path has no parent"))?,
            "installed daemon binary",
        )?;
        if fs::symlink_metadata(destination)?.uid() != 0 {
            anyhow::bail!("installed daemon binary must be owned by root");
        }
        set_mode(destination, 0o755)?;
    }
    Ok(())
}

fn require_existing_config(config_path: &Path) -> anyhow::Result<()> {
    if config_path.exists() {
        load_config(config_path)
            .with_context(|| format!("failed to load config {}", config_path.display()))?;
        Ok(())
    } else {
        anyhow::bail!(
            "config {} does not exist; create it before running --setup",
            config_path.display()
        )
    }
}

fn secure_config_permissions(config_path: &Path) -> anyhow::Result<()> {
    let config_metadata = fs::symlink_metadata(config_path)
        .with_context(|| format!("failed to inspect config {}", config_path.display()))?;
    if config_metadata.file_type().is_symlink() || !config_metadata.is_file() {
        anyhow::bail!(
            "config {} must be a real regular file, not a symlink",
            config_path.display()
        );
    }
    let config_parent = config_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("config path must have a dedicated parent directory"))?;
    if config_parent == Path::new("/")
        || config_parent
            .parent()
            .is_none_or(|parent| parent == Path::new("/"))
    {
        anyhow::bail!(
            "config {} must be stored in a dedicated subdirectory so atomic updates do not require write access to a top-level system directory",
            config_path.display()
        );
    }
    let parent_metadata = fs::symlink_metadata(config_parent).with_context(|| {
        format!(
            "failed to inspect config directory {}",
            config_parent.display()
        )
    })?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        anyhow::bail!(
            "config directory {} must be a real directory, not a symlink",
            config_parent.display()
        );
    }
    run_setup_command(
        "chown",
        &["root:root", &config_parent.display().to_string()],
    )?;
    // Same-directory atomic config replacement requires create and rename
    // access. Only the root-run daemon may enter this directory.
    set_mode(config_parent, 0o700)?;
    run_setup_command("chown", &["root:root", &config_path.display().to_string()])?;
    // The daemon persists validated config-admin changes without exposing the
    // node credentials to other local users.
    set_mode(config_path, 0o600)?;
    Ok(())
}

fn ensure_system_directories(config_path: &Path) -> anyhow::Result<()> {
    let config = load_config(config_path)?;
    let paths = configured_runtime_roots(&config);
    for path in &paths {
        fs::create_dir_all(path).with_context(|| format!("failed to create {path}"))?;
        // Do not recursively change database files: container images use their
        // own internal UIDs/GIDs, and the root-run daemon can manage them as-is.
        run_setup_command("chown", &["root:root", path.as_str()])?;
        harden_runtime_directory(Path::new(path))?;
    }
    Ok(())
}

fn remove_obsolete_managed_sudoers() -> anyhow::Result<()> {
    let path = Path::new(SUDOERS_PATH);
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            anyhow::bail!("sudoers path {SUDOERS_PATH} must be a real regular file");
        }
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("failed to inspect existing sudoers file"),
    }
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) => return Err(error).context("failed to inspect existing sudoers file"),
    };
    if !contents.starts_with("# Managed by DatabasesEverywhere --setup.\n") {
        anyhow::bail!(
            "refusing to remove unmanaged sudoers file {SUDOERS_PATH}; review it manually"
        );
    }
    fs::remove_file(path).context("failed to remove obsolete managed sudoers file")?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn write_systemd_service(config_path: &Path, engine: DaemonEngine) -> anyhow::Result<()> {
    let contents = systemd_service_contents(config_path, engine);
    atomic_replace_setup_file(Path::new(SERVICE_PATH), 0o644, "systemd service", |file| {
        file.write_all(contents.as_bytes())
    })
    .context("failed to write systemd service")?;
    Ok(())
}

fn systemd_service_contents(config_path: &Path, engine: DaemonEngine) -> String {
    let exec_start = if config_path == Path::new(defaults::CONFIG_PATH) {
        INSTALL_PATH.to_string()
    } else {
        format!("{INSTALL_PATH} --config {}", config_path.display())
    };
    let engine_unit = match engine {
        DaemonEngine::Docker => "docker.service",
        DaemonEngine::Podman => "podman.socket",
    };
    format!(
        r#"[Unit]
Description=DatabasesEverywhere
After={engine_unit}
Requires={engine_unit}
PartOf={engine_unit}

[Service]
User=root
ExecStart={exec_start} daemon
KillMode=process
Restart=on-failure
RestartSec=5s
TimeoutStopSec=21min
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
"#
    )
}

fn reload_systemd() -> anyhow::Result<()> {
    if command_exists("systemctl")? {
        run_setup_command("systemctl", &["daemon-reload"])?;
    }
    Ok(())
}

fn atomic_replace_setup_file(
    path: &Path,
    mode: u32,
    label: &str,
    write_contents: impl FnOnce(&mut fs::File) -> std::io::Result<()>,
) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    validate_setup_replace_target(path, label)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{label} path has no parent directory"))?;
    validate_setup_parent_directory(parent, label)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{label} path has no file name"))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        uuid::Uuid::new_v4()
    ));

    let result = (|| -> anyhow::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .with_context(|| format!("failed to create temporary {label}"))?;
        write_contents(&mut file).with_context(|| format!("failed to write temporary {label}"))?;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .with_context(|| format!("failed to set temporary {label} permissions"))?;
        file.sync_all()
            .with_context(|| format!("failed to sync temporary {label}"))?;
        drop(file);
        fs::rename(&temporary, path).with_context(|| format!("failed to install {label}"))?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("failed to sync {label} directory"))?;

        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("failed to verify installed {label}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o777 != mode
        {
            anyhow::bail!(
                "installed {label} must be a root-owned, singly-linked regular file with mode {mode:o}"
            );
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn validate_setup_replace_target(path: &Path, label: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.nlink() != 1 =>
        {
            anyhow::bail!(
                "{label} {} must be a real, singly-linked regular file",
                path.display()
            )
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {label}")),
    }
}

fn validate_setup_parent_directory(parent: &Path, label: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("failed to inspect {label} directory {}", parent.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        anyhow::bail!(
            "{label} directory {} must be a root-owned real directory not writable by group or others",
            parent.display()
        );
    }
    Ok(())
}

fn command_exists(program: &str) -> anyhow::Result<bool> {
    match StdCommand::new("sh")
        .arg("-c")
        .arg(format!("command -v {program} >/dev/null 2>&1"))
        .status()
    {
        Ok(status) => Ok(status.success()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("failed to check command availability"),
    }
}

fn run_setup_command(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = StdCommand::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {program}"))?;
    if output.status.success() {
        Ok(())
    } else {
        anyhow::bail!(
            "{} {} failed: {}",
            program,
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}

fn set_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("failed to chmod {:o} {}", mode, path.display()))?;
    }
    let _ = (path, mode);
    Ok(())
}

async fn migrate_metadata(config_path: PathBuf) -> anyhow::Result<()> {
    let config = load_config(&config_path)?;
    let _daemon_lock = acquire_configured_daemon_lock(&config).await?;
    init_configured_logging(&config)?;
    let pool = sqlite::connect(std::path::Path::new(&config.paths.metadata_root()))
        .await
        .context("failed to initialize sqlite storage")?;
    pool.close().await;
    println!("metadata migrations ok");
    Ok(())
}

async fn dev_clean(config_path: PathBuf) -> anyhow::Result<()> {
    let config = load_config(&config_path)?;
    let _daemon_lock = acquire_configured_daemon_lock(&config).await?;
    init_configured_logging(&config)?;
    let docker = DockerRuntime::new(&config.daemon, false)
        .context("failed to connect to container engine API")?;
    let removed = docker
        .remove_managed_containers()
        .await
        .context("failed to remove managed containers")?;
    docker
        .remove_network()
        .await
        .context("failed to remove container network")?;
    println!("removed {removed} managed containers and the legacy container network if present");
    Ok(())
}

async fn reset_metadata(config_path: PathBuf) -> anyhow::Result<()> {
    let config = load_config(&config_path)?;
    let _daemon_lock = acquire_configured_daemon_lock(&config).await?;
    init_configured_logging(&config)?;
    let metadata_root = config.paths.metadata_root();
    let data_root = std::path::Path::new(&metadata_root);
    let mut removed = 0;

    for path in sqlite::database_files(data_root) {
        match tokio::fs::remove_file(&path).await {
            Ok(()) => removed += 1,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to remove sqlite file {}", path.display()));
            }
        }
    }

    println!("removed {removed} sqlite metadata files");
    Ok(())
}

async fn migrate_paths(config_path: PathBuf, dry_run: bool, force: bool) -> anyhow::Result<()> {
    let config = load_config(&config_path)?;
    let _daemon_lock = acquire_configured_daemon_lock(&config).await?;
    init_configured_logging(&config)?;
    let plan = PathMigrationPlan::new(&config);
    let actions = plan.actions();

    if actions.is_empty() {
        println!("no path migration actions needed");
        return Ok(());
    }

    println!(
        "path migration {}",
        if dry_run { "dry-run" } else { "execution" }
    );
    for action in &actions {
        println!("{} -> {}", action.from.display(), action.to.display());
    }

    if dry_run {
        println!("dry-run only; no files moved");
        return Ok(());
    }

    if !force {
        ensure_no_active_managed_containers(&config).await?;
    }

    for root in configured_runtime_roots(&config) {
        tokio::fs::create_dir_all(&root)
            .await
            .with_context(|| format!("failed to create migration target root {root}"))?;
    }

    for action in actions {
        migrate_path_action(&action, force)?;
    }

    println!("path migration complete");
    Ok(())
}

#[derive(Debug, Clone)]
struct PathMigrationAction {
    from: PathBuf,
    to: PathBuf,
}

struct PathMigrationPlan<'a> {
    config: &'a Config,
}

impl<'a> PathMigrationPlan<'a> {
    fn new(config: &'a Config) -> Self {
        Self { config }
    }

    fn actions(&self) -> Vec<PathMigrationAction> {
        let mut actions = Vec::new();
        self.add_file_actions(
            &mut actions,
            Path::new("/var/lib/databases-everywhere"),
            Path::new(&self.config.paths.metadata_root()),
        );
        self.add_file_actions(
            &mut actions,
            Path::new(&self.config.paths.data),
            Path::new(&self.config.paths.metadata_root()),
        );
        self.add_dir_action(
            &mut actions,
            Path::new("/var/lib/databases-everywhere/instances"),
            Path::new(&self.config.paths.volumes_root()),
        );
        self.add_dir_action(
            &mut actions,
            &Path::new(&self.config.paths.data).join("instances"),
            Path::new(&self.config.paths.volumes_root()),
        );
        self.add_dir_action(
            &mut actions,
            Path::new("/var/lib/databases-everywhere/artifacts/exports"),
            Path::new(&self.config.paths.exports_root()),
        );
        self.add_dir_action(
            &mut actions,
            &Path::new(&self.config.paths.artifacts).join("exports"),
            Path::new(&self.config.paths.exports_root()),
        );
        self.add_dir_action(
            &mut actions,
            Path::new("/var/lib/databases-everywhere/artifacts/imports"),
            Path::new(&self.config.paths.imports_root()),
        );
        self.add_dir_action(
            &mut actions,
            &Path::new(&self.config.paths.artifacts).join("imports"),
            Path::new(&self.config.paths.imports_root()),
        );
        self.add_dir_action(
            &mut actions,
            Path::new("/var/log/databases-everywhere"),
            Path::new(&self.config.paths.logs),
        );
        actions
            .into_iter()
            .filter(|action| action.from != action.to)
            .collect()
    }

    fn add_file_actions(
        &self,
        actions: &mut Vec<PathMigrationAction>,
        from_root: &Path,
        to_root: &Path,
    ) {
        for file in [
            "databases-everywhere.sqlite",
            "databases-everywhere.sqlite-wal",
            "databases-everywhere.sqlite-shm",
        ] {
            self.add_path_action(actions, from_root.join(file), to_root.join(file));
        }
    }

    fn add_dir_action(&self, actions: &mut Vec<PathMigrationAction>, from: &Path, to: &Path) {
        if from == to {
            return;
        }
        if from.exists() {
            actions.push(PathMigrationAction {
                from: from.to_path_buf(),
                to: to.to_path_buf(),
            });
        }
    }

    fn add_path_action(&self, actions: &mut Vec<PathMigrationAction>, from: PathBuf, to: PathBuf) {
        if from == to {
            return;
        }
        if from.exists() {
            actions.push(PathMigrationAction { from, to });
        }
    }
}

async fn ensure_no_active_managed_containers(config: &Config) -> anyhow::Result<()> {
    let docker = DockerRuntime::new(&config.daemon, false)
        .context("failed to connect to container engine API for migration safety check")?;
    let active = docker
        .active_managed_container_count()
        .await
        .context("failed to count active managed containers for migration safety check")?;
    if active > 0 {
        anyhow::bail!(
            "refusing to migrate paths while {} managed container(s) are active; stop dbev/containers first or pass --force",
            active
        );
    }
    Ok(())
}

fn migrate_path_action(action: &PathMigrationAction, force: bool) -> anyhow::Result<()> {
    let metadata = match fs::symlink_metadata(&action.from) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {}", action.from.display()));
        }
    };
    if metadata.file_type().is_symlink() {
        migrate_symlink(&action.from, &action.to, force)
    } else if metadata.is_dir() {
        if action.to.exists() {
            migrate_directory_contents(&action.from, &action.to, force)
        } else {
            migrate_directory(&action.from, &action.to, force)
        }
    } else if metadata.is_file() {
        migrate_file(&action.from, &action.to, force)
    } else {
        anyhow::bail!("refusing to migrate special path {}", action.from.display())
    }
}

fn migrate_directory(from: &Path, to: &Path, force: bool) -> anyhow::Result<()> {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create migration target {}", parent.display()))?;
    }
    if to.exists() {
        if !force {
            anyhow::bail!(
                "refusing to overwrite existing migration target {}; pass --force to replace",
                to.display()
            );
        }
        fs::remove_dir_all(to).with_context(|| format!("failed to replace {}", to.display()))?;
    }
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(18) => {
            copy_directory_tree(from, to)?;
            fs::remove_dir_all(from)
                .with_context(|| format!("failed to remove migrated source {}", from.display()))
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to move {} to {}", from.display(), to.display())),
    }
}

fn migrate_directory_contents(from: &Path, to: &Path, force: bool) -> anyhow::Result<()> {
    fs::create_dir_all(to)
        .with_context(|| format!("failed to create migration target {}", to.display()))?;
    let entries = fs::read_dir(from)
        .with_context(|| format!("failed to read migration source {}", from.display()))?;
    for entry in entries {
        let entry =
            entry.with_context(|| format!("failed to read migration source {}", from.display()))?;
        let source = entry.path();
        let target = to.join(entry.file_name());
        migrate_path_action(
            &PathMigrationAction {
                from: source,
                to: target,
            },
            force,
        )?;
    }
    remove_empty_dir(from)?;
    Ok(())
}

fn copy_directory_tree(from: &Path, to: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(to)
        .with_context(|| format!("failed to create migration target {}", to.display()))?;
    for entry in fs::read_dir(from)
        .with_context(|| format!("failed to read migration source {}", from.display()))?
    {
        let entry =
            entry.with_context(|| format!("failed to read migration source {}", from.display()))?;
        let source = entry.path();
        let target = to.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source)
            .with_context(|| format!("failed to inspect {}", source.display()))?;
        if metadata.file_type().is_symlink() {
            copy_symlink(&source, &target)?;
        } else if metadata.is_dir() {
            copy_directory_tree(&source, &target)?;
        } else if metadata.is_file() {
            fs::copy(&source, &target).with_context(|| {
                format!(
                    "failed to copy {} to {}",
                    source.display(),
                    target.display()
                )
            })?;
        } else {
            anyhow::bail!("refusing to migrate special path {}", source.display());
        }
    }
    Ok(())
}

fn migrate_file(from: &Path, to: &Path, force: bool) -> anyhow::Result<()> {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create migration target {}", parent.display()))?;
    }
    if to.exists() {
        if !force {
            anyhow::bail!(
                "refusing to overwrite existing migration target {}; pass --force to replace",
                to.display()
            );
        }
        fs::remove_file(to).with_context(|| format!("failed to replace {}", to.display()))?;
    }
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(18) => {
            fs::copy(from, to).with_context(|| {
                format!("failed to copy {} to {}", from.display(), to.display())
            })?;
            fs::remove_file(from)
                .with_context(|| format!("failed to remove migrated source {}", from.display()))
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to move {} to {}", from.display(), to.display())),
    }
}

fn migrate_symlink(from: &Path, to: &Path, force: bool) -> anyhow::Result<()> {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create migration target {}", parent.display()))?;
    }
    if to.exists() || fs::symlink_metadata(to).is_ok() {
        if !force {
            anyhow::bail!(
                "refusing to overwrite existing migration target {}; pass --force to replace",
                to.display()
            );
        }
        remove_path_for_replace(to)?;
    }
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(18) => {
            copy_symlink(from, to)?;
            fs::remove_file(from)
                .with_context(|| format!("failed to remove migrated source {}", from.display()))
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to move {} to {}", from.display(), to.display())),
    }
}

fn copy_symlink(from: &Path, to: &Path) -> anyhow::Result<()> {
    let target = fs::read_link(from)
        .with_context(|| format!("failed to read symlink {}", from.display()))?;
    create_symlink(&target, to).with_context(|| {
        format!(
            "failed to copy symlink {} to {}",
            from.display(),
            to.display()
        )
    })
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

fn remove_path_for_replace(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect replacement target {}", path.display()))?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path).with_context(|| format!("failed to replace {}", path.display()))
    } else {
        fs::remove_file(path).with_context(|| format!("failed to replace {}", path.display()))
    }
}

fn remove_empty_dir(path: &Path) -> anyhow::Result<()> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) if error.kind() == ErrorKind::DirectoryNotEmpty => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to remove empty dir {}", path.display()))
        }
    }
}

async fn disk_test(config_path: PathBuf, quota_mib: u64, write_mib: u64) -> anyhow::Result<()> {
    if quota_mib == 0 {
        anyhow::bail!("--quota-mib must be greater than zero");
    }
    if write_mib <= quota_mib {
        anyhow::bail!("--write-mib must be greater than --quota-mib");
    }

    let mut config = load_config(&config_path)?;
    ensure_runtime_directories(&config)
        .await
        .context("failed to create runtime directories")?;
    let _daemon_lock = acquire_configured_daemon_lock(&config).await?;
    init_configured_logging(&config)?;
    detect_and_log_disk_mode(&mut config)?;
    validate_runtime_support(&config).await?;

    let limiter = DiskLimiter::with_fuse_root(config.disk.clone(), config.paths.fuse_root());
    let run_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let instance_id = format!("dbe_disk_test_{run_id}");
    let test_path = Path::new(&config.paths.volumes_root()).join(&instance_id);
    cleanup_disk_test_path(&limiter, &test_path).await;
    tokio::fs::create_dir_all(&test_path)
        .await
        .with_context(|| format!("failed to create disk test path {}", test_path.display()))?;

    let result = run_disk_test(&limiter, &instance_id, &test_path, quota_mib, write_mib).await;
    cleanup_disk_test_path(&limiter, &test_path).await;
    result
}

async fn run_disk_test(
    limiter: &DiskLimiter,
    instance_id: &str,
    test_path: &Path,
    quota_mib: u64,
    write_mib: u64,
) -> anyhow::Result<()> {
    let enforcement = limiter
        .apply_instance_limit(instance_id, test_path, quota_mib)
        .await
        .context("failed to apply disk test quota")?;

    let write_path = enforcement
        .container_data_path
        .clone()
        .unwrap_or_else(|| test_path.to_path_buf());
    tokio::fs::create_dir_all(&write_path)
        .await
        .with_context(|| {
            format!(
                "failed to create disk test write path {}",
                write_path.display()
            )
        })?;
    let target = write_path.join("quota-probe.bin");
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&target)
        .await
        .with_context(|| format!("failed to open disk test file {}", target.display()))?;
    let mut chunk = vec![0; 1024 * 1024];
    let mut seed = 0xD8E5_0001_u64;

    println!(
        "disk test applying {quota_mib}MiB quota with method {} at {}",
        enforcement.method,
        write_path.display()
    );

    for written_mib in 0..write_mib {
        fill_probe_chunk(&mut chunk, &mut seed);
        match file.write_all(&chunk).await {
            Ok(_) => {
                if written_mib == 0 || (written_mib + 1) % 8 == 0 {
                    println!("disk test wrote {}MiB", written_mib + 1);
                }
            }
            Err(error) if is_quota_like_error(&error) => {
                println!(
                    "disk test passed: write failed after about {written_mib}MiB with quota/full error: {error}"
                );
                return Ok(());
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("disk test failed with non-quota write error after {written_mib}MiB")
                });
            }
        }
    }

    anyhow::bail!(
        "disk test failed: wrote {write_mib}MiB with a {quota_mib}MiB quota and did not hit a quota/full error"
    )
}

fn fill_probe_chunk(chunk: &mut [u8], seed: &mut u64) {
    for byte in chunk {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *byte = (*seed >> 24) as u8;
    }
}

fn is_quota_like_error(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(28) | Some(122) | Some(69))
}

async fn cleanup_disk_test_path(limiter: &DiskLimiter, test_path: &Path) {
    let _ = limiter.purge_instance_data(test_path).await;
    match tokio::fs::remove_dir_all(test_path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            eprintln!(
                "warning: failed to remove disk test path {}: {error}",
                test_path.display()
            );
        }
    }
}

async fn run_daemon(config_path: PathBuf) -> anyhow::Result<()> {
    let mut config = load_config(&config_path)?;
    let runtime_directories = ensure_runtime_directories(&config)
        .await
        .context("failed to create runtime directories")?;
    let _daemon_lock = acquire_configured_daemon_lock(&config).await?;
    init_configured_logging(&config)?;
    detect_and_log_disk_mode(&mut config)?;
    let config = Arc::new(config);
    let socket_bridge_helper = crate::runtime::socket_bridge::install_helper(&config.paths)
        .await
        .context("failed to install the container socket bridge helper")?;
    tracing::info!("\n{}", startup_banner());
    for directory in runtime_directories {
        tracing::info!(
            path = %directory.path,
            existed = directory.existed,
            "runtime directory ready"
        );
    }
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %config_path.display(),
        logs = %config.paths.logs,
        uuid = %config.uuid,
        token_id = %config.token_id,
        remote = %config.remote,
        api_bind = %config.api.bind_addr(),
        api_host = %config.api.host,
        api_port = config.api.port,
        api_ssl = config.api.ssl.enabled,
        "DatabasesEverywhere daemon starting"
    );
    tracing::info!(
        path = %Path::new(&config.paths.locks).join(DAEMON_LOCK_FILE).display(),
        "exclusive daemon lock acquired"
    );
    tracing::info!(
        path = %socket_bridge_helper.display(),
        "private container socket bridge helper ready"
    );
    log_boot_configuration(&config, &config_path);
    ensure_fuse_quota_host_config(&config)
        .context("failed to prepare fuse quota host configuration")?;
    tracing::info!("runtime preflight starting");
    validate_runtime_support(&config).await?;
    tracing::info!(
        mode = %config.disk.mode.method(),
        enforced = config.disk.mode.enforced(),
        data_path = %config.paths.data,
        "disk limiter preflight ok"
    );

    let store = InstanceStore::default();
    let pool = sqlite::connect(std::path::Path::new(&config.paths.metadata_root()))
        .await
        .context("failed to initialize sqlite storage")?;
    let metadata_root = config.paths.metadata_root();
    tracing::info!(path = %metadata_root, "sqlite metadata storage ready");
    let repository = InstanceRepository::encrypted(pool.clone(), Path::new(&metadata_root))
        .context("failed to initialize encrypted metadata secret storage")?;
    let job_repository = ImportExportJobRepository::new(pool.clone());
    let interrupted_running_instances = job_repository
        .running_instance_ids()
        .await
        .context("failed to identify interrupted running import/export jobs")?;
    let failed_jobs = job_repository
        .fail_unfinished(
            "daemon restarted before import/export job completed",
            &crate::jobs::import_export::now_rfc3339(),
        )
        .await
        .context("failed to reconcile import/export jobs")?;
    if failed_jobs > 0 {
        tracing::warn!(failed_jobs, "marked unfinished import/export jobs failed");
    }
    let pruned_jobs = job_repository
        .prune_completed(10_000)
        .await
        .context("failed to prune completed import/export jobs during startup")?;
    if pruned_jobs > 0 {
        tracing::info!(pruned_jobs, "pruned old completed import/export jobs");
    }
    let import_export_jobs = ImportExportJobs::with_repository(job_repository);
    let manager = InstanceManager::new(store.clone(), repository);
    manager
        .load_from_storage()
        .await
        .context("failed to load local instance metadata from sqlite")?;
    let quarantined_interrupted_instances =
        quarantine_interrupted_job_instances(&manager, &interrupted_running_instances).await?;
    if quarantined_interrupted_instances > 0 {
        tracing::warn!(
            quarantined_interrupted_instances,
            "quarantined instances with import/export jobs interrupted by an unclean shutdown"
        );
    }

    let mut docker = DockerRuntime::new(&config.daemon, false)
        .context("failed to connect to container engine API")?;
    let docker_ping = docker
        .ping()
        .await
        .context("failed to ping container engine API")?;
    if let Err(error) = docker.refresh_engine_info().await {
        tracing::warn!(
            %error,
            "failed to read container engine info; using socket-derived engine capabilities"
        );
    }
    tracing::info!(
        engine = %docker.engine_name(),
        socket = %docker.socket_path(),
        rootless_podman = docker.uses_rootless_podman(),
        response = %docker_ping,
        "container engine api reachable"
    );
    tracing::info!(
        engine = %docker.engine_name(),
        "database containers will run with network_mode=none and private Unix sockets"
    );
    let disk_limiter = DiskLimiter::with_fuse_root(config.disk.clone(), config.paths.fuse_root());
    disk_limiter
        .verify_startup(std::path::Path::new(&config.paths.data))
        .await
        .context("failed to verify disk limiter support")?;
    reapply_instance_disk_limits(&config, &manager, &docker, &disk_limiter)
        .await
        .context("failed to reapply instance disk limits")?;
    tracing::info!("instance disk limits reconciled");
    let reconcile_summary = reconcile::reconcile_all(&manager, &docker)
        .await
        .context("failed to reconcile instance metadata")?;
    tracing::info!(
        checked = reconcile_summary.checked,
        booting = reconcile_summary.booting,
        running = reconcile_summary.running,
        stopped = reconcile_summary.stopped,
        failed = reconcile_summary.failed,
        quarantined = reconcile_summary.quarantined,
        "instance metadata reconciled"
    );
    let shutdown_jobs = import_export_jobs.clone();
    let install_progress = InstallProgressStore::default();
    let shutdown_creations = install_progress.clone();
    let instance_locks = crate::instances::locks::InstanceLocks::default();
    let state = AppState {
        config: config.clone(),
        config_path: config_path.clone(),
        config_patches: crate::api::config_admin::ConfigPatchCoordinator::default(),
        api_token: ApiToken::from_config(&config),
        instances: store,
        manager,
        docker,
        import_export_jobs,
        instance_locks,
        api_rate_limiter: crate::api::security::ApiRateLimiter::new(
            config.security.api_rate_limit_per_minute,
        ),
        install_progress,
        artifact_downloads: crate::api::artifacts::ArtifactDownloadTickets::default(),
        resource_cache: crate::api::resources::ResourceCache::default(),
        instance_runtime_cache: crate::api::instances::InstanceRuntimeInfoCache::default(),
        gateway_supervisor: GatewaySupervisor::new(),
        daemon_shutdown: crate::api::routes::DaemonShutdown::default(),
    };
    crate::api::resources::start_resource_sampler(state.clone());
    tracing::info!(
        "critical startup complete; API will accept requests while managed instances start in the background"
    );
    let managed_runtime_boot = tokio::spawn(complete_managed_runtime_boot(state.clone()));
    let gateway_supervisor = state.gateway_supervisor.clone();
    let daemon_shutdown = state.daemon_shutdown.clone();
    let server_result = serve_api(
        &config,
        build_router(state.clone()),
        shutdown_jobs.clone(),
        shutdown_creations.clone(),
        daemon_shutdown,
        gateway_supervisor,
    )
    .await;
    shutdown_jobs.close_admission();
    shutdown_creations.close_creation_admission();
    managed_runtime_boot.abort();
    let _ = managed_runtime_boot.await;
    let (jobs_drained, creations_drained) = tokio::join!(
        shutdown_jobs.wait_for_drain(IMPORT_EXPORT_DRAIN_TIMEOUT),
        shutdown_creations.wait_for_creation_drain(IMPORT_EXPORT_DRAIN_TIMEOUT),
    );
    if !jobs_drained {
        anyhow::bail!(
            "timed out after {} seconds waiting for import/export jobs to finish safely",
            IMPORT_EXPORT_DRAIN_TIMEOUT.as_secs()
        );
    }
    if !creations_drained {
        anyhow::bail!(
            "timed out after {} seconds waiting for instance creations to finish safely",
            IMPORT_EXPORT_DRAIN_TIMEOUT.as_secs()
        );
    }
    tracing::info!("active import/export jobs drained");
    tracing::info!("active instance creations drained");
    server_result
}

async fn complete_managed_runtime_boot(state: AppState) {
    if let Err(error) = start_known_instances_on_boot(
        &state.config,
        &state.manager,
        &state.docker,
        &state.instance_locks,
    )
    .await
    {
        tracing::error!(
            %error,
            "managed instance background startup failed; API remains available and database gateways remain closed"
        );
        state
            .gateway_supervisor
            .fail_and_stop("managed instance startup failed");
        return;
    }
    if !state.import_export_jobs.is_accepting() {
        return;
    }

    let postgres_role_hardening = match crate::api::instance_create::harden_postgres_roles_on_boot(
        &state.manager,
        &state.docker,
        &state.instance_locks,
    )
    .await
    {
        Ok(summary) => summary,
        Err(error) => {
            tracing::error!(
                %error,
                "legacy PostgreSQL role hardening failed; API remains available and database gateways remain closed"
            );
            state
                .gateway_supervisor
                .fail_and_stop("postgres role hardening failed");
            return;
        }
    };
    tracing::info!(
        checked = postgres_role_hardening.checked,
        hardened = postgres_role_hardening.hardened,
        "legacy PostgreSQL role hardening complete"
    );
    if !state.import_export_jobs.is_accepting() {
        return;
    }

    if let Err(error) = start_gateway_listeners(
        &state.config,
        state.instances.clone(),
        state.resource_cache.clone(),
        state.gateway_supervisor.clone(),
    )
    .await
    {
        tracing::error!(
            %error,
            "database gateway startup failed; API remains available"
        );
        return;
    }
    log_gateway_listener_summary(&state.config);
    crate::api::backups::start_scheduler(state);
}

async fn quarantine_interrupted_job_instances(
    manager: &InstanceManager,
    instance_ids: &[String],
) -> anyhow::Result<usize> {
    let store = manager.store();
    let mut quarantined = 0;
    for instance_id in instance_ids {
        let Some(mut metadata) = store.get(instance_id).await else {
            tracing::warn!(
                %instance_id,
                "interrupted running import/export job references missing instance metadata"
            );
            continue;
        };
        metadata.status = InstanceStatus::Quarantined;
        metadata.updated_at = crate::jobs::import_export::now_rfc3339();
        manager
            .upsert(metadata.clone())
            .await
            .with_context(|| format!("failed to quarantine interrupted instance {instance_id}"))?;
        quarantined += 1;
        tracing::warn!(
            event = "audit interrupted_job_instance_quarantined",
            %instance_id,
            protocol = %metadata.protocol,
            "quarantined instance before container reconciliation and gateway startup"
        );
    }
    Ok(quarantined)
}

fn log_boot_configuration(config: &Config, config_path: &Path) {
    tracing::info!(
        config = %config_path.display(),
        data = %config.paths.data,
        metadata = %config.paths.metadata_root(),
        logs = %config.paths.logs,
        sockets = %config.paths.sockets,
        artifacts = %config.paths.artifacts,
        "configured paths"
    );
    tracing::info!(
        api_bind = %config.api.bind_addr(),
        api_host = %config.api.host,
        api_port = config.api.port,
        remote = %config.remote,
        cors_allowed_hosts = ?config.cors_allowed_hosts(),
        body_limit_bytes = config.security.api_body_limit_bytes,
        api_rate_limit_per_minute = config.security.api_rate_limit_per_minute,
        "api configuration"
    );
    log_api_host_resolution(config);
    log_tls_configuration(config);
    tracing::info!(
        default_pids_limit = config.security.pids_limit,
        postgres = ?config.security.pids_limits.postgres,
        redis = ?config.security.pids_limits.redis,
        mariadb = ?config.security.pids_limits.mariadb,
        mysql = ?config.security.pids_limits.mysql,
        mongodb = ?config.security.pids_limits.mongodb,
        clickhouse = ?config.security.pids_limits.clickhouse,
        qdrant = ?config.security.pids_limits.qdrant,
        "container pid limits configured"
    );
    tracing::info!(
        postgres = %config.images.postgres,
        redis = %config.images.redis,
        mariadb = %config.images.mariadb,
        mysql = %config.images.mysql,
        mongodb = %config.images.mongodb,
        clickhouse = %config.images.clickhouse,
        qdrant = %config.images.qdrant,
        "database images configured"
    );
    let mutable_images: Vec<&str> = [
        config.images.postgres.as_str(),
        config.images.redis.as_str(),
        config.images.mariadb.as_str(),
        config.images.mysql.as_str(),
        config.images.mongodb.as_str(),
        config.images.clickhouse.as_str(),
        config.images.qdrant.as_str(),
    ]
    .into_iter()
    .filter(|image| !has_sha256_digest(image))
    .collect();
    if !mutable_images.is_empty() {
        tracing::warn!(
            images = ?mutable_images,
            "database image tags are mutable; version tags are accepted, while sha256 digests provide stronger reproducibility"
        );
    }
    tracing::info!(
        mode = %config.disk.mode.method(),
        enforced = config.disk.mode.enforced(),
        project_id_base = config.disk.project_id_base,
        fuse_quota_binary = %config.disk.fuse_quota_binary(),
        "disk limiter configured"
    );
    tracing::info!(
        "remote credential imports disabled because database containers have no network interface"
    );
}

fn log_api_host_resolution(config: &Config) {
    if config.api.host == "0.0.0.0" || config.api.host == "::" {
        tracing::info!(
            host = %config.api.host,
            port = config.api.port,
            "api binds all local interfaces; clients should use the configured DNS name or server IP"
        );
        return;
    }
    if config.api.host.parse::<IpAddr>().is_ok() {
        tracing::info!(
            host = %config.api.host,
            port = config.api.port,
            "api binds explicit local IP"
        );
        return;
    }

    let target = config.api.bind_addr();
    match target.to_socket_addrs() {
        Ok(addrs) => {
            let resolved: Vec<String> = addrs.map(|addr| addr.to_string()).collect();
            tracing::warn!(
                host = %config.api.host,
                port = config.api.port,
                resolved = ?resolved,
                "api host is a DNS name; bind succeeds only if it resolves to an address assigned to this server"
            );
        }
        Err(error) => {
            tracing::warn!(
                host = %config.api.host,
                port = config.api.port,
                %error,
                "api host DNS resolution failed; use 0.0.0.0 when exposing the daemon by domain"
            );
        }
    }
}

fn log_tls_configuration(config: &Config) {
    if config.api.ssl.enabled {
        log_tls_file("api tls certificate", &config.api.ssl.cert);
        log_tls_file("api tls private key", &config.api.ssl.key);
        tracing::info!(
            require_client_cert = config.api.ssl.require_client_cert,
            client_ca = %empty_as_unset(&config.api.ssl.client_ca),
            "api tls enabled"
        );
        if config.api.ssl.require_client_cert {
            log_tls_file("api tls client ca", &config.api.ssl.client_ca);
        }
    } else {
        tracing::warn!(
            "api tls disabled; use this only behind a trusted TLS reverse proxy or on a private network"
        );
    }

    if any_database_listener_tls_enabled(config) {
        log_tls_file("database listener tls certificate", &config.tls.cert);
        log_tls_file("database listener tls private key", &config.tls.key);
        tracing::info!("database gateway tls enabled for at least one protocol");
    } else {
        tracing::info!("database gateway tls disabled for all protocols");
    }
}

fn log_tls_file(label: &'static str, path: &str) {
    if path.trim().is_empty() {
        tracing::warn!(label, "tls path is empty");
        return;
    }
    match fs::metadata(path) {
        Ok(metadata) => {
            tracing::info!(
                label,
                path,
                bytes = metadata.len(),
                readonly = metadata.permissions().readonly(),
                "tls file accessible"
            );
        }
        Err(error) => {
            tracing::error!(label, path, %error, "tls file is not accessible");
        }
    }
}

fn any_database_listener_tls_enabled(config: &Config) -> bool {
    config.postgres.tls
        || config.redis.tls
        || config.mariadb.tls
        || config.mysql.tls
        || config.mongodb.tls
        || config.clickhouse.tls
        || config.qdrant.tls
}

fn empty_as_unset(value: &str) -> &str {
    if value.trim().is_empty() {
        "<unset>"
    } else {
        value
    }
}

fn log_gateway_listener_summary(config: &Config) {
    log_listener(
        "postgres",
        &config.postgres.bind,
        config.postgres.enabled,
        config.postgres.tls,
    );
    log_listener(
        "redis",
        &config.redis.bind,
        config.redis.enabled,
        config.redis.tls,
    );
    log_listener(
        "mariadb",
        &config.mariadb.bind,
        config.mariadb.enabled,
        config.mariadb.tls,
    );
    log_listener(
        "mysql",
        &config.mysql.bind,
        config.mysql.enabled,
        config.mysql.tls,
    );
    log_listener(
        "mongodb",
        &config.mongodb.bind,
        config.mongodb.enabled,
        config.mongodb.tls,
    );
    log_listener(
        "clickhouse native",
        &config.clickhouse.bind,
        config.clickhouse.enabled,
        config.clickhouse.tls,
    );
    log_listener(
        "clickhouse http",
        &config.clickhouse.http_bind,
        config.clickhouse.enabled,
        config.clickhouse.tls,
    );
    log_listener(
        "qdrant",
        &config.qdrant.bind,
        config.qdrant.enabled,
        config.qdrant.tls,
    );
}

fn log_listener(protocol: &'static str, bind: &str, enabled: bool, tls: bool) {
    if enabled {
        let publicly_reachable = bind
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|address| !address.ip().is_loopback());
        if !tls && publicly_reachable {
            tracing::warn!(
                protocol,
                bind,
                "gateway listener accepts authenticated database traffic without transport encryption"
            );
        } else {
            tracing::info!(protocol, bind, tls, "gateway listener configured");
        }
    } else {
        tracing::info!(protocol, bind, "gateway listener disabled");
    }
}

async fn reapply_instance_disk_limits(
    config: &Config,
    manager: &InstanceManager,
    docker: &DockerRuntime,
    disk_limiter: &DiskLimiter,
) -> anyhow::Result<()> {
    let instances = manager.store().list().await;
    let outcomes = futures::stream::iter(instances)
        .map(|metadata| async move {
            let paths = InstancePaths::new(&config.paths, &metadata.instance_id)
                .with_context(|| format!("failed to build paths for {}", metadata.instance_id))?;
            if !disk_limiter
                .instance_runtime_is_healthy(&paths.data)
                .await
                .with_context(|| {
                    format!(
                        "failed to inspect disk-limit runtime for {}",
                        metadata.instance_id
                    )
                })?
            {
                match docker.stop(metadata.protocol, &metadata.instance_id).await {
                    Ok(_) => tracing::warn!(
                        instance_id = %metadata.instance_id,
                        protocol = %metadata.protocol,
                        "stopped managed instance to recover an unavailable disk-limit runtime"
                    ),
                    Err(error) if error.is_not_found() || error.is_not_running() => {}
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!(
                                "failed to stop {} before recovering its disk-limit runtime",
                                metadata.instance_id
                            )
                        });
                    }
                }
            }
            disk_limiter
                .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
                .await
                .with_context(|| {
                    format!("failed to apply disk limit for {}", metadata.instance_id)
                })?;
            Ok::<(), anyhow::Error>(())
        })
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    for outcome in outcomes {
        outcome?;
    }
    Ok(())
}

async fn start_known_instances_on_boot(
    config: &Config,
    manager: &InstanceManager,
    docker: &DockerRuntime,
    instance_locks: &crate::instances::locks::InstanceLocks,
) -> anyhow::Result<()> {
    let instances = manager.store().list().await;
    let outcomes = futures::stream::iter(instances)
        .map(|snapshot| async move {
            start_known_instance_on_boot(config, manager, docker, instance_locks, snapshot).await
        })
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut attempted = 0_usize;
    let mut running = 0_usize;
    let mut stopped = 0_usize;
    let mut failed = 0_usize;

    for outcome in outcomes {
        let Some(status) = outcome? else {
            continue;
        };
        attempted += 1;
        match status {
            InstanceStatus::Booting => {}
            InstanceStatus::Running => running += 1,
            InstanceStatus::Stopped => stopped += 1,
            InstanceStatus::Failed | InstanceStatus::Quarantined => failed += 1,
            InstanceStatus::Creating | InstanceStatus::Deleting => {}
        }
    }

    tracing::info!(
        attempted,
        running,
        stopped,
        failed,
        concurrency = MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY,
        "daemon boot managed instance auto-start complete"
    );
    Ok(())
}

async fn start_known_instance_on_boot(
    config: &Config,
    manager: &InstanceManager,
    docker: &DockerRuntime,
    instance_locks: &crate::instances::locks::InstanceLocks,
    snapshot: crate::instances::metadata::InstanceMetadata,
) -> anyhow::Result<Option<InstanceStatus>> {
    let Some(snapshot_action) = managed_boot_action(snapshot.status) else {
        return Ok(None);
    };

    let _operation = instance_locks.lock(&snapshot.instance_id).await;
    let Some(metadata) = manager.store().get(&snapshot.instance_id).await else {
        return Ok(None);
    };
    let Some(action) = managed_boot_action(metadata.status) else {
        return Ok(None);
    };
    if action != snapshot_action {
        tracing::debug!(
            instance_id = %metadata.instance_id,
            snapshot_action = snapshot_action.as_str(),
            action = action.as_str(),
            "managed instance boot action changed after acquiring its operation lock"
        );
    }

    tracing::info!(
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        previous_status = ?metadata.status,
        action = action.as_str(),
        "activating managed instance on daemon boot"
    );

    if let Err(error) =
        ensure_instance_runtime_paths(config, docker, metadata.protocol, &metadata.instance_id)
            .await
    {
        tracing::warn!(
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            %error,
            "failed to prepare managed instance runtime directories during daemon boot; skipping container start"
        );
    } else {
        let activation = match action {
            ManagedBootAction::Start => {
                docker.start(metadata.protocol, &metadata.instance_id).await
            }
            ManagedBootAction::Restart => {
                docker
                    .restart(metadata.protocol, &metadata.instance_id)
                    .await
            }
        };
        match activation {
            Ok(_) => {
                if let Err(error) = docker
                    .wait_until_ready(
                        metadata.protocol,
                        &metadata.instance_id,
                        Duration::from_secs(180),
                    )
                    .await
                {
                    log_boot_container_failure(
                        docker,
                        metadata.protocol,
                        &metadata.instance_id,
                        "managed instance did not become ready during daemon boot",
                        error.to_string(),
                    )
                    .await;
                }
            }
            Err(error) => {
                log_boot_container_failure(
                    docker,
                    metadata.protocol,
                    &metadata.instance_id,
                    "failed to activate managed instance during daemon boot",
                    error.to_string(),
                )
                .await;
            }
        }
    }

    let reconciled = reconcile::reconcile_one(metadata, docker).await;
    let status = reconciled.status;
    manager.upsert(reconciled).await?;
    Ok(Some(status))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedBootAction {
    Start,
    Restart,
}

impl ManagedBootAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Restart => "restart",
        }
    }
}

fn managed_boot_action(status: InstanceStatus) -> Option<ManagedBootAction> {
    match status {
        InstanceStatus::Stopped => Some(ManagedBootAction::Start),
        InstanceStatus::Failed => Some(ManagedBootAction::Restart),
        InstanceStatus::Creating
        | InstanceStatus::Booting
        | InstanceStatus::Running
        | InstanceStatus::Quarantined
        | InstanceStatus::Deleting => None,
    }
}

async fn log_boot_container_failure(
    docker: &DockerRuntime,
    protocol: Protocol,
    instance_id: &str,
    message: &'static str,
    error: String,
) {
    let recent_container_logs = match docker.logs(protocol, instance_id, None).await {
        Ok(output) => {
            let combined = format!("{}{}", output.stdout, output.stderr);
            truncate_log_tail(combined.trim(), 4_000)
        }
        Err(log_error) => format!("failed to read container logs: {log_error}"),
    };

    tracing::warn!(
        instance_id,
        protocol = %protocol,
        reason = message,
        %error,
        %recent_container_logs,
        "managed instance boot start failed"
    );
}

async fn ensure_instance_runtime_paths(
    config: &Config,
    docker: &DockerRuntime,
    protocol: Protocol,
    instance_id: &str,
) -> anyhow::Result<()> {
    let paths = InstancePaths::new(&config.paths, instance_id)?;
    paths.create_dirs().await?;
    paths.clear_socket_dir().await?;
    tracing::info!(
        instance_id,
        protocol = %protocol,
        persistent_data = %paths.data.display(),
        runtime_sockets = %paths.sockets.display(),
        "daemon boot instance paths prepared; persistent data retained and runtime socket directory cleared"
    );

    if docker.rootless_podman_container_user(protocol).is_none() {
        if let Some((uid, gid)) = docker
            .configured_container_user(protocol, instance_id)
            .await
            .ok()
            .flatten()
            .and_then(|user| parse_numeric_container_user(&user))
        {
            tracing::info!(
                instance_id,
                protocol = %protocol,
                uid,
                gid,
                runtime_sockets = %paths.sockets.display(),
                "daemon boot runtime socket directory ownership applied from existing container user"
            );
            paths.apply_socket_owner(uid, gid).await?;
        } else {
            tracing::info!(
                instance_id,
                protocol = %protocol,
                runtime_sockets = %paths.sockets.display(),
                "daemon boot runtime socket directory ownership falling back to data path owner heuristic"
            );
            paths.apply_container_owner().await?;
        }
    } else {
        tracing::info!(
            instance_id,
            protocol = %protocol,
            runtime_sockets = %paths.sockets.display(),
            "daemon boot rootless podman detected; runtime socket directory ownership handled by user namespace mapping"
        );
    }
    let socket_status = paths.socket_dir_status().await?;
    tracing::info!(
        instance_id,
        protocol = %protocol,
        runtime_sockets = %paths.sockets.display(),
        socket_entries = socket_status.entries,
        socket_uid = ?socket_status.uid,
        socket_gid = ?socket_status.gid,
        socket_mode = ?socket_status.mode.map(|mode| format!("{mode:o}")),
        "daemon boot runtime socket directory verified"
    );
    Ok(())
}

fn parse_numeric_container_user(user: &str) -> Option<(u32, u32)> {
    let user = user.trim();
    if user.is_empty() || user == "root" {
        return None;
    }

    let (uid, gid) = user.split_once(':').unwrap_or((user, user));
    let uid = uid.parse::<u32>().ok()?;
    if uid == 0 {
        return None;
    }

    let gid = if gid.is_empty() {
        uid
    } else {
        gid.parse::<u32>().ok()?
    };

    Some((uid, gid))
}

struct RuntimeDirectoryStatus {
    path: String,
    existed: bool,
}

async fn ensure_runtime_directories(
    config: &Config,
) -> anyhow::Result<Vec<RuntimeDirectoryStatus>> {
    let mut statuses = Vec::new();
    for path in configured_runtime_roots(config) {
        let existed = tokio::fs::metadata(&path).await.is_ok();
        tokio::fs::create_dir_all(&path)
            .await
            .with_context(|| format!("failed to create configured directory {path}"))?;
        harden_runtime_directory(Path::new(&path))?;
        statuses.push(RuntimeDirectoryStatus { path, existed });
    }
    Ok(statuses)
}

fn harden_runtime_directory(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use rustix::fs::{FileType, Mode, OFlags, fchmod, open};

        let directory = open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)
        .with_context(|| {
            format!(
                "failed to securely open runtime directory {}; it must be a real directory, not a symlink",
                path.display()
            )
        })?;
        let stat = rustix::fs::fstat(&directory)
            .map_err(std::io::Error::from)
            .with_context(|| format!("failed to inspect runtime directory {}", path.display()))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
            anyhow::bail!("runtime path {} must be a real directory", path.display());
        }
        require_runtime_directory_owner(path, stat.st_uid, rustix::process::geteuid().as_raw())?;
        fchmod(&directory, Mode::RWXU)
            .map_err(std::io::Error::from)
            .with_context(|| {
                format!(
                    "failed to restrict runtime directory {} to mode 0700",
                    path.display()
                )
            })?;
    }

    #[cfg(not(unix))]
    {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect runtime directory {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            anyhow::bail!(
                "runtime path {} must be a real directory, not a symlink",
                path.display()
            );
        }
    }

    Ok(())
}

fn require_runtime_directory_owner(
    path: &Path,
    actual_uid: u32,
    expected_uid: u32,
) -> anyhow::Result<()> {
    if actual_uid != expected_uid {
        anyhow::bail!(
            "runtime directory {} is owned by uid {actual_uid}, expected daemon uid {expected_uid}",
            path.display()
        );
    }
    Ok(())
}

const DAEMON_LOCK_FILE: &str = "daemon.lock";

struct DaemonLock {
    _file: std::fs::File,
}

impl Drop for DaemonLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        let _ = rustix::fs::flock(&self._file, rustix::fs::FlockOperation::Unlock);
    }
}

async fn acquire_configured_daemon_lock(config: &Config) -> anyhow::Result<DaemonLock> {
    let locks_root = Path::new(&config.paths.locks);
    tokio::fs::create_dir_all(locks_root)
        .await
        .with_context(|| format!("failed to create lock directory {}", locks_root.display()))?;
    harden_runtime_directory(locks_root)?;
    acquire_daemon_lock(locks_root).context("failed to acquire the process-lifetime daemon lock")
}

fn acquire_daemon_lock(locks_root: &Path) -> anyhow::Result<DaemonLock> {
    #[cfg(unix)]
    {
        use rustix::fs::{FileType, FlockOperation, Mode, OFlags};

        let directory = rustix::fs::open(
            locks_root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)
        .with_context(|| {
            format!(
                "failed to securely open lock directory {}",
                locks_root.display()
            )
        })?;
        let lock_fd = rustix::fs::openat(
            &directory,
            DAEMON_LOCK_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(std::io::Error::from)
        .with_context(|| {
            format!(
                "failed to securely open daemon lock {}",
                locks_root.join(DAEMON_LOCK_FILE).display()
            )
        })?;

        let stat = rustix::fs::fstat(&lock_fd).map_err(std::io::Error::from)?;
        let expected_uid = rustix::process::geteuid().as_raw();
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != expected_uid
            || stat.st_nlink != 1
        {
            anyhow::bail!(
                "daemon lock {} must be a regular, singly-linked file owned by uid {expected_uid}",
                locks_root.join(DAEMON_LOCK_FILE).display()
            );
        }
        rustix::fs::fchmod(&lock_fd, Mode::RUSR | Mode::WUSR)
            .map_err(std::io::Error::from)
            .context("failed to restrict daemon lock permissions to 0600")?;

        match rustix::fs::flock(&lock_fd, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(rustix::io::Errno::WOULDBLOCK) => {
                anyhow::bail!(
                    "another dbev daemon already owns {}",
                    locks_root.join(DAEMON_LOCK_FILE).display()
                );
            }
            Err(error) => {
                return Err(std::io::Error::from(error))
                    .context("failed to apply an exclusive advisory daemon lock");
            }
        }

        let mut file = std::fs::File::from(lock_fd);
        file.set_len(0)
            .context("failed to clear daemon lock file")?;
        writeln!(file, "{}", std::process::id()).context("failed to write daemon lock owner")?;
        file.sync_data()
            .context("failed to sync daemon lock owner")?;
        Ok(DaemonLock { _file: file })
    }

    #[cfg(not(unix))]
    {
        let _ = locks_root;
        anyhow::bail!("the dbev daemon lock requires a Unix host")
    }
}

fn configured_runtime_roots(config: &Config) -> Vec<String> {
    vec![
        config.paths.data.clone(),
        config.paths.metadata_root(),
        format!(
            "{}/runtime",
            config.paths.metadata_root().trim_end_matches('/')
        ),
        config.paths.volumes_root(),
        config.paths.backups_root(),
        config.paths.logs.clone(),
        config.paths.sockets.clone(),
        config.paths.locks.clone(),
        config.paths.artifacts.clone(),
        config.paths.exports_root(),
        config.paths.imports_root(),
        config.paths.fuse_root(),
        format!(
            "{}/instances",
            config.paths.fuse_root().trim_end_matches('/')
        ),
        format!("{}/mounts", config.paths.fuse_root().trim_end_matches('/')),
        config.paths.tmp_root(),
        format!("{}/instances", config.paths.logs.trim_end_matches('/')),
    ]
}

async fn validate_runtime_support(config: &Config) -> anyhow::Result<()> {
    DiskLimiter::with_fuse_root(config.disk.clone(), config.paths.fuse_root())
        .verify_startup(Path::new(&config.paths.volumes_root()))
        .await
        .context("failed to verify disk limiter support")
}

fn detect_and_log_disk_mode(config: &mut Config) -> anyhow::Result<()> {
    let detection = crate::disk::detect_disk_mode(&config.paths)
        .context("failed to inspect configured filesystems for disk-limit selection")?;
    for filesystem in &detection.filesystems {
        tracing::info!(
            field = filesystem.field,
            path = %filesystem.path.display(),
            mountpoint = %filesystem.mountpoint.display(),
            source = %filesystem.source,
            fstype = %filesystem.fstype,
            options = %filesystem.options.join(","),
            "configured directory filesystem detected"
        );
    }
    config.disk.mode = detection.mode;
    tracing::info!(
        mode = config.disk.mode.method(),
        reason = detection.reason,
        volumes = %config.paths.volumes_root(),
        "disk-limit mode selected automatically"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum GatewayListenerKind {
    Postgres,
    Redis,
    Mariadb,
    Mysql,
    Mongodb,
    Clickhouse,
    ClickhouseHttp,
    Qdrant,
}

impl GatewayListenerKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Redis => "redis",
            Self::Mariadb => "mariadb",
            Self::Mysql => "mysql",
            Self::Mongodb => "mongodb",
            Self::Clickhouse => "clickhouse",
            Self::ClickhouseHttp => "clickhouse_http",
            Self::Qdrant => "qdrant",
        }
    }
}

struct PreparedGatewayListener {
    kind: GatewayListenerKind,
    bind: String,
    listener: TcpListener,
    tls: Option<tokio_rustls::TlsAcceptor>,
    limiter: GatewayConnectionLimiter,
}

impl PreparedGatewayListener {
    async fn bind(
        kind: GatewayListenerKind,
        bind: String,
        tls: Option<tokio_rustls::TlsAcceptor>,
        connection_limit: u32,
    ) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(&bind)
            .await
            .with_context(|| format!("failed to bind {} listener on {bind}", kind.as_str()))?;
        Ok(Self {
            kind,
            bind,
            listener,
            tls,
            limiter: GatewayConnectionLimiter::new(connection_limit),
        })
    }

    async fn run(
        self,
        resolver: RouteResolver,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), listeners::ListenerError> {
        let Self {
            kind,
            bind,
            listener,
            tls,
            limiter,
        } = self;
        match kind {
            GatewayListenerKind::Postgres => {
                listeners::run_postgres_listener(listener, &bind, resolver, tls, limiter, shutdown)
                    .await
            }
            GatewayListenerKind::Redis => {
                listeners::run_redis_listener(listener, &bind, resolver, tls, limiter, shutdown)
                    .await
            }
            GatewayListenerKind::Mariadb => {
                listeners::run_mariadb_listener(listener, &bind, resolver, tls, limiter, shutdown)
                    .await
            }
            GatewayListenerKind::Mysql => {
                listeners::run_mysql_listener(listener, &bind, resolver, tls, limiter, shutdown)
                    .await
            }
            GatewayListenerKind::Mongodb => {
                listeners::run_mongodb_listener(listener, &bind, resolver, tls, limiter, shutdown)
                    .await
            }
            GatewayListenerKind::Clickhouse => {
                listeners::run_clickhouse_listener(
                    listener, &bind, resolver, tls, limiter, shutdown,
                )
                .await
            }
            GatewayListenerKind::ClickhouseHttp => {
                listeners::run_clickhouse_http_listener(
                    listener, &bind, resolver, tls, limiter, shutdown,
                )
                .await
            }
            GatewayListenerKind::Qdrant => {
                listeners::run_qdrant_listener(listener, &bind, resolver, tls, limiter, shutdown)
                    .await
            }
        }
    }
}

async fn start_gateway_listeners(
    config: &Config,
    store: InstanceStore,
    resources: crate::api::resources::ResourceCache,
    supervisor: GatewaySupervisor,
) -> anyhow::Result<()> {
    let connection_limit = config.security.db_connection_limit_per_minute;
    let expected = usize::from(config.postgres.enabled)
        + usize::from(config.redis.enabled)
        + usize::from(config.mariadb.enabled)
        + usize::from(config.mysql.enabled)
        + usize::from(config.mongodb.enabled)
        + usize::from(config.clickhouse.enabled) * 2
        + usize::from(config.qdrant.enabled);
    if !supervisor.begin(expected) {
        anyhow::bail!("daemon shutdown started before gateway listeners were bound");
    }

    let prepared = prepare_gateway_listeners(config, connection_limit).await;
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            supervisor.fail_and_stop("gateway listener bind failed");
            return Err(error);
        }
    };
    if supervisor.is_stopping() {
        anyhow::bail!("daemon shutdown started while gateway listeners were binding");
    }
    let resolver = RouteResolver::new(store, resources);
    let mut listeners = tokio::task::JoinSet::new();
    for listener in prepared {
        let protocol = listener.kind.as_str();
        let resolver = resolver.clone();
        let shutdown = supervisor.subscribe_shutdown();
        listeners.spawn(async move {
            let result = listener.run(resolver, shutdown).await;
            (protocol, result)
        });
    }
    supervisor.mark_ready();

    if expected == 0 {
        return Ok(());
    }
    tokio::spawn(async move {
        while let Some(outcome) = listeners.join_next().await {
            if supervisor.is_stopping() {
                continue;
            }
            let failure = match outcome {
                Ok((protocol, Ok(()))) => format!("{protocol} listener stopped unexpectedly"),
                Ok((protocol, Err(error))) => {
                    tracing::error!(%error, protocol, "database listener stopped");
                    format!("{protocol} listener stopped")
                }
                Err(error) => {
                    tracing::error!(%error, "database listener task failed");
                    "database listener task failed".to_string()
                }
            };
            supervisor.fail_and_stop(failure);
            listeners.abort_all();
            while listeners.join_next().await.is_some() {}
            return;
        }
    });
    Ok(())
}

async fn prepare_gateway_listeners(
    config: &Config,
    connection_limit: u32,
) -> anyhow::Result<Vec<PreparedGatewayListener>> {
    let mut prepared = Vec::new();
    if config.postgres.enabled {
        prepared.push(
            PreparedGatewayListener::bind(
                GatewayListenerKind::Postgres,
                config.postgres.bind.clone(),
                listener_tls(config.postgres.tls, config)?,
                connection_limit,
            )
            .await?,
        );
    }
    if config.redis.enabled {
        prepared.push(
            PreparedGatewayListener::bind(
                GatewayListenerKind::Redis,
                config.redis.bind.clone(),
                listener_tls(config.redis.tls, config)?,
                connection_limit,
            )
            .await?,
        );
    }
    if config.mariadb.enabled {
        prepared.push(
            PreparedGatewayListener::bind(
                GatewayListenerKind::Mariadb,
                config.mariadb.bind.clone(),
                listener_tls(config.mariadb.tls, config)?,
                connection_limit,
            )
            .await?,
        );
    }
    if config.mysql.enabled {
        prepared.push(
            PreparedGatewayListener::bind(
                GatewayListenerKind::Mysql,
                config.mysql.bind.clone(),
                listener_tls(config.mysql.tls, config)?,
                connection_limit,
            )
            .await?,
        );
    }
    if config.mongodb.enabled {
        prepared.push(
            PreparedGatewayListener::bind(
                GatewayListenerKind::Mongodb,
                config.mongodb.bind.clone(),
                listener_tls(config.mongodb.tls, config)?,
                connection_limit,
            )
            .await?,
        );
    }
    if config.clickhouse.enabled {
        let tls = listener_tls(config.clickhouse.tls, config)?;
        prepared.push(
            PreparedGatewayListener::bind(
                GatewayListenerKind::Clickhouse,
                config.clickhouse.bind.clone(),
                tls.clone(),
                connection_limit,
            )
            .await?,
        );
        prepared.push(
            PreparedGatewayListener::bind(
                GatewayListenerKind::ClickhouseHttp,
                config.clickhouse.http_bind.clone(),
                tls,
                connection_limit,
            )
            .await?,
        );
    }
    if config.qdrant.enabled {
        prepared.push(
            PreparedGatewayListener::bind(
                GatewayListenerKind::Qdrant,
                config.qdrant.bind.clone(),
                listener_tls(config.qdrant.tls, config)?,
                connection_limit,
            )
            .await?,
        );
    }
    Ok(prepared)
}

fn listener_tls(
    enabled: bool,
    config: &Config,
) -> anyhow::Result<Option<tokio_rustls::TlsAcceptor>> {
    if !enabled {
        return Ok(None);
    }
    crate::gateway::tls::acceptor(&config.tls.cert, &config.tls.key)
        .map(Some)
        .context("failed to configure database listener tls")
}

async fn serve_api(
    config: &Config,
    router: Router,
    import_export_jobs: ImportExportJobs,
    install_progress: InstallProgressStore,
    daemon_shutdown: crate::api::routes::DaemonShutdown,
    gateway_supervisor: GatewaySupervisor,
) -> anyhow::Result<()> {
    let bind = config.api.bind_addr();
    if config.api.ssl.enabled {
        return serve_api_tls(
            config,
            router,
            import_export_jobs,
            install_progress,
            daemon_shutdown,
            gateway_supervisor,
        )
        .await;
    }

    let listener = TcpListener::bind(&bind)
        .await
        .with_context(|| format!("failed to bind API listener on {bind}"))?;
    tracing::info!(
        bind = %bind,
        configured_host = %config.api.host,
        port = config.api.port,
        "api listener started"
    );

    let (shutdown_observed, mut shutdown_observed_rx) = tokio::sync::oneshot::channel();
    let shutdown = async move {
        shutdown_signal(
            import_export_jobs,
            install_progress,
            daemon_shutdown,
            gateway_supervisor,
        )
        .await;
        let _ = shutdown_observed.send(());
    };
    let server = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .into_future();
    tokio::pin!(server);

    tokio::select! {
        result = &mut server => return result.context("api server failed"),
        _ = &mut shutdown_observed_rx => {}
    }
    match tokio::time::timeout(API_CONNECTION_DRAIN_TIMEOUT, &mut server).await {
        Ok(result) => result.context("api server failed"),
        Err(_) => {
            tracing::warn!(
                timeout_seconds = API_CONNECTION_DRAIN_TIMEOUT.as_secs(),
                "API connections did not drain before the restart deadline; closing them"
            );
            Ok(())
        }
    }
}

async fn serve_api_tls(
    config: &Config,
    router: Router,
    import_export_jobs: ImportExportJobs,
    install_progress: InstallProgressStore,
    daemon_shutdown: crate::api::routes::DaemonShutdown,
    gateway_supervisor: GatewaySupervisor,
) -> anyhow::Result<()> {
    let bind_addr = config.api.bind_addr();
    let listener = std::net::TcpListener::bind(&bind_addr)
        .with_context(|| format!("failed to bind API listener on {bind_addr}"))?;
    listener
        .set_nonblocking(true)
        .context("failed to configure API TLS listener as non-blocking")?;
    let tls = api_rustls_config(config)
        .await
        .context("failed to build API TLS configuration")?;
    tracing::info!(
        cert = %config.api.ssl.cert,
        key = %config.api.ssl.key,
        require_client_cert = config.api.ssl.require_client_cert,
        "api tls configuration loaded"
    );

    tracing::info!(
        bind = %bind_addr,
        configured_host = %config.api.host,
        port = config.api.port,
        "api tls listener started"
    );
    let handle = Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown_signal(
            import_export_jobs,
            install_progress,
            daemon_shutdown,
            gateway_supervisor,
        )
        .await;
        shutdown_handle.graceful_shutdown(Some(API_CONNECTION_DRAIN_TIMEOUT));
    });

    axum_server::from_tcp_rustls(listener, tls)
        .context("failed to create API TLS server")?
        .handle(handle)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("api tls server failed")
}

async fn api_rustls_config(config: &Config) -> anyhow::Result<RustlsConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    if !config.api.ssl.require_client_cert {
        return RustlsConfig::from_pem_file(&config.api.ssl.cert, &config.api.ssl.key)
            .await
            .with_context(|| {
                format!(
                    "failed to load API TLS cert/key from {} and {}",
                    config.api.ssl.cert, config.api.ssl.key
                )
            });
    }

    let cert_pem = tokio::fs::read(&config.api.ssl.cert)
        .await
        .with_context(|| format!("failed to read API TLS cert {}", config.api.ssl.cert))?;
    let key_pem = tokio::fs::read(&config.api.ssl.key)
        .await
        .with_context(|| format!("failed to read API TLS key {}", config.api.ssl.key))?;
    let ca_pem = tokio::fs::read(&config.api.ssl.client_ca)
        .await
        .with_context(|| format!("failed to read API client CA {}", config.api.ssl.client_ca))?;

    tokio::task::spawn_blocking(move || rustls_config_with_client_ca(cert_pem, key_pem, ca_pem))
        .await
        .context("failed to join TLS config builder")?
        .map(RustlsConfig::from_config)
}

fn rustls_config_with_client_ca(
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    ca_pem: Vec<u8>,
) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let certs = CertificateDer::pem_reader_iter(cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse API TLS certificate")?;
    let key =
        PrivateKeyDer::from_pem_slice(&key_pem).context("failed to parse API TLS private key")?;

    let mut roots = rustls::RootCertStore::empty();
    let ca_certs = CertificateDer::pem_reader_iter(ca_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse API client CA certificates")?;
    for cert in ca_certs {
        roots.add(cert).context("failed to add API client CA")?;
    }

    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("failed to build API client certificate verifier")?;
    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .context("failed to build API TLS server config")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

async fn shutdown_signal(
    import_export_jobs: ImportExportJobs,
    install_progress: InstallProgressStore,
    daemon_shutdown: crate::api::routes::DaemonShutdown,
    gateway_supervisor: GatewaySupervisor,
) {
    let signal = wait_for_termination_signal().await;
    daemon_shutdown.trigger();
    import_export_jobs.close_admission();
    install_progress.close_creation_admission();
    gateway_supervisor.shutdown();
    tracing::info!(
        signal,
        "shutdown signal received; background operation admission closed"
    );
}

#[cfg(unix)]
async fn wait_for_termination_signal() -> &'static str {
    use tokio::signal::unix::{SignalKind, signal};

    match signal(SignalKind::terminate()) {
        Ok(mut terminate) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => "SIGINT",
                _ = terminate.recv() => "SIGTERM",
            }
        }
        Err(error) => {
            tracing::warn!(%error, "failed to install SIGTERM handler; waiting for SIGINT only");
            let _ = tokio::signal::ctrl_c().await;
            "SIGINT"
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_termination_signal() -> &'static str {
    let _ = tokio::signal::ctrl_c().await;
    "CTRL_C"
}

static LOG_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

fn init_stdout_logging() {
    let filter = EnvFilter::try_from_env(constants::RUST_LOG_ENV)
        .unwrap_or_else(|_| EnvFilter::new("databases_everywhere=info,tower_http=info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .try_init();
}

fn init_configured_logging(config: &Config) -> anyhow::Result<()> {
    fs::create_dir_all(&config.paths.logs)
        .with_context(|| format!("failed to create log directory {}", config.paths.logs))?;
    harden_runtime_directory(Path::new(&config.paths.logs))?;

    let filter = EnvFilter::try_from_env(constants::RUST_LOG_ENV)
        .unwrap_or_else(|_| EnvFilter::new("databases_everywhere=info,tower_http=info"));
    let file_appender = tracing_appender::rolling::RollingFileAppender::builder()
        .filename_prefix("dbev.log")
        .build(&config.paths.logs)
        .with_context(|| format!("failed to initialize log file in {}", config.paths.logs))?;
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    let _ = LOG_GUARD.set(guard);

    let result = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .with(fmt::layer().with_ansi(false).with_writer(file_writer))
        .try_init();

    if result.is_err() {
        tracing::debug!("logging was already initialized");
    }
    Ok(())
}

fn startup_banner() -> &'static str {
    r#" ____        _        _                         _____                           _
|  _ \  __ _| |_ __ _| |__   __ _ ___  ___  ___| ____|_   _____ _ __ _   ___      _____ _ __ ___
| | | |/ _` | __/ _` | '_ \ / _` / __|/ _ \/ __|  _| \ \ / / _ \ '__| | | \ \ /\ / / _ \ '__/ _ \
| |_| | (_| | || (_| | |_) | (_| \__ \  __/\__ \ |___ \ V /  __/ |  | |_| |\ V  V /  __/ | |  __/
|____/ \__,_|\__\__,_|_.__/ \__,_|___/\___||___/_____| \_/ \___|_|   \__, | \_/\_/ \___|_|  \___|
                                                                      |___/"#
}

#[cfg(all(test, unix))]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
        process::Command,
    };

    use super::*;

    #[test]
    fn daemon_boot_preserves_running_containers() {
        assert_eq!(managed_boot_action(InstanceStatus::Running), None);
        assert_eq!(
            managed_boot_action(InstanceStatus::Failed),
            Some(ManagedBootAction::Restart)
        );
        assert_eq!(
            managed_boot_action(InstanceStatus::Stopped),
            Some(ManagedBootAction::Start)
        );
        assert_eq!(managed_boot_action(InstanceStatus::Booting), None);
    }

    #[test]
    fn hardens_existing_runtime_directory_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = temp.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o777)).unwrap();

        harden_runtime_directory(&runtime).unwrap();

        let mode = fs::metadata(runtime).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn rejects_symlinked_runtime_directory() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let runtime = temp.path().join("runtime");
        fs::create_dir(&target).unwrap();
        symlink(&target, &runtime).unwrap();

        let error = harden_runtime_directory(&runtime).unwrap_err();

        assert!(error.to_string().contains("not a symlink"));
    }

    #[test]
    fn rejects_runtime_directory_owned_by_another_uid() {
        let error = require_runtime_directory_owner(Path::new("/runtime"), 1001, 1000).unwrap_err();

        assert!(error.to_string().contains("owned by uid 1001"));
    }

    #[test]
    fn setup_config_path_rejects_unit_file_metacharacters() {
        assert!(validate_setup_config_path(Path::new("/etc/dbev/config.yml")).is_ok());
        assert!(validate_setup_config_path(Path::new("relative.yml")).is_err());
        assert!(validate_setup_config_path(Path::new("/etc/dbev/../config.yml")).is_err());
        assert!(validate_setup_config_path(Path::new("/etc/dbev/config\nExecStart=evil")).is_err());
    }

    #[test]
    fn generated_systemd_service_runs_as_root_without_service_account_sandboxing() {
        let unit = systemd_service_contents(Path::new(defaults::CONFIG_PATH), DaemonEngine::Docker);

        assert!(unit.contains("User=root\n"));
        assert!(unit.contains("ExecStart=/usr/local/bin/dbev daemon\n"));
        assert!(unit.contains("KillMode=process\n"));
        assert!(unit.contains("PartOf=docker.service\n"));
        assert!(!unit.contains("SupplementaryGroups="));
        assert!(!unit.contains("ProtectSystem="));
        assert!(!unit.contains("DBE_USE_SUDO"));
    }

    #[test]
    fn generated_systemd_service_uses_selected_engine_and_custom_config() {
        let unit =
            systemd_service_contents(Path::new("/srv/dbev/config.yml"), DaemonEngine::Podman);

        assert!(unit.contains("After=podman.socket\n"));
        assert!(unit.contains("Requires=podman.socket\n"));
        assert!(unit.contains("PartOf=podman.socket\n"));
        assert!(
            unit.contains("ExecStart=/usr/local/bin/dbev --config /srv/dbev/config.yml daemon\n")
        );
    }

    #[test]
    fn daemon_lock_is_private_and_exclusive() {
        let temp = tempfile::tempdir().unwrap();
        let locks = temp.path().join("locks");
        fs::create_dir(&locks).unwrap();
        harden_runtime_directory(&locks).unwrap();

        let first = acquire_daemon_lock(&locks).unwrap();
        let lock_path = locks.join(DAEMON_LOCK_FILE);
        let mode = fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let error = acquire_daemon_lock(&locks).err().unwrap();
        assert!(error.to_string().contains("another dbev daemon"));
        drop(first);

        acquire_daemon_lock(&locks).unwrap();
    }

    #[test]
    fn process_umask_limits_new_files_to_owner_access() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "cli::tests::restrictive_umask_child",
            ])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "umask child failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "runs in an isolated child process from process_umask_limits_new_files_to_owner_access"]
    fn restrictive_umask_child() {
        harden_process_file_creation();
        let temp = tempfile::tempdir().unwrap();
        let file_path = temp.path().join("created");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o666)
            .open(&file_path)
            .unwrap();

        let mode = fs::metadata(file_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
