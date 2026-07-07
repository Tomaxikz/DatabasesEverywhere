use std::{
    fs,
    io::{ErrorKind, Read},
    net::{IpAddr, ToSocketAddrs},
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
use tokio::{io::AsyncWriteExt, net::TcpListener};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    api::routes::{AppState, build_router},
    auth::api_token::ApiToken,
    config::{Config, DaemonEngine, DiskLimitMode, load::load_config},
    constants::{self, defaults},
    disk::DiskLimiter,
    gateway::{listeners, resolver::RouteResolver, security::GatewayConnectionLimiter},
    instances::{
        manager::InstanceManager, metadata::InstanceStatus, paths::InstancePaths, reconcile,
        state::InstanceStore,
    },
    jobs::import_export::ImportExportJobs,
    runtime::docker::DockerRuntime,
    shared::{logs::truncate_log_tail, protocol::Protocol},
    storage::{
        import_export_jobs::ImportExportJobRepository, repositories::InstanceRepository, sqlite,
    },
};

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
            let config = load_config(&cli.config)?;
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

const SERVICE_USER: &str = "databases-everywhere";
const SERVICE_GROUP: &str = "databases-everywhere";
const SERVICE_PATH: &str = "/etc/systemd/system/databases-everywhere.service";
const SUDOERS_PATH: &str = "/etc/sudoers.d/databases-everywhere";
const INSTALL_PATH: &str = "/usr/local/bin/dbev";

async fn setup_system(config_path: PathBuf) -> anyhow::Result<()> {
    ensure_root()?;
    ensure_required_setup_commands()?;
    require_existing_config(&config_path)?;
    let config = load_config(&config_path)?;
    ensure_group(SERVICE_GROUP)?;
    ensure_user(SERVICE_USER, SERVICE_GROUP)?;
    add_user_to_runtime_group_if_exists(SERVICE_USER, config.daemon.engine)?;
    ensure_fuse_quota_host_config(&config)?;
    install_current_binary(Path::new(INSTALL_PATH))?;
    secure_config_permissions(&config_path)?;
    ensure_system_directories(&config_path)?;
    write_sudoers()?;
    validate_runtime_support(&config).await?;
    write_systemd_service(&config_path)?;
    reload_systemd();
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

fn ensure_required_setup_commands() -> anyhow::Result<()> {
    for command in ["sudo", "useradd", "groupadd", "usermod", "chown"] {
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

    fs::write(path, contents).with_context(|| format!("failed to write {}", path.display()))?;
    set_mode(path, 0o644)?;
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
        "disk.mode=fuse_quota requires /dev/fuse. Install/enable host FUSE support, then rerun dbev --setup"
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_char_device() {
            anyhow::bail!(
                "disk.mode=fuse_quota requires /dev/fuse to be a character device, but it is not"
            );
        }
    }

    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(
            || "disk.mode=fuse_quota requires /dev/fuse to be openable read/write by setup",
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

fn ensure_group(group: &str) -> anyhow::Result<()> {
    if command_success("getent", &["group", group])? {
        return Ok(());
    }
    run_setup_command("groupadd", &["--system", group])
}

fn ensure_user(user: &str, group: &str) -> anyhow::Result<()> {
    if command_success("getent", &["passwd", user])? {
        return Ok(());
    }
    run_setup_command(
        "useradd",
        &[
            "--system",
            "--gid",
            group,
            "--home-dir",
            defaults::DATA_PATH,
            "--shell",
            "/usr/sbin/nologin",
            user,
        ],
    )
}

fn add_user_to_runtime_group_if_exists(user: &str, engine: DaemonEngine) -> anyhow::Result<()> {
    let group = match engine {
        DaemonEngine::Docker => "docker",
        DaemonEngine::Podman => "podman",
    };

    if command_success("getent", &["group", group])? {
        run_setup_command("usermod", &["-aG", group, user])?;
    } else {
        eprintln!(
            "warning: group {group} does not exist; {} socket access may fail",
            engine.as_str()
        );
    }
    Ok(())
}

fn install_current_binary(destination: &Path) -> anyhow::Result<()> {
    let current = std::env::current_exe().context("failed to resolve current executable")?;
    if current != destination {
        fs::copy(&current, destination).with_context(|| {
            format!(
                "failed to install {} to {}",
                current.display(),
                destination.display()
            )
        })?;
    }
    set_mode(destination, 0o755)?;
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
    run_setup_command(
        "chown",
        &[
            &format!("root:{SERVICE_GROUP}"),
            &config_path.display().to_string(),
        ],
    )?;
    set_mode(config_path, 0o640)?;
    Ok(())
}

fn ensure_system_directories(config_path: &Path) -> anyhow::Result<()> {
    let config = load_config(config_path)?;
    let paths = configured_runtime_roots(&config);
    for path in &paths {
        fs::create_dir_all(path).with_context(|| format!("failed to create {path}"))?;
    }
    for path in &paths {
        run_setup_command(
            "chown",
            &[
                "-R",
                &format!("{SERVICE_USER}:{SERVICE_GROUP}"),
                path.as_str(),
            ],
        )?;
    }
    Ok(())
}

fn write_sudoers() -> anyhow::Result<()> {
    let contents = format!(
        r#"# Managed by DatabasesEverywhere --setup.
# Allows the non-root daemon to apply host filesystem quotas only.
Cmnd_Alias DBE_QUOTA = /usr/sbin/quotaon, /sbin/quotaon, /usr/sbin/setquota, /sbin/setquota, /usr/bin/chattr, /bin/chattr, /usr/sbin/xfs_quota, /sbin/xfs_quota, /usr/bin/btrfs, /sbin/btrfs, /usr/sbin/zfs, /sbin/zfs
{SERVICE_USER} ALL=(root) NOPASSWD: DBE_QUOTA
"#
    );
    fs::write(SUDOERS_PATH, contents).context("failed to write sudoers file")?;
    set_mode(Path::new(SUDOERS_PATH), 0o440)?;
    if command_exists("visudo")? {
        run_setup_command("visudo", &["-cf", SUDOERS_PATH])?;
    }
    Ok(())
}

fn write_systemd_service(config_path: &Path) -> anyhow::Result<()> {
    let exec_start = if config_path == Path::new(defaults::CONFIG_PATH) {
        INSTALL_PATH.to_string()
    } else {
        format!("{INSTALL_PATH} --config {}", config_path.display())
    };
    let contents = format!(
        r#"[Unit]
Description=DatabasesEverywhere
After=docker.service
Requires=docker.service

[Service]
Type=simple
User={SERVICE_USER}
Group={SERVICE_GROUP}
SupplementaryGroups=docker
Environment=DBE_USE_SUDO=1
ExecStart={exec_start} daemon
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
"#
    );
    fs::write(SERVICE_PATH, contents).context("failed to write systemd service")?;
    Ok(())
}

fn reload_systemd() {
    if command_exists("systemctl").unwrap_or(false) {
        let _ = StdCommand::new("systemctl").arg("daemon-reload").status();
    }
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

fn command_success(program: &str, args: &[&str]) -> anyhow::Result<bool> {
    let status = StdCommand::new(program)
        .args(args)
        .status()
        .with_context(|| format!("failed to run {program}"))?;
    Ok(status.success())
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
    init_configured_logging(&config)?;
    let docker = DockerRuntime::new(&config.daemon, config.disk.mode.uses_docker_storage_opt())
        .context("failed to connect to container engine API")?;
    let removed = docker
        .remove_managed_containers()
        .await
        .context("failed to remove managed containers")?;
    docker
        .remove_network()
        .await
        .context("failed to remove container network")?;
    println!("removed {removed} managed containers and container network");
    Ok(())
}

async fn reset_metadata(config_path: PathBuf) -> anyhow::Result<()> {
    let config = load_config(&config_path)?;
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
    let docker = DockerRuntime::new(&config.daemon, config.disk.mode.uses_docker_storage_opt())
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

    let config = load_config(&config_path)?;
    ensure_runtime_directories(&config)
        .await
        .context("failed to create runtime directories")?;
    init_configured_logging(&config)?;
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

    if !enforcement.enforced {
        anyhow::bail!(
            "disk test requires enforced disk limits, but configured method {} is advisory",
            enforcement.method
        );
    }

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
    let config = Arc::new(load_config(&config_path)?);
    let runtime_directories = ensure_runtime_directories(&config)
        .await
        .context("failed to create runtime directories")?;
    init_configured_logging(&config)?;
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
    log_boot_configuration(&config, &config_path);
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
    tracing::info!(path = %config.paths.metadata_root(), "sqlite metadata storage ready");
    let repository = InstanceRepository::new(pool.clone());
    let job_repository = ImportExportJobRepository::new(pool.clone());
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
    let import_export_jobs = ImportExportJobs::with_repository(job_repository);
    let manager = InstanceManager::new(store.clone(), repository);
    manager
        .load_from_storage()
        .await
        .context("failed to load local instance metadata from sqlite")?;

    let mut docker = DockerRuntime::new(&config.daemon, config.disk.mode.uses_docker_storage_opt())
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
    docker
        .ensure_network()
        .await
        .context("failed to ensure container network")?;
    tracing::info!(
        engine = %docker.engine_name(),
        network = %config.daemon.network,
        internal_network = config.daemon.internal_network,
        subnet = ?config.daemon.ipam.subnet,
        gateway = ?config.daemon.ipam.gateway,
        allow_public_backend_ports = config.daemon.allow_public_backend_ports,
        "container network ready"
    );
    let disk_limiter = DiskLimiter::with_fuse_root(config.disk.clone(), config.paths.fuse_root());
    disk_limiter
        .verify_startup(std::path::Path::new(&config.paths.data))
        .await
        .context("failed to verify disk limiter support")?;
    if disk_limiter.uses_docker_storage_opt() {
        docker
            .verify_disk_limit_support(
                &config.images.redis,
                std::path::Path::new(&config.paths.data),
            )
            .await
            .context("failed to verify container disk limit support")?;
        tracing::info!("container disk limit support verified with storage_opt size probe");
    }
    reapply_instance_disk_limits(&config, &manager, &disk_limiter)
        .await
        .context("failed to reapply instance disk limits")?;
    tracing::info!("instance disk limits reconciled");
    let reconcile_summary = reconcile::reconcile_all(&manager, &docker)
        .await
        .context("failed to reconcile instance metadata")?;
    tracing::info!(
        checked = reconcile_summary.checked,
        running = reconcile_summary.running,
        stopped = reconcile_summary.stopped,
        failed = reconcile_summary.failed,
        "instance metadata reconciled"
    );
    start_known_instances_on_boot(&config, &manager, &docker)
        .await
        .context("failed to persist boot instance reconciliation")?;

    start_gateway_listeners(&config, store.clone())?;
    log_gateway_listener_summary(&config);

    let state = AppState {
        config: config.clone(),
        config_path: config_path.clone(),
        api_token: ApiToken::from_config(&config),
        instances: store,
        manager,
        docker,
        import_export_jobs,
        api_rate_limiter: crate::api::security::ApiRateLimiter::new(
            config.security.api_rate_limit_per_minute,
        ),
        install_progress: crate::api::progress::InstallProgressStore::default(),
        artifact_downloads: crate::api::artifacts::ArtifactDownloadTickets::default(),
    };
    crate::api::backups::start_scheduler(state.clone());
    serve_api(&config, build_router(state)).await
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
        mongodb = ?config.security.pids_limits.mongodb,
        clickhouse = ?config.security.pids_limits.clickhouse,
        qdrant = ?config.security.pids_limits.qdrant,
        "container pid limits configured"
    );
    tracing::info!(
        postgres = %config.images.postgres,
        redis = %config.images.redis,
        mariadb = %config.images.mariadb,
        mongodb = %config.images.mongodb,
        clickhouse = %config.images.clickhouse,
        qdrant = %config.images.qdrant,
        "database images configured"
    );
    tracing::info!(
        mode = %config.disk.mode.method(),
        enforced = config.disk.mode.enforced(),
        project_id_base = config.disk.project_id_base,
        fuse_quota_binary = %config.disk.fuse_quota_binary(),
        "disk limiter configured"
    );
    if config.security.allow_private_remote_imports {
        tracing::warn!(
            allowed_hosts = ?config.security.remote_import_allowed_hosts,
            "private remote imports are enabled"
        );
    } else {
        tracing::info!(
            allowed_hosts = ?config.security.remote_import_allowed_hosts,
            "private remote imports blocked by default"
        );
    }
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
        tracing::info!(protocol, bind, tls, "gateway listener configured");
    } else {
        tracing::info!(protocol, bind, "gateway listener disabled");
    }
}

async fn reapply_instance_disk_limits(
    config: &Config,
    manager: &InstanceManager,
    disk_limiter: &DiskLimiter,
) -> anyhow::Result<()> {
    let instances = manager.store().list().await;
    for metadata in instances {
        let paths = InstancePaths::new(&config.paths, &metadata.instance_id)
            .with_context(|| format!("failed to build paths for {}", metadata.instance_id))?;
        disk_limiter
            .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
            .await
            .with_context(|| format!("failed to apply disk limit for {}", metadata.instance_id))?;
    }
    Ok(())
}

async fn start_known_instances_on_boot(
    config: &Config,
    manager: &InstanceManager,
    docker: &DockerRuntime,
) -> anyhow::Result<()> {
    let instances = manager.store().list().await;
    let mut attempted = 0_usize;
    let mut running = 0_usize;
    let mut stopped = 0_usize;
    let mut failed = 0_usize;

    for metadata in instances {
        if !matches!(
            metadata.status,
            InstanceStatus::Stopped | InstanceStatus::Failed
        ) {
            continue;
        }

        attempted += 1;
        tracing::info!(
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            previous_status = ?metadata.status,
            "starting managed instance on daemon boot"
        );

        let runtime_paths_ready = if let Err(error) =
            ensure_instance_runtime_paths(config, docker, metadata.protocol, &metadata.instance_id)
                .await
        {
            tracing::warn!(
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                %error,
                "failed to prepare managed instance runtime directories during daemon boot; skipping container start"
            );
            false
        } else {
            true
        };

        if !runtime_paths_ready {
            let reconciled = reconcile::reconcile_one(metadata, docker).await;
            match reconciled.status {
                InstanceStatus::Running => running += 1,
                InstanceStatus::Stopped => stopped += 1,
                InstanceStatus::Failed => failed += 1,
                InstanceStatus::Creating | InstanceStatus::Deleting => {}
            }
            manager.upsert(reconciled).await?;
            continue;
        }

        match docker.start(metadata.protocol, &metadata.instance_id).await {
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
                        &error,
                    )
                    .await;
                }
            }
            Err(error) => {
                log_boot_container_failure(
                    docker,
                    metadata.protocol,
                    &metadata.instance_id,
                    "failed to start managed instance during daemon boot",
                    &error,
                )
                .await;
            }
        }

        let reconciled = reconcile::reconcile_one(metadata, docker).await;
        match reconciled.status {
            InstanceStatus::Running => running += 1,
            InstanceStatus::Stopped => stopped += 1,
            InstanceStatus::Failed => failed += 1,
            InstanceStatus::Creating | InstanceStatus::Deleting => {}
        }
        manager.upsert(reconciled).await?;
    }

    tracing::info!(
        attempted,
        running,
        stopped,
        failed,
        "daemon boot managed instance auto-start complete"
    );
    Ok(())
}

async fn log_boot_container_failure(
    docker: &DockerRuntime,
    protocol: Protocol,
    instance_id: &str,
    message: &'static str,
    error: &dyn std::fmt::Display,
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
        statuses.push(RuntimeDirectoryStatus { path, existed });
    }
    Ok(statuses)
}

fn configured_runtime_roots(config: &Config) -> Vec<String> {
    vec![
        config.paths.data.clone(),
        config.paths.metadata_root(),
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
        .verify_startup(Path::new(&config.paths.data))
        .await
        .context("failed to verify disk limiter support")
}

fn start_gateway_listeners(config: &Config, store: InstanceStore) -> anyhow::Result<()> {
    let resolver = RouteResolver::new(store);
    let db_connection_limit_per_minute = config.security.db_connection_limit_per_minute;
    if config.postgres.enabled {
        let bind = config.postgres.bind.clone();
        let resolver = resolver.clone();
        let limiter = GatewayConnectionLimiter::new(db_connection_limit_per_minute);
        let tls = listener_tls(config.postgres.tls, config)?;
        tokio::spawn(async move {
            if let Err(error) =
                listeners::run_postgres_listener(&bind, resolver, tls, limiter).await
            {
                tracing::error!(%error, "postgres listener stopped");
            }
        });
    }

    if config.redis.enabled {
        let bind = config.redis.bind.clone();
        let resolver = resolver.clone();
        let limiter = GatewayConnectionLimiter::new(db_connection_limit_per_minute);
        let tls = listener_tls(config.redis.tls, config)?;
        tokio::spawn(async move {
            if let Err(error) = listeners::run_redis_listener(&bind, resolver, tls, limiter).await {
                tracing::error!(%error, "redis listener stopped");
            }
        });
    }

    if config.mariadb.enabled {
        let bind = config.mariadb.bind.clone();
        let resolver = resolver.clone();
        let limiter = GatewayConnectionLimiter::new(db_connection_limit_per_minute);
        let tls = listener_tls(config.mariadb.tls, config)?;
        tokio::spawn(async move {
            if let Err(error) = listeners::run_mariadb_listener(&bind, resolver, tls, limiter).await
            {
                tracing::error!(%error, "mariadb listener stopped");
            }
        });
    }
    if config.mongodb.enabled {
        let bind = config.mongodb.bind.clone();
        let resolver = resolver.clone();
        let limiter = GatewayConnectionLimiter::new(db_connection_limit_per_minute);
        let tls = listener_tls(config.mongodb.tls, config)?;
        tokio::spawn(async move {
            if let Err(error) = listeners::run_mongodb_listener(&bind, resolver, tls, limiter).await
            {
                tracing::error!(%error, "mongodb listener stopped");
            }
        });
    }
    if config.clickhouse.enabled {
        let bind = config.clickhouse.bind.clone();
        let native_resolver = resolver.clone();
        let limiter = GatewayConnectionLimiter::new(db_connection_limit_per_minute);
        let tls = listener_tls(config.clickhouse.tls, config)?;
        tokio::spawn(async move {
            if let Err(error) =
                listeners::run_clickhouse_listener(&bind, native_resolver, tls, limiter).await
            {
                tracing::error!(%error, "clickhouse listener stopped");
            }
        });

        let bind = config.clickhouse.http_bind.clone();
        let http_resolver = resolver.clone();
        let limiter = GatewayConnectionLimiter::new(db_connection_limit_per_minute);
        let tls = listener_tls(config.clickhouse.tls, config)?;
        tokio::spawn(async move {
            if let Err(error) =
                listeners::run_clickhouse_http_listener(&bind, http_resolver, tls, limiter).await
            {
                tracing::error!(%error, "clickhouse http listener stopped");
            }
        });
    }
    if config.qdrant.enabled {
        let bind = config.qdrant.bind.clone();
        let resolver = resolver.clone();
        let limiter = GatewayConnectionLimiter::new(db_connection_limit_per_minute);
        let tls = listener_tls(config.qdrant.tls, config)?;
        tokio::spawn(async move {
            if let Err(error) = listeners::run_qdrant_listener(&bind, resolver, tls, limiter).await
            {
                tracing::error!(%error, "qdrant listener stopped");
            }
        });
    }
    Ok(())
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

async fn serve_api(config: &Config, router: Router) -> anyhow::Result<()> {
    let bind = config.api.bind_addr();
    if config.api.ssl.enabled {
        return serve_api_tls(config, router).await;
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

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("api server failed")
}

async fn serve_api_tls(config: &Config, router: Router) -> anyhow::Result<()> {
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
        shutdown_signal().await;
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
    });

    axum_server::from_tcp_rustls(listener, tls)
        .handle(handle)
        .serve(router.into_make_service())
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
    let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse API TLS certificate")?;
    let mut keys = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .context("failed to parse API TLS private key")?;
    let key = keys
        .take()
        .ok_or_else(|| anyhow::anyhow!("API TLS private key is missing"))?;

    let mut roots = rustls::RootCertStore::empty();
    let ca_certs = rustls_pemfile::certs(&mut ca_pem.as_slice())
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

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
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
