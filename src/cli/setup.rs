use super::*;

pub(super) const SERVICE_PATH: &str = "/etc/systemd/system/databases-everywhere.service";
pub(super) const SUDOERS_PATH: &str = "/etc/sudoers.d/databases-everywhere";
pub(super) const INSTALL_PATH: &str = "/usr/local/bin/dbev";
const MEMORY_OVERCOMMIT_SYSCTL_PATH: &str = "/etc/sysctl.d/99-dbev-memory.conf";
const MEMORY_OVERCOMMIT_PROC_PATH: &str = "/proc/sys/vm/overcommit_memory";
const SERVICE_UNIT: &str = "databases-everywhere.service";
const LEGACY_LOGS_PATH: &str = "/var/log/dbev";

pub(super) async fn setup_system(config_path: PathBuf) -> anyhow::Result<()> {
    ensure_root()?;
    validate_setup_config_path(&config_path)?;
    require_existing_config(&config_path)?;
    let mut config = load_config(&config_path)?;
    ensure_required_setup_commands(&config.daemon)?;
    install_current_binary(Path::new(INSTALL_PATH))?;
    secure_config_permissions(&config_path)?;
    migrate_unsafe_legacy_logs_path(&config_path, &mut config)?;
    ensure_system_directories(&config).await?;
    ensure_memory_overcommit_host_config()?;
    detect_and_log_disk_mode(&mut config)?;
    ensure_fuse_quota_host_config(&config)?;
    remove_obsolete_managed_sudoers()?;
    prepare_configured_podman_socket(&config.daemon)?;
    validate_runtime_support(&config).await?;
    validate_configured_container_engine(&config).await?;
    write_systemd_service(&config_path, &config.daemon)?;
    reload_systemd()?;
    enable_and_restart_systemd_service()?;
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
    println!("service: enabled and started ({SERVICE_UNIT})");
    Ok(())
}

pub(super) fn validate_setup_config_path(config_path: &Path) -> anyhow::Result<()> {
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

pub(super) fn ensure_required_setup_commands(
    config: &crate::config::DaemonConfig,
) -> anyhow::Result<()> {
    let mut commands = vec!["chown", "sysctl", "systemctl"];
    if configured_rootless_podman_uid(config).is_some() {
        commands.extend(["getent", "loginctl", "runuser"]);
    }
    for command in commands {
        if !command_exists(command)? {
            anyhow::bail!("required setup command {command} was not found");
        }
    }
    Ok(())
}

pub(super) fn ensure_memory_overcommit_host_config() -> anyhow::Result<()> {
    let path = Path::new(MEMORY_OVERCOMMIT_SYSCTL_PATH);
    atomic_replace_setup_file(path, 0o644, "DBEV memory sysctl configuration", |file| {
        file.write_all(memory_overcommit_sysctl_contents().as_bytes())
    })?;
    run_setup_command("sysctl", &["-w", "vm.overcommit_memory=1"])?;
    let effective = fs::read_to_string(MEMORY_OVERCOMMIT_PROC_PATH)
        .context("failed to verify vm.overcommit_memory")?;
    if effective.trim() != "1" {
        anyhow::bail!(
            "vm.overcommit_memory remained {} after setup",
            effective.trim()
        );
    }
    println!("memory host config ok: vm.overcommit_memory=1");
    Ok(())
}

pub(super) fn warn_if_memory_overcommit_disabled() {
    match fs::read_to_string(MEMORY_OVERCOMMIT_PROC_PATH) {
        Ok(value) if value.trim() == "1" => {}
        Ok(value) => tracing::warn!(
            event = "memory_overcommit_disabled",
            effective = value.trim(),
            "vm.overcommit_memory should be 1; Redis/Valkey background persistence may fail. Run dbev --setup to apply the managed host setting"
        ),
        Err(error) => tracing::warn!(
            %error,
            event = "memory_overcommit_status_unavailable",
            "could not verify vm.overcommit_memory"
        ),
    }
}

pub(super) fn memory_overcommit_sysctl_contents() -> &'static str {
    "# Managed by DatabasesEverywhere --setup.\nvm.overcommit_memory = 1\n"
}

fn configured_rootless_podman_uid(config: &crate::config::DaemonConfig) -> Option<u32> {
    if config.engine != DaemonEngine::Podman {
        return None;
    }
    config
        .configured_socket_path()
        .and_then(crate::runtime::docker::rootless_podman_uid_from_socket_path)
}

fn prepare_configured_podman_socket(config: &crate::config::DaemonConfig) -> anyhow::Result<()> {
    if config.engine != DaemonEngine::Podman {
        return Ok(());
    }
    if config.configured_socket_path().is_none()
        || config.configured_socket_path() == Some("/run/podman/podman.sock")
    {
        run_setup_command("systemctl", &["enable", "--now", "podman.socket"])?;
        println!("enabled rootful Podman API socket");
        return Ok(());
    }
    let Some(uid) = configured_rootless_podman_uid(config) else {
        println!(
            "podman socket mode: externally managed custom socket; dbev will validate it but not control its lifecycle"
        );
        return Ok(());
    };
    let username = username_for_uid(uid)?;
    run_setup_command("loginctl", &["enable-linger", &username])?;
    let user_unit = format!("user@{uid}.service");
    run_setup_command("systemctl", &["start", &user_unit])?;
    let runtime = format!("XDG_RUNTIME_DIR=/run/user/{uid}");
    let bus = format!("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus");
    run_setup_command(
        "runuser",
        &[
            "-u",
            &username,
            "--",
            "env",
            &runtime,
            &bus,
            "systemctl",
            "--user",
            "enable",
            "--now",
            "podman.socket",
        ],
    )?;
    println!("enabled rootless Podman socket for {username} (uid {uid}) with login lingering");
    Ok(())
}

fn username_for_uid(uid: u32) -> anyhow::Result<String> {
    let uid_string = uid.to_string();
    let output = StdCommand::new("getent")
        .args(["passwd", &uid_string])
        .output()
        .context("failed to query the rootless Podman account")?;
    if !output.status.success() {
        anyhow::bail!("no local account exists for rootless Podman uid {uid}");
    }
    let line = String::from_utf8(output.stdout)
        .context("rootless Podman account record was not valid UTF-8")?;
    let fields = line.trim().split(':').collect::<Vec<_>>();
    let username = fields.first().copied().unwrap_or_default();
    let record_uid = fields.get(2).and_then(|value| value.parse::<u32>().ok());
    if record_uid != Some(uid)
        || username.is_empty()
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        anyhow::bail!("invalid local account record for rootless Podman uid {uid}");
    }
    Ok(username.to_string())
}

async fn validate_configured_container_engine(config: &Config) -> anyhow::Result<()> {
    let mut runtime = DockerRuntime::new(&config.daemon, false)
        .context("failed to connect to the configured container engine")?;
    runtime
        .refresh_engine_info()
        .await
        .context("failed to negotiate and validate the configured container engine")?;
    runtime
        .ping()
        .await
        .context("configured container engine did not answer ping")?;
    prepare_rootless_podman_runtime_paths(config, &runtime)?;
    println!(
        "container engine ok: {} {} via {}{}",
        runtime.engine_name(),
        runtime.engine_version().unwrap_or("unknown"),
        runtime.socket_path(),
        if runtime.uses_rootless_podman() {
            " (rootless)"
        } else {
            ""
        }
    );
    Ok(())
}

pub(super) fn ensure_fuse_quota_host_config(config: &Config) -> anyhow::Result<()> {
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

pub(super) enum FuseConfUpdate {
    AlreadyEnabled,
    Updated(String),
}

pub(super) fn ensure_fuse_conf_allow_other(contents: &str) -> FuseConfUpdate {
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

pub(super) fn is_active_user_allow_other_line(line: &str) -> bool {
    let line = line.trim();
    !line.starts_with('#') && line == "user_allow_other"
}

pub(super) fn is_commented_user_allow_other_line(line: &str) -> bool {
    let line = line.trim_start();
    let Some(line) = line.strip_prefix('#') else {
        return false;
    };
    line.trim() == "user_allow_other"
}

pub(super) fn ensure_fuse_device_supported() -> anyhow::Result<()> {
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

pub(super) fn warn_if_fuse_not_listed_in_proc_filesystems() {
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

pub(super) fn ensure_root() -> anyhow::Result<()> {
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

pub(super) fn install_current_binary(destination: &Path) -> anyhow::Result<()> {
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

pub(super) fn require_existing_config(config_path: &Path) -> anyhow::Result<()> {
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

pub(super) fn secure_config_permissions(config_path: &Path) -> anyhow::Result<()> {
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

pub(super) async fn ensure_system_directories(config: &Config) -> anyhow::Result<()> {
    ensure_runtime_directories(config)
        .await
        .context("failed to securely prepare configured runtime directories")?;
    Ok(())
}

fn migrate_unsafe_legacy_logs_path(config_path: &Path, config: &mut Config) -> anyhow::Result<()> {
    let Some((migrated, replacement, legacy_error)) =
        build_legacy_logs_migration(config, Path::new(LEGACY_LOGS_PATH))?
    else {
        return Ok(());
    };

    persist_setup_config(config_path, &migrated)?;
    *config = load_config(config_path).context("failed to reload migrated setup config")?;
    println!(
        "setup changed unsafe legacy log path {LEGACY_LOGS_PATH} to {replacement} ({legacy_error}); existing files in the legacy directory were left untouched"
    );
    Ok(())
}

pub(super) fn build_legacy_logs_migration(
    config: &Config,
    legacy_logs_path: &Path,
) -> anyhow::Result<Option<(Config, String, String)>> {
    if Path::new(&config.paths.logs) != legacy_logs_path {
        return Ok(None);
    }
    let legacy_error = match validate_runtime_path_ancestors(legacy_logs_path, false) {
        Ok(()) => return Ok(None),
        Err(error) => format!("{error:#}"),
    };

    let replacement = format!("{}/logs", config.paths.data.trim_end_matches('/'));
    let mut migrated = config.clone();
    migrated.paths.logs = replacement.clone();
    crate::config::validate::validate_config(&migrated)
        .context("the safe setup log-path replacement is not valid")?;
    validate_runtime_path_ancestors(Path::new(&replacement), false).with_context(|| {
        format!(
            "legacy log path {} is unsafe ({legacy_error}); replacement {replacement} is also unsafe",
            legacy_logs_path.display()
        )
    })?;
    Ok(Some((migrated, replacement, legacy_error)))
}

fn persist_setup_config(config_path: &Path, config: &Config) -> anyhow::Result<()> {
    let yaml = serde_yaml::to_string(config).context("failed to encode migrated setup config")?;
    atomic_replace_setup_file(config_path, 0o600, "daemon config", |file| {
        file.write_all(yaml.as_bytes())
    })
    .with_context(|| format!("failed to update config {}", config_path.display()))
}

pub(super) fn remove_obsolete_managed_sudoers() -> anyhow::Result<()> {
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

pub(super) fn write_systemd_service(
    config_path: &Path,
    daemon: &crate::config::DaemonConfig,
) -> anyhow::Result<()> {
    let contents = systemd_service_contents(config_path, daemon);
    atomic_replace_setup_file(Path::new(SERVICE_PATH), 0o644, "systemd service", |file| {
        file.write_all(contents.as_bytes())
    })
    .context("failed to write systemd service")?;
    Ok(())
}

pub(super) fn systemd_service_contents(
    config_path: &Path,
    daemon: &crate::config::DaemonConfig,
) -> String {
    let exec_start = if config_path == Path::new(defaults::CONFIG_PATH) {
        INSTALL_PATH.to_string()
    } else {
        format!("{INSTALL_PATH} --config {}", config_path.display())
    };
    let engine_dependencies = match daemon.engine {
        DaemonEngine::Docker => {
            "After=docker.service\nRequires=docker.service\nPartOf=docker.service".to_string()
        }
        DaemonEngine::Podman => match configured_rootless_podman_uid(daemon) {
            Some(uid) => format!(
                "After=user@{uid}.service\nRequires=user@{uid}.service\nRequiresMountsFor=/run/user/{uid}"
            ),
            None if daemon.configured_socket_path().is_none()
                || daemon.configured_socket_path() == Some("/run/podman/podman.sock") =>
            {
                "After=podman.socket\nRequires=podman.socket\nPartOf=podman.socket".to_string()
            }
            None => "After=network.target".to_string(),
        },
    };
    format!(
        r#"[Unit]
Description=DatabasesEverywhere
{engine_dependencies}

[Service]
User=root
ExecStart={exec_start} daemon
KillMode=process
Restart=on-failure
RestartSec=5s
TimeoutStopSec=4min30s
LimitNOFILE=1048576:1048576

[Install]
WantedBy=multi-user.target
"#
    )
}

pub(super) fn reload_systemd() -> anyhow::Result<()> {
    if command_exists("systemctl")? {
        run_setup_command("systemctl", &["daemon-reload"])?;
    }
    Ok(())
}

pub(super) fn enable_and_restart_systemd_service() -> anyhow::Result<()> {
    run_setup_command("systemctl", &["enable", SERVICE_UNIT])?;
    // `enable --now` leaves an already-running service on its old resource
    // limits. An explicit restart makes setup upgrades apply LimitNOFILE and
    // lets daemon startup repair surviving per-instance FuseQuota helpers.
    run_setup_command("systemctl", &["restart", SERVICE_UNIT])?;
    Ok(())
}

pub(super) fn atomic_replace_setup_file(
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

pub(super) fn validate_setup_replace_target(path: &Path, label: &str) -> anyhow::Result<()> {
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

pub(super) fn validate_setup_parent_directory(parent: &Path, label: &str) -> anyhow::Result<()> {
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

pub(super) fn command_exists(program: &str) -> anyhow::Result<bool> {
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

pub(super) fn run_setup_command(program: &str, args: &[&str]) -> anyhow::Result<()> {
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

pub(super) fn set_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("failed to chmod {:o} {}", mode, path.display()))?;
    }
    let _ = (path, mode);
    Ok(())
}
