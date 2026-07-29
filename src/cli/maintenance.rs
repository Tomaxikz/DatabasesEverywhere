use super::*;

pub(super) async fn migrate_metadata(config_path: PathBuf) -> anyhow::Result<()> {
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

pub(super) async fn dev_clean(config_path: PathBuf) -> anyhow::Result<()> {
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

pub(super) async fn reset_metadata(config_path: PathBuf) -> anyhow::Result<()> {
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

pub(super) async fn migrate_paths(
    config_path: PathBuf,
    dry_run: bool,
    force: bool,
) -> anyhow::Result<()> {
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
pub(super) struct PathMigrationAction {
    from: PathBuf,
    to: PathBuf,
}

pub(super) struct PathMigrationPlan<'a> {
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

pub(super) async fn ensure_no_active_managed_containers(config: &Config) -> anyhow::Result<()> {
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

pub(super) fn migrate_path_action(action: &PathMigrationAction, force: bool) -> anyhow::Result<()> {
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

pub(super) fn migrate_directory(from: &Path, to: &Path, force: bool) -> anyhow::Result<()> {
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

pub(super) fn migrate_directory_contents(
    from: &Path,
    to: &Path,
    force: bool,
) -> anyhow::Result<()> {
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

pub(super) fn copy_directory_tree(from: &Path, to: &Path) -> anyhow::Result<()> {
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

pub(super) fn migrate_file(from: &Path, to: &Path, force: bool) -> anyhow::Result<()> {
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

pub(super) fn migrate_symlink(from: &Path, to: &Path, force: bool) -> anyhow::Result<()> {
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

pub(super) fn copy_symlink(from: &Path, to: &Path) -> anyhow::Result<()> {
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
pub(super) fn create_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
pub(super) fn create_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

pub(super) fn remove_path_for_replace(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect replacement target {}", path.display()))?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path).with_context(|| format!("failed to replace {}", path.display()))
    } else {
        fs::remove_file(path).with_context(|| format!("failed to replace {}", path.display()))
    }
}

pub(super) fn remove_empty_dir(path: &Path) -> anyhow::Result<()> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) if error.kind() == ErrorKind::DirectoryNotEmpty => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("failed to remove empty dir {}", path.display()))
        }
    }
}

pub(super) async fn disk_test(
    config_path: PathBuf,
    quota_mib: u64,
    write_mib: u64,
) -> anyhow::Result<()> {
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

pub(super) async fn run_disk_test(
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

pub(super) fn fill_probe_chunk(chunk: &mut [u8], seed: &mut u64) {
    for byte in chunk {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *byte = (*seed >> 24) as u8;
    }
}

pub(super) fn is_quota_like_error(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(28) | Some(122) | Some(69))
}

pub(super) async fn cleanup_disk_test_path(limiter: &DiskLimiter, test_path: &Path) {
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
