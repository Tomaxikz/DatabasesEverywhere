use super::*;

pub(super) async fn ensure_instance_runtime_paths(
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

pub(super) fn parse_numeric_container_user(user: &str) -> Option<(u32, u32)> {
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

pub(super) struct RuntimeDirectoryStatus {
    pub(super) path: String,
    pub(super) existed: bool,
}

pub(super) async fn ensure_runtime_directories(
    config: &Config,
) -> anyhow::Result<Vec<RuntimeDirectoryStatus>> {
    let mut statuses = Vec::new();
    for path in configured_runtime_roots(config) {
        validate_runtime_path_ancestors(Path::new(&path), false)?;
        let existed = match fs::symlink_metadata(&path) {
            Ok(_) => true,
            Err(error) if error.kind() == ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect configured directory {path}"));
            }
        };
        create_runtime_directory_tree(Path::new(&path))
            .with_context(|| format!("failed to securely create configured directory {path}"))?;
        harden_runtime_directory(Path::new(&path))?;
        validate_runtime_path_ancestors(Path::new(&path), true)?;
        statuses.push(RuntimeDirectoryStatus { path, existed });
    }
    Ok(statuses)
}

pub(super) fn create_runtime_directory_tree(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::path::Component;

        use rustix::fs::{Mode, OFlags, mkdirat, open, openat};

        if !path.is_absolute() || path == Path::new("/") {
            anyhow::bail!(
                "runtime directory {} must be an absolute path below the filesystem root",
                path.display()
            );
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut directory = open("/", flags, Mode::empty())
            .map_err(std::io::Error::from)
            .context("failed to securely open the filesystem root")?;
        let daemon_uid = rustix::process::geteuid().as_raw();
        let mut traversed = PathBuf::from("/");

        for component in path.components() {
            let name = match component {
                Component::RootDir => continue,
                Component::Normal(name) => name,
                Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                    anyhow::bail!(
                        "runtime directory {} contains an unsupported path component",
                        path.display()
                    );
                }
            };
            traversed.push(name);
            let child = match openat(&directory, name, flags, Mode::empty()) {
                Ok(child) => child,
                Err(rustix::io::Errno::NOENT) => {
                    match mkdirat(&directory, name, Mode::RWXU) {
                        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                        Err(error) => {
                            return Err(std::io::Error::from(error)).with_context(|| {
                                format!(
                                    "failed to create runtime directory component {}",
                                    traversed.display()
                                )
                            });
                        }
                    }
                    openat(&directory, name, flags, Mode::empty())
                        .map_err(std::io::Error::from)
                        .with_context(|| {
                            format!(
                                "failed to securely open newly created runtime directory component {}",
                                traversed.display()
                            )
                        })?
                }
                Err(error) => {
                    return Err(std::io::Error::from(error)).with_context(|| {
                        format!(
                            "runtime directory component {} must be a real directory, not a symlink",
                            traversed.display()
                        )
                    });
                }
            };
            validate_runtime_directory_fd(&child, &traversed, daemon_uid)?;
            directory = child;
        }
    }

    #[cfg(not(unix))]
    {
        fs::create_dir_all(path).with_context(|| {
            format!(
                "failed to create configured runtime directory {}",
                path.display()
            )
        })?;
    }
    Ok(())
}

#[cfg(unix)]
pub(super) fn validate_runtime_directory_fd(
    directory: &impl std::os::fd::AsFd,
    path: &Path,
    daemon_uid: u32,
) -> anyhow::Result<()> {
    let stat = rustix::fs::fstat(directory)
        .map_err(std::io::Error::from)
        .with_context(|| {
            format!(
                "failed to inspect runtime path component {}",
                path.display()
            )
        })?;
    let owner = stat.st_uid;
    if owner != 0 && owner != daemon_uid {
        anyhow::bail!(
            "runtime path component {} is owned by untrusted uid {}; expected root or daemon uid {}",
            path.display(),
            owner,
            daemon_uid
        );
    }
    let mode = stat.st_mode;
    let writable_by_others = mode & 0o022 != 0;
    let protected_sticky_directory = owner == 0 && mode & 0o1000 != 0;
    if writable_by_others && !protected_sticky_directory {
        anyhow::bail!(
            "runtime path component {} is writable by group or others (mode {:04o})",
            path.display(),
            mode & 0o7777
        );
    }
    Ok(())
}

pub(super) fn validate_runtime_path_ancestors(
    path: &Path,
    include_target: bool,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let daemon_uid = rustix::process::geteuid().as_raw();
        let start = if include_target {
            path
        } else {
            path.parent().unwrap_or(path)
        };
        let mut ancestors = start.ancestors().collect::<Vec<_>>();
        ancestors.reverse();
        for ancestor in ancestors {
            let metadata = match fs::symlink_metadata(ancestor) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to inspect runtime path ancestor {} for {}",
                            ancestor.display(),
                            path.display()
                        )
                    });
                }
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                anyhow::bail!(
                    "runtime path ancestor {} for {} must be a real directory",
                    ancestor.display(),
                    path.display()
                );
            }

            let owner = metadata.uid();
            if owner != 0 && owner != daemon_uid {
                anyhow::bail!(
                    "runtime path ancestor {} for {} is owned by untrusted uid {}; expected root or daemon uid {}",
                    ancestor.display(),
                    path.display(),
                    owner,
                    daemon_uid
                );
            }

            let mode = metadata.permissions().mode();
            let writable_by_others = mode & 0o022 != 0;
            let protected_sticky_directory = owner == 0 && mode & 0o1000 != 0;
            if writable_by_others && !protected_sticky_directory {
                anyhow::bail!(
                    "runtime path ancestor {} for {} is writable by group or others (mode {:04o})",
                    ancestor.display(),
                    path.display(),
                    mode & 0o7777
                );
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = (path, include_target);
    }
    Ok(())
}

pub(super) fn harden_runtime_directory(path: &Path) -> anyhow::Result<()> {
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

pub(super) fn require_runtime_directory_owner(
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

pub(super) const DAEMON_LOCK_FILE: &str = "daemon.lock";

pub(super) struct DaemonLock {
    _file: std::fs::File,
}

impl Drop for DaemonLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        let _ = rustix::fs::flock(&self._file, rustix::fs::FlockOperation::Unlock);
    }
}

pub(super) async fn acquire_configured_daemon_lock(config: &Config) -> anyhow::Result<DaemonLock> {
    let locks_root = Path::new(&config.paths.locks);
    tokio::fs::create_dir_all(locks_root)
        .await
        .with_context(|| format!("failed to create lock directory {}", locks_root.display()))?;
    harden_runtime_directory(locks_root)?;
    acquire_daemon_lock(locks_root).context("failed to acquire the process-lifetime daemon lock")
}

pub(super) fn acquire_daemon_lock(locks_root: &Path) -> anyhow::Result<DaemonLock> {
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

pub(super) fn configured_runtime_roots(config: &Config) -> Vec<String> {
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

pub(super) async fn validate_runtime_support(config: &Config) -> anyhow::Result<()> {
    DiskLimiter::with_fuse_root(config.disk.clone(), config.paths.fuse_root())
        .verify_startup(Path::new(&config.paths.volumes_root()))
        .await
        .context("failed to verify disk limiter support")
}

pub(super) fn detect_and_log_disk_mode(config: &mut Config) -> anyhow::Result<()> {
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
