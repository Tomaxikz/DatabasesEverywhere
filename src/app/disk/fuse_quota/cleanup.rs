use std::{collections::HashSet, os::unix::fs::MetadataExt};

use super::*;

#[derive(Default, Debug)]
pub(crate) struct CleanupSummary {
    pub checked: usize,
    pub retained: usize,
    pub removed: usize,
    pub deferred: usize,
}

/// Boot-only: the daemon lock is held and no API or background mutations exist.
/// Never remove database files, force-unmount, or signal a PID by process name.
pub(crate) async fn cleanup_unused_helpers(
    fuse_root: &Path,
    protected: &[PathBuf],
    docker: &crate::runtime::docker::DockerRuntime,
) -> anyhow::Result<CleanupSummary> {
    match fs::symlink_metadata(fuse_root) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(CleanupSummary::default()),
        result => {
            result?;
        }
    }
    check_private_directory(fuse_root)?;
    let sockets = fuse_root.join("mounts");
    let mounts = fuse_root.join("instances");
    check_private_directory(&sockets)?;
    check_private_directory(&mounts)?;
    let mut candidates = HashSet::new();
    let mut scanned = 0;
    for (directory, socket) in [(&sockets, true), (&mounts, false)] {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            scanned += 1;
            anyhow::ensure!(
                scanned <= 8192,
                "FUSE runtime directory scan limit exceeded"
            );
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let name = if socket {
                let Some(name) = name.strip_suffix(".sock") else {
                    continue;
                };
                name
            } else {
                name
            };
            if valid_name(name) {
                candidates.insert(name.to_owned());
            }
            anyhow::ensure!(
                candidates.len() <= 4096,
                "FUSE cleanup inventory limit exceeded"
            );
        }
    }
    let mut summary = CleanupSummary::default();
    for name in candidates {
        summary.checked += 1;
        let mount = mounts.join(&name);
        if referenced(&mount, protected) {
            summary.retained += 1;
            continue;
        }
        // Re-inspect all containers immediately before each candidate, including
        // those outside DBEV. Failure leaves everything untouched.
        let sources = timeout(
            Duration::from_secs(15),
            docker.all_container_mount_sources(),
        )
        .await??;
        if referenced(&mount, &sources) || referenced_device(&mount, &sources)? {
            summary.retained += 1;
            continue;
        }
        let socket = sockets.join(format!("{name}.sock"));
        match cleanup_one(fuse_root, &mount, &socket).await {
            Ok(()) => {
                summary.removed += 1;
                tracing::info!(event = "audit orphan_fuse_helper_removed", mount = %mount.display(),
                    "removed an unused FUSE mount/helper; backing data was retained");
            }
            Err(error) => {
                summary.deferred += 1;
                tracing::warn!(event = "audit orphan_fuse_cleanup_deferred", mount = %mount.display(), %error,
                    "could not verify safe helper cleanup; retained its runtime paths");
            }
        }
    }
    Ok(summary)
}

fn check_private_directory(path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(path.is_absolute(), "FUSE cleanup root must be absolute");
    anyhow::ensure!(
        !path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir)),
        "FUSE cleanup path must not contain parent traversal"
    );
    // Reject symlinked/writable ancestors, not just the final runtime leaf.
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        anyhow::ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && (metadata.uid() == 0 || metadata.uid() == rustix::process::geteuid().as_raw())
                && metadata.mode() & 0o022 == 0,
            "FUSE cleanup path has an untrusted directory: {}",
            ancestor.display()
        );
    }
    Ok(())
}

fn valid_name(name: &str) -> bool {
    let (prefix, hash) = name.rsplit_once('-').unwrap_or(("", name));
    prefix.len() <= 24
        && prefix
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        && hash.len() == 24
        && hash
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn referenced(mount: &Path, sources: &[PathBuf]) -> bool {
    sources
        .iter()
        .any(|source| mount.starts_with(source) || source.starts_with(mount))
}

fn referenced_device(mount: &Path, sources: &[PathBuf]) -> anyhow::Result<bool> {
    if !mounts::is_mountpoint(mount)? {
        return Ok(false);
    }
    let device = fs::metadata(mount)?.dev();
    for source in sources {
        // Bind aliases of the same FUSE filesystem need not share path prefixes.
        // An unreadable/deleted source makes the inventory uncertain: defer.
        if fs::metadata(source)?.dev() == device {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn cleanup_one(root: &Path, mount: &Path, socket: &Path) -> anyhow::Result<()> {
    let mounted = mounts::is_mountpoint(mount)?;
    if mounted {
        let info = mounts::find_mount(mount)?;
        anyhow::ensure!(
            info.mountpoint == mount && info.fstype == "fuse.fusequota",
            "refusing cleanup of a non-FuseQuota mount"
        );
    } else if let Ok(metadata) = fs::symlink_metadata(mount) {
        anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "invalid mount directory"
        );
        anyhow::ensure!(
            fs::read_dir(mount)?.next().is_none(),
            "unmounted directory is not empty"
        );
    }
    let helper = match send_command_detailed(socket, "get quota_used", None).await {
        Ok(response) => {
            verify_helper(response.peer_pid, root, mount, socket).await?;
            Some(response.peer_pid)
        }
        Err(error) if mounted => return Err(error.into()),
        Err(DiskLimitError::PathIo { source, .. })
            if matches!(
                source.kind(),
                ErrorKind::NotFound | ErrorKind::ConnectionRefused
            ) =>
        {
            None
        }
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        mounted || helper.is_none(),
        "live helper has no host mount; another mount namespace may still depend on it"
    );
    // Unmount normally BEFORE asking the helper to exit. EBUSY must preserve
    // the helper and mount rather than breaking a filesystem still in use.
    unmount(mount).await?;
    if let Some(pid) = helper {
        // A normal unmount may already have terminated the helper.
        match send_command_detailed(socket, "get quota_used", Some(pid)).await {
            Ok(_) => {
                verify_helper(pid, root, mount, socket).await?;
                send_command_detailed(socket, "do end", Some(pid)).await?;
            }
            Err(DiskLimitError::PathIo { source, .. })
                if matches!(
                    source.kind(),
                    ErrorKind::NotFound | ErrorKind::ConnectionRefused
                ) => {}
            Err(error) => return Err(error.into()),
        }
        let started = Instant::now();
        while Path::new(&format!("/proc/{pid}")).exists() {
            anyhow::ensure!(
                started.elapsed() < Duration::from_secs(3),
                "helper shutdown is not yet confirmed; runtime paths retained"
            );
            sleep(Duration::from_millis(100)).await;
        }
    }
    remove_control_socket(socket).await?;
    match fs::remove_dir(mount) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

async fn verify_helper(pid: i32, root: &Path, mount: &Path, socket: &Path) -> anyhow::Result<()> {
    let executable = fs::read_link(format!("/proc/{pid}/exe"))?;
    let name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    // Unknown/external helpers are retained rather than guessed at.
    anyhow::ensure!(
        executable.starts_with(root.join("bin")) && name.starts_with("fusequota-"),
        "helper executable is not a managed FuseQuota binary"
    );
    let file = tokio::fs::File::open(format!("/proc/{pid}/cmdline")).await?;
    let mut bytes = Vec::new();
    file.take((MAX_HELPER_CMDLINE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    anyhow::ensure!(
        bytes.len() <= MAX_HELPER_CMDLINE_BYTES && bytes.ends_with(&[0]),
        "invalid helper command line"
    );
    let args: Vec<_> = bytes
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .collect();
    anyhow::ensure!(
        helper_matches(&args, root, mount, socket),
        "helper paths do not match the managed mount"
    );
    Ok(())
}

fn helper_matches(args: &[&[u8]], root: &Path, mount: &Path, socket: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    if args.len() < 3 || args.last().copied() != Some(mount.as_os_str().as_bytes()) {
        return false;
    }
    let data = Path::new(std::ffi::OsStr::from_bytes(args[args.len() - 2]));
    if !data.is_absolute() {
        return false;
    }
    let Ok(expected) = fuse_paths_with_root(data, Some(root)) else {
        return false;
    };
    let sockets: Vec<_> = args
        .windows(2)
        .filter(|pair| pair[0] == b"--communication-socket-path")
        .collect();
    expected.mount_path == mount
        && expected.socket_path == socket
        && sockets.len() == 1
        && sockets[0][1] == socket.as_os_str().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_exact_parent_and_child_mount_references() {
        let mount = Path::new("/var/lib/dbev/fuse/instances/tenant-hash");
        for source in [
            mount.to_path_buf(),
            mount.join("db"),
            mount.parent().unwrap().to_path_buf(),
        ] {
            assert!(referenced(mount, &[source]));
        }
        assert!(!referenced(
            mount,
            &[PathBuf::from("/var/lib/dbev/fuse/instances/other")]
        ));
    }

    #[test]
    fn accepts_only_generated_mount_names() {
        assert!(valid_name("tenant-0123456789abcdef01234567"));
        for name in [
            "../tenant",
            "tenant",
            "-",
            "tenant-0123456789ABCDEF01234567",
            "x/0123456789abcdef01234567",
        ] {
            assert!(!valid_name(name));
        }
    }

    #[test]
    fn helper_identity_requires_all_paths_and_generated_hash_to_match() {
        use std::os::unix::ffi::OsStrExt;
        let root = Path::new("/var/lib/dbev/fuse");
        let data = Path::new("/var/lib/dbev/volumes/tenant");
        let paths = fuse_paths_with_root(data, Some(root)).unwrap();
        let args: Vec<&[u8]> = vec![
            b"fusequota",
            b"--communication-socket-path",
            paths.socket_path.as_os_str().as_bytes(),
            data.as_os_str().as_bytes(),
            paths.mount_path.as_os_str().as_bytes(),
        ];
        assert!(helper_matches(
            &args,
            root,
            &paths.mount_path,
            &paths.socket_path
        ));
        assert!(!helper_matches(
            &args,
            root,
            &root.join("other"),
            &paths.socket_path
        ));
        assert!(!helper_matches(
            &args,
            root,
            &paths.mount_path,
            &root.join("other.sock")
        ));
    }

    #[tokio::test]
    async fn cleanup_preserves_nonempty_unmounted_directories() {
        let temp = tempfile::tempdir().unwrap();
        let mount = temp.path().join("mount");
        fs::create_dir(&mount).unwrap();
        fs::write(mount.join("data"), b"retained").unwrap();
        assert!(
            cleanup_one(temp.path(), &mount, &temp.path().join("socket"))
                .await
                .is_err()
        );
        assert_eq!(fs::read(mount.join("data")).unwrap(), b"retained");
    }

    #[tokio::test]
    async fn cleanup_removes_only_empty_abandoned_runtime_paths() {
        use std::os::unix::{fs::PermissionsExt, net::UnixListener};
        let temp = tempfile::tempdir().unwrap();
        let mount = temp.path().join("mount");
        let socket = temp.path().join("control.sock");
        fs::create_dir(&mount).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        drop(listener);
        cleanup_one(temp.path(), &mount, &socket).await.unwrap();
        assert!(!mount.exists());
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn cleanup_rejects_symlinked_mount_and_non_socket_control_path() {
        let temp = tempfile::tempdir().unwrap();
        let mount = temp.path().join("mount");
        let socket = temp.path().join("control.sock");
        std::os::unix::fs::symlink(temp.path(), &mount).unwrap();
        assert!(cleanup_one(temp.path(), &mount, &socket).await.is_err());
        fs::remove_file(&mount).unwrap();
        fs::create_dir(&mount).unwrap();
        fs::write(&socket, b"keep").unwrap();
        assert!(cleanup_one(temp.path(), &mount, &socket).await.is_err());
        assert_eq!(fs::read(&socket).unwrap(), b"keep");
    }
}
