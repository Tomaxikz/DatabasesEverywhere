use super::*;

pub(super) fn prepare_fuse_dirs(fuse_root: &Path) -> Result<(), DiskLimitError> {
    for path in [
        fuse_root.to_path_buf(),
        fuse_root.join("instances"),
        fuse_root.join("mounts"),
    ] {
        fs::create_dir_all(&path).map_err(path_io_error(&path))?;
        secure_fuse_directory(&path)?;
    }
    Ok(())
}

fn secure_fuse_directory(path: &Path) -> Result<(), DiskLimitError> {
    use rustix::fs::{FileType, Mode, OFlags};

    let directory = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .map_err(path_io_error(path))?;
    let stat = rustix::fs::fstat(&directory)
        .map_err(std::io::Error::from)
        .map_err(path_io_error(path))?;
    let expected_uid = rustix::process::geteuid().as_raw();
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory || stat.st_uid != expected_uid {
        return Err(DiskLimitError::FuseSocket(format!(
            "fusequota runtime directory {} must be a real directory owned by uid {expected_uid}",
            path.display()
        )));
    }
    // Rootless Podman setup grants its trusted runtime group execute-only
    // traversal by setting the directory to exactly 0710. Preserve only that
    // deliberate state; an ordinary mkdir affected by a permissive umask may
    // start as 0755 or 0775 and must still be hardened to 0700.
    let permissions = stat.st_mode & 0o777;
    let mode = if permissions == (Mode::RWXU | Mode::XGRP).bits() {
        Mode::RWXU | Mode::XGRP
    } else {
        Mode::RWXU
    };
    rustix::fs::fchmod(&directory, mode)
        .map_err(std::io::Error::from)
        .map_err(path_io_error(path))
}

pub(super) async fn path_owner(path: &Path) -> Result<(u32, u32), DiskLimitError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(path_io_error(path))?;
    Ok((metadata.uid(), metadata.gid()))
}

pub(super) async fn mount_owner_matches(mount_path: &Path, expected: (u32, u32)) -> bool {
    path_owner(mount_path)
        .await
        .map(|actual| actual == expected)
        .unwrap_or(false)
}

pub(super) fn fuse_paths_with_root(
    data_path: &Path,
    fuse_root: Option<&Path>,
) -> Result<FuseQuotaPaths, DiskLimitError> {
    let instance_id = data_path.file_name().ok_or_else(|| {
        DiskLimitError::FuseSocket("instance data path has no basename".to_string())
    })?;
    let fuse_root = match fuse_root {
        Some(root) => root.to_path_buf(),
        None => {
            let instances_dir = data_path.parent().ok_or_else(|| {
                DiskLimitError::FuseSocket("instance data path has no parent directory".to_string())
            })?;
            let data_root = instances_dir.parent().ok_or_else(|| {
                DiskLimitError::FuseSocket("instance data path has no data root".to_string())
            })?;
            data_root.join("fuse")
        }
    };

    let mount_name = fuse_mount_name(data_path, instance_id);

    Ok(FuseQuotaPaths {
        root_path: fuse_root.clone(),
        mount_path: fuse_root.join("instances").join(&mount_name),
        socket_path: fuse_root
            .join("mounts")
            .join(mount_name)
            .with_extension("sock"),
    })
}

fn fuse_mount_name(data_path: &Path, instance_id: &std::ffi::OsStr) -> String {
    let mut hash = Sha256::new();
    hash.update(data_path.as_os_str().as_encoded_bytes());
    let digest = hash.finalize();
    let encoded = hex_prefix(&digest, 24);
    let readable = instance_id
        .to_string_lossy()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
        .take(24)
        .collect::<String>();
    if readable.is_empty() {
        encoded
    } else {
        format!("{readable}-{encoded}")
    }
}

fn hex_prefix(bytes: &[u8], chars: usize) -> String {
    let mut output = crate::utils::hex::encode_lower(bytes);
    output.truncate(chars.min(output.len()));
    output
}
