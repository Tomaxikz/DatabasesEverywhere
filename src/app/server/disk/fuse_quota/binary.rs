use super::*;

pub(super) async fn resolve_binary(
    binary: &str,
    binary_sha256: &str,
    runtime_root: Option<&Path>,
) -> Result<PathBuf, DiskLimitError> {
    if is_embedded_binary(binary) {
        let runtime_root = runtime_root.ok_or_else(|| DiskLimitError::FuseBinaryIo {
            binary: EMBEDDED_BINARY.to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "embedded fusequota requires a configured private runtime root",
            ),
        })?;
        return crate::bins::get_fusequota_bin_path(runtime_root)
            .await
            .map_err(|source| DiskLimitError::FuseBinaryIo {
                binary: EMBEDDED_BINARY.to_string(),
                source,
            });
    }
    let binary_path = PathBuf::from(binary.trim());
    let checked_path = binary_path.clone();
    let expected_digest = binary_sha256.trim().to_string();
    tokio::task::spawn_blocking(move || verify_external_binary(&checked_path, &expected_digest))
        .await
        .map_err(|source| DiskLimitError::FuseBinaryIo {
            binary: binary.to_string(),
            source: Error::other(source),
        })?
        .map_err(|source| DiskLimitError::FuseBinaryIo {
            binary: binary.to_string(),
            source,
        })?;
    Ok(binary_path)
}

fn is_embedded_binary(binary: &str) -> bool {
    binary.trim().eq_ignore_ascii_case(EMBEDDED_BINARY)
}

fn has_parent_segment(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
}

fn is_lowercase_sha256_hex(digest: &str) -> bool {
    digest.len() == SHA256_HEX_LENGTH
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn verify_external_binary(path: &Path, expected_digest: &str) -> Result<(), Error> {
    use rustix::fs::{FileType, Mode, OFlags};

    if !path.is_absolute() || has_parent_segment(path) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "external fuse quota helper must use an absolute path without parent segments",
        ));
    }
    if !is_lowercase_sha256_hex(expected_digest) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "external fuse quota helper requires a lowercase SHA-256 digest",
        ));
    }

    let parent = path.parent().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "external fuse quota helper has no parent directory",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "external fuse quota helper has no file name",
        )
    })?;
    let directory = open_trusted_root_dir(parent)?;
    let binary = rustix::fs::openat(
        &directory,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(Error::other)?;
    let stat = rustix::fs::fstat(&binary).map_err(Error::other)?;
    check_external_binary(
        FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile,
        stat.st_uid,
        link_count_u64(stat.st_nlink),
        stat.st_mode,
    )?;

    let actual_digest = sha256_hex(File::from(binary))?;
    if actual_digest != expected_digest {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "external fuse quota helper {} failed SHA-256 verification",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn sha256_hex(mut file: File) -> Result<String, Error> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(crate::utils::hex::encode_lower(&hasher.finalize()))
}

fn open_trusted_root_dir(path: &Path) -> Result<rustix::fd::OwnedFd, Error> {
    use rustix::fs::{FileType, Mode, OFlags};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = rustix::fs::open("/", flags, Mode::empty()).map_err(Error::other)?;
    for component in path.components() {
        match component {
            std::path::Component::RootDir => continue,
            std::path::Component::Normal(name) => {
                let next = rustix::fs::openat(&directory, name, flags, Mode::empty())
                    .map_err(Error::other)?;
                let stat = rustix::fs::fstat(&next).map_err(Error::other)?;
                if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
                    || stat.st_uid != 0
                    || stat.st_mode & 0o022 != 0
                {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        format!(
                            "external fuse quota helper parent {} must be a root-owned directory not writable by group or others",
                            path.display()
                        ),
                    ));
                }
                directory = next;
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "external fuse quota helper path contains an unsupported component",
                ));
            }
        }
    }
    Ok(directory)
}

fn link_count_u64<T: Into<u64>>(link_count: T) -> u64 {
    link_count.into()
}

pub(super) fn check_external_binary(
    is_regular_file: bool,
    uid: u32,
    link_count: u64,
    mode: u32,
) -> Result<(), Error> {
    if !is_regular_file || uid != 0 || link_count != 1 || mode & 0o022 != 0 || mode & 0o111 == 0 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "external fuse quota helper must be a root-owned, singly-linked executable regular file not writable by group or others",
        ));
    }
    Ok(())
}

pub(super) fn display_binary(configured: &str, resolved: &Path) -> String {
    if is_embedded_binary(configured) {
        format!("embedded ({})", resolved.display())
    } else {
        configured.to_string()
    }
}
