use std::{
    ffi::OsStr,
    fs::File,
    io::{ErrorKind, Read, Write},
    path::Path,
};

fn path_parts(path: &Path) -> Result<(&Path, &OsStr), std::io::Error> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidInput, "file path has no parent directory")
    })?;
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidInput, "file path has no file name")
    })?;
    Ok((parent, name))
}

fn open_parent(path: &Path) -> Result<(File, &OsStr), std::io::Error> {
    use rustix::fs::{Mode, OFlags};

    let (parent, name) = path_parts(path)?;
    let descriptor = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    Ok((File::from(descriptor), name))
}

/// Creates a private directory tree and rejects a symlink or non-directory at
/// the final path.
pub fn ensure_private_dir(path: &Path) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(path)?;
    secure_private_dir(path)
}

/// Rejects a symlink or non-directory and limits access to the owning user.
pub(crate) fn secure_private_dir(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("{} is not a real directory", path.display()),
        ));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

pub fn is_safe_flat_file_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && !name
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
}

/// Durably replaces a file without ever following the destination if it is a symlink.
///
/// The caller is responsible for ensuring that the parent directory is private. The
/// directory is opened once and all create/rename operations are relative to that
/// descriptor, preventing a last-component swap during the replacement.
pub fn atomic_write_private(path: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    atomic_write_private_inner(path, contents, false)
}

/// Durably replaces an existing singly-linked regular file without following
/// the destination or its parent directory.
pub(crate) fn atomic_replace_private(path: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    atomic_write_private_inner(path, contents, true)
}

fn atomic_write_private_inner(
    path: &Path,
    contents: &[u8],
    require_existing: bool,
) -> Result<(), std::io::Error> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};

    let (directory, file_name) = open_parent(path)?;
    if require_existing {
        let existing = rustix::fs::openat(
            &directory,
            file_name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        let stat = rustix::fs::fstat(&existing).map_err(std::io::Error::from)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_nlink != 1 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "replacement target {} must be a singly-linked regular file",
                    path.display()
                ),
            ));
        }
    }
    let temporary_name = format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        uuid::Uuid::new_v4()
    );
    let temporary_fd = rustix::fs::openat(
        &directory,
        temporary_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(std::io::Error::from)?;
    let mut temporary = File::from(temporary_fd);

    let result = (|| {
        temporary.write_all(contents)?;
        temporary.flush()?;
        rustix::fs::fchmod(&temporary, Mode::RUSR | Mode::WUSR).map_err(std::io::Error::from)?;
        temporary.sync_all()?;
        drop(temporary);
        rustix::fs::renameat_with(
            &directory,
            temporary_name.as_str(),
            &directory,
            file_name,
            RenameFlags::empty(),
        )
        .map_err(std::io::Error::from)?;
        sync_directory(&directory)
    })();

    if result.is_err() {
        let _ = rustix::fs::unlinkat(&directory, temporary_name.as_str(), AtFlags::empty());
    }
    result
}

/// Durably removes a private regular marker without following its parent or
/// final path component. A missing marker is already committed.
pub fn remove_private_file_durable(path: &Path) -> Result<(), std::io::Error> {
    use rustix::fs::AtFlags;

    let (directory, file_name) = open_parent(path)?;
    match rustix::fs::unlinkat(&directory, file_name, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => sync_directory(&directory),
        Err(error) => Err(std::io::Error::from(error)),
    }
}

/// Opens a private file without following symlinks, verifies it is regular,
/// flushes its contents, and then flushes the containing directory.
pub fn sync_private_file(path: &Path) -> Result<(), std::io::Error> {
    use rustix::fs::{Mode, OFlags};

    let (directory, file_name) = open_parent(path)?;
    let descriptor = rustix::fs::openat(
        &directory,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(descriptor);
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "recovery data is not a regular file",
        ));
    }
    file.sync_all()?;
    sync_directory(&directory)
}

/// Copies one inspected regular file into a new private inode and commits it
/// only when its exact length and SHA-256 still match the inspected source.
/// The destination must not already exist.
pub fn copy_private_snapshot(
    source: &Path,
    destination: &Path,
    expected_bytes: u64,
    expected_sha256: &[u8; 32],
) -> Result<(), std::io::Error> {
    use rustix::fs::{AtFlags, Mode, OFlags};
    use sha2::{Digest, Sha256};

    let (source_directory, source_name) = open_parent(source)?;
    let source_fd = rustix::fs::openat(
        &source_directory,
        source_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let mut input = File::from(source_fd);
    let metadata = input.metadata()?;
    if !metadata.is_file() || metadata.len() != expected_bytes {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "private snapshot source changed after inspection",
        ));
    }

    let (destination_directory, destination_name) = open_parent(destination)?;
    let destination_fd = rustix::fs::openat(
        &destination_directory,
        destination_name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(std::io::Error::from)?;
    let mut output = File::from(destination_fd);

    let result = (|| {
        let mut digest = Sha256::new();
        let mut copied = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            copied = copied.checked_add(read as u64).ok_or_else(|| {
                std::io::Error::new(ErrorKind::InvalidData, "private snapshot size overflowed")
            })?;
            if copied > expected_bytes {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "private snapshot source grew after inspection",
                ));
            }
            digest.update(&buffer[..read]);
            output.write_all(&buffer[..read])?;
        }
        let actual_sha256: [u8; 32] = digest.finalize().into();
        if copied != expected_bytes || &actual_sha256 != expected_sha256 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "private snapshot source digest changed after inspection",
            ));
        }
        output.flush()?;
        rustix::fs::fchmod(&output, Mode::RUSR | Mode::WUSR).map_err(std::io::Error::from)?;
        output.sync_all()?;
        drop(output);
        sync_directory(&destination_directory)
    })();
    if result.is_err() {
        let _ = rustix::fs::unlinkat(&destination_directory, destination_name, AtFlags::empty());
        let _ = sync_directory(&destination_directory);
    }
    result
}

/// Reads a private regular file through a no-follow descriptor and enforces a hard byte limit
/// even if the file grows after it is opened.
pub fn read_bounded_private_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, std::io::Error> {
    use rustix::fs::{Mode, OFlags};

    let (directory, file_name) = open_parent(path)?;
    let descriptor = rustix::fs::openat(
        &directory,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "private input is not a regular file",
        ));
    }
    if metadata.len() > max_bytes {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("private input exceeds the {max_bytes}-byte limit"),
        ));
    }
    let capacity = usize::try_from(metadata.len().min(max_bytes)).unwrap_or(usize::MAX);
    let mut contents = Vec::with_capacity(capacity);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut contents)?;
    if u64::try_from(contents.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("private input exceeds the {max_bytes}-byte limit"),
        ));
    }
    Ok(contents)
}

pub(crate) fn sync_directory(directory: &impl std::os::fd::AsFd) -> Result<(), std::io::Error> {
    match rustix::fs::fsync(directory) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::INVAL | rustix::io::Errno::OPNOTSUPP) => Ok(()),
        Err(error) => Err(std::io::Error::from(error)),
    }
}

pub fn safe_header_filename(name: &str) -> String {
    name.chars()
        .map(|character| match character {
            '"' | '\\' | '\r' | '\n' => '_',
            character => character,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomically_replaces_private_file() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let private = directory.path().join("private");
        ensure_private_dir(&private).unwrap();
        assert_eq!(
            std::fs::metadata(private).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let path = directory.path().join("state");
        std::fs::write(&path, b"old").unwrap();

        atomic_write_private(&path, b"new").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn replaces_destination_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let victim = directory.path().join("victim");
        let path = directory.path().join("state");
        let strict_path = directory.path().join("strict-state");
        std::fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, &path).unwrap();
        symlink(&victim, &strict_path).unwrap();

        atomic_write_private(&path, b"replacement").unwrap();
        assert!(atomic_replace_private(&strict_path, b"replacement").is_err());

        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        assert!(
            !std::fs::symlink_metadata(path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn bounded_private_read_rejects_symlinks_and_oversized_files() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let regular = directory.path().join("regular");
        let linked = directory.path().join("linked");
        std::fs::write(&regular, b"contents").unwrap();
        symlink(&regular, &linked).unwrap();

        assert_eq!(read_bounded_private_file(&regular, 8).unwrap(), b"contents");
        assert!(read_bounded_private_file(&regular, 7).is_err());
        assert!(read_bounded_private_file(&linked, 8).is_err());
    }

    #[test]
    fn private_snapshot_is_independent_and_digest_checked() {
        use sha2::{Digest, Sha256};

        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let snapshot = directory.path().join("snapshot");
        std::fs::write(&source, b"inspected").unwrap();
        let digest: [u8; 32] = Sha256::digest(b"inspected").into();

        copy_private_snapshot(&source, &snapshot, 9, &digest).unwrap();
        std::fs::write(&source, b"mutated!!").unwrap();

        assert_eq!(std::fs::read(snapshot).unwrap(), b"inspected");
        let wrong: [u8; 32] = Sha256::digest(b"different").into();
        assert!(
            copy_private_snapshot(&source, &directory.path().join("rejected"), 9, &wrong).is_err()
        );
        assert!(!directory.path().join("rejected").exists());
    }
}
