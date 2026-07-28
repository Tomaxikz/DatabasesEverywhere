use std::path::Path;
#[cfg(unix)]
use std::{
    fs::File,
    io::{ErrorKind, Read, Write},
};

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
#[cfg(unix)]
pub fn atomic_write_private(path: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidInput, "file path has no parent directory")
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidInput, "file path has no file name")
    })?;
    let directory = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
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

#[cfg(not(unix))]
pub fn atomic_write_private(_path: &Path, _contents: &[u8]) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "private atomic file replacement is only available on Unix",
    ))
}

/// Durably removes a private regular marker without following its parent or
/// final path component. A missing marker is already committed.
#[cfg(unix)]
pub fn remove_private_file_durable(path: &Path) -> Result<(), std::io::Error> {
    use rustix::fs::{AtFlags, Mode, OFlags};

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidInput, "file path has no parent directory")
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidInput, "file path has no file name")
    })?;
    let directory = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    match rustix::fs::unlinkat(&directory, file_name, AtFlags::empty()) {
        Ok(()) | Err(rustix::io::Errno::NOENT) => sync_directory(&directory),
        Err(error) => Err(std::io::Error::from(error)),
    }
}

#[cfg(not(unix))]
pub fn remove_private_file_durable(_path: &Path) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "durable private file removal is only available on Unix",
    ))
}

/// Opens a private file without following symlinks, verifies it is regular,
/// flushes its contents, and then flushes the containing directory.
#[cfg(unix)]
pub fn sync_private_regular_file_durable(path: &Path) -> Result<(), std::io::Error> {
    use rustix::fs::{Mode, OFlags};

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidInput, "file path has no parent directory")
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidInput, "file path has no file name")
    })?;
    let directory = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
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

#[cfg(not(unix))]
pub fn sync_private_regular_file_durable(_path: &Path) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "durable private file sync is only available on Unix",
    ))
}

/// Reads a private regular file through a no-follow descriptor and enforces a hard byte limit
/// even if the file grows after it is opened.
#[cfg(unix)]
pub fn read_private_regular_file_bounded(
    path: &Path,
    max_bytes: u64,
) -> Result<Vec<u8>, std::io::Error> {
    use rustix::fs::{Mode, OFlags};

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidInput, "file path has no parent directory")
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidInput, "file path has no file name")
    })?;
    let directory = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
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

#[cfg(not(unix))]
pub fn read_private_regular_file_bounded(
    _path: &Path,
    _max_bytes: u64,
) -> Result<Vec<u8>, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "private no-follow reads are only available on Unix",
    ))
}

#[cfg(unix)]
fn sync_directory(directory: &impl std::os::fd::AsFd) -> Result<(), std::io::Error> {
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn atomically_replaces_private_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state");
        std::fs::write(&path, b"old").unwrap();

        atomic_write_private(&path, b"new").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"new");
    }

    #[test]
    fn replaces_destination_symlink_without_following_it() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let victim = directory.path().join("victim");
        let path = directory.path().join("state");
        std::fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, &path).unwrap();

        atomic_write_private(&path, b"replacement").unwrap();

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

        assert_eq!(
            read_private_regular_file_bounded(&regular, 8).unwrap(),
            b"contents"
        );
        assert!(read_private_regular_file_bounded(&regular, 7).is_err());
        assert!(read_private_regular_file_bounded(&linked, 8).is_err());
    }
}
