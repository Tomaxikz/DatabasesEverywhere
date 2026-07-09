use std::{
    fs::File,
    io::{ErrorKind, Write},
    path::Path,
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

#[cfg(test)]
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

    #[cfg(unix)]
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
}
