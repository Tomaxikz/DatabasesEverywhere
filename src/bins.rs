use std::{
    fs::{self, File},
    io::{Error, ErrorKind, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};
use sha2::{Digest, Sha256};

pub const FUSEQUOTA_VERSION: &str = env!("FUSEQUOTA_VERSION");
const FUSEQUOTA_SHA256: &str = env!("FUSEQUOTA_SHA256");
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
static FUSEQUOTA_BIN: &[u8] = include_bytes!("../bins/fusequota");
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
static FUSEQUOTA_BIN: &[u8] = &[];
static BIN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub fn embedded_fusequota_available() -> bool {
    !FUSEQUOTA_BIN.is_empty()
        && !FUSEQUOTA_VERSION.trim().is_empty()
        && !FUSEQUOTA_SHA256.trim().is_empty()
}

pub async fn get_fusequota_bin_path(runtime_root: &Path) -> Result<PathBuf, Error> {
    if !embedded_fusequota_available() {
        return Err(Error::new(
            ErrorKind::NotFound,
            "embedded fusequota binary is not available for this target",
        ));
    }

    let _lock = BIN_LOCK.lock().await;
    let runtime_root = runtime_root.to_path_buf();
    tokio::task::spawn_blocking(move || install_embedded_fusequota(&runtime_root))
        .await
        .map_err(Error::other)?
}

fn install_embedded_fusequota(runtime_root: &Path) -> Result<PathBuf, Error> {
    let helper_dir = runtime_root.join("bin");
    create_private_helper_dir(&helper_dir)?;

    let directory = rustix::fs::open(
        &helper_dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(Error::other)?;
    verify_private_directory(&directory, &helper_dir)?;

    let file_name = format!("fusequota-{FUSEQUOTA_VERSION}");
    if let Some(existing) = open_existing_helper(&directory, &file_name)? {
        verify_helper_file(existing, &helper_dir.join(&file_name))?;
        return Ok(helper_dir.join(file_name));
    }

    let executable = zstd::decode_all(FUSEQUOTA_BIN).map_err(Error::other)?;
    verify_digest(&executable, "embedded fusequota payload")?;
    install_helper_atomically(&directory, &helper_dir, &file_name, &executable)?;
    Ok(helper_dir.join(file_name))
}

fn create_private_helper_dir(path: &Path) -> Result<(), Error> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
}

fn verify_private_directory(directory: &impl std::os::fd::AsFd, path: &Path) -> Result<(), Error> {
    let metadata = File::from(
        directory
            .as_fd()
            .try_clone_to_owned()
            .map_err(Error::other)?,
    )
    .metadata()?;
    let expected_uid = rustix::process::geteuid().as_raw();
    if !metadata.is_dir() || metadata.uid() != expected_uid {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "embedded helper directory {} must be a directory owned by uid {expected_uid}",
                path.display()
            ),
        ));
    }

    rustix::fs::fchmod(directory, Mode::RWXU).map_err(Error::other)?;
    let mode = File::from(
        directory
            .as_fd()
            .try_clone_to_owned()
            .map_err(Error::other)?,
    )
    .metadata()?
    .permissions()
    .mode()
        & 0o777;
    if mode != 0o700 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "embedded helper directory {} has insecure mode {mode:o}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn open_existing_helper(
    directory: &impl std::os::fd::AsFd,
    file_name: &str,
) -> Result<Option<File>, Error> {
    match rustix::fs::openat(
        directory,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => Ok(Some(File::from(file))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(Error::other(error)),
    }
}

fn verify_helper_file(mut file: File, path: &Path) -> Result<(), Error> {
    let metadata = file.metadata()?;
    let expected_uid = rustix::process::geteuid().as_raw();
    let mode = metadata.permissions().mode() & 0o777;
    if !metadata.is_file() || metadata.uid() != expected_uid || mode != 0o500 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "embedded helper {} must be a regular uid-{expected_uid} file with mode 500",
                path.display()
            ),
        ));
    }

    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    verify_digest(&bytes, &format!("embedded helper {}", path.display()))
}

fn install_helper_atomically(
    directory: &impl std::os::fd::AsFd,
    helper_dir: &Path,
    file_name: &str,
    executable: &[u8],
) -> Result<(), Error> {
    let temporary_name = format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4());
    let temporary_fd = rustix::fs::openat(
        directory,
        temporary_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RWXU,
    )
    .map_err(Error::other)?;
    let mut temporary = File::from(temporary_fd);

    let write_result: Result<(), Error> = (|| {
        temporary.write_all(executable)?;
        temporary.sync_all()?;
        rustix::fs::fchmod(&temporary, Mode::RUSR | Mode::XUSR).map_err(Error::other)?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = rustix::fs::unlinkat(directory, temporary_name.as_str(), AtFlags::empty());
        return Err(error);
    }
    drop(temporary);

    match rustix::fs::renameat_with(
        directory,
        temporary_name.as_str(),
        directory,
        file_name,
        RenameFlags::NOREPLACE,
    ) {
        Ok(()) => rustix::fs::fsync(directory).map_err(Error::other)?,
        Err(rustix::io::Errno::EXIST) => {
            let _ = rustix::fs::unlinkat(directory, temporary_name.as_str(), AtFlags::empty());
        }
        Err(error) => {
            let _ = rustix::fs::unlinkat(directory, temporary_name.as_str(), AtFlags::empty());
            return Err(Error::other(error));
        }
    }

    let installed = open_existing_helper(directory, file_name)?.ok_or_else(|| {
        Error::new(
            ErrorKind::NotFound,
            format!(
                "embedded helper disappeared after installation in {}",
                helper_dir.display()
            ),
        )
    })?;
    verify_helper_file(installed, &helper_dir.join(file_name))
}

fn verify_digest(bytes: &[u8], label: &str) -> Result<(), Error> {
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual == FUSEQUOTA_SHA256 {
        return Ok(());
    }
    Err(Error::new(
        ErrorKind::InvalidData,
        format!("{label} failed SHA-256 verification"),
    ))
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[tokio::test]
    async fn installs_hash_verified_helper_in_private_directory() {
        let root = tempfile::tempdir().unwrap();

        let path = get_fusequota_bin_path(root.path()).await.unwrap();

        assert_eq!(path.parent(), Some(root.path().join("bin").as_path()));
        let directory_mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let file_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(directory_mode, 0o700);
        assert_eq!(file_mode, 0o500);
        verify_digest(&fs::read(path).unwrap(), "test helper").unwrap();
    }

    #[tokio::test]
    async fn rejects_preexisting_helper_symlink() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("bin");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(
            "/bin/true",
            directory.join(format!("fusequota-{FUSEQUOTA_VERSION}")),
        )
        .unwrap();

        assert!(get_fusequota_bin_path(root.path()).await.is_err());
    }

    #[tokio::test]
    async fn rejects_tampered_preexisting_helper() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("bin");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join(format!("fusequota-{FUSEQUOTA_VERSION}"));
        fs::write(&path, b"not the embedded helper").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();

        let error = get_fusequota_bin_path(root.path()).await.unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }
}
