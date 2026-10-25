//! Writing the generated config: root-owned, mode 0600, in a 0700 directory,
//! and never over an existing file.

use std::{
    fs,
    io::{ErrorKind, Write},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Component, Path},
};

use anyhow::{Context, bail};

/// Refuses config paths `dbev --setup` would reject, before anything is
/// written: it needs an absolute path in a dedicated directory.
pub(super) fn check_location(path: &Path) -> anyhow::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        bail!(
            "the config path {} must be absolute, without . or .. parts",
            path.display()
        );
    }
    let dedicated = path
        .parent()
        .and_then(Path::parent)
        .is_some_and(|grandparent| grandparent != Path::new("/"));
    if !dedicated {
        bail!(
            "the config {} must live in a dedicated directory such as /etc/databases-everywhere",
            path.display()
        );
    }
    Ok(())
}

/// Whether the file exists. A path that cannot be checked is an error, so a
/// config hidden from a non-root user is not mistaken for a first run.
pub(in crate::commands::console) fn exists(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "cannot check the config {}; run the console with sudo",
                path.display()
            )
        }),
    }
}

/// Writes a new private file atomically. `replace` allows an existing file
/// to be swapped out; without it an existing file is an error.
pub(super) fn write_private(
    path: &Path,
    contents: &str,
    replace: bool,
    root_owned: bool,
) -> anyhow::Result<()> {
    let directory = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    prepare_directory(directory, root_owned)?;
    let mut file = tempfile::Builder::new()
        .prefix(".dbev-new-")
        .permissions(fs::Permissions::from_mode(0o600))
        .tempfile_in(directory)
        .with_context(|| format!("failed to create a file in {}", directory.display()))?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.as_file().sync_all())
        .with_context(|| format!("failed to write {}", path.display()))?;
    if root_owned {
        rustix::fs::fchown(
            file.as_file(),
            Some(rustix::fs::Uid::ROOT),
            Some(rustix::fs::Gid::ROOT),
        )
        .with_context(|| format!("failed to make {} root-owned", path.display()))?;
    }
    let persisted = if replace {
        file.persist(path)
    } else {
        file.persist_noclobber(path)
    };
    match persisted {
        Ok(_) => {}
        Err(error) if error.error.kind() == ErrorKind::AlreadyExists => {
            bail!("{} already exists; it was left unchanged", path.display())
        }
        Err(error) => {
            return Err(error.error).with_context(|| format!("failed to save {}", path.display()));
        }
    }
    fs::File::open(directory)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("failed to sync {}", directory.display()))
}

fn prepare_directory(directory: &Path, root_owned: bool) -> anyhow::Result<()> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!(
                "{} must be a real directory, not a symlink",
                directory.display()
            )
        }
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(directory)
            .with_context(|| format!("failed to create {}", directory.display()))?,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect {}", directory.display()));
        }
    }
    if root_owned {
        rustix::fs::chown(
            directory,
            Some(rustix::fs::Uid::ROOT),
            Some(rustix::fs::Gid::ROOT),
        )
        .with_context(|| format!("failed to make {} root-owned", directory.display()))?;
    }
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to chmod 700 {}", directory.display()))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().mode() & 0o7777
    }

    #[test]
    fn new_files_are_private_and_never_replace_a_config() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("etc/databases-everywhere");
        let path = directory.join("config.yml");
        assert!(!exists(&path).unwrap());
        write_private(&path, "first\n", false, false).unwrap();
        assert!(exists(&path).unwrap());
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&directory), 0o700);

        let error = write_private(&path, "second\n", false, false).unwrap_err();
        assert!(error.to_string().contains("already exists"), "{error:#}");
        assert_eq!(fs::read_to_string(&path).unwrap(), "first\n");
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1, "no temp left");

        write_private(&path, "third\n", true, false).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "third\n");
    }

    #[test]
    fn an_existing_directory_is_tightened_and_symlinks_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("conf");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
        write_private(&directory.join("config.yml"), "x", false, false).unwrap();
        assert_eq!(mode(&directory), 0o700);

        let link = root.path().join("link");
        std::os::unix::fs::symlink(&directory, &link).unwrap();
        assert!(write_private(&link.join("other.yml"), "x", false, false).is_err());
        // A dangling symlink at the config path counts as an existing config.
        let dangling = directory.join("dangling.yml");
        std::os::unix::fs::symlink(root.path().join("missing"), &dangling).unwrap();
        assert!(exists(&dangling).unwrap());
        assert!(write_private(&dangling, "x", false, false).is_err());
    }

    #[test]
    fn config_locations_match_what_setup_accepts() {
        check_location(Path::new("/etc/databases-everywhere/config.yml")).unwrap();
        check_location(Path::new("/srv/dbev/conf/node.yml")).unwrap();
        for path in [
            "config.yml",
            "etc/databases-everywhere/config.yml",
            "/etc/../tmp/x/config.yml",
            "/etc/config.yml",
            "/config.yml",
        ] {
            assert!(check_location(Path::new(path)).is_err(), "{path}");
        }
    }
}
