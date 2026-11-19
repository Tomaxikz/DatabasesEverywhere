use std::{ffi::CString, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostOwner {
    pub uid: u32,
    pub gid: u32,
}

fn no_follow_directory_flags() -> rustix::fs::OFlags {
    use rustix::fs::OFlags;

    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

pub fn chown_recursive(path: &Path, owner: HostOwner) -> std::io::Result<()> {
    use rustix::fs::{Mode, open};

    let directory = match open(path, no_follow_directory_flags(), Mode::empty()) {
        Ok(directory) => directory,
        Err(rustix::io::Errno::NOENT) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    chown_directory_fd(&directory, path, owner)
}

fn chown_directory_fd(
    directory: &impl std::os::fd::AsFd,
    display_path: &Path,
    owner: HostOwner,
) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    use rustix::{
        fs::{AtFlags, Dir, FileType, Mode, chownat, fchown, openat, statat},
        process::{Gid, Uid},
    };

    let uid = Uid::from_raw(owner.uid);
    let gid = Gid::from_raw(owner.gid);
    fchown(directory, Some(uid), Some(gid)).map_err(std::io::Error::from)?;

    let mut entries = Dir::read_from(directory).map_err(std::io::Error::from)?;
    let mut names = Vec::<CString>::new();
    for entry in &mut entries {
        let entry = entry.map_err(std::io::Error::from)?;
        let name = entry.file_name();
        if !matches!(name.to_bytes(), b"." | b"..") {
            names.push(name.to_owned());
        }
    }

    for name in names {
        let child_path = display_path.join(std::ffi::OsStr::from_bytes(name.to_bytes()));
        let stat = match statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(rustix::io::Errno::NOENT) => continue,
            Err(error) => return Err(error.into()),
        };
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Symlink => {}
            FileType::Directory => {
                let child =
                    match openat(directory, &name, no_follow_directory_flags(), Mode::empty()) {
                        Ok(child) => child,
                        Err(rustix::io::Errno::NOENT) => continue,
                        Err(error) => return Err(error.into()),
                    };
                chown_directory_fd(&child, &child_path, owner)?;
            }
            _ => {
                chownat(
                    directory,
                    &name,
                    Some(uid),
                    Some(gid),
                    AtFlags::SYMLINK_NOFOLLOW,
                )
                .map_err(std::io::Error::from)?;
            }
        }
    }
    Ok(())
}

pub fn allow_directory_traversal(path: &Path, daemon_uid: u32, gid: u32) -> std::io::Result<()> {
    use rustix::{
        fs::{FileType, Mode, fchmod, fchown, fstat, open},
        process::{Gid, Uid},
    };

    let directory =
        open(path, no_follow_directory_flags(), Mode::empty()).map_err(std::io::Error::from)?;
    let stat = fstat(&directory).map_err(std::io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory || stat.st_uid != daemon_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} must be a real directory owned by daemon uid {daemon_uid}",
                path.display()
            ),
        ));
    }
    if stat.st_gid != gid {
        // Close the directory to the old group before handing it to the new
        // one, so stale group bits never apply to the new group.
        fchmod(&directory, Mode::RWXU).map_err(std::io::Error::from)?;
    }
    fchown(
        &directory,
        Some(Uid::from_raw(daemon_uid)),
        Some(Gid::from_raw(gid)),
    )
    .map_err(std::io::Error::from)?;
    fchmod(&directory, Mode::RWXU | Mode::XGRP).map_err(std::io::Error::from)
}

static TRAVERSAL_GRANTS: std::sync::RwLock<std::collections::BTreeMap<std::path::PathBuf, u32>> =
    std::sync::RwLock::new(std::collections::BTreeMap::new());

/// Records that `path` is a designated bind-mount ancestor which `gid` must
/// keep traversing (rootless Podman only). Callers that re-secure a private
/// directory consult this so they do not revoke the grant while jobs run.
pub fn register_traversal_grant(path: &Path, gid: u32) {
    TRAVERSAL_GRANTS
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(path.to_path_buf(), gid);
}

pub fn registered_traversal_gid(path: &Path) -> Option<u32> {
    TRAVERSAL_GRANTS
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(path)
        .copied()
}

/// Grants `gid` execute-only traversal ([`allow_directory_traversal`]) of
/// `root` and of every directory between it and `path`, so a rootless runtime
/// can bind-mount `path`. `path` itself is left to its own owner and mode.
pub fn allow_traversal_below(
    root: &Path,
    path: &Path,
    daemon_uid: u32,
    gid: u32,
) -> std::io::Result<()> {
    use std::path::Component;

    let not_below = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not below {}", path.display(), root.display()),
        )
    };
    let relative = path
        .parent()
        .and_then(|parent| parent.strip_prefix(root).ok())
        .ok_or_else(not_below)?;
    let mut current = root.to_path_buf();
    allow_directory_traversal(&current, daemon_uid, gid)?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(not_below());
        };
        current.push(name);
        allow_directory_traversal(&current, daemon_uid, gid)?;
    }
    Ok(())
}

/// Hardens a directory to 0700 but keeps the deliberate execute-only group
/// traversal grant (exactly 0710), so preparing a private directory never
/// revokes a rootless runtime's path to a bind mount below it.
pub fn secure_private_dir_keeping_traversal(path: &Path) -> std::io::Result<()> {
    use rustix::fs::{FileType, Mode, fchmod, fstat, open};

    let not_directory = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a real directory", path.display()),
        )
    };
    let directory = match open(path, no_follow_directory_flags(), Mode::empty()) {
        Ok(directory) => directory,
        Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => return Err(not_directory()),
        Err(error) => return Err(error.into()),
    };
    let stat = fstat(&directory).map_err(std::io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(not_directory());
    }
    let traversal = Mode::RWXU | Mode::XGRP;
    let mode = if stat.st_mode & 0o777 == traversal.bits() {
        traversal
    } else {
        Mode::RWXU
    };
    fchmod(&directory, mode).map_err(std::io::Error::from)
}

pub fn ensure_traversable(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    for ancestor in path.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!(
                    "failed to inspect bind-mount ancestor {}: {error}",
                    ancestor.display()
                ),
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "bind-mount ancestor {} must be a real directory",
                    ancestor.display()
                ),
            ));
        }
        let mode = metadata.permissions().mode();
        let execute_bit = if metadata.uid() == uid {
            0o100
        } else if metadata.gid() == gid {
            0o010
        } else {
            0o001
        };
        if mode & execute_bit == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "uid {uid}/gid {gid} cannot traverse bind-mount ancestor {} (owner {}:{}, mode {:04o}); grant that account execute-only traversal or use the default DBE paths",
                    ancestor.display(),
                    metadata.uid(),
                    metadata.gid(),
                    mode & 0o7777
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    use super::*;

    #[test]
    fn recursive_owner_walk_never_follows_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let managed = temp.path().join("managed");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&managed).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("must-not-be-traversed"), b"outside").unwrap();
        symlink(&outside, managed.join("outside-link")).unwrap();
        let metadata = std::fs::metadata(&managed).unwrap();

        chown_recursive(
            &managed,
            HostOwner {
                uid: metadata.uid(),
                gid: metadata.gid(),
            },
        )
        .unwrap();

        assert_eq!(
            std::fs::read(outside.join("must-not-be-traversed")).unwrap(),
            b"outside"
        );
        assert!(
            std::fs::symlink_metadata(managed.join("outside-link"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn traversal_below_a_root_stops_at_the_mounted_directory() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("backups");
        let capture = root.join(".staging/inst_one/.job.capture");
        std::fs::create_dir_all(&capture).unwrap();
        for directory in [&root, &root.join(".staging/inst_one"), &capture] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let metadata = std::fs::metadata(&root).unwrap();

        allow_traversal_below(&root, &capture, metadata.uid(), metadata.gid()).unwrap();

        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        for ancestor in [
            root.clone(),
            root.join(".staging"),
            root.join(".staging/inst_one"),
        ] {
            assert_eq!(mode(&ancestor), 0o710, "{}", ancestor.display());
        }
        assert_eq!(mode(&capture), 0o700);
        assert!(allow_traversal_below(&capture, &root, metadata.uid(), metadata.gid()).is_err());
    }

    #[test]
    fn private_hardening_keeps_only_the_execute_only_traversal_grant() {
        let temp = tempfile::tempdir().unwrap();
        for (initial, expected) in [(0o710, 0o710), (0o755, 0o700), (0o750, 0o700)] {
            std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(initial))
                .unwrap();
            secure_private_dir_keeping_traversal(temp.path()).unwrap();
            assert_eq!(
                std::fs::metadata(temp.path()).unwrap().permissions().mode() & 0o777,
                expected,
                "{initial:o}"
            );
        }
        let link = temp.path().join("link");
        symlink(temp.path(), &link).unwrap();
        assert_eq!(
            secure_private_dir_keeping_traversal(&link)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn traversal_check_names_the_blocking_ancestor() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let managed = temp.path().join("managed");
        std::fs::create_dir(&managed).unwrap();
        let metadata = std::fs::metadata(temp.path()).unwrap();

        ensure_traversable(&managed, metadata.uid(), metadata.gid()).unwrap();
        let error = ensure_traversable(
            &managed,
            metadata.uid().saturating_add(1),
            metadata.gid().saturating_add(1),
        )
        .unwrap_err();
        assert!(error.to_string().contains("cannot traverse"));
    }
}
