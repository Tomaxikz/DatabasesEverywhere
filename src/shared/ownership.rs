use std::{ffi::CString, path::Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostOwner {
    pub uid: u32,
    pub gid: u32,
}

pub fn chown_directory_recursive(path: &Path, owner: HostOwner) -> std::io::Result<()> {
    use rustix::fs::{Mode, OFlags, open};

    let directory = match open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
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
        fs::{AtFlags, Dir, FileType, Mode, OFlags, chownat, fchown, openat, statat},
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
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
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
                let child = match openat(
                    directory,
                    &name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                ) {
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

/// Keeps a daemon-owned directory non-listable while allowing one trusted
/// runtime group to traverse known bind-mount paths beneath it.
pub fn share_directory_for_traversal(
    path: &Path,
    daemon_uid: u32,
    gid: u32,
) -> std::io::Result<()> {
    use rustix::{
        fs::{FileType, Mode, OFlags, fchmod, fchown, fstat, open},
        process::{Gid, Uid},
    };

    let directory = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
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
    fchown(
        &directory,
        Some(Uid::from_raw(daemon_uid)),
        Some(Gid::from_raw(gid)),
    )
    .map_err(std::io::Error::from)?;
    fchmod(&directory, Mode::RWXU | Mode::XGRP).map_err(std::io::Error::from)
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

        chown_directory_recursive(
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
    fn traversal_share_does_not_grant_directory_listing() {
        let temp = tempfile::tempdir().unwrap();
        let metadata = std::fs::metadata(temp.path()).unwrap();

        share_directory_for_traversal(temp.path(), metadata.uid(), metadata.gid()).unwrap();

        assert_eq!(
            std::fs::metadata(temp.path()).unwrap().permissions().mode() & 0o777,
            0o710
        );
    }
}
