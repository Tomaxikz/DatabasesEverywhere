use std::path::Path;

use super::DiskLimitError;

pub(super) async fn assign(root: &Path, project_id: u32) -> Result<(), DiskLimitError> {
    run(root, project_id, ProjectAction::Assign).await
}

pub(super) async fn clear(root: &Path, project_id: u32) -> Result<(), DiskLimitError> {
    run(root, project_id, ProjectAction::Clear).await
}

/// Undo an interrupted project adoption. A pending claim may have moved only
/// part of the tree to `project_id`; restore both the source- and target-owned
/// entries to the boundary's original parent project before releasing it.
pub(super) async fn rollback_pending(root: &Path, project_id: u32) -> Result<(), DiskLimitError> {
    run(root, project_id, ProjectAction::Rollback).await
}

pub(super) async fn verify_root(root: &Path, project_id: u32) -> Result<(), DiskLimitError> {
    let root = root.to_path_buf();
    let display_root = root.display().to_string();
    tokio::task::spawn_blocking(move || platform::verify_root(&root, project_id))
        .await
        .map_err(|error| DiskLimitError::Task(error.to_string()))?
        .map_err(|source| DiskLimitError::PathIo {
            path: display_root,
            source,
        })
}

async fn run(root: &Path, project_id: u32, action: ProjectAction) -> Result<(), DiskLimitError> {
    let root = root.to_path_buf();
    let display_root = root.display().to_string();
    tokio::task::spawn_blocking(move || platform::set(&root, project_id, action))
        .await
        .map_err(|error| DiskLimitError::Task(error.to_string()))?
        .map_err(|source| DiskLimitError::PathIo {
            path: display_root,
            source,
        })
}

#[derive(Debug, Clone, Copy)]
enum ProjectAction {
    Assign,
    Clear,
    Rollback,
}

mod platform {
    use std::{
        collections::HashSet,
        ffi::{CStr, OsStr},
        os::{
            fd::{AsFd, BorrowedFd, OwnedFd},
            unix::ffi::OsStrExt,
        },
        path::Path,
    };

    use rustix::{
        fs::{AtFlags, FileType, Mode, OFlags, RawDir, ResolveFlags, fstat, open, openat2, statat},
        ioctl::{Getter, Setter, ioctl, opcode},
    };

    use super::ProjectAction;

    const MAX_DEPTH: usize = 128;
    const MAX_RECONCILE_PASSES: usize = 8;
    const FS_XFLAG_PROJINHERIT: u32 = 0x0000_0200;
    const FS_IOC_FSGETXATTR: rustix::ioctl::Opcode = opcode::read::<Fsxattr>(b'X', 31);
    const FS_IOC_FSSETXATTR: rustix::ioctl::Opcode = opcode::write::<Fsxattr>(b'X', 32);

    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    struct Fsxattr {
        xflags: u32,
        extsize: u32,
        nextents: u32,
        project_id: u32,
        cowextsize: u32,
        pad: [u8; 8],
    }

    #[derive(Debug, Clone, Copy)]
    struct SourceProject {
        id: u32,
        inherit: bool,
    }

    pub(super) fn set(
        root: &Path,
        project_id: u32,
        action: ProjectAction,
    ) -> Result<(), std::io::Error> {
        let source = match action {
            ProjectAction::Assign | ProjectAction::Rollback => {
                Some(adoption_source(root, project_id)?)
            }
            ProjectAction::Clear => None,
        };
        validate_tree(root, project_id, source, action)?;
        for _ in 0..MAX_RECONCILE_PASSES {
            let mut relabel = Relabel {
                project_id,
                source,
                action,
            };
            let applied_stably = walk_tree(root, &mut relabel)?;

            let mut verify = Verify {
                project_id,
                source,
                action,
                clean: true,
            };
            let verified_stably = walk_tree(root, &mut verify)?;
            if applied_stably && verified_stably && verify.clean {
                return Ok(());
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            format!(
                "project quota tree {} kept changing during relabeling",
                root.display()
            ),
        ))
    }

    fn validate_tree(
        root: &Path,
        project_id: u32,
        source: Option<SourceProject>,
        action: ProjectAction,
    ) -> Result<(), std::io::Error> {
        for _ in 0..MAX_RECONCILE_PASSES {
            let mut validate = Validate {
                project_id,
                source,
                action,
            };
            if walk_tree(root, &mut validate)? {
                return Ok(());
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            format!(
                "project quota tree {} kept changing during validation",
                root.display()
            ),
        ))
    }

    pub(super) fn verify_root(root: &Path, project_id: u32) -> Result<(), std::io::Error> {
        let fd = open_root(root)?;
        let attrs = get_attrs(fd.as_fd()).map_err(|source| at(root, source))?;
        if attrs_match(&attrs, project_id, Some(true)) {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "project quota root {} does not have project id {project_id} with inheritance enabled",
                    root.display()
                ),
            ))
        }
    }

    trait Visitor {
        fn enter(
            &mut self,
            fd: BorrowedFd<'_>,
            path: &Path,
            directory: bool,
        ) -> Result<(), std::io::Error>;

        fn leave_directory(
            &mut self,
            _fd: BorrowedFd<'_>,
            _path: &Path,
        ) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    struct Relabel {
        project_id: u32,
        source: Option<SourceProject>,
        action: ProjectAction,
    }

    struct Validate {
        project_id: u32,
        source: Option<SourceProject>,
        action: ProjectAction,
    }

    impl Visitor for Validate {
        fn enter(
            &mut self,
            fd: BorrowedFd<'_>,
            _path: &Path,
            directory: bool,
        ) -> Result<(), std::io::Error> {
            let current = get_attrs(fd)?;
            match self.action {
                ProjectAction::Assign | ProjectAction::Rollback => validate_assign(
                    &current,
                    self.source
                        .expect("assign and rollback validation record the source project")
                        .id,
                    self.project_id,
                ),
                ProjectAction::Clear => validate_clear(&current, self.project_id, directory),
            }
        }
    }

    impl Visitor for Relabel {
        fn enter(
            &mut self,
            fd: BorrowedFd<'_>,
            _path: &Path,
            directory: bool,
        ) -> Result<(), std::io::Error> {
            // Project inheritance is established before getdents. Anything
            // created after this point is born inside the new project instead
            // of escaping the in-progress adoption. During clear and rollback,
            // source inheritance temporarily remains enabled and is restored
            // only after the directory's existing children have been handled.
            match self.action {
                ProjectAction::Assign => assign_attrs(
                    fd,
                    self.source
                        .expect("assign traversal always records its source project")
                        .id,
                    self.project_id,
                    directory,
                ),
                ProjectAction::Clear => clear_attrs(fd, self.project_id, directory, true),
                ProjectAction::Rollback => restore_attrs(
                    fd,
                    self.source
                        .expect("rollback traversal always records its source project"),
                    self.project_id,
                    directory,
                    true,
                ),
            }
        }

        fn leave_directory(
            &mut self,
            fd: BorrowedFd<'_>,
            _path: &Path,
        ) -> Result<(), std::io::Error> {
            match self.action {
                ProjectAction::Assign => {}
                ProjectAction::Clear => clear_attrs(fd, self.project_id, true, false)?,
                ProjectAction::Rollback => {
                    let source = self
                        .source
                        .expect("rollback traversal always records its source project");
                    restore_attrs(fd, source, self.project_id, true, source.inherit)?;
                }
            }
            Ok(())
        }
    }

    struct Verify {
        project_id: u32,
        source: Option<SourceProject>,
        action: ProjectAction,
        clean: bool,
    }

    impl Visitor for Verify {
        fn enter(
            &mut self,
            fd: BorrowedFd<'_>,
            _path: &Path,
            directory: bool,
        ) -> Result<(), std::io::Error> {
            let project_id = match self.action {
                ProjectAction::Assign => self.project_id,
                ProjectAction::Clear => 0,
                ProjectAction::Rollback => {
                    self.source
                        .expect("rollback verification records the source project")
                        .id
                }
            };
            let inherit = directory.then_some(match self.action {
                ProjectAction::Assign => true,
                ProjectAction::Clear => false,
                ProjectAction::Rollback => {
                    self.source
                        .expect("rollback verification records the source project")
                        .inherit
                }
            });
            self.clean &= attrs_match(&get_attrs(fd)?, project_id, inherit);
            Ok(())
        }
    }

    fn walk_tree(root: &Path, visitor: &mut impl Visitor) -> Result<bool, std::io::Error> {
        let root_fd = open_root(root)?;
        let root_stat = fstat(&root_fd)
            .map_err(std::io::Error::from)
            .map_err(|source| at(root, source))?;
        let root_identity = (root_stat.st_dev as u64, root_stat.st_ino as u64);
        let mut seen_directories = HashSet::new();
        let mut stable = true;
        walk_node(
            &root_fd,
            root,
            root_stat.st_dev as u64,
            0,
            &mut seen_directories,
            &mut stable,
            visitor,
        )?;

        // Reopen only to validate that the caller's root name still selects
        // the pinned inode. No mutation is ever performed through this second
        // pathname lookup.
        match open_root(root) {
            Ok(current) => {
                let stat = fstat(current).map_err(std::io::Error::from)?;
                stable &= (stat.st_dev as u64, stat.st_ino as u64) == root_identity;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => stable = false,
            Err(error) => return Err(error),
        }
        Ok(stable)
    }

    fn open_root(root: &Path) -> Result<OwnedFd, std::io::Error> {
        open(
            root,
            OFlags::RDONLY
                | OFlags::DIRECTORY
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::NOCTTY
                | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)
        .map_err(|source| at(root, source))
    }

    fn adoption_source(root: &Path, target_id: u32) -> Result<SourceProject, std::io::Error> {
        let root_fd = open_root(root)?;
        let root_attrs = get_attrs(root_fd.as_fd()).map_err(|source| at(root, source))?;
        let parent = root.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "project quota root has no parent directory",
            )
        })?;
        let parent_fd = open_root(parent)?;
        let parent_attrs = get_attrs(parent_fd.as_fd()).map_err(|source| at(parent, source))?;

        // A retry after an interrupted adoption can find the target ID on the
        // root, and a retry after interrupted rollback can find the source ID
        // with the traversal's temporary inheritance bit. The parent remains
        // stable in both cases, so use it whenever it names the same source;
        // only preserve a distinct pre-existing root project boundary.
        Ok(select_source(root_attrs, parent_attrs, target_id))
    }

    fn source_project(attrs: Fsxattr) -> SourceProject {
        SourceProject {
            id: attrs.project_id,
            inherit: attrs.xflags & FS_XFLAG_PROJINHERIT != 0,
        }
    }

    fn select_source(root: Fsxattr, parent: Fsxattr, target_id: u32) -> SourceProject {
        if root.project_id == target_id || root.project_id == parent.project_id {
            source_project(parent)
        } else {
            source_project(root)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_node(
        fd: &OwnedFd,
        path: &Path,
        root_device: u64,
        depth: usize,
        seen_directories: &mut HashSet<(u64, u64)>,
        stable: &mut bool,
        visitor: &mut impl Visitor,
    ) -> Result<(), std::io::Error> {
        if depth > MAX_DEPTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("project quota tree exceeds {MAX_DEPTH} directory levels"),
            ));
        }
        let stat = fstat(fd)
            .map_err(std::io::Error::from)
            .map_err(|source| at(path, source))?;
        if stat.st_dev as u64 != root_device {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "project quota tree crosses a filesystem boundary at {}",
                    path.display()
                ),
            ));
        }

        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                if !seen_directories.insert((stat.st_dev as u64, stat.st_ino as u64)) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "project quota tree contains a repeated directory at {}",
                            path.display()
                        ),
                    ));
                }
                visitor
                    .enter(fd.as_fd(), path, true)
                    .map_err(|source| at(path, source))?;
                let mut buffer = Vec::with_capacity(16 * 1024);
                let mut entries = RawDir::new(fd, buffer.spare_capacity_mut());
                while let Some(entry) = entries.next() {
                    let entry = entry
                        .map_err(std::io::Error::from)
                        .map_err(|source| at(path, source))?;
                    let name = entry.file_name().to_owned();
                    if matches!(name.to_bytes(), b"." | b"..") {
                        continue;
                    }
                    let child_path = path.join(OsStr::from_bytes(name.to_bytes()));
                    let Some(child) = open_child(fd, &name, &child_path)? else {
                        *stable = false;
                        continue;
                    };
                    let child_stat = fstat(&child)
                        .map_err(std::io::Error::from)
                        .map_err(|source| at(&child_path, source))?;
                    let child_identity = (child_stat.st_dev as u64, child_stat.st_ino as u64);
                    walk_node(
                        &child,
                        &child_path,
                        root_device,
                        depth + 1,
                        seen_directories,
                        stable,
                        visitor,
                    )?;
                    *stable &= entry_still_names(fd, &name, child_identity, &child_path)?;
                }
                visitor
                    .leave_directory(fd.as_fd(), path)
                    .map_err(|source| at(path, source))?;
            }
            FileType::RegularFile => visitor
                .enter(fd.as_fd(), path, false)
                .map_err(|source| at(path, source))?,
            FileType::Symlink => {
                return Err(invalid_entry(path, "a symbolic link"));
            }
            _ => return Err(invalid_entry(path, "a special file")),
        }
        Ok(())
    }

    fn open_child(
        parent: &OwnedFd,
        name: &CStr,
        path: &Path,
    ) -> Result<Option<OwnedFd>, std::io::Error> {
        let flags =
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC;
        match openat2(
            parent,
            name,
            flags,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS
                | ResolveFlags::NO_XDEV,
        ) {
            Ok(fd) => Ok(Some(fd)),
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::STALE) => Ok(None),
            Err(rustix::io::Errno::LOOP) => Err(invalid_entry(path, "a symbolic link")),
            Err(rustix::io::Errno::XDEV) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "project quota tree crosses a mount boundary at {}",
                    path.display()
                ),
            )),
            Err(error) => Err(at(path, std::io::Error::from(error))),
        }
    }

    fn entry_still_names(
        parent: &OwnedFd,
        name: &CStr,
        expected: (u64, u64),
        path: &Path,
    ) -> Result<bool, std::io::Error> {
        match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok((stat.st_dev, stat.st_ino) == expected),
            Err(rustix::io::Errno::NOENT | rustix::io::Errno::STALE) => Ok(false),
            Err(error) => Err(at(path, std::io::Error::from(error))),
        }
    }

    fn get_attrs(fd: BorrowedFd<'_>) -> Result<Fsxattr, std::io::Error> {
        // SAFETY: FS_IOC_FSGETXATTR writes exactly one Linux `fsxattr` into
        // the matching repr(C) output type.
        let request = unsafe { Getter::<FS_IOC_FSGETXATTR, Fsxattr>::new() };
        // SAFETY: the descriptor remains open and the opcode/type pair matches
        // the Linux UAPI contract above.
        unsafe { ioctl(fd, request) }.map_err(std::io::Error::from)
    }

    fn assign_attrs(
        fd: BorrowedFd<'_>,
        source_id: u32,
        target_id: u32,
        directory: bool,
    ) -> Result<(), std::io::Error> {
        let current = get_attrs(fd)?;
        validate_assign(&current, source_id, target_id)?;
        write_attrs(fd, current, target_id, directory.then_some(true))
    }

    fn clear_attrs(
        fd: BorrowedFd<'_>,
        project_id: u32,
        directory: bool,
        inherit: bool,
    ) -> Result<(), std::io::Error> {
        let current = get_attrs(fd)?;
        validate_clear(&current, project_id, directory)?;
        write_attrs(fd, current, 0, directory.then_some(inherit))
    }

    fn restore_attrs(
        fd: BorrowedFd<'_>,
        source: SourceProject,
        target_id: u32,
        directory: bool,
        inherit: bool,
    ) -> Result<(), std::io::Error> {
        let current = get_attrs(fd)?;
        validate_assign(&current, source.id, target_id)?;
        write_attrs(fd, current, source.id, directory.then_some(inherit))
    }

    fn validate_assign(
        current: &Fsxattr,
        source_id: u32,
        target_id: u32,
    ) -> Result<(), std::io::Error> {
        if current.project_id == source_id || current.project_id == target_id {
            Ok(())
        } else {
            Err(foreign_project(current.project_id, source_id, target_id))
        }
    }

    fn validate_clear(
        current: &Fsxattr,
        project_id: u32,
        directory: bool,
    ) -> Result<(), std::io::Error> {
        if current.project_id != project_id && current.project_id != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "refusing to clear foreign project id {}; expected {project_id} or 0",
                    current.project_id
                ),
            ));
        }
        if directory
            && current.project_id == project_id
            && current.xflags & FS_XFLAG_PROJINHERIT == 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "project {project_id} directory is missing project inheritance before clear"
                ),
            ));
        }
        Ok(())
    }

    fn write_attrs(
        fd: BorrowedFd<'_>,
        current: Fsxattr,
        project_id: u32,
        inherit: Option<bool>,
    ) -> Result<(), std::io::Error> {
        if attrs_match(&current, project_id, inherit) {
            return Ok(());
        }
        let desired = updated_attrs(current, project_id, inherit);
        // SAFETY: FS_IOC_FSSETXATTR reads exactly one Linux `fsxattr` from
        // the matching repr(C) input. Unrelated fields and flags came from
        // FSGETXATTR and are preserved.
        let request = unsafe { Setter::<FS_IOC_FSSETXATTR, Fsxattr>::new(desired) };
        // SAFETY: the descriptor remains open and the opcode/type pair matches
        // the Linux UAPI contract above.
        unsafe { ioctl(fd, request) }.map_err(std::io::Error::from)?;
        if attrs_match(&get_attrs(fd)?, project_id, inherit) {
            Ok(())
        } else {
            Err(std::io::Error::other(
                "kernel did not retain the requested project attributes",
            ))
        }
    }

    fn foreign_project(actual: u32, source: u32, target: u32) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "refusing to overwrite foreign project id {actual}; expected source {source} or target {target}"
            ),
        )
    }

    fn updated_attrs(mut attrs: Fsxattr, project_id: u32, inherit: Option<bool>) -> Fsxattr {
        attrs.project_id = project_id;
        match inherit {
            Some(true) => attrs.xflags |= FS_XFLAG_PROJINHERIT,
            Some(false) => attrs.xflags &= !FS_XFLAG_PROJINHERIT,
            None => {}
        }
        attrs
    }

    fn attrs_match(attrs: &Fsxattr, project_id: u32, inherit: Option<bool>) -> bool {
        attrs.project_id == project_id
            && inherit.is_none_or(|expected| (attrs.xflags & FS_XFLAG_PROJINHERIT != 0) == expected)
    }

    fn invalid_entry(path: &Path, kind: &str) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("project quota tree contains {kind} at {}", path.display()),
        )
    }

    fn at(path: &Path, source: std::io::Error) -> std::io::Error {
        std::io::Error::new(source.kind(), format!("{}: {source}", path.display()))
    }

    #[cfg(test)]
    mod tests {
        use std::{os::unix::fs::symlink, path::PathBuf};

        use super::*;

        #[derive(Default)]
        struct Recorder {
            entered: Vec<PathBuf>,
            create_in: Option<PathBuf>,
        }

        impl Visitor for Recorder {
            fn enter(
                &mut self,
                _fd: BorrowedFd<'_>,
                path: &Path,
                directory: bool,
            ) -> Result<(), std::io::Error> {
                self.entered.push(path.to_path_buf());
                if directory && self.create_in.as_deref() == Some(path) {
                    std::fs::write(path.join("created-after-enter"), b"new")?;
                    self.create_in = None;
                }
                Ok(())
            }
        }

        #[test]
        fn directory_is_entered_before_children_are_enumerated() {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("tenant");
            let nested = root.join("nested");
            std::fs::create_dir_all(&nested).unwrap();
            let mut recorder = Recorder {
                create_in: Some(nested.clone()),
                ..Recorder::default()
            };

            assert!(walk_tree(&root, &mut recorder).unwrap());

            let created = nested.join("created-after-enter");
            let nested_index = recorder
                .entered
                .iter()
                .position(|path| path == &nested)
                .unwrap();
            let created_index = recorder
                .entered
                .iter()
                .position(|path| path == &created)
                .unwrap();
            assert!(nested_index < created_index);
        }

        #[test]
        fn fd_relative_walk_never_follows_symlinks() {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("tenant");
            let outside = temp.path().join("outside");
            std::fs::create_dir(&root).unwrap();
            std::fs::create_dir(&outside).unwrap();
            std::fs::write(outside.join("keep"), b"outside").unwrap();
            symlink(&outside, root.join("escape")).unwrap();

            let error = walk_tree(&root, &mut Recorder::default()).unwrap_err();

            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
            assert_eq!(std::fs::read(outside.join("keep")).unwrap(), b"outside");
        }

        struct SwapName {
            target: PathBuf,
            moved: PathBuf,
            outside: PathBuf,
            opened_inode: Option<u64>,
        }

        impl Visitor for SwapName {
            fn enter(
                &mut self,
                fd: BorrowedFd<'_>,
                path: &Path,
                directory: bool,
            ) -> Result<(), std::io::Error> {
                if !directory && path == self.target {
                    self.opened_inode =
                        Some(fstat(fd).map_err(std::io::Error::from)?.st_ino as u64);
                    std::fs::rename(&self.target, &self.moved)?;
                    symlink(&self.outside, &self.target)?;
                }
                Ok(())
            }
        }

        #[test]
        fn name_replacement_after_open_is_detected_without_following_replacement() {
            use std::os::unix::fs::MetadataExt;

            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("tenant");
            let target = root.join("entry");
            let moved = root.join("opened-entry");
            let outside = temp.path().join("outside");
            std::fs::create_dir(&root).unwrap();
            std::fs::write(&target, b"inside").unwrap();
            std::fs::write(&outside, b"outside").unwrap();
            let mut swap = SwapName {
                target: target.clone(),
                moved: moved.clone(),
                outside: outside.clone(),
                opened_inode: None,
            };

            assert!(!walk_tree(&root, &mut swap).unwrap());
            assert_eq!(
                swap.opened_inode,
                Some(std::fs::metadata(moved).unwrap().ino())
            );
            assert_eq!(std::fs::read(outside).unwrap(), b"outside");
        }

        #[test]
        fn project_attribute_updates_preserve_unrelated_fields_and_flags() {
            let original = Fsxattr {
                xflags: 0x4000_0001,
                extsize: 17,
                nextents: 23,
                project_id: 7,
                cowextsize: 31,
                pad: [9; 8],
            };

            let assigned = updated_attrs(original, 42, Some(true));
            assert_eq!(assigned.project_id, 42);
            assert_ne!(assigned.xflags & FS_XFLAG_PROJINHERIT, 0);
            assert_eq!(assigned.xflags & !FS_XFLAG_PROJINHERIT, original.xflags);
            assert_eq!(assigned.extsize, original.extsize);
            assert_eq!(assigned.nextents, original.nextents);
            assert_eq!(assigned.cowextsize, original.cowextsize);
            assert_eq!(assigned.pad, original.pad);

            let cleared = updated_attrs(assigned, 0, Some(false));
            assert_eq!(cleared.project_id, 0);
            assert_eq!(cleared.xflags & FS_XFLAG_PROJINHERIT, 0);
            assert_eq!(cleared.xflags & !FS_XFLAG_PROJINHERIT, original.xflags);
        }

        #[test]
        fn assign_only_moves_the_boundary_source_project() {
            let attrs = |project_id| Fsxattr {
                project_id,
                ..Fsxattr::default()
            };

            assert!(validate_assign(&attrs(7), 7, 42).is_ok());
            assert!(validate_assign(&attrs(42), 7, 42).is_ok());
            let error = validate_assign(&attrs(99), 7, 42).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        }

        #[test]
        fn pending_rollback_restores_source_id_and_inheritance() {
            let source_attrs = Fsxattr {
                project_id: 7,
                xflags: 0x4000_0001 | FS_XFLAG_PROJINHERIT,
                ..Fsxattr::default()
            };
            let source = source_project(source_attrs);
            let partially_adopted = Fsxattr {
                project_id: 42,
                xflags: 0x4000_0001 | FS_XFLAG_PROJINHERIT,
                ..Fsxattr::default()
            };

            assert_eq!(source.id, 7);
            assert!(source.inherit);
            assert!(validate_assign(&partially_adopted, source.id, 42).is_ok());

            let restored = updated_attrs(partially_adopted, source.id, Some(source.inherit));
            assert_eq!(restored.project_id, source.id);
            assert_ne!(restored.xflags & FS_XFLAG_PROJINHERIT, 0);
            assert_eq!(restored.xflags & !FS_XFLAG_PROJINHERIT, 0x4000_0001);

            let source_without_inherit = source_project(Fsxattr {
                project_id: 7,
                ..Fsxattr::default()
            });
            let restored = updated_attrs(
                partially_adopted,
                source_without_inherit.id,
                Some(source_without_inherit.inherit),
            );
            assert_eq!(restored.project_id, 7);
            assert_eq!(restored.xflags & FS_XFLAG_PROJINHERIT, 0);

            // A crash after rollback enters the root can leave its temporary
            // inheritance bit set. The stable parent must win when it names
            // the same source project, or retries would preserve that bit.
            let temporary_root = Fsxattr {
                project_id: 7,
                xflags: FS_XFLAG_PROJINHERIT,
                ..Fsxattr::default()
            };
            let stable_parent = Fsxattr {
                project_id: 7,
                ..Fsxattr::default()
            };
            assert!(!select_source(temporary_root, stable_parent, 42).inherit);

            // A genuinely distinct pre-adoption root project is retained.
            let distinct_root = Fsxattr {
                project_id: 9,
                ..Fsxattr::default()
            };
            assert_eq!(select_source(distinct_root, source_attrs, 42).id, 9);
        }

        #[test]
        fn clear_rejects_foreign_projects_and_broken_boundaries() {
            let attrs = |project_id, inherit| Fsxattr {
                project_id,
                xflags: if inherit { FS_XFLAG_PROJINHERIT } else { 0 },
                ..Fsxattr::default()
            };

            assert!(validate_clear(&attrs(42, true), 42, true).is_ok());
            assert!(validate_clear(&attrs(0, false), 42, true).is_ok());
            assert!(validate_clear(&attrs(42, false), 42, false).is_ok());
            assert_eq!(
                validate_clear(&attrs(99, true), 42, true)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidData
            );
            assert_eq!(
                validate_clear(&attrs(42, false), 42, true)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidData
            );
        }

        #[test]
        fn fsxattr_layout_matches_linux_uapi() {
            assert_eq!(std::mem::size_of::<Fsxattr>(), 28);
            assert_eq!(std::mem::align_of::<Fsxattr>(), 4);
        }
    }
}
