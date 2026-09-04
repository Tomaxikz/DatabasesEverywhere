use std::{
    io::{Error as IoError, ErrorKind},
    path::Path,
    time::{Duration, Instant},
};

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, open, openat, statat};

const MAX_ENTRIES: usize = 1_000_000;
const MAX_DEPTH: usize = 128;

pub(super) fn directory_size(path: &Path, budget: Duration) -> Result<u64, IoError> {
    let started = Instant::now();
    let root = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(IoError::from)?;
    let mut directories = vec![(root, 0_usize)];
    let mut visited_entries = 0_usize;
    let mut total = 0_u64;

    while let Some((directory, depth)) = directories.pop() {
        check_budget(started, budget, visited_entries)?;
        let entries = Dir::read_from(&directory).map_err(IoError::from)?;
        for entry in entries {
            check_budget(started, budget, visited_entries)?;
            let entry = entry.map_err(IoError::from)?;
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            visited_entries = visited_entries.checked_add(1).ok_or_else(|| {
                IoError::new(ErrorKind::InvalidData, "disk scan entry count overflow")
            })?;
            if visited_entries > MAX_ENTRIES {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    format!("disk scan exceeded {MAX_ENTRIES} entries"),
                ));
            }

            let stat =
                statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(IoError::from)?;
            match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => {
                    if depth >= MAX_DEPTH {
                        return Err(IoError::new(
                            ErrorKind::InvalidData,
                            format!("disk scan exceeded depth {MAX_DEPTH}"),
                        ));
                    }
                    let child = openat(
                        &directory,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(IoError::from)?;
                    directories.push((child, depth + 1));
                }
                FileType::RegularFile => {
                    let size = u64::try_from(stat.st_size).map_err(|_| {
                        IoError::new(ErrorKind::InvalidData, "file reported a negative size")
                    })?;
                    total = total.checked_add(size).ok_or_else(|| {
                        IoError::new(ErrorKind::InvalidData, "disk usage size overflow")
                    })?;
                }
                _ => {}
            }
        }
    }
    Ok(total)
}

fn check_budget(started: Instant, budget: Duration, visited_entries: usize) -> Result<(), IoError> {
    if started.elapsed() >= budget {
        return Err(IoError::new(
            ErrorKind::TimedOut,
            format!("disk scan timed out after {visited_entries} entries"),
        ));
    }
    Ok(())
}
