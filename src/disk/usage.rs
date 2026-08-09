use std::{
    io::{Error, ErrorKind},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use rustix::{
    fs::{AtFlags, Dir, FileType, Mode, OFlags, open, openat, statat},
    io::Errno,
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DirectoryUsage {
    /// Sum of apparent file lengths. Sparse and preallocated files can make
    /// this differ materially from host space consumption.
    pub logical_bytes: u64,
    /// Filesystem blocks allocated to files and directories (`st_blocks *
    /// 512`), matching host-capacity pressure more closely than apparent size.
    pub physical_bytes: u64,
    pub entries: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ScanLimits {
    pub timeout: Duration,
    pub max_entries: usize,
    pub max_depth: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_entries: 1_000_000,
            max_depth: 128,
        }
    }
}

pub async fn scan_directory(path: PathBuf, limits: ScanLimits) -> Result<DirectoryUsage, Error> {
    tokio::task::spawn_blocking(move || scan_directory_blocking(&path, limits))
        .await
        .map_err(Error::other)?
}

pub fn scan_directory_blocking(path: &Path, limits: ScanLimits) -> Result<DirectoryUsage, Error> {
    let started = Instant::now();
    let root_metadata = std::fs::symlink_metadata(path)?;
    if !root_metadata.file_type().is_dir() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "disk scan root is not a directory",
        ));
    }
    let root = open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(Error::from)?;
    let mut scanner = DirectoryScanner {
        started,
        limits,
        usage: DirectoryUsage {
            physical_bytes: root_metadata.blocks().saturating_mul(512),
            ..DirectoryUsage::default()
        },
    };
    scanner.scan_open_directory(&root, 0)?;
    Ok(scanner.usage)
}

struct DirectoryScanner {
    started: Instant,
    limits: ScanLimits,
    usage: DirectoryUsage,
}

impl DirectoryScanner {
    /// Depth-first traversal holds only the current directory and its
    /// ancestors open. A tenant-created wide tree therefore consumes O(depth)
    /// descriptors instead of one descriptor per queued directory.
    fn scan_open_directory(
        &mut self,
        directory: &rustix::fd::OwnedFd,
        depth: usize,
    ) -> Result<(), Error> {
        ensure_budget(self.started, self.limits, self.usage.entries)?;
        let entries = Dir::read_from(directory).map_err(Error::from)?;
        for entry in entries {
            ensure_budget(self.started, self.limits, self.usage.entries)?;
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if transient_entry_error(error) => continue,
                Err(error) => return Err(Error::from(error)),
            };
            let name = entry.file_name();
            if matches!(name.to_bytes(), b"." | b"..") {
                continue;
            }
            self.usage.entries = self.usage.entries.checked_add(1).ok_or_else(|| {
                Error::new(ErrorKind::InvalidData, "disk scan entry count overflow")
            })?;
            if self.usage.entries > self.limits.max_entries as u64 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("disk scan exceeded {} entries", self.limits.max_entries),
                ));
            }

            let stat = match statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                // Database WAL/SST/temp files are renamed and unlinked during
                // ordinary operation. A vanished/stale entry no longer holds
                // linked space in this tree and must not count as a scanner
                // failure that could stop a healthy, busy database.
                Err(error) if transient_entry_error(error) => continue,
                Err(error) => return Err(Error::from(error)),
            };
            let blocks = u64::try_from(stat.st_blocks).map_err(|_| {
                Error::new(
                    ErrorKind::InvalidData,
                    "file reported a negative allocated block count",
                )
            })?;
            let allocated = blocks.checked_mul(512).ok_or_else(|| {
                Error::new(ErrorKind::InvalidData, "allocated disk usage overflow")
            })?;
            self.usage.physical_bytes = self
                .usage
                .physical_bytes
                .checked_add(allocated)
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "disk usage overflow"))?;

            match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => {
                    if depth >= self.limits.max_depth {
                        return Err(Error::new(
                            ErrorKind::InvalidData,
                            format!("disk scan exceeded depth {}", self.limits.max_depth),
                        ));
                    }
                    let child = match openat(
                        directory,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    ) {
                        Ok(child) => child,
                        Err(error) if transient_entry_error(error) => continue,
                        Err(error) => return Err(Error::from(error)),
                    };
                    self.scan_open_directory(&child, depth + 1)?;
                }
                FileType::RegularFile => {
                    let size = u64::try_from(stat.st_size).map_err(|_| {
                        Error::new(ErrorKind::InvalidData, "file reported a negative size")
                    })?;
                    self.usage.logical_bytes =
                        self.usage.logical_bytes.checked_add(size).ok_or_else(|| {
                            Error::new(ErrorKind::InvalidData, "logical disk usage overflow")
                        })?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn transient_entry_error(error: Errno) -> bool {
    matches!(error, Errno::NOENT | Errno::STALE)
}

fn ensure_budget(started: Instant, limits: ScanLimits, entries: u64) -> Result<(), Error> {
    if started.elapsed() >= limits.timeout {
        return Err(Error::new(
            ErrorKind::TimedOut,
            format!("disk scan timed out after {entries} entries"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use super::*;

    #[test]
    fn reports_logical_and_allocated_bytes_without_following_symlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let data = temporary.path().join("data");
        let outside = temporary.path().join("outside");
        fs::create_dir_all(data.join("nested")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(data.join("root.bin"), [0_u8; 7]).unwrap();
        fs::write(data.join("nested/child.bin"), [0_u8; 11]).unwrap();
        fs::write(outside.join("secret.bin"), [0_u8; 101]).unwrap();
        symlink(&outside, data.join("outside-link")).unwrap();

        let usage = scan_directory_blocking(&data, ScanLimits::default()).unwrap();
        assert_eq!(usage.logical_bytes, 18);
        assert!(usage.physical_bytes >= 18);
        assert_eq!(usage.entries, 4);
    }

    #[test]
    fn enforces_the_entry_bound() {
        let temporary = tempfile::tempdir().unwrap();
        fs::write(temporary.path().join("one"), b"1").unwrap();
        fs::write(temporary.path().join("two"), b"2").unwrap();

        let error = scan_directory_blocking(
            temporary.path(),
            ScanLimits {
                max_entries: 1,
                ..ScanLimits::default()
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("exceeded 1 entries"));
    }

    #[test]
    fn scans_a_wide_tree_without_retaining_one_descriptor_per_directory() {
        let temporary = tempfile::tempdir().unwrap();
        for index in 0..1_024 {
            fs::create_dir(temporary.path().join(format!("child-{index}"))).unwrap();
        }

        let usage = scan_directory_blocking(temporary.path(), ScanLimits::default()).unwrap();
        assert_eq!(usage.entries, 1_024);
    }

    #[test]
    fn database_churn_entry_errors_are_retryable_but_permissions_are_not() {
        assert!(transient_entry_error(Errno::NOENT));
        assert!(transient_entry_error(Errno::STALE));
        assert!(!transient_entry_error(Errno::ACCESS));
        assert!(!transient_entry_error(Errno::IO));
    }
}
