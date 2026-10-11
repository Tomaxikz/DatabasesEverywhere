//! Packages a completed online backup capture into a data directory archive.
//!
//! The source is daemon-owned staging written by a native backup tool that
//! has already exited, never a live database directory. Every file must read
//! back at exactly the size recorded in its tar header; a file that shrinks or
//! grows while being packaged fails the archive instead of being padded or
//! truncated, so the result never contains fabricated bytes.

use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    time::Instant,
};

use flate2::{Compression, write::GzEncoder};
use tar::{Builder, EntryType};

use super::{
    ARCHIVE_GZIP_LEVEL, DATA_ARCHIVE_LIMITS,
    create::{BoundedWriter, create_private_file},
    error::ImportExportError,
    extract::{validate_archive_limits, validate_archive_path_depth},
};
use crate::io::files::ensure_private_dir;

type ArchiveBuilder = Builder<GzEncoder<BoundedWriter<File>>>;

pub struct StagedDataArchive {
    builder: Option<ArchiveBuilder>,
    artifact_path: PathBuf,
    root: PathBuf,
    started: Instant,
    entries: usize,
    bytes: u64,
}

impl StagedDataArchive {
    /// Starts an archive whose root entry is `root_name` (the restore target's
    /// data directory name), using `root_reference` for its metadata.
    pub fn create(
        root_name: &str,
        root_reference: &Path,
        artifact_path: &Path,
        max_output_bytes: u64,
    ) -> Result<Self, ImportExportError> {
        let root_metadata = std::fs::symlink_metadata(root_reference)?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(ImportExportError::InvalidArchive(
                "staged capture root must be a real directory".to_string(),
            ));
        }
        if !crate::io::files::is_safe_flat_file_name(root_name) {
            return Err(ImportExportError::InvalidArchive(
                "invalid archive root name".to_string(),
            ));
        }
        let parent = artifact_path.parent().ok_or_else(|| {
            ImportExportError::InvalidArchive("artifact has no parent".to_string())
        })?;
        ensure_private_dir(parent)?;
        let file = create_private_file(artifact_path)?;
        let encoder = GzEncoder::new(
            BoundedWriter::new(file, max_output_bytes),
            Compression::new(ARCHIVE_GZIP_LEVEL),
        );
        let mut builder = Builder::new(encoder);
        builder.follow_symlinks(false);
        let mut archive = Self {
            builder: Some(builder),
            artifact_path: artifact_path.to_path_buf(),
            root: PathBuf::from(root_name),
            started: Instant::now(),
            entries: 1,
            bytes: 0,
        };
        let root = archive.root.clone();
        archive.builder()?.append_dir(&root, root_reference)?;
        Ok(archive)
    }

    /// Adds `archive_relative` and each missing parent as directory entries
    /// carrying `reference` metadata.
    pub fn append_directory_chain(
        &mut self,
        archive_relative: &Path,
        reference: &Path,
    ) -> Result<(), ImportExportError> {
        let mut current = PathBuf::new();
        for component in archive_relative.components() {
            let std::path::Component::Normal(name) = component else {
                return Err(ImportExportError::InvalidArchive(
                    "archive directory must be a plain relative path".to_string(),
                ));
            };
            current.push(name);
            let archive_path = self.root.join(&current);
            self.count_entry(&archive_path, 0)?;
            self.builder()?.append_dir(&archive_path, reference)?;
        }
        Ok(())
    }

    /// Recursively appends `source_dir` below `archive_relative`. Symlinks and
    /// special files are refused; nothing in staging may disappear meanwhile.
    pub fn append_tree(
        &mut self,
        source_dir: &Path,
        archive_relative: &Path,
    ) -> Result<(), ImportExportError> {
        let mut pending = vec![(source_dir.to_path_buf(), archive_relative.to_path_buf())];
        while let Some((directory, relative_dir)) = pending.pop() {
            let mut children = std::fs::read_dir(&directory)?.collect::<Result<Vec<_>, _>>()?;
            children.sort_by_key(std::fs::DirEntry::file_name);
            for child in children {
                let relative = relative_dir.join(child.file_name());
                let source = child.path();
                let metadata = std::fs::symlink_metadata(&source)?;
                let archive_path = self.root.join(&relative);
                self.count_entry(&archive_path, 0)?;
                if metadata.file_type().is_symlink() {
                    return Err(ImportExportError::InvalidArchive(format!(
                        "capture archive refuses symbolic link {}",
                        source.display()
                    )));
                }
                if metadata.is_dir() {
                    self.builder()?.append_dir(&archive_path, &source)?;
                    pending.push((source, relative));
                    continue;
                }
                if !metadata.is_file() {
                    return Err(ImportExportError::InvalidArchive(format!(
                        "capture archive refuses special file {}",
                        source.display()
                    )));
                }
                self.append_exact_file(&source, &archive_path)?;
            }
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), ImportExportError> {
        let builder = self.builder.take().ok_or_else(|| {
            ImportExportError::InvalidArchive("capture archive was already finished".to_string())
        })?;
        let result = (|| {
            let encoder = builder.into_inner()?;
            let writer = encoder.finish()?;
            writer.inner.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&self.artifact_path);
        }
        result
    }

    fn builder(&mut self) -> Result<&mut ArchiveBuilder, ImportExportError> {
        self.builder.as_mut().ok_or_else(|| {
            ImportExportError::InvalidArchive("capture archive was already finished".to_string())
        })
    }

    fn count_entry(&mut self, archive_path: &Path, size: u64) -> Result<(), ImportExportError> {
        self.entries += 1;
        self.bytes = self.bytes.checked_add(size).ok_or_else(|| {
            ImportExportError::InvalidArchive("archive size overflow".to_string())
        })?;
        validate_archive_path_depth(archive_path, DATA_ARCHIVE_LIMITS.depth)?;
        validate_archive_limits(self.started, self.entries, self.bytes, DATA_ARCHIVE_LIMITS)
    }

    fn append_exact_file(
        &mut self,
        source: &Path,
        archive_path: &Path,
    ) -> Result<(), ImportExportError> {
        let file = File::open(source)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(ImportExportError::InvalidArchive(format!(
                "capture file {} changed type while packaging",
                source.display()
            )));
        }
        let size = metadata.len();
        self.bytes = self.bytes.checked_add(size).ok_or_else(|| {
            ImportExportError::InvalidArchive("archive size overflow".to_string())
        })?;
        validate_archive_limits(self.started, self.entries, self.bytes, DATA_ARCHIVE_LIMITS)?;
        let mut header = tar::Header::new_gnu();
        header.set_metadata(&metadata);
        header.set_entry_type(EntryType::Regular);
        header.set_size(size);
        let mut reader = ExactReader {
            inner: file,
            remaining: size,
            started: self.started,
            source: source.to_path_buf(),
        };
        self.builder()?
            .append_data(&mut header, archive_path, &mut reader)?;
        reader.ensure_at_end()?;
        Ok(())
    }
}

impl Drop for StagedDataArchive {
    fn drop(&mut self) {
        if self.builder.take().is_some() {
            let _ = std::fs::remove_file(&self.artifact_path);
        }
    }
}

/// Reads exactly the header size; early EOF or trailing bytes are errors.
struct ExactReader<R> {
    inner: R,
    remaining: u64,
    started: Instant,
    source: PathBuf,
}

impl<R: Read> ExactReader<R> {
    fn ensure_at_end(&mut self) -> io::Result<()> {
        let mut probe = [0_u8; 1];
        if self.inner.read(&mut probe)? != 0 {
            return Err(self.changed("grew"));
        }
        Ok(())
    }

    fn changed(&self, how: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "capture file {} {how} while it was being packaged",
                self.source.display()
            ),
        )
    }
}

impl<R: Read> Read for ExactReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.started.elapsed() > DATA_ARCHIVE_LIMITS.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "archive operation exceeded time limit",
            ));
        }
        if self.remaining == 0 || buffer.is_empty() {
            return Ok(0);
        }
        let wanted =
            usize::try_from(self.remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = self.inner.read(&mut buffer[..wanted])?;
        if read == 0 {
            return Err(self.changed("shrank"));
        }
        self.remaining = self.remaining.saturating_sub(read as u64);
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::GzDecoder;

    fn entries(artifact: &Path) -> Vec<(String, Vec<u8>)> {
        let mut archive = tar::Archive::new(GzDecoder::new(File::open(artifact).unwrap()));
        archive
            .entries()
            .unwrap()
            .map(|entry| {
                let mut entry = entry.unwrap();
                let path = entry.path().unwrap().to_string_lossy().into_owned();
                let mut contents = Vec::new();
                entry.read_to_end(&mut contents).unwrap();
                (path, contents)
            })
            .collect()
    }

    #[test]
    fn packages_a_capture_below_its_restore_target() {
        let temp = tempfile::tempdir().unwrap();
        let capture = temp.path().join("capture/data");
        std::fs::create_dir_all(capture.join("base")).unwrap();
        std::fs::write(capture.join("base/1"), b"page").unwrap();
        std::fs::write(capture.join("backup_label"), b"label").unwrap();
        let artifact = temp.path().join("out/archive.tar.gz");

        let mut archive =
            StagedDataArchive::create("inst_live", &capture, &artifact, u64::MAX).unwrap();
        archive
            .append_directory_chain(Path::new("pgdata"), &capture)
            .unwrap();
        archive.append_tree(&capture, Path::new("pgdata")).unwrap();
        archive.finish().unwrap();

        let entries = entries(&artifact);
        let names = entries
            .iter()
            .map(|(name, _)| name.trim_end_matches('/'))
            .collect::<Vec<_>>();
        assert_eq!(names[0], "inst_live");
        assert!(names.contains(&"inst_live/pgdata"));
        assert!(names.contains(&"inst_live/pgdata/base/1"));
        assert!(entries.iter().any(|(name, contents)| {
            name == "inst_live/pgdata/backup_label" && contents == b"label"
        }));
    }

    #[test]
    fn abandoned_archive_is_removed() {
        let temp = tempfile::tempdir().unwrap();
        let capture = temp.path().join("capture");
        std::fs::create_dir_all(&capture).unwrap();
        let artifact = temp.path().join("out/archive.tar.gz");
        let archive = StagedDataArchive::create("inst", &capture, &artifact, u64::MAX).unwrap();
        assert!(artifact.exists());
        drop(archive);
        assert!(!artifact.exists());
    }

    #[test]
    fn shrinking_or_growing_files_fail_instead_of_being_padded() {
        let mut shrank = ExactReader {
            inner: &b"ab"[..],
            remaining: 4,
            started: Instant::now(),
            source: PathBuf::from("file"),
        };
        let mut output = Vec::new();
        let error = shrank.read_to_end(&mut output).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let mut grew = ExactReader {
            inner: &b"abcd"[..],
            remaining: 2,
            started: Instant::now(),
            source: PathBuf::from("file"),
        };
        let mut output = Vec::new();
        grew.read_to_end(&mut output).unwrap();
        assert_eq!(output, b"ab");
        assert!(grew.ensure_at_end().is_err());
    }

    #[test]
    fn refuses_symlinks_in_staging() {
        let temp = tempfile::tempdir().unwrap();
        let capture = temp.path().join("capture");
        std::fs::create_dir_all(&capture).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", capture.join("link")).unwrap();
        let artifact = temp.path().join("out/archive.tar.gz");
        let mut archive = StagedDataArchive::create("inst", &capture, &artifact, u64::MAX).unwrap();
        assert!(archive.append_tree(&capture, Path::new("data")).is_err());
    }
}
