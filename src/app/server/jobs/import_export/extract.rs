use std::{
    fs::File,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

use flate2::read::GzDecoder;
use tar::{Archive, EntryType};

use super::{
    ARCHIVE_COPY_BUFFER_BYTES, ArchiveLimits, DATA_ARCHIVE_ENTRY_DISK_OVERHEAD_BYTES,
    DATA_ARCHIVE_LIMITS, MAX_DATA_ARCHIVE_BYTES, create::create_private_file,
    error::ImportExportError,
};
use crate::io::files::ensure_private_dir;

pub async fn extract_bounded_archive(
    artifact_path: PathBuf,
    data_parent: PathBuf,
    expected_root: String,
    max_extracted_bytes: u64,
) -> Result<(), ImportExportError> {
    tokio::task::spawn_blocking(move || {
        extract_bounded_archive_blocking(
            &artifact_path,
            &data_parent,
            &expected_root,
            max_extracted_bytes,
        )
    })
    .await
    .map_err(|error| ImportExportError::Join(error.to_string()))?
}

#[cfg(test)]
pub(super) fn extract_archive_blocking(
    artifact_path: &Path,
    data_parent: &Path,
    expected_root: &str,
) -> Result<(), ImportExportError> {
    extract_bounded_archive_blocking(
        artifact_path,
        data_parent,
        expected_root,
        MAX_DATA_ARCHIVE_BYTES,
    )
}

pub(super) fn extract_bounded_archive_blocking(
    artifact_path: &Path,
    data_parent: &Path,
    expected_root: &str,
    max_extracted_bytes: u64,
) -> Result<(), ImportExportError> {
    if max_extracted_bytes == 0 {
        return Err(ImportExportError::InvalidArchive(
            "archive extraction byte limit must be nonzero".to_string(),
        ));
    }
    ensure_private_dir(data_parent)?;
    let file = File::open(artifact_path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    let limits = ArchiveLimits {
        bytes: max_extracted_bytes.min(MAX_DATA_ARCHIVE_BYTES),
        ..DATA_ARCHIVE_LIMITS
    };
    extract_archive_entries(&mut archive, data_parent, expected_root, limits)?;
    Ok(())
}

#[cfg(test)]
pub(super) fn validate_archive_blocking(
    artifact_path: &Path,
    expected_root: &str,
) -> Result<(), ImportExportError> {
    let file = File::open(artifact_path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    let started = Instant::now();
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    for entry in archive.entries()? {
        let entry = entry?;
        let path = entry.path()?;
        entries += 1;
        validate_archive_limits(started, entries, bytes, DATA_ARCHIVE_LIMITS)?;
        validate_archive_path(&path, expected_root, DATA_ARCHIVE_LIMITS.depth)?;
        let entry_type = entry.header().entry_type();
        validate_entry_type(entry_type)?;
        bytes = account_extracted_entry(bytes, entry.header().size()?)?;
        validate_archive_limits(started, entries, bytes, DATA_ARCHIVE_LIMITS)?;
    }
    Ok(())
}

pub(super) fn validate_archive_path(
    path: &Path,
    expected_root: &str,
    max_depth: usize,
) -> Result<(), ImportExportError> {
    let mut components = path.components();
    let first = components
        .next()
        .ok_or_else(|| ImportExportError::InvalidArchive("empty archive path".to_string()))?;
    if !matches!(first, Component::Normal(name) if name.to_str() == Some(expected_root)) {
        return Err(ImportExportError::InvalidArchive(format!(
            "archive entry must be under {expected_root}"
        )));
    }
    let mut depth = 1_usize;
    for component in components {
        if !matches!(component, Component::Normal(_)) {
            return Err(ImportExportError::InvalidArchive(format!(
                "unsafe archive path {}",
                path.display()
            )));
        }
        depth += 1;
        if depth > max_depth {
            return Err(ImportExportError::InvalidArchive(format!(
                "archive path depth exceeds {max_depth}"
            )));
        }
    }
    Ok(())
}

fn validate_entry_type(entry_type: EntryType) -> Result<(), ImportExportError> {
    if entry_type.is_file() || entry_type.is_dir() {
        Ok(())
    } else {
        Err(ImportExportError::InvalidArchive(
            "archive contains a symbolic link or unsupported special entry".to_string(),
        ))
    }
}

fn require_real_dir(path: &Path) -> Result<(), ImportExportError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ImportExportError::InvalidArchive(format!(
            "archive destination must be a real directory: {}",
            path.display()
        )));
    }
    Ok(())
}

pub(super) fn extract_archive_entries<R: Read>(
    archive: &mut Archive<R>,
    data_parent: &Path,
    expected_root: &str,
    limits: ArchiveLimits,
) -> Result<(), ImportExportError> {
    require_real_dir(data_parent)?;
    let started = Instant::now();
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        entries += 1;
        validate_archive_limits(started, entries, bytes, limits)?;
        let path = entry.path()?.to_path_buf();
        validate_archive_path(&path, expected_root, limits.depth)?;
        let entry_type = entry.header().entry_type();
        validate_entry_type(entry_type)?;
        let entry_size = entry.header().size()?;
        bytes = account_extracted_entry(bytes, entry_size)?;
        validate_archive_limits(started, entries, bytes, limits)?;
        let target = data_parent.join(&path);
        if !target.starts_with(data_parent) {
            return Err(ImportExportError::InvalidArchive(format!(
                "unsafe archive path {}",
                path.display()
            )));
        }
        if entry_type.is_dir() {
            ensure_private_dir(&target)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            ensure_private_dir(parent)?;
        }
        let mut output = create_private_file(&target)?;
        copy_archive_entry(&mut entry, &mut output, entry_size, started, limits)?;
        output.flush()?;
    }
    Ok(())
}

fn account_extracted_entry(current: u64, entry_size: u64) -> Result<u64, ImportExportError> {
    current
        .checked_add(entry_size)
        .and_then(|bytes| bytes.checked_add(DATA_ARCHIVE_ENTRY_DISK_OVERHEAD_BYTES))
        .ok_or_else(|| ImportExportError::InvalidArchive("archive size overflow".to_string()))
}

pub(super) fn validate_archive_limits(
    started: Instant,
    entries: usize,
    bytes: u64,
    limits: ArchiveLimits,
) -> Result<(), ImportExportError> {
    if entries > limits.entries {
        return Err(ImportExportError::InvalidArchive(format!(
            "archive has more than {} entries",
            limits.entries
        )));
    }
    if bytes > limits.bytes {
        return Err(ImportExportError::InvalidArchive(format!(
            "archive expands beyond {} bytes",
            limits.bytes
        )));
    }
    if started.elapsed() > limits.deadline {
        return Err(ImportExportError::InvalidArchive(
            "archive operation exceeded time limit".to_string(),
        ));
    }
    Ok(())
}

fn copy_archive_entry<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    expected_size: u64,
    started: Instant,
    limits: ArchiveLimits,
) -> Result<(), ImportExportError> {
    let mut remaining = expected_size;
    let mut buffer = [0_u8; ARCHIVE_COPY_BUFFER_BYTES];
    while remaining > 0 {
        validate_archive_limits(started, 0, expected_size - remaining, limits)?;
        let wanted = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = reader.read(&mut buffer[..wanted])?;
        if read == 0 {
            return Err(ImportExportError::InvalidArchive(
                "archive entry ended before its declared size".to_string(),
            ));
        }
        writer.write_all(&buffer[..read])?;
        remaining -= read as u64;
    }
    Ok(())
}

pub(super) struct DeadlineBoundedReader<R> {
    pub(super) inner: R,
    pub(super) remaining: u64,
    pub(super) started: Instant,
    pub(super) deadline: Duration,
}

impl<R: Read> Read for DeadlineBoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.started.elapsed() > self.deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "archive operation exceeded time limit",
            ));
        }
        if self.remaining == 0 || buffer.is_empty() {
            return Ok(0);
        }
        let wanted =
            usize::try_from(self.remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = self.inner.read(&mut buffer[..wanted])?;
        self.remaining = self.remaining.saturating_sub(read as u64);
        Ok(read)
    }
}

pub(super) fn validate_archive_path_depth(
    path: &Path,
    max_depth: usize,
) -> Result<(), ImportExportError> {
    let depth = path
        .components()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count();
    if depth > max_depth {
        return Err(ImportExportError::InvalidArchive(format!(
            "archive path depth exceeds {max_depth}"
        )));
    }
    Ok(())
}
