use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataArchiveSourcePolicy {
    Strict,
    MysqlDataDirectory,
}

pub async fn create_bounded_archive_with_policy(
    data_dir: PathBuf,
    artifact_path: PathBuf,
    policy: DataArchiveSourcePolicy,
    max_output_bytes: u64,
) -> Result<(), ImportExportError> {
    tokio::task::spawn_blocking(move || {
        create_bounded_archive_blocking(&data_dir, &artifact_path, policy, max_output_bytes)
    })
    .await
    .map_err(|error| ImportExportError::Join(error.to_string()))?
}

pub async fn create_bounded_archive(
    data_dir: PathBuf,
    artifact_path: PathBuf,
    max_output_bytes: u64,
) -> Result<(), ImportExportError> {
    create_bounded_archive_with_policy(
        data_dir,
        artifact_path,
        DataArchiveSourcePolicy::Strict,
        max_output_bytes,
    )
    .await
}

#[cfg(test)]
pub(super) fn create_archive_blocking(
    data_dir: &Path,
    artifact_path: &Path,
    policy: DataArchiveSourcePolicy,
) -> Result<(), ImportExportError> {
    create_bounded_archive_blocking(data_dir, artifact_path, policy, u64::MAX)
}

pub(super) fn create_bounded_archive_blocking(
    data_dir: &Path,
    artifact_path: &Path,
    policy: DataArchiveSourcePolicy,
    max_output_bytes: u64,
) -> Result<(), ImportExportError> {
    let parent = artifact_path
        .parent()
        .ok_or_else(|| ImportExportError::InvalidArchive("artifact has no parent".to_string()))?;
    ensure_private_dir(parent)?;
    let file = create_private_file(artifact_path)?;
    let root_name = data_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ImportExportError::InvalidArchive("invalid data dir".to_string()))?;
    let result = (|| {
        let encoder = GzEncoder::new(
            BoundedWriter::new(file, max_output_bytes),
            Compression::new(ARCHIVE_GZIP_LEVEL),
        );
        let mut builder = Builder::new(encoder);
        builder.follow_symlinks(false);
        append_archive_tree(&mut builder, data_dir, Path::new(root_name), policy)?;
        let encoder = builder.into_inner()?;
        encoder.finish()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(artifact_path);
    }
    result
}

struct BoundedWriter<W> {
    pub(super) inner: W,
    pub(super) remaining: u64,
}

impl<W> BoundedWriter<W> {
    pub(super) const fn new(inner: W, max_bytes: u64) -> Self {
        Self {
            inner,
            remaining: max_bytes,
        }
    }
}

impl<W: Write> Write for BoundedWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() as u64 > self.remaining {
            return Err(io::Error::other(
                "archive output exceeds configured byte limit",
            ));
        }
        let written = self.inner.write(buffer)?;
        self.remaining = self.remaining.saturating_sub(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn append_archive_tree<W: Write>(
    builder: &mut Builder<W>,
    data_dir: &Path,
    archive_root: &Path,
    policy: DataArchiveSourcePolicy,
) -> Result<(), ImportExportError> {
    let root_metadata = std::fs::symlink_metadata(data_dir)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(ImportExportError::InvalidArchive(
            "data root must be a real directory".to_string(),
        ));
    }

    builder.append_dir(archive_root, data_dir)?;
    let started = Instant::now();
    let mut entries = 1_usize;
    let mut bytes = 0_u64;
    let mut pending = vec![(data_dir.to_path_buf(), archive_root.to_path_buf())];
    while let Some((source_dir, archive_dir)) = pending.pop() {
        let mut children = Vec::new();
        for child in std::fs::read_dir(&source_dir)? {
            validate_archive_limits(
                started,
                entries.saturating_add(children.len()).saturating_add(1),
                bytes,
                DATA_ARCHIVE_LIMITS,
            )?;
            children.push(child?);
        }
        children.sort_by_key(std::fs::DirEntry::file_name);
        for child in children {
            entries += 1;
            validate_archive_limits(started, entries, bytes, DATA_ARCHIVE_LIMITS)?;
            let source = child.path();
            let archive_path = archive_dir.join(child.file_name());
            validate_archive_path_depth(&archive_path, DATA_ARCHIVE_LIMITS.depth)?;
            let metadata = std::fs::symlink_metadata(&source)?;
            if metadata.file_type().is_symlink() {
                let link_name = std::fs::read_link(&source)?;
                if should_skip_source_symlink(policy, &source, data_dir, &link_name) {
                    continue;
                }
                return Err(ImportExportError::InvalidArchive(format!(
                    "data archive refuses symbolic link {}",
                    source.display()
                )));
            }
            if metadata.is_dir() {
                builder.append_dir(&archive_path, &source)?;
                pending.push((source, archive_path));
                continue;
            }
            if !metadata.is_file() {
                return Err(ImportExportError::InvalidArchive(format!(
                    "data archive refuses special file {}",
                    source.display()
                )));
            }

            bytes = bytes.checked_add(metadata.len()).ok_or_else(|| {
                ImportExportError::InvalidArchive("archive size overflow".to_string())
            })?;
            validate_archive_limits(started, entries, bytes, DATA_ARCHIVE_LIMITS)?;
            let file = open_verified_regular_file(&source, &metadata)?;
            append_bounded_archive_file(
                builder,
                &archive_path,
                file,
                &metadata,
                started,
                DATA_ARCHIVE_LIMITS,
            )?;
        }
    }
    Ok(())
}

fn should_skip_source_symlink(
    policy: DataArchiveSourcePolicy,
    source: &Path,
    data_dir: &Path,
    link_name: &Path,
) -> bool {
    policy == DataArchiveSourcePolicy::MysqlDataDirectory
        && source.parent() == Some(data_dir)
        && source.file_name().is_some_and(|name| name == "mysql.sock")
        && link_name == Path::new("/var/run/mysqld/mysqld.sock")
}

pub(super) fn append_bounded_archive_file<W: Write>(
    builder: &mut Builder<W>,
    archive_path: &Path,
    file: File,
    metadata: &std::fs::Metadata,
    started: Instant,
    limits: ArchiveLimits,
) -> Result<(), ImportExportError> {
    let expected_size = metadata.len();
    let mut header = tar::Header::new_gnu();
    header.set_metadata(metadata);
    header.set_entry_type(EntryType::Regular);
    header.set_size(expected_size);
    let mut reader = DeadlineBoundedReader {
        inner: file,
        remaining: expected_size,
        started,
        deadline: limits.deadline,
    };
    builder.append_data(&mut header, archive_path, &mut reader)?;
    if reader.remaining != 0 {
        return Err(ImportExportError::InvalidArchive(format!(
            "data file shrank while archiving {}",
            archive_path.display()
        )));
    }
    Ok(())
}

fn open_verified_regular_file(
    path: &Path,
    expected: &std::fs::Metadata,
) -> Result<File, ImportExportError> {
    let file = File::open(path)?;
    let opened = file.metadata()?;
    let current = std::fs::symlink_metadata(path)?;
    if current.file_type().is_symlink()
        || !opened.is_file()
        || opened.len() != expected.len()
        || current.len() != expected.len()
        || !same_file_identity(expected, &opened)
        || !same_file_identity(&opened, &current)
    {
        return Err(ImportExportError::InvalidArchive(format!(
            "data file changed while archiving {}",
            path.display()
        )));
    }
    Ok(file)
}

fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

pub(super) fn create_private_file(path: &Path) -> Result<File, ImportExportError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
