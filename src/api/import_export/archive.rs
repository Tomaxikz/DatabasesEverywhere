//! Logical dump decompression and safe archive extraction.

use super::{files::*, *};

pub(super) async fn prepare_logical_import_artifact(
    protocol: Protocol,
    artifact_path: &FsPath,
    host_temp: &FsPath,
    staging_root: &FsPath,
    options: &ImportOptions,
    max_unarchived_bytes: u64,
) -> Result<(), ApiError> {
    let Some(requested_format) = options.archive_format.as_deref() else {
        ensure_source_within_limit(artifact_path, max_unarchived_bytes).await?;
        copy_file(artifact_path, host_temp).await?;
        return Ok(());
    };

    let format = ImportArchiveFormat::parse(requested_format)?;
    match format {
        ImportArchiveFormat::Plain => {
            ensure_source_within_limit(artifact_path, max_unarchived_bytes).await?;
            copy_file(artifact_path, host_temp).await
        }
        ImportArchiveFormat::Gzip => {
            decompress_gzip(artifact_path, host_temp, max_unarchived_bytes).await
        }
        ImportArchiveFormat::Bzip2 => {
            decompress_bzip2(artifact_path, host_temp, max_unarchived_bytes).await
        }
        ImportArchiveFormat::Tar | ImportArchiveFormat::TarGzip => {
            let staging = staging_root.join(format!(".dbe-unarchive-{}", uuid::Uuid::new_v4()));
            let result = match extract_tar_archive(
                artifact_path,
                &staging,
                format == ImportArchiveFormat::TarGzip,
                max_unarchived_bytes,
            )
            .await
            {
                Ok(()) => install_selected_dump(protocol, &staging, host_temp).await,
                Err(error) => Err(error),
            };
            cleanup_dir(&staging).await;
            result
        }
        ImportArchiveFormat::Zip => {
            let staging = staging_root.join(format!(".dbe-unarchive-{}", uuid::Uuid::new_v4()));
            let result =
                match extract_zip_archive(artifact_path, &staging, max_unarchived_bytes).await {
                    Ok(()) => install_selected_dump(protocol, &staging, host_temp).await,
                    Err(error) => Err(error),
                };
            cleanup_dir(&staging).await;
            result
        }
    }
}

async fn ensure_source_within_limit(path: &FsPath, limit: u64) -> Result<(), ApiError> {
    let size = ensure_import_file_size(path).await?;
    if size > limit {
        return Err(ApiError::BadRequest(format!(
            "import artifact is too large after preparation: {size} bytes exceeds {limit} bytes"
        )));
    }
    Ok(())
}

pub(super) async fn decompress_gzip(
    source: &FsPath,
    target: &FsPath,
    max_unarchived_bytes: u64,
) -> Result<(), ApiError> {
    let source = source.to_path_buf();
    let target = target.to_path_buf();
    run_archive_file_operation(
        "decompress gzip",
        true,
        move |deadline| -> Result<(), std::io::Error> {
            let input = std::fs::File::open(source)?;
            let mut decoder = flate2::read::GzDecoder::new(input);
            write_new_private_file(&target, |mut output| {
                copy_limited_until(&mut decoder, &mut output, max_unarchived_bytes, deadline)?;
                output.flush()
            })
        },
    )
    .await
}

pub(super) async fn decompress_bzip2(
    source: &FsPath,
    target: &FsPath,
    max_unarchived_bytes: u64,
) -> Result<(), ApiError> {
    let source = source.to_path_buf();
    let target = target.to_path_buf();
    run_archive_file_operation(
        "decompress bzip2",
        true,
        move |deadline| -> Result<(), std::io::Error> {
            let input = std::fs::File::open(source)?;
            let mut decoder = bzip2::read::BzDecoder::new(input);
            write_new_private_file(&target, |mut output| {
                copy_limited_until(&mut decoder, &mut output, max_unarchived_bytes, deadline)?;
                output.flush()
            })
        },
    )
    .await
}

pub(super) async fn extract_tar_archive(
    source: &FsPath,
    target_dir: &FsPath,
    gzipped: bool,
    max_unarchived_bytes: u64,
) -> Result<(), ApiError> {
    let source = source.to_path_buf();
    let target_dir = target_dir.to_path_buf();
    tokio::task::spawn_blocking(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let deadline = archive_operation_deadline();
            create_private_directory_blocking(&target_dir)?;
            let input = std::fs::File::open(source)?;
            if gzipped {
                let decoder = flate2::read::GzDecoder::new(input);
                let mut archive = tar::Archive::new(decoder);
                unpack_tar_safely(&mut archive, &target_dir, deadline, max_unarchived_bytes)?;
            } else {
                let mut archive = tar::Archive::new(input);
                unpack_tar_safely(&mut archive, &target_dir, deadline, max_unarchived_bytes)?;
            }
            Ok(())
        },
    )
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to extract tar archive: {error}")))?
    .map_err(|error| ApiError::BadRequest(format!("failed to extract tar archive: {error}")))
}

pub(super) async fn extract_zip_archive(
    source: &FsPath,
    target_dir: &FsPath,
    max_unarchived_bytes: u64,
) -> Result<(), ApiError> {
    let source = source.to_path_buf();
    let target_dir = target_dir.to_path_buf();
    tokio::task::spawn_blocking(
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let deadline = archive_operation_deadline();
            create_private_directory_blocking(&target_dir)?;
            let input = std::fs::File::open(source)?;
            let mut archive = zip::ZipArchive::new(input)?;
            if archive.len() > MAX_ARCHIVE_ENTRIES {
                return Err(format!("archive has more than {MAX_ARCHIVE_ENTRIES} entries").into());
            }
            let mut total = 0_u64;
            for index in 0..archive.len() {
                ensure_archive_deadline(deadline)?;
                let mut file = archive.by_index(index)?;
                let enclosed = file
                    .enclosed_name()
                    .ok_or_else(|| format!("zip entry {} has unsafe path", file.name()))?
                    .to_path_buf();
                validate_relative_archive_path(&enclosed)?;
                total = total
                    .checked_add(file.size())
                    .ok_or("archive uncompressed size overflow")?;
                if total > max_unarchived_bytes {
                    return Err(
                        format!("archive expands beyond {max_unarchived_bytes} bytes").into(),
                    );
                }
                let size = file.size();
                let target = target_dir.join(enclosed);
                if file.is_dir() {
                    create_private_directory_blocking(&target)?;
                    continue;
                }
                if let Some(parent) = target.parent() {
                    create_private_directory_blocking(parent)?;
                }
                let mut output = create_private_file_blocking(&target)?;
                copy_limited_until(&mut file, &mut output, size, deadline)?;
            }
            Ok(())
        },
    )
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to extract zip archive: {error}")))?
    .map_err(|error| ApiError::BadRequest(format!("failed to extract zip archive: {error}")))
}

pub(super) fn unpack_tar_safely<R: Read>(
    archive: &mut tar::Archive<R>,
    target_dir: &FsPath,
    deadline: Instant,
    max_unarchived_bytes: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut total = 0_u64;
    let mut entries = 0_usize;
    for entry in archive.entries()? {
        ensure_archive_deadline(deadline)?;
        entries += 1;
        if entries > MAX_ARCHIVE_ENTRIES {
            return Err(format!("archive has more than {MAX_ARCHIVE_ENTRIES} entries").into());
        }
        let mut entry = entry?;
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            return Err("archive contains unsupported link/device/special entry".into());
        }
        let path = entry.path()?.to_path_buf();
        validate_relative_archive_path(&path)?;
        let size = entry.header().size()?;
        total = total
            .checked_add(size)
            .ok_or("archive uncompressed size overflow")?;
        if total > max_unarchived_bytes {
            return Err(format!("archive expands beyond {max_unarchived_bytes} bytes").into());
        }
        let target = target_dir.join(&path);
        if kind.is_dir() {
            create_private_directory_blocking(&target)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            create_private_directory_blocking(parent)?;
        }
        let mut output = create_private_file_blocking(&target)?;
        copy_limited_until(&mut entry, &mut output, size, deadline)?;
    }
    Ok(())
}

pub(super) fn validate_relative_archive_path(
    path: &FsPath,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut depth = 0_usize;
    for component in path.components() {
        match component {
            Component::Normal(_) => {
                depth += 1;
                if depth > MAX_ARCHIVE_DEPTH {
                    return Err(format!("archive path depth exceeds {MAX_ARCHIVE_DEPTH}").into());
                }
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!("archive contains unsafe path {}", path.display()).into());
            }
        }
    }
    if depth == 0 {
        return Err("archive contains empty path".into());
    }
    Ok(())
}

pub(super) fn archive_operation_deadline() -> Instant {
    Instant::now() + ARCHIVE_OPERATION_TIMEOUT
}

pub(super) fn ensure_archive_deadline(deadline: Instant) -> Result<(), std::io::Error> {
    if Instant::now() >= deadline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "archive operation exceeded time limit",
        ));
    }
    Ok(())
}

pub(super) fn copy_limited_until<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    limit: u64,
    deadline: Instant,
) -> Result<u64, std::io::Error> {
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        ensure_archive_deadline(deadline)?;
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            return Ok(total);
        }
        total = total.saturating_add(read as u64);
        if total > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "decompressed data exceeded configured limit",
            ));
        }
        writer.write_all(&buffer[..read])?;
    }
}

pub(super) async fn install_selected_dump(
    protocol: Protocol,
    staging_dir: &FsPath,
    host_temp: &FsPath,
) -> Result<(), ApiError> {
    let staging_dir = staging_dir.to_path_buf();
    let candidate =
        tokio::task::spawn_blocking(move || find_dump_candidate(protocol, &staging_dir))
            .await
            .map_err(|error| {
                ApiError::Runtime(format!("failed to inspect archive contents: {error}"))
            })?
            .map_err(ApiError::BadRequest)?;
    move_or_copy_file(&candidate, host_temp).await
}

pub(super) fn find_dump_candidate(protocol: Protocol, root: &FsPath) -> Result<PathBuf, String> {
    let mut files = Vec::new();
    collect_regular_files(root, &mut files).map_err(|error| error.to_string())?;
    files.sort();
    let suffixes = dump_candidate_suffixes(protocol);
    for suffix in suffixes {
        let matches: Vec<_> = files
            .iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.to_ascii_lowercase().ends_with(suffix))
            })
            .cloned()
            .collect();
        match matches.len() {
            1 => return Ok(matches[0].clone()),
            0 => {}
            _ => {
                return Err(format!(
                    "archive contains multiple candidate dump files ending with {suffix}"
                ));
            }
        }
    }
    Err(format!(
        "archive does not contain a supported {} dump file",
        protocol.as_str()
    ))
}

pub(super) fn collect_regular_files(
    dir: &FsPath,
    files: &mut Vec<PathBuf>,
) -> Result<(), std::io::Error> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            collect_regular_files(&path, files)?;
        } else if metadata.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

pub(super) fn dump_candidate_suffixes(protocol: Protocol) -> &'static [&'static str] {
    match protocol {
        Protocol::Postgres => &[".postgres.sql", ".pgsql.sql", ".sql"],
        Protocol::Redis => &[".redis.tar.gz", ".tar.gz"],
        Protocol::Valkey => &[".valkey.tar.gz", ".tar.gz"],
        Protocol::Mariadb => &[".mariadb.sql", ".mysql.sql", ".sql"],
        Protocol::Mysql => &[".mysql.sql", ".sql"],
        Protocol::Mongodb => &[".mongodb.archive.gz", ".archive.gz"],
        Protocol::Clickhouse => &[".clickhouse.sql", ".sql"],
        Protocol::Qdrant => &[".qdrant.tar.gz", ".tar.gz"],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ImportArchiveFormat {
    Plain,
    Gzip,
    Bzip2,
    Tar,
    TarGzip,
    Zip,
}

impl ImportArchiveFormat {
    pub(super) fn parse(value: &str) -> Result<Self, ApiError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "plain" => Ok(Self::Plain),
            "gzip" => Ok(Self::Gzip),
            "bzip2" => Ok(Self::Bzip2),
            "tar" => Ok(Self::Tar),
            "tar.gz" => Ok(Self::TarGzip),
            "zip" => Ok(Self::Zip),
            other => Err(ApiError::BadRequest(format!(
                "unsupported archive_format {other}; use plain, gzip, bzip2, tar, tar.gz, or zip"
            ))),
        }
    }
}
