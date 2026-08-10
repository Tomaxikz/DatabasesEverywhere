//! Bounded, side-effect-free inspection of uploaded database dumps.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    path::{Component, Path},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{api::api_response::ApiError, shared::protocol::Protocol};

mod mongodb;
mod sql;

use mongodb::{MongoArchiveCatalog, inspect_native_gzip};
use sql::inspect_sql_reader;

const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_INSPECTED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 4_096;
const MAX_ARCHIVE_DEPTH: usize = 32;
const MAX_OBJECTS: usize = 512;
const MAX_NAMESPACES: usize = 512;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_SQL_TOKENS_PER_STATEMENT: usize = 96;
const INSPECTION_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DumpArchiveFormat {
    Plain,
    Gzip,
    Bzip2,
    Tar,
    #[serde(rename = "tar.gz")]
    TarGzip,
    Zip,
}

impl DumpArchiveFormat {
    fn parse(value: &str) -> Result<Self, InspectionError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "plain" => Ok(Self::Plain),
            "gzip" | "gz" => Ok(Self::Gzip),
            "bzip2" | "bz2" => Ok(Self::Bzip2),
            "tar" => Ok(Self::Tar),
            "tar.gz" | "tgz" => Ok(Self::TarGzip),
            "zip" => Ok(Self::Zip),
            _ => Err(InspectionError::Invalid(
                "unsupported archive format; use plain, gzip, bzip2, tar, tar.gz, or zip",
            )),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Tar => "tar",
            Self::TarGzip => "tar.gz",
            Self::Zip => "zip",
        }
    }

    pub(crate) fn import_archive_format(self, protocol: Protocol) -> Option<&'static str> {
        match (protocol, self) {
            (Protocol::Redis | Protocol::Valkey | Protocol::Qdrant, Self::TarGzip)
            | (Protocol::Mongodb, Self::Gzip)
            | (_, Self::Plain) => None,
            (_, format) => Some(format.as_str()),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DumpSelectionKind {
    Tables,
    Collections,
    FullOnly,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DumpObjectKind {
    Table,
    Collection,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct DumpSelectableObject {
    pub kind: DumpObjectKind,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub selection_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct DumpInspection {
    pub protocol: Protocol,
    pub sha256: String,
    pub source_size_bytes: u64,
    pub detected_archive_format: DumpArchiveFormat,
    pub selection_kind: DumpSelectionKind,
    pub selective_supported: bool,
    pub catalog_complete: bool,
    pub namespaces: Vec<String>,
    pub objects: Vec<DumpSelectableObject>,
    pub unselectable_object_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selective_unavailable_reason: Option<String>,
}

/// Inspects an immutable uploaded dump without executing it or exposing its contents.
#[cfg(test)]
pub(crate) async fn inspect_uploaded_dump(
    path: &Path,
    protocol: Protocol,
    archive_format: Option<&str>,
) -> Result<DumpInspection, ApiError> {
    inspect_uploaded_dump_with_format(path, protocol, archive_format)
        .await
        .map_err(|failure| failure.error)
}

pub(crate) struct DumpInspectionFailure {
    pub(crate) error: ApiError,
    pub(crate) detected_archive_format: Option<DumpArchiveFormat>,
}

pub(crate) async fn inspect_uploaded_dump_with_format(
    path: &Path,
    protocol: Protocol,
    archive_format: Option<&str>,
) -> Result<DumpInspection, DumpInspectionFailure> {
    let path = path.to_path_buf();
    let requested_format = archive_format.map(str::to_owned);
    let attempt = tokio::task::spawn_blocking(move || {
        inspect_uploaded_dump_blocking(&path, protocol, requested_format.as_deref())
    })
    .await
    .map_err(|error| DumpInspectionFailure {
        error: ApiError::Runtime(format!("dump inspection worker failed: {error}")),
        detected_archive_format: None,
    })?;
    attempt.result.map_err(|error| DumpInspectionFailure {
        error: error.into_api_error(),
        detected_archive_format: attempt.detected_archive_format,
    })
}

struct BlockingInspectionAttempt {
    result: Result<DumpInspection, InspectionError>,
    detected_archive_format: Option<DumpArchiveFormat>,
}

fn inspect_uploaded_dump_blocking(
    path: &Path,
    protocol: Protocol,
    requested_format: Option<&str>,
) -> BlockingInspectionAttempt {
    let mut detected_archive_format = None;
    let result = (|| {
        let deadline = Instant::now() + INSPECTION_TIMEOUT;
        let mut source = open_regular_no_follow(path)?;
        let source_size = source.metadata()?.len();
        if source_size > MAX_SOURCE_BYTES {
            return Err(InspectionError::Limit(
                "uploaded dump exceeds the size limit",
            ));
        }

        let sha256 = sha256_reader(&mut source, deadline)?;
        source.seek(SeekFrom::Start(0))?;
        let detected = detect_archive_format(&mut source, deadline)?;
        detected_archive_format = Some(detected);
        source.seek(SeekFrom::Start(0))?;
        let format = match requested_format {
            Some(value) => {
                let requested = DumpArchiveFormat::parse(value)?;
                if requested != detected {
                    return Err(InspectionError::Invalid(
                        "archive format does not match the uploaded file",
                    ));
                }
                requested
            }
            None => detected,
        };

        if matches!(
            protocol,
            Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
        ) {
            validate_physical_wrapper(&mut source, format, deadline)?;
            return Ok(full_only_inspection(protocol, sha256, source_size, format));
        }

        if protocol == Protocol::Mongodb {
            let catalog = inspect_mongodb_wrapper(&mut source, format, deadline)?;
            return Ok(DumpInspection {
                protocol,
                sha256,
                source_size_bytes: source_size,
                detected_archive_format: format,
                selection_kind: DumpSelectionKind::Collections,
                selective_supported: false,
                catalog_complete: catalog.complete,
                namespaces: catalog.databases,
                objects: Vec::new(),
                unselectable_object_count: 0,
                selective_unavailable_reason: Some(
                    "MongoDB upload inspection detects source databases, but collection-level selective import is not safely supported yet; import the complete selected source database"
                        .to_string(),
                ),
            });
        }

        let mut catalog = CatalogBuilder::new(protocol);
        inspect_sql_source(&mut source, format, protocol, deadline, &mut catalog)?;
        catalog.validate_dialect()?;
        Ok(catalog.finish(sha256, source_size, format))
    })();
    BlockingInspectionAttempt {
        result,
        detected_archive_format,
    }
}

fn full_only_inspection(
    protocol: Protocol,
    sha256: String,
    source_size_bytes: u64,
    format: DumpArchiveFormat,
) -> DumpInspection {
    DumpInspection {
        protocol,
        sha256,
        source_size_bytes,
        detected_archive_format: format,
        selection_kind: DumpSelectionKind::FullOnly,
        selective_supported: false,
        catalog_complete: true,
        namespaces: Vec::new(),
        objects: Vec::new(),
        unselectable_object_count: 0,
        selective_unavailable_reason: Some(format!(
            "{} uploaded dumps are physical archives and can only replace the complete database",
            protocol.as_str()
        )),
    }
}

#[derive(Debug, thiserror::Error)]
enum InspectionError {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Limit(&'static str),
    #[error("I/O failure while inspecting the uploaded dump")]
    Io(#[from] io::Error),
}

impl InspectionError {
    fn into_api_error(self) -> ApiError {
        match self {
            Self::Invalid(message) => ApiError::BadRequest(message.to_string()),
            Self::Limit(message) => ApiError::ServiceUnavailable(format!(
                "dump catalog inspection reached a bounded resource limit: {message}; full import remains available"
            )),
            Self::Io(error) if error.kind() == io::ErrorKind::InvalidData => {
                ApiError::BadRequest("uploaded dump is malformed".to_string())
            }
            Self::Io(error) if error.kind() == io::ErrorKind::TimedOut => {
                ApiError::ServiceUnavailable(
                    "dump catalog inspection timed out; full import remains available".to_string(),
                )
            }
            Self::Io(_) => ApiError::Runtime(
                "failed to read the uploaded dump during bounded inspection".to_string(),
            ),
        }
    }
}

#[cfg(unix)]
fn open_regular_no_follow(path: &Path) -> Result<File, InspectionError> {
    use rustix::fs::{Mode, OFlags};

    let parent = path.parent().ok_or(InspectionError::Invalid(
        "uploaded dump path has no parent directory",
    ))?;
    let name = path.file_name().ok_or(InspectionError::Invalid(
        "uploaded dump path has no file name",
    ))?;
    let directory = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let descriptor = rustix::fs::openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let file = File::from(descriptor);
    if !file.metadata()?.is_file() {
        return Err(InspectionError::Invalid(
            "uploaded dump must be a real regular file",
        ));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_regular_no_follow(path: &Path) -> Result<File, InspectionError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(InspectionError::Invalid(
            "uploaded dump must be a real regular file",
        ));
    }
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(InspectionError::Invalid(
            "uploaded dump must be a real regular file",
        ));
    }
    Ok(file)
}

fn sha256_reader(file: &mut File, deadline: Instant) -> Result<String, InspectionError> {
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        ensure_deadline(deadline)?;
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(InspectionError::Limit(
                "uploaded dump exceeds the size limit",
            ))?;
        if total > MAX_SOURCE_BYTES {
            return Err(InspectionError::Limit(
                "uploaded dump exceeds the size limit",
            ));
        }
        hash.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn detect_archive_format(
    file: &mut File,
    deadline: Instant,
) -> Result<DumpArchiveFormat, InspectionError> {
    ensure_deadline(deadline)?;
    let mut header = [0_u8; 512];
    let read = read_up_to(file, &mut header)?;
    file.seek(SeekFrom::Start(0))?;
    if header[..read].starts_with(&[0x1f, 0x8b]) {
        let mut decoder = flate2::read::GzDecoder::new(&mut *file);
        let mut inner = [0_u8; 512];
        let inner_read = read_up_to(&mut decoder, &mut inner)
            .map_err(|_| InspectionError::Invalid("uploaded gzip stream is malformed"))?;
        return Ok(if is_tar_header(&inner[..inner_read]) {
            DumpArchiveFormat::TarGzip
        } else {
            DumpArchiveFormat::Gzip
        });
    }
    if header[..read].starts_with(b"BZh") {
        return Ok(DumpArchiveFormat::Bzip2);
    }
    if header[..read].starts_with(b"PK\x03\x04")
        || header[..read].starts_with(b"PK\x05\x06")
        || header[..read].starts_with(b"PK\x07\x08")
    {
        return Ok(DumpArchiveFormat::Zip);
    }
    if is_tar_header(&header[..read]) {
        return Ok(DumpArchiveFormat::Tar);
    }
    Ok(DumpArchiveFormat::Plain)
}

fn is_tar_header(bytes: &[u8]) -> bool {
    bytes.len() >= 265 && matches!(&bytes[257..262], b"ustar")
}

fn read_up_to(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    let mut total = 0_usize;
    while total < buffer.len() {
        match reader.read(&mut buffer[total..]) {
            Ok(0) => break,
            Ok(read) => total += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(total)
}

fn inspect_sql_source(
    source: &mut File,
    format: DumpArchiveFormat,
    protocol: Protocol,
    deadline: Instant,
    catalog: &mut CatalogBuilder,
) -> Result<(), InspectionError> {
    source.seek(SeekFrom::Start(0))?;
    match format {
        DumpArchiveFormat::Plain => inspect_sql_reader(
            BoundedReader::new(source, MAX_INSPECTED_BYTES, deadline),
            protocol,
            catalog,
        ),
        DumpArchiveFormat::Gzip => {
            let decoder = flate2::read::GzDecoder::new(source);
            inspect_sql_reader(
                BoundedReader::new(decoder, MAX_INSPECTED_BYTES, deadline),
                protocol,
                catalog,
            )
        }
        DumpArchiveFormat::Bzip2 => {
            let decoder = bzip2::read::BzDecoder::new(source);
            inspect_sql_reader(
                BoundedReader::new(decoder, MAX_INSPECTED_BYTES, deadline),
                protocol,
                catalog,
            )
        }
        DumpArchiveFormat::Tar => inspect_tar(source, false, protocol, deadline, catalog),
        DumpArchiveFormat::TarGzip => inspect_tar(source, true, protocol, deadline, catalog),
        DumpArchiveFormat::Zip => inspect_zip(source, protocol, deadline, catalog),
    }
}

fn inspect_tar(
    source: &mut File,
    gzipped: bool,
    protocol: Protocol,
    deadline: Instant,
    catalog: &mut CatalogBuilder,
) -> Result<(), InspectionError> {
    if gzipped {
        let decoder = flate2::read::GzDecoder::new(source);
        inspect_tar_reader(decoder, protocol, deadline, catalog)
    } else {
        inspect_tar_reader(source, protocol, deadline, catalog)
    }
}

fn inspect_tar_reader<R: Read>(
    reader: R,
    protocol: Protocol,
    deadline: Instant,
    catalog: &mut CatalogBuilder,
) -> Result<(), InspectionError> {
    let bounded = BoundedReader::new(reader, MAX_INSPECTED_BYTES, deadline);
    let mut archive = tar::Archive::new(bounded);
    let mut entries_seen = 0_usize;
    let mut expanded_bytes = 0_u64;
    let mut candidate_seen = false;
    let entries = archive
        .entries()
        .map_err(|_| InspectionError::Invalid("uploaded tar archive is malformed"))?;
    for entry in entries {
        ensure_deadline(deadline)?;
        entries_seen += 1;
        if entries_seen > MAX_ARCHIVE_ENTRIES {
            return Err(InspectionError::Limit("archive contains too many entries"));
        }
        let mut entry =
            entry.map_err(|_| InspectionError::Invalid("uploaded tar archive is malformed"))?;
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            return Err(InspectionError::Invalid(
                "archive contains a link, device, or unsupported special entry",
            ));
        }
        let path = entry
            .path()
            .map_err(|_| InspectionError::Invalid("archive contains an invalid entry path"))?
            .into_owned();
        validate_archive_path(&path)?;
        let size = entry
            .header()
            .size()
            .map_err(|_| InspectionError::Invalid("uploaded tar archive is malformed"))?;
        expanded_bytes = expanded_bytes
            .checked_add(size)
            .ok_or(InspectionError::Limit(
                "archive expansion exceeds the size limit",
            ))?;
        if expanded_bytes > MAX_INSPECTED_BYTES {
            return Err(InspectionError::Limit(
                "archive expansion exceeds the size limit",
            ));
        }
        if kind.is_file() && is_sql_candidate(&path, protocol)? {
            if candidate_seen {
                return Err(InspectionError::Invalid(
                    "archive contains multiple candidate dump files",
                ));
            }
            candidate_seen = true;
            inspect_sql_reader(
                BoundedReader::new(&mut entry, size.min(MAX_INSPECTED_BYTES), deadline),
                protocol,
                catalog,
            )?;
        }
    }
    if !candidate_seen {
        return Err(InspectionError::Invalid(
            "archive does not contain one supported SQL dump file",
        ));
    }
    Ok(())
}

fn inspect_zip(
    source: &mut File,
    protocol: Protocol,
    deadline: Instant,
    catalog: &mut CatalogBuilder,
) -> Result<(), InspectionError> {
    let mut archive = zip::ZipArchive::new(source.try_clone()?)
        .map_err(|_| InspectionError::Invalid("uploaded zip archive is malformed"))?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(InspectionError::Limit("archive contains too many entries"));
    }
    let mut expanded_bytes = 0_u64;
    let mut candidate_seen = false;
    for index in 0..archive.len() {
        ensure_deadline(deadline)?;
        let mut entry = archive
            .by_index(index)
            .map_err(|_| InspectionError::Invalid("uploaded zip archive is malformed"))?;
        let path = entry
            .enclosed_name()
            .ok_or(InspectionError::Invalid(
                "archive contains an unsafe entry path",
            ))?
            .to_path_buf();
        validate_archive_path(&path)?;
        validate_zip_entry_type(&entry)?;
        expanded_bytes = expanded_bytes
            .checked_add(entry.size())
            .ok_or(InspectionError::Limit(
                "archive expansion exceeds the size limit",
            ))?;
        if expanded_bytes > MAX_INSPECTED_BYTES {
            return Err(InspectionError::Limit(
                "archive expansion exceeds the size limit",
            ));
        }
        if !entry.is_dir() && is_sql_candidate(&path, protocol)? {
            if candidate_seen {
                return Err(InspectionError::Invalid(
                    "archive contains multiple candidate dump files",
                ));
            }
            candidate_seen = true;
            let size = entry.size();
            inspect_sql_reader(
                BoundedReader::new(&mut entry, size.min(MAX_INSPECTED_BYTES), deadline),
                protocol,
                catalog,
            )?;
        } else if !entry.is_dir() {
            let size = entry.size();
            let mut bounded = BoundedReader::new(&mut entry, size, deadline);
            io::copy(&mut bounded, &mut io::sink()).map_err(|_| {
                InspectionError::Invalid("uploaded zip archive contains malformed file data")
            })?;
        }
    }
    if !candidate_seen {
        return Err(InspectionError::Invalid(
            "archive does not contain one supported SQL dump file",
        ));
    }
    Ok(())
}

fn validate_zip_entry_type(entry: &zip::read::ZipFile<'_>) -> Result<(), InspectionError> {
    let Some(mode) = entry.unix_mode() else {
        return Ok(());
    };
    let kind = mode & 0o170_000;
    if kind == 0 || kind == 0o100_000 || kind == 0o040_000 {
        Ok(())
    } else {
        Err(InspectionError::Invalid(
            "archive contains a link, device, or unsupported special entry",
        ))
    }
}

fn validate_archive_path(path: &Path) -> Result<(), InspectionError> {
    let mut depth = 0_usize;
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                if part.to_str().is_none() {
                    return Err(InspectionError::Invalid(
                        "archive contains a non-UTF-8 entry path",
                    ));
                }
                depth += 1;
                if depth > MAX_ARCHIVE_DEPTH {
                    return Err(InspectionError::Limit("archive entry path is too deep"));
                }
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(InspectionError::Invalid(
                    "archive contains an unsafe entry path",
                ));
            }
        }
    }
    if depth == 0 {
        return Err(InspectionError::Invalid(
            "archive contains an empty entry path",
        ));
    }
    Ok(())
}

fn is_sql_candidate(path: &Path, protocol: Protocol) -> Result<bool, InspectionError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(InspectionError::Invalid(
            "archive contains a non-UTF-8 entry name",
        ))?
        .to_ascii_lowercase();
    let specific = match protocol {
        Protocol::Postgres => name.ends_with(".postgres.sql") || name.ends_with(".pgsql.sql"),
        Protocol::Mariadb => name.ends_with(".mariadb.sql"),
        Protocol::Mysql => name.ends_with(".mysql.sql"),
        Protocol::Clickhouse => name.ends_with(".clickhouse.sql"),
        _ => false,
    };
    Ok(specific || name.ends_with(".sql"))
}

fn validate_physical_wrapper(
    source: &mut File,
    format: DumpArchiveFormat,
    deadline: Instant,
) -> Result<(), InspectionError> {
    match format {
        DumpArchiveFormat::TarGzip => validate_tar_container(source, true, deadline),
        _ => Err(InspectionError::Invalid(
            "physical database uploads must be gzip-compressed tar archives",
        )),
    }
}

fn inspect_mongodb_wrapper(
    source: &mut File,
    format: DumpArchiveFormat,
    deadline: Instant,
) -> Result<MongoArchiveCatalog, InspectionError> {
    match format {
        DumpArchiveFormat::Gzip => {
            source.seek(SeekFrom::Start(0))?;
            inspect_native_gzip(source, deadline)
        }
        DumpArchiveFormat::Tar => inspect_mongodb_tar_container(source, false, deadline),
        DumpArchiveFormat::TarGzip => inspect_mongodb_tar_container(source, true, deadline),
        DumpArchiveFormat::Zip => inspect_mongodb_zip_container(source, deadline),
        DumpArchiveFormat::Bzip2 => inspect_bzip2_wrapped_mongodb(source, deadline),
        DumpArchiveFormat::Plain => Err(InspectionError::Invalid(
            "MongoDB uploads must be native gzip archives or wrappers containing exactly one .archive.gz file",
        )),
    }
}

fn inspect_bzip2_wrapped_mongodb(
    source: &mut File,
    deadline: Instant,
) -> Result<MongoArchiveCatalog, InspectionError> {
    source.seek(SeekFrom::Start(0))?;
    let bzip2 = bzip2::read::MultiBzDecoder::new(source);
    let bounded = BoundedReader::new(bzip2, MAX_INSPECTED_BYTES, deadline);
    inspect_native_gzip(bounded, deadline).map_err(|error| match error {
        InspectionError::Limit(_) => error,
        _ => InspectionError::Invalid(
            "MongoDB bzip2 wrapper does not contain a valid native gzip archive",
        ),
    })
}

fn inspect_mongodb_tar_container(
    source: &mut File,
    gzipped: bool,
    deadline: Instant,
) -> Result<MongoArchiveCatalog, InspectionError> {
    source.seek(SeekFrom::Start(0))?;
    if gzipped {
        inspect_mongodb_tar_entries(flate2::read::MultiGzDecoder::new(source), deadline)
    } else {
        inspect_mongodb_tar_entries(source, deadline)
    }
}

fn inspect_mongodb_tar_entries<R: Read>(
    reader: R,
    deadline: Instant,
) -> Result<MongoArchiveCatalog, InspectionError> {
    let bounded = BoundedReader::new(reader, MAX_INSPECTED_BYTES, deadline);
    let mut archive = tar::Archive::new(bounded);
    let mut count = 0_usize;
    let mut total = 0_u64;
    let mut catalog = None;
    let entries = archive
        .entries()
        .map_err(|_| InspectionError::Invalid("uploaded tar archive is malformed"))?;
    for entry in entries {
        ensure_deadline(deadline)?;
        count += 1;
        if count > MAX_ARCHIVE_ENTRIES {
            return Err(InspectionError::Limit("archive contains too many entries"));
        }
        let mut entry =
            entry.map_err(|_| InspectionError::Invalid("uploaded tar archive is malformed"))?;
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            return Err(InspectionError::Invalid(
                "archive contains a link, device, or unsupported special entry",
            ));
        }
        let path = entry
            .path()
            .map_err(|_| InspectionError::Invalid("archive contains an invalid entry path"))?;
        validate_archive_path(&path)?;
        let candidate = kind.is_file() && is_mongodb_archive_candidate(&path)?;
        total = total
            .checked_add(
                entry
                    .header()
                    .size()
                    .map_err(|_| InspectionError::Invalid("uploaded tar archive is malformed"))?,
            )
            .ok_or(InspectionError::Limit(
                "archive expansion exceeds the size limit",
            ))?;
        if total > MAX_INSPECTED_BYTES {
            return Err(InspectionError::Limit(
                "archive expansion exceeds the size limit",
            ));
        }
        if candidate {
            if catalog.is_some() {
                return Err(InspectionError::Invalid(
                    "MongoDB wrapper contains multiple .archive.gz dumps",
                ));
            }
            catalog = Some(inspect_native_gzip(&mut entry, deadline)?);
        }
    }
    let mut remainder = archive.into_inner();
    io::copy(&mut remainder, &mut io::sink())
        .map_err(|error| map_mongodb_read_error(error, "MongoDB tar wrapper is malformed"))?;
    catalog.ok_or(InspectionError::Invalid(
        "MongoDB wrapper does not contain a .archive.gz dump",
    ))
}

fn inspect_mongodb_zip_container(
    source: &mut File,
    deadline: Instant,
) -> Result<MongoArchiveCatalog, InspectionError> {
    source.seek(SeekFrom::Start(0))?;
    let mut archive = zip::ZipArchive::new(source.try_clone()?)
        .map_err(|_| InspectionError::Invalid("uploaded zip archive is malformed"))?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(InspectionError::Limit("archive contains too many entries"));
    }
    let mut total = 0_u64;
    let mut catalog = None;
    for index in 0..archive.len() {
        ensure_deadline(deadline)?;
        let mut entry = archive
            .by_index(index)
            .map_err(|_| InspectionError::Invalid("uploaded zip archive is malformed"))?;
        let path = entry.enclosed_name().ok_or(InspectionError::Invalid(
            "archive contains an unsafe entry path",
        ))?;
        validate_archive_path(&path)?;
        validate_zip_entry_type(&entry)?;
        let candidate = !entry.is_dir() && is_mongodb_archive_candidate(&path)?;
        total = total
            .checked_add(entry.size())
            .ok_or(InspectionError::Limit(
                "archive expansion exceeds the size limit",
            ))?;
        if total > MAX_INSPECTED_BYTES {
            return Err(InspectionError::Limit(
                "archive expansion exceeds the size limit",
            ));
        }
        if candidate {
            if catalog.is_some() {
                return Err(InspectionError::Invalid(
                    "MongoDB wrapper contains multiple .archive.gz dumps",
                ));
            }
            catalog = Some(inspect_native_gzip(&mut entry, deadline)?);
        } else if !entry.is_dir() {
            let size = entry.size();
            let mut bounded = BoundedReader::new(&mut entry, size, deadline);
            io::copy(&mut bounded, &mut io::sink()).map_err(|_| {
                InspectionError::Invalid("uploaded zip archive contains malformed file data")
            })?;
        }
    }
    catalog.ok_or(InspectionError::Invalid(
        "MongoDB wrapper does not contain a .archive.gz dump",
    ))
}

fn validate_tar_container(
    source: &mut File,
    gzipped: bool,
    deadline: Instant,
) -> Result<(), InspectionError> {
    source.seek(SeekFrom::Start(0))?;
    if gzipped {
        validate_tar_entries(flate2::read::GzDecoder::new(source), deadline)
    } else {
        validate_tar_entries(source, deadline)
    }
}

fn validate_tar_entries<R: Read>(reader: R, deadline: Instant) -> Result<(), InspectionError> {
    let bounded = BoundedReader::new(reader, MAX_INSPECTED_BYTES, deadline);
    let mut archive = tar::Archive::new(bounded);
    let mut count = 0_usize;
    let mut total = 0_u64;
    let entries = archive
        .entries()
        .map_err(|_| InspectionError::Invalid("uploaded tar archive is malformed"))?;
    for entry in entries {
        ensure_deadline(deadline)?;
        count += 1;
        if count > MAX_ARCHIVE_ENTRIES {
            return Err(InspectionError::Limit("archive contains too many entries"));
        }
        let entry =
            entry.map_err(|_| InspectionError::Invalid("uploaded tar archive is malformed"))?;
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            return Err(InspectionError::Invalid(
                "archive contains a link, device, or unsupported special entry",
            ));
        }
        let path = entry
            .path()
            .map_err(|_| InspectionError::Invalid("archive contains an invalid entry path"))?;
        validate_archive_path(&path)?;
        total = total
            .checked_add(
                entry
                    .header()
                    .size()
                    .map_err(|_| InspectionError::Invalid("uploaded tar archive is malformed"))?,
            )
            .ok_or(InspectionError::Limit(
                "archive expansion exceeds the size limit",
            ))?;
        if total > MAX_INSPECTED_BYTES {
            return Err(InspectionError::Limit(
                "archive expansion exceeds the size limit",
            ));
        }
    }
    Ok(())
}

fn is_mongodb_archive_candidate(path: &Path) -> Result<bool, InspectionError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(InspectionError::Invalid(
            "archive contains a non-UTF-8 entry name",
        ))?
        .to_ascii_lowercase();
    Ok(name.ends_with(".mongodb.archive.gz") || name.ends_with(".archive.gz"))
}

fn ensure_deadline(deadline: Instant) -> Result<(), InspectionError> {
    if Instant::now() >= deadline {
        Err(InspectionError::Limit(
            "dump inspection exceeded its time limit",
        ))
    } else {
        Ok(())
    }
}

fn map_mongodb_read_error(error: io::Error, malformed_message: &'static str) -> InspectionError {
    if error.kind() == io::ErrorKind::TimedOut {
        return InspectionError::Limit("dump inspection exceeded its time limit");
    }
    if error.kind() == io::ErrorKind::InvalidData
        && error
            .to_string()
            .contains("decompressed dump exceeds inspection limit")
    {
        return InspectionError::Limit("MongoDB archive expansion exceeds the size limit");
    }
    InspectionError::Invalid(malformed_message)
}

struct BoundedReader<R> {
    inner: R,
    read: u64,
    limit: u64,
    deadline: Instant,
}

impl<R> BoundedReader<R> {
    fn new(inner: R, limit: u64, deadline: Instant) -> Self {
        Self {
            inner,
            read: 0,
            limit,
            deadline,
        }
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "dump inspection exceeded its time limit",
            ));
        }
        let remaining = self.limit.saturating_sub(self.read);
        let request = if remaining >= buffer.len() as u64 {
            buffer.len()
        } else {
            usize::try_from(remaining)
                .unwrap_or(buffer.len().saturating_sub(1))
                .saturating_add(1)
                .min(buffer.len())
        };
        let count = self.inner.read(&mut buffer[..request])?;
        self.read = self.read.saturating_add(count as u64);
        if self.read > self.limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decompressed dump exceeds inspection limit",
            ));
        }
        Ok(count)
    }
}

#[derive(Default)]
struct DialectHints {
    postgres: bool,
    mysql: bool,
    clickhouse: bool,
}

struct CatalogBuilder {
    protocol: Protocol,
    namespaces: BTreeSet<String>,
    objects: BTreeMap<String, DumpSelectableObject>,
    observed_objects: BTreeSet<String>,
    unselectable: usize,
    truncated: bool,
    hints: DialectHints,
}

impl CatalogBuilder {
    fn new(protocol: Protocol) -> Self {
        Self {
            protocol,
            namespaces: BTreeSet::new(),
            objects: BTreeMap::new(),
            observed_objects: BTreeSet::new(),
            unselectable: 0,
            truncated: false,
            hints: DialectHints::default(),
        }
    }

    fn add_namespace(&mut self, namespace: String) -> Result<(), InspectionError> {
        if !portable_identifier(&namespace) {
            return Ok(());
        }
        self.namespaces.insert(namespace);
        if self.namespaces.len() > MAX_NAMESPACES {
            self.namespaces.pop_last();
            self.truncated = true;
        }
        Ok(())
    }

    fn add_table(
        &mut self,
        namespace: Option<String>,
        name: String,
    ) -> Result<(), InspectionError> {
        let observed_key = match &namespace {
            Some(namespace) => format!("{namespace}.{name}"),
            None => name.clone(),
        };
        if self.observed_objects.contains(&observed_key) {
            return Ok(());
        }
        if self.observed_objects.len() == MAX_OBJECTS {
            self.truncated = true;
            return Ok(());
        }
        self.observed_objects.insert(observed_key.clone());
        if !portable_identifier(&name)
            || namespace
                .as_deref()
                .is_some_and(|value| !portable_identifier(value))
        {
            self.unselectable = self.unselectable.saturating_add(1);
            return Ok(());
        }
        if let Some(namespace) = &namespace {
            self.add_namespace(namespace.clone())?;
        }
        let selection_key = if self.protocol == Protocol::Clickhouse {
            name.clone()
        } else {
            observed_key
        };
        self.objects
            .entry(selection_key.clone())
            .or_insert(DumpSelectableObject {
                kind: DumpObjectKind::Table,
                name,
                namespace,
                selection_key,
            });
        Ok(())
    }

    fn add_unselectable_object(&mut self) {
        if self.observed_objects.len() == MAX_OBJECTS {
            self.truncated = true;
            return;
        }
        let key = format!("#unselectable-{}", self.unselectable);
        if self.observed_objects.insert(key) {
            self.unselectable = self.unselectable.saturating_add(1);
        }
    }

    fn observe_comment(&mut self, comment: &[u8]) {
        if contains_ascii_case_insensitive(comment, b"postgresql database dump") {
            self.hints.postgres = true;
        }
        if contains_ascii_case_insensitive(comment, b"mysql dump")
            || contains_ascii_case_insensitive(comment, b"mariadb dump")
        {
            self.hints.mysql = true;
        }
        if contains_ascii_case_insensitive(comment, b"databaseseverywhere clickhouse logical dump")
        {
            self.hints.clickhouse = true;
        }
    }

    fn validate_dialect(&self) -> Result<(), InspectionError> {
        let mismatch = match self.protocol {
            Protocol::Postgres => self.hints.mysql || self.hints.clickhouse,
            Protocol::Mariadb | Protocol::Mysql => self.hints.postgres || self.hints.clickhouse,
            Protocol::Clickhouse => self.hints.postgres || self.hints.mysql,
            _ => false,
        };
        let ambiguous = [self.hints.postgres, self.hints.mysql, self.hints.clickhouse]
            .into_iter()
            .filter(|hint| *hint)
            .count()
            > 1;
        if mismatch || ambiguous {
            Err(InspectionError::Invalid(
                "dump content does not match the target database protocol",
            ))
        } else {
            Ok(())
        }
    }

    fn finish(
        self,
        sha256: String,
        source_size_bytes: u64,
        format: DumpArchiveFormat,
    ) -> DumpInspection {
        DumpInspection {
            protocol: self.protocol,
            sha256,
            source_size_bytes,
            detected_archive_format: format,
            selection_kind: DumpSelectionKind::Tables,
            selective_supported: false,
            catalog_complete: !self.truncated,
            namespaces: self.namespaces.into_iter().collect(),
            objects: self.objects.into_values().collect(),
            unselectable_object_count: self.unselectable,
            selective_unavailable_reason: Some(
                "uploaded logical dumps can be previewed, but safe object-level filtering is not available yet; import the complete dump"
                    .to_string(),
            ),
        }
    }
}

fn portable_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

#[cfg(test)]
mod tests;
