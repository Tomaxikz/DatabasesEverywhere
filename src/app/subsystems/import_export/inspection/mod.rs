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

use crate::{
    databases::engine::EngineFamily, databases::protocol::Protocol,
    routes::http::response::ApiError, utils::ids::portable_identifier,
};

mod mongodb;

pub(crate) mod shared_import;

mod sql;

use mongodb::{MongoArchiveCatalog, inspect_native_gzip};

use sql::inspect_sql_reader;

pub(crate) use sql::validate_shared_mysql_command;

mod source;
use source::*;
mod archive;
use archive::*;
mod wrappers;
use wrappers::*;
mod catalog;
use catalog::*;

const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_INSPECTED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 4_096;
const MAX_ARCHIVE_DEPTH: usize = 32;
const MAX_OBJECTS: usize = 512;
const MAX_NAMESPACES: usize = 512;
const MAX_IDENTIFIER_BYTES: usize = 128;

// Large CREATE TABLE statements need enough retained syntax for the shared-tenant
// policy to inspect trailing engine/options clauses. INSERT/COPY payload bytes are
// streamed separately, so this remains a bounded metadata cost rather than a dump-
// sized allocation.
const MAX_SQL_TOKENS_PER_STATEMENT: usize = 4_096;
const INSPECTION_TIMEOUT: Duration = Duration::from_secs(60);
const HASH_BUFFER_BYTES: usize = 64 * 1024;
const FORMAT_SNIFF_BYTES: usize = 512;
const GZIP_MAGIC: &[u8] = &[0x1f, 0x8b];
const BZIP2_MAGIC: &[u8] = b"BZh";
const ZIP_SIGNATURES: [&[u8]; 3] = [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"];
const TAR_MAGIC: &[u8] = b"ustar";
const TAR_MAGIC_OFFSET: usize = 257;
const TAR_MIN_HEADER_BYTES: usize = 265;
const UNIX_FILE_TYPE_MASK: u32 = 0o170_000;
const UNIX_REGULAR_FILE: u32 = 0o100_000;
const UNIX_DIRECTORY: u32 = 0o040_000;

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
            (protocol, Self::TarGzip) if protocol.engine().is_physical() => None,
            (Protocol::Mongodb, Self::Gzip) | (_, Self::Plain) => None,
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
    let result = inspect_dump_file(
        path,
        protocol,
        requested_format,
        &mut detected_archive_format,
    );
    BlockingInspectionAttempt {
        result,
        detected_archive_format,
    }
}

fn inspect_dump_file(
    path: &Path,
    protocol: Protocol,
    requested_format: Option<&str>,
    detected_archive_format: &mut Option<DumpArchiveFormat>,
) -> Result<DumpInspection, InspectionError> {
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
    *detected_archive_format = Some(detected);
    source.seek(SeekFrom::Start(0))?;
    let format = resolve_requested_format(requested_format, detected)?;

    if protocol.engine().is_physical() {
        validate_physical_wrapper(&mut source, format, deadline)?;
        return Ok(full_only_inspection(protocol, sha256, source_size, format));
    }

    if protocol.engine().inspects_archive_catalogs() {
        let catalog = inspect_mongodb_wrapper(&mut source, format, deadline)?;
        return Ok(mongodb_inspection(
            protocol,
            sha256,
            source_size,
            format,
            catalog,
        ));
    }

    let mut catalog = CatalogBuilder::new(protocol);
    inspect_sql_source(&mut source, format, protocol, deadline, &mut catalog)?;
    catalog.validate_dialect()?;
    Ok(catalog.finish(sha256, source_size, format))
}

fn resolve_requested_format(
    requested_format: Option<&str>,
    detected: DumpArchiveFormat,
) -> Result<DumpArchiveFormat, InspectionError> {
    let Some(value) = requested_format else {
        return Ok(detected);
    };
    let requested = DumpArchiveFormat::parse(value)?;
    if requested != detected {
        return Err(InspectionError::Invalid(
            "archive format does not match the uploaded file",
        ));
    }
    Ok(requested)
}

fn mongodb_inspection(
    protocol: Protocol,
    sha256: String,
    source_size_bytes: u64,
    format: DumpArchiveFormat,
    catalog: MongoArchiveCatalog,
) -> DumpInspection {
    DumpInspection {
        protocol,
        sha256,
        source_size_bytes,
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

#[cfg(test)]
mod tests;
