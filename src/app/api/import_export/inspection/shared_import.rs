use std::{
    io::{BufRead, BufReader, Read, Seek},
    path::Path,
    time::Instant,
};

use serde::{Deserialize, Serialize};

use super::{
    BoundedReader, DumpArchiveFormat, INSPECTION_TIMEOUT, InspectionError, MAX_INSPECTED_BYTES,
    MAX_SOURCE_BYTES, detect_archive_format, inspect_mongodb_wrapper,
    mongodb::MongoSharedIssue,
    open_regular_no_follow, scan_sql_source, sha256_reader,
    sql::{SharedSqlError, SharedSqlIssue, validate_shared_sql_reader},
};
use crate::shared::protocol::Protocol;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SharedImportLayout {
    LogicalDump,
    PhysicalRestore,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SharedImportRejection {
    UnsupportedProtocol,
    PhysicalRestore,
    InvalidTarget,
    MalformedDump,
    UnsafeArchive,
    ResourceLimit,
    CrossTenantNamespace,
    SystemNamespace,
    PrivilegedStatement,
    ExternalAccess,
    UnsafeMongoMetadata,
    AmbiguousSyntax,
    ReadFailure,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub(crate) struct SharedImportPolicyError {
    pub(crate) reason: SharedImportRejection,
    pub(crate) message: String,
}

impl SharedImportPolicyError {
    fn reject(reason: SharedImportRejection, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct SharedImportApproval {
    pub(crate) protocol: Protocol,
    pub(crate) target_database: String,
    pub(crate) sha256: String,
    pub(crate) source_size_bytes: u64,
    pub(crate) detected_archive_format: DumpArchiveFormat,
    pub(crate) statements_checked: usize,
    pub(crate) namespaces_checked: Vec<String>,
    pub(crate) objects_checked: usize,
    /// Parsing is admission control, not a sandbox. The restore path must still
    /// stage into an isolated helper and authenticate as the target tenant.
    pub(crate) requires_isolated_staging: bool,
    pub(crate) restore_as_tenant: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SharedImportRequest<'a> {
    pub(crate) protocol: Protocol,
    pub(crate) target_database: &'a str,
    pub(crate) source_database: Option<&'a str>,
    pub(crate) layout: SharedImportLayout,
    pub(crate) archive_format: Option<&'a str>,
    /// Exact PostgreSQL pg_dump safety-wrapper lines removed by the execution
    /// stream. Admission validates that same effective byte stream.
    pub(crate) postgres_wrapper_lines: Option<(u64, u64)>,
}

/// Performs bounded, side-effect-free admission checks for a shared-engine import.
///
/// Approval never authorizes an administrator/root restore. Callers must still use
/// an isolated staging helper and the exact tenant credential represented here.
/// Shared imports intentionally reject engine-level database creation, roles,
/// grants, executable routines, triggers, events, external/remote table engines,
/// system namespaces, and cross-database objects. MongoDB imports additionally
/// reject system collections, cross-database namespaces, views, and executable
/// validator metadata. Physical data-directory restores are never supported for
/// shared runtimes because they cannot preserve tenant isolation.
pub(crate) async fn validate_shared_import(
    path: &Path,
    request: SharedImportRequest<'_>,
) -> Result<SharedImportApproval, SharedImportPolicyError> {
    validate_request(request.protocol, request.target_database, request.layout)?;
    let path = path.to_path_buf();
    let target_database = request.target_database.to_string();
    let source_database = request.source_database.map(str::to_owned);
    let requested_format = request.archive_format.map(str::to_owned);
    let protocol = request.protocol;
    let postgres_wrapper_lines = request.postgres_wrapper_lines;
    tokio::task::spawn_blocking(move || {
        validate_blocking(
            &path,
            protocol,
            &target_database,
            source_database.as_deref(),
            requested_format.as_deref(),
            postgres_wrapper_lines,
        )
    })
    .await
    .map_err(|error| {
        SharedImportPolicyError::reject(
            SharedImportRejection::ReadFailure,
            format!("shared import policy worker failed: {error}"),
        )
    })?
}

fn validate_request(
    protocol: Protocol,
    target_database: &str,
    layout: SharedImportLayout,
) -> Result<(), SharedImportPolicyError> {
    if layout == SharedImportLayout::PhysicalRestore {
        return Err(SharedImportPolicyError::reject(
            SharedImportRejection::PhysicalRestore,
            "physical data-directory restores are never allowed on a shared database engine",
        ));
    }
    if !matches!(
        protocol,
        Protocol::Postgres
            | Protocol::Mariadb
            | Protocol::Mysql
            | Protocol::Mongodb
            | Protocol::Clickhouse
    ) {
        return Err(SharedImportPolicyError::reject(
            SharedImportRejection::UnsupportedProtocol,
            format!("{protocol} does not support shared-engine imports"),
        ));
    }
    let max_database_bytes = match protocol {
        Protocol::Postgres | Protocol::Mongodb => 63,
        Protocol::Mariadb | Protocol::Mysql => 64,
        Protocol::Clickhouse => 128,
        _ => {
            return Err(SharedImportPolicyError::reject(
                SharedImportRejection::UnsupportedProtocol,
                format!("{protocol} does not support shared-engine imports"),
            ));
        }
    };
    if target_database.is_empty()
        || target_database.len() > max_database_bytes
        || target_database
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(SharedImportPolicyError::reject(
            SharedImportRejection::InvalidTarget,
            "shared import target database is invalid",
        ));
    }
    Ok(())
}

fn validate_blocking(
    path: &Path,
    protocol: Protocol,
    target_database: &str,
    source_database: Option<&str>,
    requested_format: Option<&str>,
    postgres_wrapper_lines: Option<(u64, u64)>,
) -> Result<SharedImportApproval, SharedImportPolicyError> {
    let deadline = Instant::now() + INSPECTION_TIMEOUT;
    let mut source = open_regular_no_follow(path).map_err(map_inspection_error)?;
    let source_size = source
        .metadata()
        .map_err(InspectionError::from)
        .map_err(map_inspection_error)?
        .len();
    if source_size > MAX_SOURCE_BYTES {
        return Err(SharedImportPolicyError::reject(
            SharedImportRejection::ResourceLimit,
            "shared import exceeds the bounded source-size limit",
        ));
    }
    let sha256 = sha256_reader(&mut source, deadline).map_err(map_inspection_error)?;
    source
        .rewind()
        .map_err(InspectionError::from)
        .map_err(map_inspection_error)?;
    let detected = detect_archive_format(&mut source, deadline).map_err(map_inspection_error)?;
    if let Some(requested) = requested_format {
        let requested = DumpArchiveFormat::parse(requested).map_err(map_inspection_error)?;
        if requested != detected {
            return Err(SharedImportPolicyError::reject(
                SharedImportRejection::MalformedDump,
                "archive format does not match the uploaded shared import",
            ));
        }
    }

    let (statements_checked, namespaces_checked, objects_checked) = if protocol == Protocol::Mongodb
    {
        let catalog = inspect_mongodb_wrapper(&mut source, detected, deadline)
            .map_err(map_inspection_error)?;
        validate_mongodb_catalog(&catalog, source_database.unwrap_or(target_database))?;
        (0, catalog.databases, catalog.collections)
    } else if let Some(lines) = postgres_wrapper_lines {
        if protocol != Protocol::Postgres || detected != DumpArchiveFormat::Plain {
            return Err(SharedImportPolicyError::reject(
                SharedImportRejection::MalformedDump,
                "PostgreSQL wrapper filtering requires one prepared plain SQL dump",
            ));
        }
        source
            .rewind()
            .map_err(InspectionError::from)
            .map_err(map_inspection_error)?;
        let bounded = BoundedReader::new(&mut source, MAX_INSPECTED_BYTES, deadline);
        let filtered = OmitLines::new(BufReader::new(bounded), lines)?;
        let report = validate_shared_sql_reader(filtered, protocol, target_database)
            .map_err(map_sql_error)?;
        (report.statements_checked, report.namespaces, 0)
    } else {
        let mut report = None;
        let mut validate = |reader: &mut dyn std::io::Read| {
            let checked = validate_shared_sql_reader(reader, protocol, target_database)?;
            if report.replace(checked).is_some() {
                return Err(SharedSqlError::Rejected {
                    issue: SharedSqlIssue::AmbiguousStatement,
                    message: "archive contains multiple SQL dump payloads".to_string(),
                });
            }
            Ok(())
        };
        scan_sql_source::<SharedSqlError, _>(
            &mut source,
            detected,
            protocol,
            deadline,
            &mut validate,
        )
        .map_err(map_sql_error)?;
        let report = report.ok_or_else(|| {
            SharedImportPolicyError::reject(
                SharedImportRejection::MalformedDump,
                "shared import contains no SQL dump payload",
            )
        })?;
        (report.statements_checked, report.namespaces, 0)
    };

    Ok(SharedImportApproval {
        protocol,
        target_database: target_database.to_string(),
        sha256,
        source_size_bytes: source_size,
        detected_archive_format: detected,
        statements_checked,
        namespaces_checked,
        objects_checked,
        requires_isolated_staging: true,
        restore_as_tenant: true,
    })
}

struct OmitLines<R> {
    reader: R,
    omitted: [u64; 2],
    line: u64,
}

impl<R: BufRead> OmitLines<R> {
    fn new(reader: R, lines: (u64, u64)) -> Result<Self, SharedImportPolicyError> {
        if lines.0 == 0 || lines.1 <= lines.0 {
            return Err(SharedImportPolicyError::reject(
                SharedImportRejection::MalformedDump,
                "PostgreSQL dump wrapper line numbers are invalid",
            ));
        }
        Ok(Self {
            reader,
            omitted: [lines.0, lines.1],
            line: 1,
        })
    }
}

impl<R: BufRead> Read for OmitLines<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let mut written = 0;
        while written < output.len() {
            let available = self.reader.fill_buf()?;
            if available.is_empty() {
                break;
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let segment = newline.map_or(available.len(), |index| index + 1);
            if self.omitted.contains(&self.line) {
                self.reader.consume(segment);
                if newline.is_some() {
                    self.line = self.line.saturating_add(1);
                }
                continue;
            }
            let copied = segment.min(output.len() - written);
            output[written..written + copied].copy_from_slice(&available[..copied]);
            self.reader.consume(copied);
            written += copied;
            if copied == segment && newline.is_some() {
                self.line = self.line.saturating_add(1);
            }
        }
        Ok(written)
    }
}

fn validate_mongodb_catalog(
    catalog: &super::mongodb::MongoArchiveCatalog,
    target_database: &str,
) -> Result<(), SharedImportPolicyError> {
    if let Some(issue) = catalog.shared_issue {
        let (reason, message) = match issue {
            MongoSharedIssue::SystemDatabase | MongoSharedIssue::SystemCollection => (
                SharedImportRejection::SystemNamespace,
                "MongoDB shared imports cannot contain admin, config, local, or system namespaces",
            ),
            MongoSharedIssue::InvalidDatabase | MongoSharedIssue::InvalidCollection => (
                SharedImportRejection::CrossTenantNamespace,
                "MongoDB shared import contains an invalid or unrouteable namespace",
            ),
            MongoSharedIssue::UnsafeCollectionMetadata => (
                SharedImportRejection::UnsafeMongoMetadata,
                "MongoDB shared import contains executable, view, or unsafe collection metadata",
            ),
        };
        return Err(SharedImportPolicyError::reject(reason, message));
    }
    if !catalog.complete {
        return Err(SharedImportPolicyError::reject(
            SharedImportRejection::AmbiguousSyntax,
            "MongoDB shared import catalog could not be inspected completely",
        ));
    }
    if catalog.databases.len() > 1 {
        return Err(SharedImportPolicyError::reject(
            SharedImportRejection::CrossTenantNamespace,
            "MongoDB shared import contains more than one source database",
        ));
    }
    if catalog.databases.is_empty() {
        return Err(SharedImportPolicyError::reject(
            SharedImportRejection::AmbiguousSyntax,
            "MongoDB shared import does not identify one source database",
        ));
    }
    let source = &catalog.databases[0];
    if source != target_database {
        return Err(SharedImportPolicyError::reject(
            SharedImportRejection::CrossTenantNamespace,
            format!("MongoDB shared import contains database {source}; expected {target_database}"),
        ));
    }
    Ok(())
}

fn map_sql_error(error: SharedSqlError) -> SharedImportPolicyError {
    match error {
        SharedSqlError::Inspection(error) => map_inspection_error(error),
        SharedSqlError::Rejected { issue, message } => {
            let reason = match issue {
                SharedSqlIssue::CrossDatabase => SharedImportRejection::CrossTenantNamespace,
                SharedSqlIssue::SystemNamespace => SharedImportRejection::SystemNamespace,
                SharedSqlIssue::PrivilegedStatement => SharedImportRejection::PrivilegedStatement,
                SharedSqlIssue::ExternalAccess => SharedImportRejection::ExternalAccess,
                SharedSqlIssue::UnsupportedStatement | SharedSqlIssue::AmbiguousStatement => {
                    SharedImportRejection::AmbiguousSyntax
                }
            };
            SharedImportPolicyError::reject(reason, message)
        }
    }
}

fn map_inspection_error(error: InspectionError) -> SharedImportPolicyError {
    match error {
        InspectionError::Invalid(message) => {
            let unsafe_archive = ["archive", "path", "link", "device", "special entry"]
                .into_iter()
                .any(|needle| message.contains(needle));
            SharedImportPolicyError::reject(
                if unsafe_archive {
                    SharedImportRejection::UnsafeArchive
                } else {
                    SharedImportRejection::MalformedDump
                },
                message,
            )
        }
        InspectionError::Limit(message) => {
            SharedImportPolicyError::reject(SharedImportRejection::ResourceLimit, message)
        }
        InspectionError::Io(error) => SharedImportPolicyError::reject(
            SharedImportRejection::ReadFailure,
            format!("failed to read shared import safely: {error}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{Compression, write::GzEncoder};
    use tempfile::TempDir;

    use super::*;

    fn write_file(directory: &TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = directory.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn mongo_archive(database: &str, collection: &str, metadata: &str) -> Vec<u8> {
        let mut bytes = vec![0x6d, 0xe2, 0x99, 0x81];
        bytes.extend(
            bson::to_vec(&bson::doc! {
                "concurrent_collections": 1_i32,
                "version": "0.1",
                "server_version": "8.0.0",
                "tool_version": "100.12.2",
            })
            .unwrap(),
        );
        bytes.extend(
            bson::to_vec(&bson::doc! {
                "db": database,
                "collection": collection,
                "metadata": metadata,
                "size": 0_i32,
                "type": "collection",
            })
            .unwrap(),
        );
        bytes.extend(u32::MAX.to_le_bytes());
        let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
        gzip.write_all(&bytes).unwrap();
        gzip.finish().unwrap()
    }

    #[tokio::test]
    async fn approval_is_explicitly_tenant_only_and_staged() {
        let directory = TempDir::new().unwrap();
        let path = write_file(
            &directory,
            "tenant.mysql.sql",
            b"USE tenant_db; CREATE TABLE tenant_db.items(id BIGINT) ENGINE=InnoDB;",
        );
        let approval = validate_shared_import(
            &path,
            SharedImportRequest {
                protocol: Protocol::Mysql,
                target_database: "tenant_db",
                source_database: None,
                layout: SharedImportLayout::LogicalDump,
                archive_format: None,
                postgres_wrapper_lines: None,
            },
        )
        .await
        .unwrap();
        assert!(approval.requires_isolated_staging);
        assert!(approval.restore_as_tenant);
        assert_eq!(approval.namespaces_checked, ["tenant_db"]);
    }

    #[tokio::test]
    async fn archive_links_and_physical_restore_fail_closed() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("linked.tar");
        {
            let output = std::fs::File::create(&path).unwrap();
            let mut archive = tar::Builder::new(output);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_link_name("../../etc/passwd").unwrap();
            header.set_cksum();
            archive
                .append_data(&mut header, "dump.sql", std::io::empty())
                .unwrap();
            archive.finish().unwrap();
        }
        let error = validate_shared_import(
            &path,
            SharedImportRequest {
                protocol: Protocol::Postgres,
                target_database: "tenant_db",
                source_database: None,
                layout: SharedImportLayout::LogicalDump,
                archive_format: Some("tar"),
                postgres_wrapper_lines: None,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.reason, SharedImportRejection::UnsafeArchive);

        let physical = validate_shared_import(
            Path::new("not-opened"),
            SharedImportRequest {
                protocol: Protocol::Postgres,
                target_database: "tenant_db",
                source_database: None,
                layout: SharedImportLayout::PhysicalRestore,
                archive_format: None,
                postgres_wrapper_lines: None,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(physical.reason, SharedImportRejection::PhysicalRestore);
    }

    #[tokio::test]
    async fn validates_every_compressed_stream_member() {
        let directory = TempDir::new().unwrap();
        let mut wrapped = Vec::new();
        for sql in [
            b"USE tenant_db;".as_slice(),
            b"DROP USER tenant_admin;".as_slice(),
        ] {
            let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
            gzip.write_all(sql).unwrap();
            wrapped.extend(gzip.finish().unwrap());
        }
        let path = write_file(&directory, "members.mysql.sql.gz", &wrapped);
        let error = validate_shared_import(
            &path,
            SharedImportRequest {
                protocol: Protocol::Mysql,
                target_database: "tenant_db",
                source_database: None,
                layout: SharedImportLayout::LogicalDump,
                archive_format: None,
                postgres_wrapper_lines: None,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.reason, SharedImportRejection::PrivilegedStatement);
    }

    #[tokio::test]
    async fn mongodb_requires_exact_safe_namespace_and_metadata() {
        let directory = TempDir::new().unwrap();
        for (name, database, collection, metadata, expected) in [
            ("safe", "tenant_db", "items", "{}", None),
            (
                "cross",
                "other_db",
                "items",
                "{}",
                Some(SharedImportRejection::CrossTenantNamespace),
            ),
            (
                "system",
                "tenant_db",
                "system.users",
                "{}",
                Some(SharedImportRejection::SystemNamespace),
            ),
            (
                "code",
                "tenant_db",
                "items",
                r#"{"options":{"validator":{"$where":"evil()"}}}"#,
                Some(SharedImportRejection::UnsafeMongoMetadata),
            ),
        ] {
            let path = write_file(
                &directory,
                &format!("{name}.archive.gz"),
                &mongo_archive(database, collection, metadata),
            );
            let result = validate_shared_import(
                &path,
                SharedImportRequest {
                    protocol: Protocol::Mongodb,
                    target_database: "tenant_db",
                    source_database: None,
                    layout: SharedImportLayout::LogicalDump,
                    archive_format: None,
                    postgres_wrapper_lines: None,
                },
            )
            .await;
            match expected {
                Some(reason) => assert_eq!(result.unwrap_err().reason, reason),
                None => assert!(result.is_ok(), "{result:?}"),
            }
        }
    }

    #[tokio::test]
    async fn postgres_admission_checks_the_same_wrapper_filtered_stream_as_execution() {
        let directory = TempDir::new().unwrap();
        let path = write_file(
            &directory,
            "tenant.postgres.sql",
            b"-- dump\n\\restrict key123\nCREATE TABLE items(id bigint);\n\\unrestrict key123\n",
        );
        let request = SharedImportRequest {
            protocol: Protocol::Postgres,
            target_database: "tenant_db",
            source_database: None,
            layout: SharedImportLayout::LogicalDump,
            archive_format: Some("plain"),
            postgres_wrapper_lines: Some((2, 4)),
        };
        let approval = validate_shared_import(&path, request).await.unwrap();
        assert_eq!(approval.statements_checked, 1);

        let error = validate_shared_import(
            &path,
            SharedImportRequest {
                postgres_wrapper_lines: None,
                ..request
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.reason, SharedImportRejection::PrivilegedStatement);
    }
}
