use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write},
    path::{Component, Path as FsPath, PathBuf},
    time::{Duration, Instant},
};

use crate::{
    api::{
        api_response::{ApiError, ApiOptionalJson, ApiPath, ApiQuery, ApiResponse, ApiResult},
        instances::{LifecycleAction, lifecycle_instance_locked},
        public_diagnostic::PublicDiagnostic,
        remote_import::{
            ImportMode, RemoteImportRequest, RemoteImportSource, RemoteJobAdmissionPermit,
            acquire_logical_dump, import_qdrant, import_redis, import_valkey, try_admit_remote_job,
            validate_remote_source,
        },
        routes::AppState,
        security_policy::ApiRequestContext,
    },
    auth::scopes,
    instances::{
        metadata::{InstanceMetadata, InstanceStatus},
        paths::InstancePaths,
    },
    jobs::import_export::{
        ArchiveSymlinkPolicy, ImportExportAction, ImportExportJob, ImportExportJobPermit,
        ImportExportStatus, JobAdmissionError, JobEstimateInput, JobResourceCost,
        SchedulerAcquireError, conservative_import_input_bytes, extract_data_archive_bounded,
        protocol_uses_logical_dumps, protocol_uses_native_compression,
    },
    shared::{files::is_safe_flat_file_name, protocol::Protocol, shell::sh_quote},
};
use axum::extract::State;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

pub(crate) const MAX_UNARCHIVED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 4096;
const ARCHIVE_ENTRY_DISK_OVERHEAD_BYTES: u64 = 16 * 1024;
const MAX_ARCHIVE_DEPTH: usize = 32;
const ARCHIVE_OPERATION_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_SELECTION_ITEMS: usize = 512;
const MAX_SELECTION_FIELDS_PER_ITEM: usize = 512;
const FAIL_CLOSED_STOP_TIMEOUT: Duration = Duration::from_secs(30);
const LOGICAL_ROLLBACK_READINESS_TIMEOUT: Duration = Duration::from_secs(120);
pub(crate) const CLICKHOUSE_ENGINE_AWK_PROGRAM: &str = r#"
/^[[:space:]]*ENGINE[[:space:]]*=/ {
  candidate = $0
  sub(/^[[:space:]]*ENGINE[[:space:]]*=[[:space:]]*/, "", candidate)
  if (candidate !~ /^[A-Za-z][A-Za-z0-9_]*([[:space:](]|$)/) {
    invalid = 1
    next
  }
  sub(/[^A-Za-z0-9_].*$/, "", candidate)
  engine = candidate
  count++
}
END {
  if (invalid || count != 1) {
    exit 64
  }
  print engine
}
"#;

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ExportRequest {
    pub selection: Option<ImportExportSelection>,
    #[serde(default)]
    pub archive_format: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRequest {
    pub source: ImportSource,
    #[serde(default)]
    pub mode: ImportMode,
    #[serde(default)]
    pub selection: Option<ImportExportSelection>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImportSource {
    Artifact {
        artifact_id: String,
        #[serde(default)]
        archive_format: Option<String>,
    },
    Upload {
        upload_id: String,
        #[serde(default)]
        source_database: Option<String>,
    },
    Remote(RemoteImportRequest),
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SelectionMode {
    #[default]
    Full,
    Selective,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ImportExportSelection {
    pub mode: SelectionMode,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    #[serde(deserialize_with = "deserialize_selection_fields")]
    pub fields: HashMap<String, Vec<String>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SelectionFieldsInput {
    Map(HashMap<String, Vec<String>>),
    Sequence(Vec<serde::de::IgnoredAny>),
}

fn deserialize_selection_fields<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    match SelectionFieldsInput::deserialize(deserializer)? {
        SelectionFieldsInput::Map(fields) => Ok(fields),
        SelectionFieldsInput::Sequence(fields) if fields.is_empty() => Ok(HashMap::new()),
        SelectionFieldsInput::Sequence(_) => Err(D::Error::custom(
            "selection.fields must be an object or an empty array",
        )),
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ImportOptions {
    archive_format: Option<String>,
    source: ImportSourceOptions,
    source_database: Option<String>,
    mode: ImportMode,
    selection: ImportExportSelection,
    upload_staging: Option<UploadStagingBudget>,
}

#[derive(Debug, Clone)]
enum UploadStagingBudget {
    Logical {
        budget: logical::UploadLogicalStagingBudget,
        target_created_at: String,
        disk_mib: u64,
    },
    Physical {
        extracted_bytes: u64,
        target_created_at: String,
        disk_mib: u64,
    },
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ExportOptions {
    selection: ImportExportSelection,
    archive_format: ExportArchiveFormat,
    delivery: ExportDelivery,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum ExportDelivery {
    #[default]
    InternalRetained,
    ClientRetained,
    ClientOneUse,
}

impl ExportDelivery {
    fn for_client(state: &AppState) -> Self {
        if state.config.artifacts.stream_exports_only {
            Self::ClientOneUse
        } else {
            Self::ClientRetained
        }
    }

    fn is_client(self) -> bool {
        !matches!(self, Self::InternalRetained)
    }

    fn is_one_use(self) -> bool {
        matches!(self, Self::ClientOneUse)
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExportArchiveFormat {
    #[default]
    Plain,
    Gzip,
    Bzip2,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ReplayDescriptor {
    Export {
        selection: ImportExportSelection,
        archive_format: ExportArchiveFormat,
    },
    ArtifactImport {
        mode: ImportMode,
        selection: ImportExportSelection,
        archive_format: Option<String>,
    },
    UploadImport {
        upload_id: String,
        #[serde(default)]
        source_database: Option<String>,
        mode: ImportMode,
        selection: ImportExportSelection,
    },
}

impl ExportArchiveFormat {
    fn detect(format: Option<&str>) -> Result<Self, ApiError> {
        if format.is_none() {
            return Ok(Self::Plain);
        }
        match format
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "plain" => Ok(Self::Plain),
            "gzip" => Ok(Self::Gzip),
            "bzip2" => Ok(Self::Bzip2),
            other => Err(ApiError::BadRequest(format!(
                "unsupported export archive_format {other}; use plain, gzip, or bzip2"
            ))),
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::Plain => "",
            Self::Gzip => ".gz",
            Self::Bzip2 => ".bz2",
        }
    }
}

fn normalized_export_archive_format(
    protocol: Protocol,
    archive_format: ExportArchiveFormat,
) -> ExportArchiveFormat {
    if protocol == Protocol::Mongodb && archive_format == ExportArchiveFormat::Gzip {
        ExportArchiveFormat::Plain
    } else {
        archive_format
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ImportSourceOptions {
    Artifact(PathBuf),
    Upload { upload_id: String, path: PathBuf },
    RemoteRequest(RemoteImportRequest),
    Remote(RemoteImportSource),
}

impl Default for ImportSourceOptions {
    fn default() -> Self {
        Self::Artifact(PathBuf::new())
    }
}

impl ImportOptions {
    pub(crate) fn artifact(path: impl Into<PathBuf>) -> Self {
        Self {
            source: ImportSourceOptions::Artifact(path.into()),
            ..Self::default()
        }
    }

    pub(crate) fn recovery_restore(path: impl Into<PathBuf>, protocol: Protocol) -> Self {
        let path = path.into();
        Self {
            archive_format: recovery_archive_format(&path, protocol),
            source: ImportSourceOptions::Artifact(path),
            source_database: None,
            mode: ImportMode::Wipe,
            selection: ImportExportSelection::default(),
            upload_staging: None,
        }
    }

    fn replay_artifact(
        path: impl Into<PathBuf>,
        mode: ImportMode,
        selection: ImportExportSelection,
        archive_format: Option<String>,
    ) -> Self {
        Self {
            archive_format,
            source: ImportSourceOptions::Artifact(path.into()),
            source_database: None,
            mode,
            selection,
            upload_staging: None,
        }
    }
}

fn recovery_archive_format(path: &FsPath, protocol: Protocol) -> Option<String> {
    if matches!(
        protocol,
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
    ) {
        return None;
    }
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if protocol == Protocol::Mongodb
        && (filename.ends_with(".mongodb.archive.gz") || filename.ends_with(".archive.gz"))
    {
        return None;
    }
    [
        (".tar.gz", "tar.gz"),
        (".tgz", "tar.gz"),
        (".tar", "tar"),
        (".zip", "zip"),
        (".gzip", "gzip"),
        (".gz", "gzip"),
        (".bzip2", "bzip2"),
        (".bz2", "bzip2"),
    ]
    .into_iter()
    .find_map(|(suffix, format)| filename.ends_with(suffix).then(|| format.to_string()))
}

impl From<&ImportRequest> for ImportOptions {
    fn from(request: &ImportRequest) -> Self {
        let selection = request.selection.clone().unwrap_or_default();
        match &request.source {
            ImportSource::Artifact {
                artifact_id,
                archive_format,
            } => Self {
                archive_format: archive_format.clone(),
                source: ImportSourceOptions::Artifact(PathBuf::from(artifact_id)),
                source_database: None,
                mode: request.mode,
                selection,
                upload_staging: None,
            },
            ImportSource::Upload {
                upload_id,
                source_database,
            } => Self {
                archive_format: None,
                source: ImportSourceOptions::Upload {
                    upload_id: upload_id.clone(),
                    path: PathBuf::new(),
                },
                source_database: source_database.clone(),
                mode: request.mode,
                selection,
                upload_staging: None,
            },
            ImportSource::Remote(remote) => Self {
                archive_format: None,
                source: ImportSourceOptions::RemoteRequest(remote.clone()),
                source_database: None,
                mode: request.mode,
                selection,
                upload_staging: None,
            },
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobListQuery {
    pub status: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ImportExportJobResponse {
    pub job_id: String,
    pub instance_id: String,
    pub action: ImportExportAction,
    pub status: ImportExportStatus,
    pub artifact_id: Option<String>,
    pub artifact_size_bytes: Option<u64>,
    pub error: Option<PublicDiagnostic>,
    pub created_at: String,
    pub updated_at: String,
}

mod archive;
mod files;
pub(crate) mod inspection;
mod jobs;
mod logical;
mod physical;
mod protocol;
mod upload_recovery;
mod uploads;

pub use jobs::{export_instance, get_import_export_job, list_import_export_jobs};
pub(crate) use jobs::{
    export_instance_to_default_artifact, import_default_artifact_into_metadata,
    public_job_response, queue_import_instance, replay_failed_job,
};
pub(crate) use logical::quarantine_after_uncertain_import;
pub(crate) use physical::{
    finish_physical_operation, restore_data_from_archive_bounded, rollback_data_from_archive,
    verify_physical_data_replacement,
};
pub(crate) use upload_recovery::{reconcile_import_uploads_once, run_import_upload_sweeper};
pub(crate) use uploads::{DiskCapacityReservation, ImportUploadService};
pub(crate) use uploads::{
    delete_import_upload, get_import_upload, import_entry, inspect_import_upload,
    list_import_uploads,
};

#[cfg(test)]
mod tests;
