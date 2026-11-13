pub mod recovery;
pub mod remote;

use std::{
    path::{Path as FsPath, PathBuf},
    time::Duration,
};

pub(crate) use crate::databases::clickhouse::transfer::CLICKHOUSE_ENGINE_AWK_PROGRAM;
pub use crate::server::jobs::import_export::selection::{ImportExportSelection, SelectionMode};
use crate::{
    databases::protocol::Protocol,
    routes::http::{diagnostics::PublicDiagnostic, response::ApiError, router::AppState},
    runtime::docker::ExecRecovery,
    server::jobs::import_export::{ImportExportAction, ImportExportStatus},
    server::metadata::InstanceMetadata,
    server::placement::DeploymentMode,
    subsystems::import_export::remote::{ImportMode, RemoteImportRequest, RemoteImportSource},
};
use serde::{Deserialize, Serialize};
use utoipa::openapi::{Ref, RefOr, Schema, schema::Discriminator, schema::OneOfBuilder};

pub(crate) const MAX_UNARCHIVED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 4096;
const ARCHIVE_ENTRY_DISK_OVERHEAD_BYTES: u64 = 16 * 1024;
const MAX_ARCHIVE_DEPTH: usize = 32;
const ARCHIVE_OPERATION_TIMEOUT: Duration = Duration::from_secs(300);
const FAIL_CLOSED_STOP_TIMEOUT: Duration = Duration::from_secs(30);
const LOGICAL_ROLLBACK_READINESS_TIMEOUT: Duration = Duration::from_secs(120);
const LOGICAL_STREAM_EXEC_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Recovery policy for operator-requested logical imports and exports. Backups never reach
/// `RestartRuntime`; shared tenant backups are always `CallerHandles`.
pub(super) fn logical_exec_recovery(metadata: &InstanceMetadata) -> ExecRecovery {
    match metadata.deployment_mode {
        DeploymentMode::Dedicated => ExecRecovery::RestartRuntime,
        DeploymentMode::Shared => ExecRecovery::CallerHandles,
    }
}

#[derive(Debug, Deserialize, Default, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportRequest {
    pub selection: Option<ImportExportSelection>,
    #[serde(default)]
    #[schema(schema_with = crate::routes::openapi::literals::export_archive_format)]
    pub archive_format: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportRequest {
    #[schema(inline)]
    pub source: ImportSource,
    #[serde(default)]
    #[schema(inline)]
    pub mode: ImportMode,
    #[serde(default)]
    pub selection: Option<ImportExportSelection>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ImportSource {
    Artifact(ArtifactImportSource),
    Upload(UploadImportSource),
    Remote(RemoteImportRequest),
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactImportSource {
    pub artifact_id: String,
    #[serde(default)]
    #[schema(schema_with = crate::routes::openapi::literals::import_archive_format)]
    pub archive_format: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
#[schema(
    description = "A temporary dump received through the octet-stream form of this instance's import endpoint."
)]
pub struct UploadImportSource {
    #[schema(pattern = "^upl_[0-9a-f]{32}$")]
    pub upload_id: String,
    #[serde(default)]
    #[schema(
        nullable = false,
        min_length = 1,
        max_length = 63,
        example = "legacy_tenant"
    )]
    pub source_database: Option<String>,
}

impl utoipa::PartialSchema for ImportSource {
    fn schema() -> RefOr<Schema> {
        let variants = [
            ("artifact", "ArtifactImportSource"),
            ("remote", "RemoteImportSource"),
            ("upload", "UploadImportSource"),
        ];
        let mut discriminator = Discriminator::new("type");
        let mut one_of = OneOfBuilder::new();
        for (tag, name) in variants {
            discriminator
                .mapping
                .insert(tag.into(), format!("#/components/schemas/{name}"));
            one_of = one_of.item(Ref::from_schema_name(name));
        }
        one_of.discriminator(Some(discriminator)).into()
    }
}

impl utoipa::ToSchema for ImportSource {
    fn schemas(schemas: &mut Vec<(String, RefOr<Schema>)>) {
        schemas.extend([
            tagged::<ArtifactImportSource>("artifact"),
            tagged::<RemoteImportRequest>("remote"),
            tagged::<UploadImportSource>("upload"),
        ]);
    }
}

fn tagged<T: utoipa::ToSchema>(tag: &str) -> (String, RefOr<Schema>) {
    let mut schema = T::schema();
    if let RefOr::T(Schema::Object(object)) = &mut schema {
        let literal = crate::routes::openapi::literal([tag.into()]);
        object
            .properties
            .shift_insert(0, "type".into(), literal.into());
        object.required.insert(0, "type".into());
    }
    (T::name().into_owned(), schema)
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
        let Some(format) = format else {
            return Ok(Self::Plain);
        };
        match format.trim().to_ascii_lowercase().as_str() {
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

fn export_archive_format(
    protocol: Protocol,
    archive_format: ExportArchiveFormat,
) -> ExportArchiveFormat {
    if protocol.engine().native_gzip_logical_dump() && archive_format == ExportArchiveFormat::Gzip {
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
    if protocol.engine().is_physical() {
        return None;
    }
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if protocol.engine().native_gzip_logical_dump()
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
            ImportSource::Artifact(ArtifactImportSource {
                artifact_id,
                archive_format,
            }) => Self {
                archive_format: archive_format.clone(),
                source: ImportSourceOptions::Artifact(PathBuf::from(artifact_id)),
                source_database: None,
                mode: request.mode,
                selection,
                upload_staging: None,
            },
            ImportSource::Upload(UploadImportSource {
                upload_id,
                source_database,
            }) => Self {
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

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct JobListQuery {
    pub status: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
#[schema(as = ImportExportJob)]
pub struct ImportExportJobResponse {
    pub job_id: String,
    pub instance_id: String,
    #[schema(inline)]
    pub action: ImportExportAction,
    #[schema(inline)]
    pub status: ImportExportStatus,
    #[schema(required)]
    pub artifact_id: Option<String>,
    #[schema(required)]
    pub artifact_size_bytes: Option<u64>,
    #[schema(required)]
    pub error: Option<PublicDiagnostic>,
    #[schema(format = DateTime)]
    pub created_at: String,
    #[schema(format = DateTime)]
    pub updated_at: String,
}

mod archive;
mod files;
pub(crate) mod inspection;
pub(crate) mod jobs;
pub(crate) mod logical;
mod physical;
mod postgres_dump;
mod protocol;
mod shared_restore;
mod shared_security;
mod upload_recovery;
pub(crate) mod uploads;

pub(crate) use crate::server::disk::capacity::DiskCapacityReservation;
pub(crate) use files::logical_staging_root;
pub(crate) use jobs::{
    export_default_artifact, public_job_response, queue_import_instance, register_default_artifact,
    replay_failed_job,
};
pub use jobs::{export_instance, get_import_export_job, list_import_export_jobs};
pub(crate) use logical::quarantine_uncertain_import;
pub(crate) use physical::{
    StagedDataPreparation, check_restore_layout, finish_physical_change, restore_bounded_archive,
    restore_prepared_archive, rollback_from_archive,
};
pub(crate) use upload_recovery::{reconcile_import_uploads, run_upload_sweeper};
pub(crate) use uploads::ImportUploadService;
pub(crate) use uploads::{
    delete_import_upload, get_import_catalog, get_import_upload, import_entry,
    inspect_import_upload, list_import_uploads,
};

#[cfg(test)]
pub(crate) mod roundtrip_tests;
#[cfg(test)]
mod tests;
