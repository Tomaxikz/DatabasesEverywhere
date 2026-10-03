use std::{
    path::{Path as FsPath, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::extract::State;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::{
    auth::scopes,
    databases::protocol::Protocol,
    routes::http::{
        diagnostics::PublicDiagnostic,
        policy::{ApiRequestContext, DestructiveActionConfirmation, DestructiveActionPolicy},
        response::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResponse, ApiResult},
        router::AppState,
    },
    server::backup::{
        BackupBundle, BackupLayout, BackupStorage, BackupStoreError, MaterializedBackup,
        StoredBackup, build_manifest,
        catalog::{BackupCatalog, BackupCatalogColumn},
        new_backup_id, prepare_private_dir,
    },
    server::jobs::import_export::{
        DataArchiveSourcePolicy, ImportExportJobPermit, JobAdmissionError, JobEstimateInput,
        JobResourceCost, SchedulerAcquireError, create_bounded_archive_with_policy,
    },
    server::metadata::{DesiredInstanceState, InstanceMetadata, InstanceStatus},
    server::placement::DeploymentMode,
    subsystems::artifacts::DeleteArtifactResponse,
    utils::{ids::validate_instance_id, limits::mib_to_bytes, time::now_unix},
};

const DEFAULT_BROWSE_LIMIT: usize = 25;
const MAX_BROWSE_LIMIT: usize = 100;
const MAX_BROWSE_OBJECT_ID_BYTES: usize = 1024;
const PHYSICAL_BACKUP_HEADROOM_BYTES: u64 = 64 * 1024 * 1024;
const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

mod catalog;
mod checks;
mod handlers;
mod restore;
mod run;
mod scheduler;
mod storage;
mod types;
use catalog::*;
use checks::*;
pub use handlers::*;
use restore::*;
use run::*;
pub use scheduler::*;
pub(crate) use storage::*;
pub use types::*;

#[cfg(test)]
mod tests;
