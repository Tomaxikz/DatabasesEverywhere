use std::{future::Future, path::PathBuf, sync::Arc, time::Duration};

use axum::{
    body::Body,
    extract::{FromRequest, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

use futures::StreamExt;

use serde::Serialize;

use sha2::{Digest, Sha256};

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use tokio::{io::AsyncWriteExt, sync::Semaphore};

use crate::{
    instance::disk::capacity::{CapacityError, DiskCapacityService},
    instance::paths::InstancePaths,
    routes::http::response::{ApiError, ApiJson, ApiPath, ApiResponse},
    storage::import_uploads::{
        ImportUpload, ImportUploadAdmission, ImportUploadArchiveFormat, ImportUploadRepository,
        ImportUploadState, NewImportUpload,
    },
    utils::{hex::nibble, time::now_rfc3339},
};

use super::{
    ImportRequest,
    files::{create_private_file_sync, has_allowed_artifact_extension, prepare_private_dir},
    inspection::{
        DumpArchiveFormat, DumpInspection, DumpInspectionFailure, inspect_uploaded_dump_with_format,
    },
    jobs::queue_import_instance,
    *,
};

const FILENAME_HEADER: &str = "x-dbev-filename";
const SHA256_HEADER: &str = "x-dbev-sha256";
const MAX_ORIGINAL_FILENAME_BYTES: usize = 180;
const MAX_LISTED_UPLOADS: u32 = 100;
const MAX_CONCURRENT_IMPORT_STAGING: usize = 2;
const UPLOADS_DIRECTORY: &str = ".uploads";
const SHA256_HEX_LEN: usize = 64;
const UPLOAD_ID_PREFIX: &str = "upl_";
const UPLOAD_ID_LEN: usize = 36;

mod mongodb;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod upload_tests;

mod worker;

pub(super) use mongodb::resolve_upload_catalog;

use worker::{
    UploadWorkerGuards, UploadWorkerOptions, UploadWorkerRecovery, recover_interrupted_upload,
    spawn_upload_worker,
};

#[derive(Debug, Clone)]
pub struct ImportUploadService {
    repository: ImportUploadRepository,
    admission: Arc<Semaphore>,
    inspection_admission: Arc<Semaphore>,
    disk_capacity: DiskCapacityService,
    staging_admission: Arc<Semaphore>,
}

impl ImportUploadService {
    pub fn new(repository: ImportUploadRepository, max_concurrent: usize) -> Self {
        Self::new_with_staging_limit(
            repository,
            max_concurrent,
            max_concurrent.min(MAX_CONCURRENT_IMPORT_STAGING),
        )
    }

    pub fn new_with_staging_limit(
        repository: ImportUploadRepository,
        max_concurrent: usize,
        max_concurrent_staging: usize,
    ) -> Self {
        Self::with_limits(
            repository,
            max_concurrent,
            max_concurrent_staging,
            crate::config::RuntimeLimits::default().upload_inspections,
        )
    }

    pub(crate) fn with_limits(
        repository: ImportUploadRepository,
        max_concurrent: usize,
        max_concurrent_staging: usize,
        max_inspections: usize,
    ) -> Self {
        let max_concurrent = max_concurrent.max(1);
        Self {
            repository,
            admission: Arc::new(Semaphore::new(max_concurrent)),
            inspection_admission: Arc::new(Semaphore::new(
                max_concurrent.min(max_inspections.max(1)),
            )),
            disk_capacity: DiskCapacityService::default(),
            staging_admission: Arc::new(Semaphore::new(max_concurrent_staging.max(1))),
        }
    }

    pub fn repo(&self) -> &ImportUploadRepository {
        &self.repository
    }

    pub(super) async fn acquire_staging(
        &self,
        root: &std::path::Path,
        requested: u64,
    ) -> Result<ImportStagingPermit, ApiError> {
        prepare_private_dir(root, "logical import staging directory").await?;
        self.acquire_staging_on_existing_root(root, requested).await
    }

    pub(super) async fn acquire_staging_on_existing_root(
        &self,
        root: &std::path::Path,
        requested: u64,
    ) -> Result<ImportStagingPermit, ApiError> {
        let metadata = tokio::fs::symlink_metadata(root).await.map_err(|error| {
            ApiError::Runtime(format!(
                "failed to inspect import staging filesystem: {error}"
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ApiError::Runtime(
                "import staging filesystem root must be a real directory".to_string(),
            ));
        }
        let admission = self
            .staging_admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError::RateLimited)?;
        let reservation = self
            .disk_capacity
            .reserve(root, requested)
            .await
            .map_err(|error| capacity_api_error(error, "import staging"))?;
        Ok(ImportStagingPermit {
            _admission: admission,
            _reservation: reservation,
        })
    }

    pub(crate) async fn reserve_output_capacity(
        &self,
        root: &std::path::Path,
        requested: u64,
    ) -> Result<DiskCapacityReservation, ApiError> {
        let metadata = tokio::fs::symlink_metadata(root).await.map_err(|error| {
            ApiError::Runtime(format!("failed to inspect output filesystem: {error}"))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ApiError::Runtime(
                "output filesystem root must be a real directory".to_string(),
            ));
        }
        self.disk_capacity
            .reserve(root, requested)
            .await
            .map_err(|error| capacity_api_error(error, "output"))
    }

    pub(crate) async fn output_roots_share_filesystem(
        &self,
        first: &std::path::Path,
        second: &std::path::Path,
    ) -> Result<bool, ApiError> {
        self.disk_capacity
            .roots_share_filesystem(first, second)
            .await
            .map_err(|error| capacity_api_error(error, "output"))
    }
}

pub(super) struct ImportStagingPermit {
    _admission: tokio::sync::OwnedSemaphorePermit,
    _reservation: DiskCapacityReservation,
}

pub(crate) use crate::instance::disk::capacity::DiskCapacityReservation;

mod handlers;
pub(crate) use handlers::*;
mod finalize;
use finalize::*;
mod ingest;
use ingest::*;
mod records;
pub(super) use records::*;
mod storage;
pub(super) use storage::*;
mod lifecycle;
pub(super) use lifecycle::*;

#[derive(Debug, Serialize)]
pub(crate) struct ImportUploadResponse {
    pub upload_id: String,
    pub instance_id: String,
    pub original_filename: String,
    pub protocol: Protocol,
    pub archive_format: Option<&'static str>,
    pub state: &'static str,
    pub size_bytes: u64,
    pub sha256: Option<String>,
    pub catalog_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ImportUploadDeleteResponse {
    pub upload_id: String,
    pub deleted: bool,
}
