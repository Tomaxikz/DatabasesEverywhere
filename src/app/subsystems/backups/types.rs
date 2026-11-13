use crate::databases::protocol::Protocol;
use crate::routes::http::diagnostics::PublicDiagnostic;
use crate::routes::http::response::ApiError;
use crate::server::backup::BackupLayout;
use crate::server::backup::catalog::BackupCatalogColumn;
use crate::server::backup::manifest::ConsistencyLevel;
use crate::server::metadata::InstanceMetadata;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BackupStatusResponse {
    pub enabled: bool,
    pub interval_minutes: u64,
    pub run_on_startup: bool,
    pub retention_keep_latest_per_instance: usize,
    pub retention_max_age_days: u64,
    pub redis_excluded: bool,
    #[schema(schema_with = crate::routes::openapi::literals::backup_storage_driver)]
    pub storage_driver: String,
    pub browsing_enabled: bool,
    #[schema(schema_with = crate::routes::openapi::literals::dedicated_backup_mode)]
    pub dedicated_mode: &'static str,
}

#[derive(Debug, Default, Serialize, utoipa::ToSchema)]
#[schema(
    as = RunBackupsResponse,
    description = "A completed batch request can contain per-instance failures. Check failed even on HTTP 200; skipped contains only intentionally stopped instances, not operational errors."
)]
pub struct RunBackupResponse {
    pub backups: Vec<BackupInfo>,
    pub skipped: Vec<BackupIssue>,
    pub failed: Vec<BackupIssue>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BackupInfo {
    pub id: String,
    pub instance_id: String,
    pub protocol: Protocol,
    pub layout: BackupLayout,
    pub size_bytes: u64,
    #[schema(format = DateTime)]
    pub modified_at: String,
    pub sha256: String,
    pub manifest_schema_version: u32,
    /// `null` for legacy backups, which never recorded one.
    #[schema(required, schema_with = crate::routes::openapi::literals::consistency_level)]
    pub consistency: Option<ConsistencyLevel>,
    #[schema(required)]
    pub restore_recipe: Option<String>,
}

/// Retention never deletes it.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UnsupportedBackupInfo {
    pub id: String,
    pub instance_id: String,
    pub diagnostic: String,
}

#[derive(Debug, Deserialize, Default, utoipa::IntoParams)]
#[serde(default, deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct RunBackupQuery {
    #[param(schema_with = crate::routes::openapi::literals::dedicated_backup_mode)]
    pub mode: Option<crate::config::DedicatedBackupMode>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RestoreBackupResponse {
    pub instance_id: String,
    pub backup_id: String,
    pub restored: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BackupIssue {
    pub instance_id: String,
    pub protocol: Protocol,
    pub reason: PublicDiagnostic,
}

pub(super) enum BackupAttempt {
    Completed(BackupInfo),
    Skipped(BackupIssue),
}

impl RunBackupResponse {
    pub(super) fn record(
        &mut self,
        metadata: &InstanceMetadata,
        result: Result<BackupAttempt, ApiError>,
    ) {
        match result {
            Ok(BackupAttempt::Completed(backup)) => self.backups.push(backup),
            Ok(BackupAttempt::Skipped(issue)) => {
                tracing::info!(
                    event = "audit instance_backup_skipped",
                    instance_id = issue.instance_id,
                    protocol = issue.protocol.as_str(),
                    reason = issue.reason.code,
                    "backup omitted for an intentionally stopped instance"
                );
                self.skipped.push(issue);
            }
            Err(error) => {
                let reason = PublicDiagnostic::from_api_error("instance backup", &error);
                tracing::error!(
                    event = "audit instance_backup_failed",
                    instance_id = metadata.instance_id,
                    protocol = metadata.protocol.as_str(),
                    error_id = reason.error_id.as_deref(),
                    error = %error,
                    "instance backup failed; no new backup was confirmed for this pass"
                );
                self.failed.push(BackupIssue {
                    instance_id: metadata.instance_id.clone(),
                    protocol: metadata.protocol,
                    reason,
                });
            }
        }
    }

    pub(super) fn status(&self) -> &'static str {
        if !self.failed.is_empty() {
            if self.backups.is_empty() {
                "failed"
            } else {
                "partial_failure"
            }
        } else if !self.skipped.is_empty() {
            "completed_with_skips"
        } else {
            "completed"
        }
    }
}

#[derive(Debug, Deserialize, Default, utoipa::IntoParams)]
#[serde(default, deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct BackupContentsQuery {
    #[param(max_length = 1024)]
    pub object: Option<String>,
    #[param(default = 0)]
    pub offset: usize,
    #[param(minimum = 1, maximum = 100, default = 25)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BackupContentsResponse {
    pub backup_id: String,
    pub instance_id: String,
    pub protocol: Protocol,
    pub database_name: String,
    #[schema(required, format = DateTime)]
    pub captured_at: Option<String>,
    #[schema(required)]
    pub consistency: Option<String>,
    pub catalog_available: bool,
    pub truncated: bool,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(nullable = false)]
    pub objects: Option<Vec<BackupObjectSummary>>,
    #[schema(required)]
    pub selection: Option<BackupObjectSelection>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BackupObjectSummary {
    pub id: String,
    pub namespace: String,
    pub name: String,
    pub kind: String,
    #[schema(required)]
    pub estimated_rows: Option<u64>,
    pub column_count: usize,
    pub captured_preview_rows: usize,
    pub preview_truncated: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BackupObjectSelection {
    pub columns: Vec<BackupCatalogColumn>,
    pub object_id: String,
    pub offset: usize,
    #[schema(minimum = 1, maximum = 100)]
    pub limit: usize,
    pub returned: usize,
    pub total_captured: usize,
    pub rows: Vec<serde_json::Value>,
    pub truncated: bool,
}
