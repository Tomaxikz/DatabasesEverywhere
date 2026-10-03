use super::*;

#[derive(Debug, Serialize)]
pub struct BackupStatusResponse {
    pub enabled: bool,
    pub interval_minutes: u64,
    pub run_on_startup: bool,
    pub retention_keep_latest_per_instance: usize,
    pub retention_max_age_days: u64,
    pub redis_excluded: bool,
    pub storage_driver: String,
    pub browsing_enabled: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct RunBackupResponse {
    pub backups: Vec<BackupInfo>,
    pub skipped: Vec<BackupIssue>,
    pub failed: Vec<BackupIssue>,
}

#[derive(Debug, Serialize)]
pub struct BackupInfo {
    pub id: String,
    pub instance_id: String,
    pub protocol: Protocol,
    pub layout: BackupLayout,
    pub size_bytes: u64,
    pub modified_at: String,
    pub sha256: String,
}

#[derive(Debug, Serialize)]
pub struct RestoreBackupResponse {
    pub instance_id: String,
    pub backup_id: String,
    pub restored: bool,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct BackupContentsQuery {
    pub object: Option<String>,
    pub offset: usize,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct BackupContentsResponse {
    pub backup_id: String,
    pub instance_id: String,
    pub protocol: Protocol,
    pub database_name: String,
    pub captured_at: Option<String>,
    pub consistency: Option<String>,
    pub catalog_available: bool,
    pub truncated: bool,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub objects: Option<Vec<BackupObjectSummary>>,
    pub selection: Option<BackupObjectSelection>,
}

#[derive(Debug, Serialize)]
pub struct BackupObjectSummary {
    pub id: String,
    pub namespace: String,
    pub name: String,
    pub kind: String,
    pub estimated_rows: Option<u64>,
    pub column_count: usize,
    pub captured_preview_rows: usize,
    pub preview_truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct BackupObjectSelection {
    pub columns: Vec<BackupCatalogColumn>,
    pub object_id: String,
    pub offset: usize,
    pub limit: usize,
    pub returned: usize,
    pub total_captured: usize,
    pub rows: Vec<serde_json::Value>,
    pub truncated: bool,
}
