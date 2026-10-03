use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArtifactConfig {
    pub retention_keep_latest: usize,
    pub retention_max_age_days: u64,
    /// When true, generated client exports are delivered from a private
    /// one-use spool and removed after download instead of entering the
    /// retained artifact inventory.
    pub stream_exports_only: bool,
    /// Maximum retained artifacts, or pending one-use exports, per instance.
    pub max_artifacts_per_instance: usize,
    pub import_upload_max_bytes: u64,
    pub import_upload_max_total_bytes: u64,
    pub import_upload_max_per_instance: usize,
    pub import_upload_max_concurrent: usize,
    pub import_upload_ttl_hours: u64,
    pub import_upload_timeout_seconds: u64,
    pub import_upload_idle_timeout_seconds: u64,
    pub import_export_scheduler: ImportExportSchedulerConfig,
}

impl Default for ArtifactConfig {
    fn default() -> Self {
        Self {
            retention_keep_latest: 20,
            retention_max_age_days: 30,
            stream_exports_only: false,
            max_artifacts_per_instance: 20,
            import_upload_max_bytes: 8 * 1024 * 1024 * 1024,
            import_upload_max_total_bytes: 32 * 1024 * 1024 * 1024,
            import_upload_max_per_instance: 4,
            import_upload_max_concurrent: 2,
            import_upload_ttl_hours: 24,
            import_upload_timeout_seconds: 3600,
            import_upload_idle_timeout_seconds: 30,
            import_export_scheduler: ImportExportSchedulerConfig::default(),
        }
    }
}
