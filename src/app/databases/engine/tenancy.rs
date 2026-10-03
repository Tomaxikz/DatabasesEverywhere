use std::time::Duration;

use super::EngineInfo;
use crate::{
    server::monitoring::engine::backends::EngineTelemetry,
    server::placement::tenant::backends::TenantBackend,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TenantDiskBoundary {
    PostgresTablespace,
    MysqlMarkerFile,
    SoftScanner,
}

impl TenantDiskBoundary {
    pub(crate) const fn is_hard_path(self) -> bool {
        matches!(self, Self::PostgresTablespace | Self::MysqlMarkerFile)
    }
}

pub(crate) trait EngineTenancy: EngineInfo {
    fn tenant_backend(&self) -> Option<&'static dyn TenantBackend> {
        None
    }

    fn tenant_disk_boundary(&self) -> Option<TenantDiskBoundary> {
        None
    }

    fn telemetry(&self) -> Option<&'static dyn EngineTelemetry> {
        None
    }

    fn telemetry_reports_operations(&self) -> bool {
        false
    }

    fn manifest_query_command(
        &self,
        _statement: &str,
        _username: &str,
        _database: &str,
    ) -> Option<String> {
        None
    }

    fn manifest_statement_timeout_sql(&self, _timeout: Duration) -> Option<String> {
        None
    }

    fn rollback_gap_sql(&self, _database: &str, _username: &str) -> Option<String> {
        None
    }

    fn has_hosted_config(&self) -> bool {
        false
    }

    fn cleans_stale_import_bridges(&self) -> bool {
        false
    }
}
