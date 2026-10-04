use std::time::Duration;

use crate::{
    databases::engine::{EngineTenancy, TenantDiskBoundary},
    server::monitoring::engine::backends::EngineTelemetry,
    server::placement::{policy, tenant::backends::TenantBackend},
    utils::{limits::InstanceLimits, shell::sh_quote},
};

use super::{
    engine::Mysql, provision::TenantQuota, telemetry::MysqlTelemetry, tenant_backend::MysqlFlavor,
};

impl EngineTenancy for Mysql {
    fn tenant_backend(&self) -> Option<&'static dyn TenantBackend> {
        Some(&MysqlFlavor::Mysql)
    }

    fn telemetry(&self) -> Option<&'static dyn EngineTelemetry> {
        Some(&MysqlTelemetry)
    }

    fn tenant_disk_boundary(&self) -> Option<TenantDiskBoundary> {
        Some(TenantDiskBoundary::MysqlMarkerFile)
    }

    fn manifest_query_command(
        &self,
        statement: &str,
        username: &str,
        database: &str,
    ) -> Option<String> {
        Some(format!(
            "set -eu\nprintf %s {} | MYSQL_PWD=\"$DBE_TENANT_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock --batch --skip-column-names --raw -u {} {}",
            sh_quote(statement),
            sh_quote(username),
            sh_quote(database),
        ))
    }

    fn manifest_statement_timeout_sql(&self, timeout: Duration) -> Option<String> {
        Some(format!(
            "SET SESSION MAX_EXECUTION_TIME={};",
            timeout.as_millis()
        ))
    }

    fn rollback_gap_sql(&self, database: &str, username: &str) -> Option<String> {
        Some(crate::databases::mysql_rollback_gap_sql(database, username))
    }
}

pub(crate) fn tenant_quota(limits: &InstanceLimits) -> TenantQuota {
    TenantQuota {
        max_queries_per_hour: 0,
        max_updates_per_hour: 0,
        max_connections_per_hour: 0,
        max_connections: policy::max_connections(limits),
    }
}
