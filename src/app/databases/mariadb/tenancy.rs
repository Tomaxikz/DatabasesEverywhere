use std::time::Duration;

use crate::{
    databases::engine::{EngineTenancy, TenantDiskBoundary},
    instance::monitoring::engine::backends::{EngineTelemetry, MariadbTelemetry},
    instance::placement::{
        policy,
        tenant::backends::{MysqlFlavor, TenantBackend},
    },
    utils::{limits::InstanceLimits, shell::sh_quote},
};

use super::{engine::Mariadb, provision::TenantQuota};

const STATEMENT_TIMEOUT_MS: u64 = 15 * 60 * 1_000;

impl EngineTenancy for Mariadb {
    fn tenant_backend(&self) -> Option<&'static dyn TenantBackend> {
        Some(&MysqlFlavor::Mariadb)
    }

    fn telemetry(&self) -> Option<&'static dyn EngineTelemetry> {
        Some(&MariadbTelemetry)
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
            "set -eu\nprintf %s {} | MYSQL_PWD=\"$DBE_TENANT_PASSWORD\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock --batch --skip-column-names --raw -u {} {}",
            sh_quote(statement),
            sh_quote(username),
            sh_quote(database),
        ))
    }

    fn manifest_statement_timeout_sql(&self, timeout: Duration) -> Option<String> {
        Some(format!(
            "SET SESSION max_statement_time={};",
            timeout.as_secs_f64()
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
        max_statement_millis: STATEMENT_TIMEOUT_MS,
    }
}
