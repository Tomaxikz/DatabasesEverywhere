use crate::{
    databases::engine::{EngineTenancy, TenantDiskBoundary},
    server::placement::{policy, tenant::backends::TenantBackend},
    utils::{limits::InstanceLimits, shell::sh_quote},
};

use super::{engine::Postgres, provision::TenantQuota, tenant_backend};

const STATEMENT_TIMEOUT_MS: u64 = 15 * 60 * 1_000;

impl EngineTenancy for Postgres {
    fn tenant_backend(&self) -> Option<&'static dyn TenantBackend> {
        Some(&tenant_backend::Postgres)
    }

    fn tenant_disk_boundary(&self) -> Option<TenantDiskBoundary> {
        Some(TenantDiskBoundary::PostgresTablespace)
    }

    fn manifest_query_command(
        &self,
        statement: &str,
        username: &str,
        database: &str,
    ) -> Option<String> {
        Some(format!(
            "set -eu\nprintf %s {} | PGPASSWORD=\"$DBE_TENANT_PASSWORD\" psql -X -A -t -q -h /var/run/postgresql -U {} -d {} -v ON_ERROR_STOP=1",
            sh_quote(statement),
            sh_quote(username),
            sh_quote(database),
        ))
    }
}

pub(crate) fn tenant_quota(limits: &InstanceLimits) -> TenantQuota {
    TenantQuota {
        max_connections: policy::max_connections(limits),
        statement_timeout_ms: STATEMENT_TIMEOUT_MS,
        lock_timeout_ms: 30 * 1_000,
        idle_transaction_timeout_ms: 5 * 60 * 1_000,
        temp_file_limit_kib: limits.memory_mib.saturating_mul(1024),
    }
}
