use crate::{
    databases::engine::{EngineTenancy, TenantDiskBoundary},
    instance::monitoring::engine::backends::{ClickhouseTelemetry, EngineTelemetry},
    instance::placement::tenant::backends::{ClickhouseTenantBackend, TenantBackend},
    utils::{
        limits::{InstanceLimits, mib_to_bytes},
        shell::sh_quote,
    },
};

use super::{engine::Clickhouse, provision::TenantQuota};

pub(crate) const SHARED_QUERIES_PER_HOUR: u64 = 20_000;

impl EngineTenancy for Clickhouse {
    fn tenant_backend(&self) -> Option<&'static dyn TenantBackend> {
        Some(&ClickhouseTenantBackend)
    }

    fn telemetry(&self) -> Option<&'static dyn EngineTelemetry> {
        Some(&ClickhouseTelemetry)
    }

    fn telemetry_reports_operations(&self) -> bool {
        true
    }

    fn tenant_disk_boundary(&self) -> Option<TenantDiskBoundary> {
        Some(TenantDiskBoundary::SoftScanner)
    }

    fn manifest_query_command(
        &self,
        statement: &str,
        username: &str,
        database: &str,
    ) -> Option<String> {
        Some(format!(
            "set -eu\nprintf %s {} | CLICKHOUSE_PASSWORD=\"$DBE_TENANT_PASSWORD\" clickhouse-client --host 127.0.0.1 --user {} --database {} --multiquery",
            sh_quote(statement),
            sh_quote(username),
            sh_quote(database),
        ))
    }

    fn has_hosted_config(&self) -> bool {
        true
    }
}

pub(crate) fn tenant_quota(limits: &InstanceLimits) -> TenantQuota {
    let memory_bytes = mib_to_bytes(limits.memory_mib);
    TenantQuota {
        max_memory_bytes: memory_bytes,
        max_threads: limits.cpu_cores.ceil().clamp(1.0, 64.0) as u32,
        max_execution_time_seconds: 15 * 60,
        max_result_bytes: memory_bytes / 2,
        max_temp_bytes: mib_to_bytes(limits.disk_mib),
        // Query history is an accounting input in shared pools. A finite
        // quota bounds the engine-owned query_log independently of tenant
        // table quotas; sustained higher-throughput workloads should use a
        // dedicated ClickHouse engine.
        max_queries_per_hour: SHARED_QUERIES_PER_HOUR,
        max_read_bytes_per_hour: 0,
        max_written_bytes_per_hour: 0,
    }
}
