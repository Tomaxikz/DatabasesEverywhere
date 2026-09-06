use crate::shared::{
    limits::{InstanceLimits, mib_to_bytes},
    protocol::Protocol,
};

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct RuntimeTotals {
    pub cpu_cores: f64,
    pub memory_mib: u64,
    pub disk_mib: u64,
}

/// Adds the hard limits of physical engines. This includes provisional
/// migration targets that do not have a public instance route yet.
pub(crate) fn sum_runtime_limits<'a>(
    limits: impl IntoIterator<Item = &'a InstanceLimits>,
) -> RuntimeTotals {
    limits
        .into_iter()
        .fold(RuntimeTotals::default(), |mut total, limits| {
            total.cpu_cores += limits.cpu_cores;
            total.memory_mib = total.memory_mib.saturating_add(limits.memory_mib);
            total.disk_mib = total.disk_mib.saturating_add(limits.disk_mib);
            total
        })
}

const ROOT_SPILL_DIVISOR: u64 = 20;
const ROOT_SPILL_CAP_MIB: u64 = 8 * 1024;
const SHARED_CLICKHOUSE_QUERIES_PER_HOUR: u64 = 20_000;

/// Engine-global disk overhead, separate from tenant data allowances.
/// PostgreSQL needs WAL/checkpoint headroom; ClickHouse includes bounded query history.
pub(crate) const fn engine_disk_overhead(protocol: Protocol) -> Option<u64> {
    match protocol {
        Protocol::Postgres => Some(2048),
        Protocol::Mysql | Protocol::Mariadb | Protocol::Mongodb => Some(512),
        Protocol::Clickhouse => Some(1024),
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => None,
    }
}

/// Reserves root-project space for files whose growth is caused by tenant
/// writes but which the engine stores outside tenant child projects, such as
/// WAL, redo/undo logs, and shared journals. The reserve is pooled because
/// those files cannot be attributed reliably to one tenant.
pub(crate) const fn root_spill_mib(protocol: Protocol, tenant_disk_mib: u64) -> Option<u64> {
    if engine_disk_overhead(protocol).is_none() {
        return None;
    }
    let rounded = tenant_disk_mib / ROOT_SPILL_DIVISOR
        + if tenant_disk_mib.is_multiple_of(ROOT_SPILL_DIVISOR) {
            0
        } else {
            1
        };
    Some(if rounded < ROOT_SPILL_CAP_MIB {
        rounded
    } else {
        ROOT_SPILL_CAP_MIB
    })
}

/// Returns the physical disk capacity committed by one shared runtime.
pub(crate) fn pool_disk_mib(protocol: Protocol, tenant_disk_mib: u64) -> Option<u64> {
    let overhead = engine_disk_overhead(protocol)?;
    let spill = root_spill_mib(protocol, tenant_disk_mib)?;
    Some(
        tenant_disk_mib
            .saturating_add(overhead)
            .saturating_add(spill),
    )
}

pub(crate) fn runtime_id(protocol: Protocol) -> String {
    format!(
        "pool_{}_{}",
        protocol.as_str(),
        uuid::Uuid::new_v4().simple()
    )
}

pub(crate) fn max_connections(limits: &InstanceLimits) -> u32 {
    let memory_bound = limits.memory_mib / 32;
    u32::try_from(memory_bound.clamp(4, 100)).unwrap_or(100)
}

pub(crate) fn postgres_quota(
    limits: &InstanceLimits,
) -> crate::databases::postgres::provision::TenantQuota {
    crate::databases::postgres::provision::TenantQuota {
        max_connections: max_connections(limits),
        statement_timeout_ms: 15 * 60 * 1_000,
        lock_timeout_ms: 30 * 1_000,
        idle_transaction_timeout_ms: 5 * 60 * 1_000,
        temp_file_limit_kib: limits.memory_mib.saturating_mul(1024),
    }
}

pub(crate) fn mysql_quota(
    limits: &InstanceLimits,
) -> crate::databases::mysql::provision::TenantQuota {
    crate::databases::mysql::provision::TenantQuota {
        max_queries_per_hour: 0,
        max_updates_per_hour: 0,
        max_connections_per_hour: 0,
        max_connections: max_connections(limits),
    }
}

pub(crate) fn mariadb_quota(
    limits: &InstanceLimits,
) -> crate::databases::mariadb::provision::TenantQuota {
    crate::databases::mariadb::provision::TenantQuota {
        max_queries_per_hour: 0,
        max_updates_per_hour: 0,
        max_connections_per_hour: 0,
        max_connections: max_connections(limits),
        max_statement_millis: 15 * 60 * 1_000,
    }
}

pub(crate) fn clickhouse_quota(
    limits: &InstanceLimits,
) -> crate::databases::clickhouse::provision::TenantQuota {
    let memory_bytes = mib_to_bytes(limits.memory_mib);
    crate::databases::clickhouse::provision::TenantQuota {
        max_memory_bytes: memory_bytes,
        max_threads: limits.cpu_cores.ceil().clamp(1.0, 64.0) as u32,
        max_execution_time_seconds: 15 * 60,
        max_result_bytes: memory_bytes / 2,
        max_temp_bytes: mib_to_bytes(limits.disk_mib),
        // Query history is an accounting input in shared pools. A finite
        // quota bounds the engine-owned query_log independently of tenant
        // table quotas; sustained higher-throughput workloads should use a
        // dedicated ClickHouse engine.
        max_queries_per_hour: SHARED_CLICKHOUSE_QUERIES_PER_HOUR,
        max_read_bytes_per_hour: 0,
        max_written_bytes_per_hour: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_tenant_safe_engines_have_shared_capacity() {
        for protocol in Protocol::ALL {
            assert_eq!(
                engine_disk_overhead(protocol).is_some(),
                crate::placement::DeploymentMode::Shared.supports(protocol)
            );
        }
    }

    #[test]
    fn connection_budget_is_bounded() {
        let mut limits = InstanceLimits {
            memory_mib: 64,
            ..InstanceLimits::default()
        };
        assert_eq!(max_connections(&limits), 4);
        limits.memory_mib = 4096;
        assert_eq!(max_connections(&limits), 100);
    }

    #[test]
    fn shared_clickhouse_query_history_has_a_finite_row_budget() {
        let limits = InstanceLimits {
            cpu_cores: 1.0,
            memory_mib: 1024,
            disk_mib: 10_240,
            ..InstanceLimits::default()
        };
        assert_eq!(
            clickhouse_quota(&limits).max_queries_per_hour,
            SHARED_CLICKHOUSE_QUERIES_PER_HOUR
        );
    }

    #[test]
    fn pool_disk_budget_includes_global_overhead_and_spill() {
        assert_eq!(pool_disk_mib(Protocol::Postgres, 20_000), Some(23_048));
        assert!(pool_disk_mib(Protocol::Redis, 1024).is_none());
    }

    #[test]
    fn root_spill_rounds_up_and_caps() {
        let cases = [
            (0, 0),
            (1, 1),
            (19, 1),
            (20, 1),
            (21, 2),
            (163_840, 8192),
            (u64::MAX, 8192),
        ];
        for (tenant_disk_mib, expected) in cases {
            assert_eq!(
                root_spill_mib(Protocol::Postgres, tenant_disk_mib),
                Some(expected)
            );
        }
        assert_eq!(root_spill_mib(Protocol::Redis, 1024), None);
    }

    #[test]
    fn physical_runtime_totals_include_unrouted_targets() {
        let source = InstanceLimits {
            cpu_cores: 1.0,
            memory_mib: 1024,
            disk_mib: 4096,
            ..InstanceLimits::default()
        };
        let provisional_target = InstanceLimits {
            cpu_cores: 1.25,
            memory_mib: 1280,
            disk_mib: 4608,
            ..InstanceLimits::default()
        };

        let total = sum_runtime_limits([&source, &provisional_target]);

        assert_eq!(total.cpu_cores, 2.25);
        assert_eq!(total.memory_mib, 2304);
        assert_eq!(total.disk_mib, 8704);
    }
}
