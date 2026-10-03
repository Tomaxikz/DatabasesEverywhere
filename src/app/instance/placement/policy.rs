use crate::utils::{limits::InstanceLimits, protocol::Protocol};

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
const MEMORY_MIB_PER_CONNECTION: u64 = 32;
const MIN_CONNECTIONS: u64 = 4;
const MAX_CONNECTIONS: u64 = 100;

/// Engine-global disk overhead, separate from tenant data allowances.
/// PostgreSQL needs WAL/checkpoint headroom; ClickHouse includes bounded query history.
pub(crate) fn engine_disk_overhead(protocol: Protocol) -> Option<u64> {
    protocol
        .engine()
        .shared_pool()
        .map(|pool| pool.disk_overhead_mib)
}

/// Reserves root-project space for files whose growth is caused by tenant
/// writes but which the engine stores outside tenant child projects, such as
/// WAL, redo/undo logs, and shared journals. The reserve is pooled because
/// those files cannot be attributed reliably to one tenant.
pub(crate) fn root_spill_mib(protocol: Protocol, tenant_disk_mib: u64) -> Option<u64> {
    engine_disk_overhead(protocol)?;
    let rounded = tenant_disk_mib.div_ceil(ROOT_SPILL_DIVISOR);
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
    let memory_bound = limits.memory_mib / MEMORY_MIB_PER_CONNECTION;
    u32::try_from(memory_bound.clamp(MIN_CONNECTIONS, MAX_CONNECTIONS)).unwrap_or(100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_tenant_safe_engines_have_shared_capacity() {
        for protocol in Protocol::ALL {
            assert_eq!(
                engine_disk_overhead(protocol).is_some(),
                crate::instance::placement::DeploymentMode::Shared.supports(protocol)
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
            crate::databases::clickhouse::tenancy::tenant_quota(&limits).max_queries_per_hour,
            crate::databases::clickhouse::tenancy::SHARED_QUERIES_PER_HOUR
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
