use std::time::Duration;

mod activation;
mod compatibility;
pub(crate) mod failure;
pub(crate) use activation::activate_locked;
pub(crate) mod paths;

pub(crate) use compatibility::attest_runtime_locked;
pub(crate) use compatibility::attestation_matches;
pub(crate) use compatibility::sync_shared_compatibility;

mod boot;
mod events;
mod limits;
mod reconcile;
mod runtime_store;
mod snapshot;
mod start_disk;
mod tenants;
#[cfg(test)]
mod tests;

use self::boot::{SharedBootAction, container_event_is_known_stale, shared_boot_action};
pub(crate) use self::events::reconcile_shared_event;
use self::limits::pool_is_isolated;
pub(crate) use self::limits::{
    recover_pool_deletions, restore_shared_limits, sync_shared_cpu_burst,
};
pub(crate) use self::reconcile::{honor_stop, reconcile_shared_runtimes, start_shared_runtimes};
use self::runtime_store::shared_runtimes;
pub(crate) use self::runtime_store::{clear_runtime_caches, fence_runtime, save_runtime};
pub(crate) use self::snapshot::reconcile_shared_snapshot;
pub(crate) use self::start_disk::{
    check_shared_start_disk, isolate_runtime, mark_shared_disk_blocked,
};
use self::tenants::{
    classify_runtime_status, report_missing_tenant, runtime_tenants, store_tenants, tenant_status,
};

const POOL_READY_TIMEOUT: Duration = Duration::from_secs(180);
const ISOLATED_NETWORK_MODE: &str = "none";
const MIN_CONTAINER_ID_PREFIX_LEN: usize = 12;

#[derive(Debug, Clone, Default)]
pub(crate) struct SharedReconcileSummary {
    pub checked: usize,
    pub booting: usize,
    pub running: usize,
    pub stopped: usize,
    pub failed: usize,
    pub quarantined: usize,
}
