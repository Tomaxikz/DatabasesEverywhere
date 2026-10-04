use std::time::Duration;

const QDRANT_MIGRATION_READY_TIMEOUT: Duration = Duration::from_secs(120);
const BOOT_ACTIVATION_READY_TIMEOUT: Duration = Duration::from_secs(180);
const BOOT_FAILURE_LOG_TAIL_CHARS: usize = 4_000;

mod boot_action;
mod disk_limits;
mod known_instances;
mod logging;
mod qdrant_migration;

#[cfg(test)]
pub(super) use boot_action::{ManagedBootAction, managed_boot_action};
#[cfg(test)]
pub(super) use disk_limits::isolate_disk_failure;
pub(super) use disk_limits::restore_disk_limits;
#[cfg(test)]
pub(super) use known_instances::start_known_instance;
pub(super) use known_instances::{start_known_instances, sync_cpu_burst_limits};
pub(super) use logging::{log_boot_config, log_gateway_listeners};
#[cfg(test)]
pub(super) use qdrant_migration::{
    QdrantMigrationContainer, legacy_qdrant_uses_fuse, qdrant_migration_actions,
    qdrant_migration_is_safe, qdrant_migration_spec,
};
