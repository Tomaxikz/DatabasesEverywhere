use std::collections::HashMap;
use std::time::Duration;

use anyhow::Context;
use futures::StreamExt;

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

use self::boot::*;
pub(crate) use self::events::*;
pub(crate) use self::limits::*;
pub(crate) use self::reconcile::*;
pub(crate) use self::runtime_store::*;
pub(crate) use self::snapshot::*;
pub(crate) use self::start_disk::*;
use self::tenants::*;

use crate::{
    config::{Config, DiskLimitMode},
    instance::disk::{DiskLimiter, soft::SoftDiskTarget},
    instance::placement::{
        DeploymentMode, EngineRuntime, EngineRuntimeStatus, PlacementRepository,
        TenantReservationState, containment,
    },
    instance::{
        locks::InstanceLocks,
        manager::InstanceManager,
        metadata::{DesiredInstanceState, InstanceStatus},
        paths::InstancePaths,
    },
    runtime::docker::{DockerContainerStatus, DockerRuntime, ManagedContainerEvent},
    state::AppState,
    storage::quarantine::QuarantineKind,
    utils::constants::MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY,
    utils::{backend::BackendEndpoint, limits::mib_to_bytes, time::now_rfc3339},
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
