use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use tokio::sync::OwnedMutexGuard;

use super::{
    DeleteResponse, LifecycleAction, ResetInstancePasswordResponse, docker_error,
    purge_runtime_paths, purge_shared_tenant_paths, route_fence,
};
use crate::{
    instance::disk::DiskEnforcement,
    instance::metadata::{DesiredInstanceState, InstanceMetadata, InstanceStatus},
    instance::placement::{
        DeploymentMode, EngineRuntime, EngineRuntimeStatus, runtime as shared_runtime,
        tenant::{self, TenantTarget},
    },
    routes::http::{
        response::{ApiError, ApiResponse, ApiResult},
        router::AppState,
    },
    runtime::docker::DockerContainerStatus,
    utils::{
        limits::{InstanceLimits, mib_to_bytes},
        time::now_rfc3339,
    },
};

mod lifecycle;
mod maintenance;

use lifecycle::{
    SharedLifecycleError, check_power_state, completion_report, limits_match, mark_quarantined,
    placement_error, route_was_open, same_shared_identity, target,
};
pub(crate) use maintenance::delete_empty_pool;
use maintenance::{clear_caches, drain_tenant_sessions, maintain_pool_after_delete};

const SESSION_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const POOL_READY_TIMEOUT: Duration = Duration::from_secs(30);
const TENANT_USAGE_TIMEOUT: Duration = Duration::from_secs(20);

mod delete;
mod password;
mod reconcile;
mod resize;
mod runtime;
mod state;
pub(crate) use delete::*;
pub(super) use password::*;
pub(super) use reconcile::*;
pub(super) use resize::*;
pub(crate) use runtime::*;
pub(super) use state::*;

pub(super) fn reject_logs() -> ApiError {
    ApiError::Conflict(
        "raw engine logs are pool-wide and are not exposed to shared tenants because they may contain activity from other databases"
            .to_string(),
    )
}

pub(super) async fn recover_lifecycle_panic(state: &AppState, instance_id: &str) -> String {
    route_fence::fence(state, instance_id).await;
    match state.manager.get_persisted(instance_id).await {
        Ok(Some(mut metadata)) => {
            mark_quarantined(&mut metadata);
            match state
                .manager
                .quarantine(
                    metadata,
                    crate::storage::quarantine::QuarantineKind::MetadataUncertain,
                )
                .await
            {
                Ok(()) => "the tenant was fenced and quarantined without mutating its shared pool"
                    .to_string(),
                Err(error) => format!(
                    "the tenant was fenced in memory, but durable quarantine failed: {error}"
                ),
            }
        }
        Ok(None) => {
            state.instances.remove(instance_id).await;
            "the tenant route was removed because its durable metadata is missing".to_string()
        }
        Err(error) => format!(
            "the tenant was fenced in memory, but its durable state could not be read: {error}"
        ),
    }
}

#[cfg(test)]
mod tests;
