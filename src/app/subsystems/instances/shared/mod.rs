use std::time::Duration;

use super::{docker_error, purge_runtime_paths, route_fence};
use crate::{
    routes::http::{response::ApiError, router::AppState},
    server::metadata::InstanceMetadata,
    server::placement::{EngineRuntime, EngineRuntimeStatus, runtime as shared_runtime},
};

mod lifecycle;
mod maintenance;

use lifecycle::{mark_quarantined, placement_error};
pub(crate) use maintenance::delete_empty_pool;

const SESSION_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const POOL_READY_TIMEOUT: Duration = Duration::from_secs(30);
const TENANT_USAGE_TIMEOUT: Duration = Duration::from_secs(20);

mod delete;
mod password;
mod reconcile;
mod resize;
mod runtime;
mod state;
pub(super) use delete::delete;
pub(crate) use delete::recover_deleting;
pub(super) use password::reset_password;
pub(super) use reconcile::reconcile;
pub(super) use resize::resize;
pub(crate) use runtime::reload_after_runtime_lock;
pub(super) use state::change_state;

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
