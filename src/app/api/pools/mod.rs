pub(crate) mod image;
mod limits;
mod operations;
mod power;
mod provision;
pub(crate) mod streams;
pub(crate) use limits::resize_pool;
pub(crate) use operations::{create, create_database, delete, power, status};

use crate::{
    api::http::{response::ApiError, router::AppState},
    instances::metadata::InstanceMetadata,
    placement::{DeploymentMode, EngineRuntime},
};

pub(crate) async fn load(state: &AppState, runtime_id: &str) -> Result<EngineRuntime, ApiError> {
    state
        .placements
        .get(runtime_id)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?
        .filter(|pool| pool.deployment_mode == DeploymentMode::Shared)
        .ok_or(ApiError::NotFound)
}

/// Reservations charge capacity before a child can be published. Only return
/// published members; missing metadata without active work is still an error.
pub(crate) async fn tenants(
    state: &AppState,
    pool: &EngineRuntime,
) -> Result<Vec<InstanceMetadata>, ApiError> {
    let reservations = state
        .placements
        .reservations(&pool.runtime_id)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let mut tenants = Vec::with_capacity(reservations.len());
    for reservation in reservations {
        let id = &reservation.instance_id;
        if state.install_progress.is_creating(id) {
            continue;
        }
        let metadata = match state.instances.get(id).await {
            Some(metadata) => Some(metadata),
            None => {
                // Re-read durable membership after the cache lookup: a writer may
                // have completed creation, deletion or cutover between the reads.
                // get_orphan also excludes journaled provisional migration targets.
                let orphan = state
                    .placements
                    .get_orphan(id)
                    .await
                    .map_err(|error| ApiError::Runtime(error.to_string()))?;
                if state.install_progress.is_creating(id)
                    || orphan
                        .as_ref()
                        .is_some_and(|current| current != &reservation)
                {
                    continue;
                }
                if orphan.is_none() {
                    // A journaled shadow target or a deleted member has no public
                    // metadata. A real stored child missing from the cache must
                    // not disappear silently once its creation worker has ended.
                    let stored = state
                        .manager
                        .get_persisted(id)
                        .await
                        .map_err(|error| ApiError::Runtime(error.to_string()))?;
                    if stored.is_none() || state.install_progress.is_creating(id) {
                        continue;
                    }
                    state.instances.get(id).await
                } else {
                    None
                }
            }
        };
        let Some(metadata) = metadata else {
            return Err(ApiError::Runtime(format!(
                "shared pool {} references missing tenant {id}",
                pool.runtime_id
            )));
        };
        if metadata.deployment_mode != DeploymentMode::Shared
            || metadata.runtime_id() != pool.runtime_id
            || metadata.protocol != pool.protocol
            || metadata.owner != pool.owner
            || metadata.database.name != reservation.database
            || metadata.database.username != reservation.username
        {
            let current = state
                .placements
                .get_reservation(id)
                .await
                .map_err(|error| ApiError::Runtime(error.to_string()))?;
            if current
                .as_ref()
                .is_none_or(|current| current != &reservation)
            {
                continue;
            }
            return Err(ApiError::Runtime(format!(
                "shared pool {} has inconsistent tenant metadata",
                pool.runtime_id
            )));
        }
        tenants.push(metadata);
    }
    Ok(tenants)
}

#[cfg(test)]
mod tests;
