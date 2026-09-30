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
    placement::{DeploymentMode, EngineRuntime, TenantReservation},
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
        let metadata = match lookup_published_tenant(state, &reservation).await? {
            TenantLookup::Skip => continue,
            TenantLookup::Found(metadata) => *metadata,
            TenantLookup::Missing => {
                return Err(ApiError::Runtime(format!(
                    "shared pool {} references missing tenant {id}",
                    pool.runtime_id
                )));
            }
        };
        if !tenant_matches_reservation(&metadata, pool, &reservation) {
            if reservation_has_changed(state, &reservation).await? {
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

enum TenantLookup {
    Skip,
    Found(Box<InstanceMetadata>),
    Missing,
}

async fn lookup_published_tenant(
    state: &AppState,
    reservation: &TenantReservation,
) -> Result<TenantLookup, ApiError> {
    let id = &reservation.instance_id;
    if let Some(metadata) = state.instances.get(id).await {
        return Ok(TenantLookup::Found(Box::new(metadata)));
    }
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
            .is_some_and(|current| current != reservation)
    {
        return Ok(TenantLookup::Skip);
    }
    if orphan.is_some() {
        return Ok(TenantLookup::Missing);
    }
    // A journaled shadow target or a deleted member has no public
    // metadata. A real stored child missing from the cache must
    // not disappear silently once its creation worker has ended.
    let stored = state
        .manager
        .get_persisted(id)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    if stored.is_none() || state.install_progress.is_creating(id) {
        return Ok(TenantLookup::Skip);
    }
    Ok(match state.instances.get(id).await {
        Some(metadata) => TenantLookup::Found(Box::new(metadata)),
        None => TenantLookup::Missing,
    })
}

fn tenant_matches_reservation(
    metadata: &InstanceMetadata,
    pool: &EngineRuntime,
    reservation: &TenantReservation,
) -> bool {
    metadata.deployment_mode == DeploymentMode::Shared
        && metadata.runtime_id() == pool.runtime_id
        && metadata.protocol == pool.protocol
        && metadata.owner == pool.owner
        && metadata.database.name == reservation.database
        && metadata.database.username == reservation.username
}

async fn reservation_has_changed(
    state: &AppState,
    reservation: &TenantReservation,
) -> Result<bool, ApiError> {
    let current = state
        .placements
        .get_reservation(&reservation.instance_id)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    Ok(current
        .as_ref()
        .is_none_or(|current| current != reservation))
}

#[cfg(test)]
mod tests;
