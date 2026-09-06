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

#[cfg(test)]
mod tests;
