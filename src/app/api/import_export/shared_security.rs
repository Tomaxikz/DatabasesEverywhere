use std::time::Duration;

use super::ImportMode;
use crate::{
    api::http::{response::ApiError, router::AppState},
    instances::metadata::InstanceMetadata,
    placement::{
        DeploymentMode, EngineRuntimeStatus,
        tenant::{self, TenantTarget},
    },
    shared::protocol::Protocol,
};

const MIB: u64 = 1024 * 1024;
const MEASURE_TIMEOUT: Duration = Duration::from_secs(20);

pub(super) async fn admit_import(
    state: &AppState,
    metadata: &InstanceMetadata,
    prepared_bytes: u64,
    _mode: ImportMode,
) -> Result<(), ApiError> {
    if metadata.deployment_mode != DeploymentMode::Shared {
        return Ok(());
    }
    let limit = metadata
        .limits
        .disk_mib
        .checked_mul(MIB)
        .ok_or_else(|| ApiError::Conflict("shared tenant disk limit overflowed".to_string()))?;
    check_source(metadata.protocol, prepared_bytes)?;
    check_usage(
        measure_usage(state, metadata).await?,
        limit,
        "before import",
    )
}

fn check_source(protocol: Protocol, prepared_bytes: u64) -> Result<(), ApiError> {
    if prepared_bytes == 0 {
        return Err(ApiError::BadRequest(
            "shared import source must not be empty".to_string(),
        ));
    }
    match protocol {
        Protocol::Postgres
        | Protocol::Mariadb
        | Protocol::Mysql
        | Protocol::Mongodb
        | Protocol::Clickhouse => Ok(()),
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => Err(ApiError::BadRequest(
            format!("{} cannot use shared logical import", protocol.as_str()),
        )),
    }
}

pub(super) async fn verify_import_size(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<(), ApiError> {
    if metadata.deployment_mode != DeploymentMode::Shared {
        return Ok(());
    }
    let limit = metadata
        .limits
        .disk_mib
        .checked_mul(MIB)
        .ok_or_else(|| ApiError::Conflict("shared tenant disk limit overflowed".to_string()))?;
    check_usage(measure_usage(state, metadata).await?, limit, "after import")
}

fn check_usage(used: u64, limit: u64, phase: &str) -> Result<(), ApiError> {
    if used < limit {
        return Ok(());
    }
    Err(ApiError::Conflict(format!(
        "shared tenant uses {used} bytes {phase}, which reaches its {limit}-byte disk reservation"
    )))
}

async fn measure_usage(state: &AppState, metadata: &InstanceMetadata) -> Result<u64, ApiError> {
    let runtime = state
        .placements
        .get(metadata.runtime_id())
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to load shared runtime: {error}")))?
        .ok_or_else(|| ApiError::Conflict("shared runtime is missing".to_string()))?;
    if runtime.deployment_mode != DeploymentMode::Shared
        || runtime.protocol != metadata.protocol
        || runtime.status != EngineRuntimeStatus::Running
    {
        return Err(ApiError::Conflict(
            "shared runtime is not available for import admission".to_string(),
        ));
    }
    let target = TenantTarget {
        database: &metadata.database.name,
        username: &metadata.database.username,
    };
    if metadata.limits.disk_enforced {
        return tokio::time::timeout(
            MEASURE_TIMEOUT,
            tenant::disk::quota_usage_bytes(&state.config, &runtime, target),
        )
        .await
        .map_err(|_| {
            ApiError::Runtime("shared tenant project-quota measurement timed out".to_string())
        })?
        .map_err(|error| {
            ApiError::Runtime(format!(
                "shared tenant project-quota measurement failed: {error}"
            ))
        });
    }
    let values = tokio::time::timeout(
        MEASURE_TIMEOUT,
        tenant::measure_storage(&state.docker, &runtime, &[target]),
    )
    .await
    .map_err(|_| ApiError::Runtime("shared tenant storage measurement timed out".to_string()))?
    .map_err(|error| {
        ApiError::Runtime(format!("shared tenant storage measurement failed: {error}"))
    })?;
    values
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::Runtime("shared tenant storage was not reported".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_shared_engines_accept_nonempty_sources_without_guessing_expansion() {
        for protocol in [
            Protocol::Postgres,
            Protocol::Mariadb,
            Protocol::Mysql,
            Protocol::Mongodb,
            Protocol::Clickhouse,
        ] {
            assert!(check_source(protocol, 1).is_ok());
        }
    }

    #[test]
    fn post_restore_capacity_check_is_exact_and_fail_closed() {
        assert!(check_usage(99, 100, "after import").is_ok());
        assert!(check_usage(100, 100, "after import").is_err());
        assert!(check_usage(101, 100, "after import").is_err());
    }

    #[test]
    fn unsupported_shared_protocols_fail_closed() {
        for protocol in [Protocol::Redis, Protocol::Valkey, Protocol::Qdrant] {
            assert!(check_source(protocol, 1).is_err());
        }
        assert!(check_source(Protocol::Postgres, 0).is_err());
    }
}
