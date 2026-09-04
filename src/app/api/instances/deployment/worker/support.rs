use super::*;

pub(super) fn target_request(
    source: &InstanceMetadata,
    source_runtime: &EngineRuntime,
    temp_id: &str,
    password: &str,
) -> CreateInstanceRequest {
    CreateInstanceRequest {
        instance_id: temp_id.to_string(),
        protocol: source.protocol,
        deployment_mode: DeploymentMode::Shared,
        database: source.database.name.clone(),
        username: source.database.username.clone(),
        password: password.to_string(),
        public_host: source.public.host.clone(),
        public_port: Some(source.public.port),
        project_id: None,
        image: Some(source_runtime.image.clone()),
        limits: Some(LimitsRequest {
            cpu_cores: source.limits.cpu_cores,
            memory_mib: source.limits.memory_mib,
            disk_mib: source.limits.disk_mib,
        }),
        purge_stale_resources: false,
        purge_stale_resources_confirmation: None,
    }
}

pub(super) fn dedicated_target_request(
    source: &InstanceMetadata,
    source_runtime: &EngineRuntime,
) -> Result<CreateInstanceRequest, ApiError> {
    let password = source
        .tenant_password
        .clone()
        .ok_or_else(|| ApiError::Conflict("source tenant credential disappeared".to_string()))?;
    Ok(CreateInstanceRequest {
        instance_id: source.instance_id.clone(),
        protocol: source.protocol,
        deployment_mode: DeploymentMode::Dedicated,
        database: source.database.name.clone(),
        username: source.database.username.clone(),
        password,
        public_host: source.public.host.clone(),
        public_port: Some(source.public.port),
        project_id: None,
        image: Some(source_runtime.image.clone()),
        limits: Some(LimitsRequest {
            cpu_cores: source.limits.cpu_cores,
            memory_mib: source.limits.memory_mib,
            disk_mib: source.limits.disk_mib,
        }),
        purge_stale_resources: false,
        purge_stale_resources_confirmation: None,
    })
}

pub(super) fn tenant_target(metadata: &InstanceMetadata) -> TenantTarget<'_> {
    TenantTarget {
        database: &metadata.database.name,
        username: &metadata.database.username,
    }
}

pub(super) fn temp_instance_id(migration_id: &str) -> Result<String, ApiError> {
    let uuid = uuid::Uuid::parse_str(migration_id)
        .map_err(|_| ApiError::Runtime("invalid persisted migration id".to_string()))?;
    Ok(format!("migration_{}", uuid.simple()))
}

pub(super) fn temporary_password() -> String {
    format!(
        "dbe-migrate-{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

pub(super) fn artifact_path(state: &AppState, migration_id: &str) -> Result<PathBuf, ApiError> {
    uuid::Uuid::parse_str(migration_id)
        .map_err(|_| ApiError::Runtime("invalid persisted migration id".to_string()))?;
    Ok(PathBuf::from(state.config.paths.tmp_root())
        .join("deployment-migrations")
        .join(migration_id)
        .join("logical.dump"))
}

pub(super) fn migration_staging_bytes(export_bytes: u64) -> Result<u64, ApiError> {
    export_bytes
        .checked_mul(2)
        .ok_or_else(|| ApiError::Conflict("deployment migration staging overflowed".to_string()))
}

pub(super) async fn remove_artifact_root(state: &AppState, migration_id: &str) {
    let Ok(path) = artifact_path(state, migration_id) else {
        return;
    };
    let Some(root) = path.parent() else { return };
    match tokio::fs::remove_dir_all(root).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(%migration_id, %error, "failed to remove migration staging"),
    }
}

pub(super) async fn clear_caches(state: &AppState, instance_id: &str) {
    state.soft_disk_limiter.remove(instance_id).await;
    state.instance_runtime_cache.remove(instance_id).await;
    state.resource_cache.invalidate_runtime(instance_id).await;
    state.monitoring_cache.invalidate().await;
}

pub(super) fn scheduler_error(error: SchedulerAcquireError) -> ApiError {
    match error {
        SchedulerAcquireError::Closed => {
            ApiError::ServiceUnavailable("the daemon is shutting down".to_string())
        }
        SchedulerAcquireError::InsufficientCapacity => ApiError::Conflict(
            "deployment migration exceeds the configured import/export scheduler budget"
                .to_string(),
        ),
    }
}

pub(super) fn runtime_error(error: impl std::fmt::Display) -> ApiError {
    ApiError::Runtime(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::protocol::Protocol;

    #[test]
    fn dedicated_targets_bootstrap_with_the_durable_tenant_identity() {
        for protocol in [
            Protocol::Postgres,
            Protocol::Mysql,
            Protocol::Mariadb,
            Protocol::Mongodb,
            Protocol::Clickhouse,
        ] {
            let mut source = crate::instances::test_support::metadata("tenant", protocol);
            source.deployment_mode = DeploymentMode::Shared;
            source.tenant_password = Some("current-tenant-password".to_string());
            let runtime = EngineRuntime::legacy_dedicated(
                &source,
                EngineRuntimeStatus::Running,
                "test:1".to_string(),
            );
            let request = dedicated_target_request(&source, &runtime).unwrap();
            assert_eq!(request.deployment_mode, DeploymentMode::Dedicated);
            assert_eq!(request.instance_id, source.instance_id);
            assert_eq!(request.database, source.database.name);
            assert_eq!(request.username, source.database.username);
            assert_eq!(request.password, source.tenant_password.clone().unwrap());
            source.tenant_password = None;
            assert!(dedicated_target_request(&source, &runtime).is_err());
        }
    }

    #[test]
    fn migration_reserves_its_export_and_pinned_restore_copy() {
        assert_eq!(migration_staging_bytes(17).unwrap(), 34);
        assert!(migration_staging_bytes(u64::MAX).is_err());
    }
}
