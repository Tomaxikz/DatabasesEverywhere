use tokio::sync::OwnedMutexGuard;

use super::resolve_image;
use crate::{
    api::{
        http::{response::ApiError, router::AppState},
        instances::requests::CreateInstanceRequest,
    },
    instances::metadata::{
        DatabaseIdentity, DesiredInstanceState, InstanceDatabaseVersion, InstanceImageStatus,
        InstanceMetadata, InstanceStatus, PublicEndpoint, SCHEMA_VERSION,
    },
    placement::{
        DeploymentMode, EngineRuntime, EngineRuntimeStatus, PlacementRepositoryError,
        ReserveTenant, runtime as shared_runtime,
        tenant::{self, TenantTarget},
    },
    shared::{limits::InstanceLimits, protocol::Protocol, time::now_rfc3339},
};

pub(super) async fn create(
    state: &AppState,
    request: CreateInstanceRequest,
) -> Result<InstanceMetadata, ApiError> {
    let image = resolve_image(state, &request)?;
    state
        .install_progress
        .begin(&request.instance_id, request.protocol, &image);
    state.install_progress.stage(
        &request.instance_id,
        "select_pool",
        "using the requested server-owned pool",
    );

    let mut tenant_limits = crate::shared::limits::InstanceLimits {
        disk_mib: request
            .limits
            .as_ref()
            .expect("validated tenant disk")
            .disk_mib,
        disk_enforced: false,
        disk_enforcement_method: "shared_pool_reservation".into(),
        ..Default::default()
    };
    let (claimed_runtime, _runtime_operation) =
        claim_runtime(state, &request, &image, &mut tenant_limits)
            .await
            .inspect_err(|error| {
                state.install_progress.fail_api_error(
                    &request.instance_id,
                    "shared instance creation",
                    error,
                )
            })?;
    let runtime = state
        .placements
        .get(&claimed_runtime.runtime_id)
        .await
        .map_err(placement_error)?;
    let Some(runtime) = runtime else {
        let _ = state.placements.release(&request.instance_id).await;
        return Err(fail(
            state,
            &request.instance_id,
            "the selected shared runtime disappeared after capacity was reserved",
        ));
    };
    if runtime.status != EngineRuntimeStatus::Running {
        cleanup_failed_tenant(
            state,
            &runtime,
            &request.instance_id,
            &request.database,
            &request.username,
        )
        .await;
        return Err(fail(
            state,
            &request.instance_id,
            "the selected shared runtime stopped accepting tenants",
        ));
    }

    if let Err(error) =
        shared_runtime::apply_limits(&state.docker, &state.config, &state.placements, &runtime)
            .await
    {
        release_claim(state, &runtime, &request.instance_id).await;
        return Err(fail(state, &request.instance_id, error));
    }

    state.install_progress.stage(
        &request.instance_id,
        "provision_tenant",
        "creating an isolated database and tenant account in the shared runtime",
    );
    let target = TenantTarget {
        database: &request.database,
        username: &request.username,
    };
    if let Err(error) = tenant::disk::prepare(
        &state.config,
        &state.docker,
        &runtime,
        target,
        tenant_limits.disk_mib,
    )
    .await
    {
        cleanup_failed_tenant(
            state,
            &runtime,
            &request.instance_id,
            &request.database,
            &request.username,
        )
        .await;
        return Err(fail(
            state,
            &request.instance_id,
            format!("shared tenant storage preparation failed: {error}"),
        ));
    }
    if let Err(error) = tenant::create(
        &state.docker,
        &runtime,
        target,
        &request.password,
        &tenant_limits,
    )
    .await
    {
        cleanup_failed_tenant(
            state,
            &runtime,
            &request.instance_id,
            &request.database,
            &request.username,
        )
        .await;
        return Err(fail(state, &request.instance_id, error));
    }
    let disk = match tenant::disk::set_limit(
        &state.config,
        &state.docker,
        &runtime,
        target,
        tenant_limits.disk_mib,
    )
    .await
    {
        Ok(disk) => disk,
        Err(error) => {
            cleanup_failed_tenant(
                state,
                &runtime,
                &request.instance_id,
                &request.database,
                &request.username,
            )
            .await;
            return Err(fail(
                state,
                &request.instance_id,
                format!("shared tenant disk limit failed: {error}"),
            ));
        }
    };
    tenant_limits.disk_enforced = disk.enforced;
    tenant_limits.disk_enforcement_method = disk.method;
    if let Err(error) = state
        .placements
        .mark_provisioned(&request.instance_id)
        .await
    {
        cleanup_failed_tenant(
            state,
            &runtime,
            &request.instance_id,
            &request.database,
            &request.username,
        )
        .await;
        return Err(fail(
            state,
            &request.instance_id,
            format!("failed to persist shared tenant provisioning: {error}"),
        ));
    }

    let metadata = build_shared_metadata(state, &request, &runtime, tenant_limits, &runtime.image);
    if let Err(error) = state.manager.upsert_fenced(metadata.clone()).await {
        match state.manager.get_persisted(&metadata.instance_id).await {
            Ok(Some(persisted)) if same_created_tenant(&persisted, &metadata) => {
                state.instances.upsert_fenced(metadata.clone()).await;
                tracing::warn!(
                    event = "audit shared_tenant_create_commit_ack_lost",
                    instance_id = %metadata.instance_id,
                    runtime_id = %runtime.runtime_id,
                    %error,
                    "shared tenant metadata was committed despite a lost SQLite acknowledgement"
                );
            }
            Ok(None) => {
                cleanup_failed_tenant(
                    state,
                    &runtime,
                    &metadata.instance_id,
                    &metadata.database.name,
                    &metadata.database.username,
                )
                .await;
                return Err(fail(
                    state,
                    &metadata.instance_id,
                    format!("failed to persist shared tenant metadata: {error}"),
                ));
            }
            persisted => {
                let containment = crate::api::instances::containment::contain_locked(
                    state,
                    &runtime,
                    "shared tenant metadata commit became ambiguous",
                )
                .await;
                return Err(fail(
                    state,
                    &metadata.instance_id,
                    format!(
                        "shared tenant metadata commit became ambiguous after {error}; durable state: {}; pool containment: {}",
                        match persisted {
                            Ok(Some(_)) => "unexpected",
                            Ok(None) => "missing",
                            Err(_) => "unreadable",
                        },
                        containment.summary(),
                    ),
                ));
            }
        }
    }

    if let Err(error) =
        tenant::verify_password(&state.docker, &runtime, target, &request.password).await
    {
        let containment = crate::api::instances::containment::contain_locked(
            state,
            &runtime,
            "new shared tenant credential verification failed",
        )
        .await;
        return Err(fail(
            state,
            &metadata.instance_id,
            format!(
                "shared tenant was persisted but its live credential could not be verified: {error}; pool containment: {}",
                containment.summary()
            ),
        ));
    }

    // Persist the hard child-quota fact before removing this tenant from the
    // root charge. Until this point the unattached reservation keeps its full
    // disk allowance in the shared root, including across a crash.
    if let Err(error) =
        shared_runtime::apply_root_disk_limit(&state.config, &state.placements, &runtime).await
    {
        let containment = crate::api::instances::containment::contain_locked(
            state,
            &runtime,
            "new shared tenant root quota could not be reconciled",
        )
        .await;
        return Err(fail(
            state,
            &metadata.instance_id,
            format!(
                "shared tenant was persisted but its pool root quota could not be reconciled: {error}; pool containment: {}",
                containment.summary()
            ),
        ));
    }
    state.instances.upsert(metadata.clone()).await;

    state.soft_disk_limiter.remove(&metadata.instance_id).await;
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state
        .resource_cache
        .invalidate_runtime(&metadata.instance_id)
        .await;
    state
        .install_progress
        .complete(&metadata.instance_id, "shared database tenant is running");
    tracing::info!(
        event = "audit shared_tenant_created",
        instance_id = %metadata.instance_id,
        runtime_id = %runtime.runtime_id,
        protocol = %metadata.protocol,
        database = %metadata.database.name,
        username = %metadata.database.username,
    );
    Ok(metadata)
}

pub(crate) async fn claim_runtime(
    state: &AppState,
    request: &CreateInstanceRequest,
    image: &str,
    tenant_limits: &mut InstanceLimits,
) -> Result<(EngineRuntime, OwnedMutexGuard<()>), ApiError> {
    let owner = request.owner.as_ref().ok_or_else(|| {
        ApiError::BadRequest("shared_pool_owner_required: server_id is required".into())
    })?;
    owner.check().map_err(ApiError::BadRequest)?;
    let pool_id = request
        .pool_id
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("shared deployment requires pool_id".into()))?;
    if let Some(candidate) = state
        .placements
        .get(pool_id)
        .await
        .map_err(placement_error)?
    {
        let operation = state.instance_locks.lock(&candidate.runtime_id).await;
        let runtime = state.placements.get(&candidate.runtime_id).await.map_err(placement_error)?
            .ok_or_else(|| ApiError::Conflict("shared_pool_unavailable: the server pool disappeared; retry after reconciliation".into()))?;
        if runtime.owner.as_ref() != Some(owner) || runtime.protocol != request.protocol {
            return Err(ApiError::Conflict(
                "shared_pool_owner_mismatch: pool ownership does not match".into(),
            ));
        }
        if runtime.deployment_mode != DeploymentMode::Shared
            || runtime.pending_image.is_some()
            || runtime.desired_state != DesiredInstanceState::Running
            || runtime.status != EngineRuntimeStatus::Running
        {
            return Err(ApiError::Conflict("shared_pool_unavailable: the server pool is not running; repair or start it before adding databases".into()));
        }
        if request.image.is_some() && runtime.image != image {
            return Err(ApiError::Conflict("shared_pool_image_mismatch: use the existing pool image or migrate/upgrade it explicitly".into()));
        }
        tenant_limits.cpu_cores = runtime.limits.cpu_cores;
        tenant_limits.memory_mib = runtime.limits.memory_mib;
        state
            .placements
            .check_tenant_identity(&runtime.runtime_id, &request.database, &request.username)
            .await
            .map_err(placement_error)?;
        let runtime = state
            .placements
            .reserve(ReserveTenant {
                owner: owner.clone(),
                instance_id: &request.instance_id,
                runtime_id: &runtime.runtime_id,
                database: &request.database,
                username: &request.username,
                limits: tenant_limits,
            })
            .await
            .map_err(placement_error)?;
        return Ok((runtime, operation));
    }
    Err(ApiError::Conflict(
        "shared_pool_missing: create the selected pool before adding databases".into(),
    ))
}

pub(crate) fn build_shared_metadata(
    state: &AppState,
    request: &CreateInstanceRequest,
    runtime: &EngineRuntime,
    limits: InstanceLimits,
    image: &str,
) -> InstanceMetadata {
    let now = now_rfc3339();
    InstanceMetadata {
        owner: runtime.owner.clone(),
        schema_version: SCHEMA_VERSION,
        instance_id: request.instance_id.clone(),
        deployment_mode: DeploymentMode::Shared,
        runtime_id: runtime.runtime_id.clone(),
        protocol: request.protocol,
        status: InstanceStatus::Running,
        desired_state: DesiredInstanceState::Running,
        disk_limit_blocked: false,
        public: PublicEndpoint {
            host: request.public_host.clone(),
            port: request
                .public_port
                .unwrap_or_else(|| super::public_port(state, request.protocol)),
        },
        backend: runtime.backend.clone(),
        runtime: runtime.runtime.clone(),
        database: DatabaseIdentity {
            name: request.database.clone(),
            username: request.username.clone(),
        },
        route_key_sha256: None,
        mariadb_native_password_sha1_stage2: (request.protocol == Protocol::Mariadb)
            .then(|| crate::protocols::mariadb::native_password_sha1_stage2_hex(&request.password)),
        mariadb_root_password: None,
        mysql_native_password_sha1_stage2: (request.protocol == Protocol::Mysql)
            .then(|| crate::protocols::mariadb::native_password_sha1_stage2_hex(&request.password)),
        mysql_root_password: None,
        mongodb_root_password: None,
        postgres_admin_password: None,
        tenant_password: Some(request.password.clone()),
        limits,
        image: Some(InstanceImageStatus {
            current: Some(image.to_string()),
            configured: image.to_string(),
            update_available: false,
        }),
        database_version: Some(InstanceDatabaseVersion {
            current: runtime.database_version.clone(),
            error: None,
        }),
        created_at: now.clone(),
        updated_at: now,
    }
}

async fn cleanup_failed_tenant(
    state: &AppState,
    runtime: &EngineRuntime,
    instance_id: &str,
    database: &str,
    username: &str,
) {
    let target = TenantTarget { database, username };
    if let Err(error) = tenant::disk::prepare_drop(&state.config, runtime, target).await {
        let containment = crate::api::instances::containment::contain_locked(
            state,
            runtime,
            "failed shared tenant storage cleanup could not be prepared",
        )
        .await;
        tracing::error!(
            event = "audit shared_tenant_storage_cleanup_failed",
            %instance_id,
            runtime_id = %runtime.runtime_id,
            %error,
            containment = %containment.summary(),
            "retained the reservation because its storage boundary could not be made safe"
        );
        return;
    }
    let dropped = tenant::drop_tenant(&state.docker, runtime, target).await;
    if let Err(error) = dropped {
        let containment = crate::api::instances::containment::contain_locked(
            state,
            runtime,
            "failed shared tenant creation could not be removed",
        )
        .await;
        tracing::error!(
            event = "audit shared_tenant_cleanup_failed",
            %instance_id,
            runtime_id = %runtime.runtime_id,
            %error,
            containment = %containment.summary(),
            contained = containment.contained(),
            "retained the tenant reservation and contained the shared runtime"
        );
        return;
    }
    if let Err(error) = tenant::disk::remove(&state.config, runtime, target).await {
        let containment = crate::api::instances::containment::contain_locked(
            state,
            runtime,
            "failed shared tenant quota cleanup remained uncertain",
        )
        .await;
        tracing::error!(
            event = "audit shared_tenant_quota_cleanup_failed",
            %instance_id,
            runtime_id = %runtime.runtime_id,
            %error,
            containment = %containment.summary(),
            "retained the reservation after the engine tenant was removed"
        );
        return;
    }
    release_claim(state, runtime, instance_id).await;
}

async fn release_claim(state: &AppState, runtime: &EngineRuntime, instance_id: &str) {
    if let Err(error) = state.placements.release(instance_id).await {
        let containment = crate::api::instances::containment::contain_locked(
            state,
            runtime,
            "shared tenant reservation cleanup became uncertain",
        )
        .await;
        tracing::error!(
            event = "audit shared_tenant_reservation_cleanup_failed",
            %instance_id,
            runtime_id = %runtime.runtime_id,
            %error,
            containment = %containment.summary(),
            contained = containment.contained(),
            "failed to release a tenant claim; contained the runtime around the uncertain reservation"
        );
        return;
    }
    match state.placements.get(&runtime.runtime_id).await {
        Ok(Some(current)) => {
            if let Err(error) = shared_runtime::apply_limits(
                &state.docker,
                &state.config,
                &state.placements,
                &current,
            )
            .await
            {
                let containment = crate::api::instances::containment::contain_locked(
                    state,
                    &current,
                    "failed reservation cleanup left aggregate pool limits uncertain",
                )
                .await;
                tracing::error!(
                    event = "audit shared_runtime_limit_cleanup_failed",
                    %instance_id,
                    runtime_id = %runtime.runtime_id,
                    %error,
                    containment = %containment.summary(),
                    contained = containment.contained(),
                    "removed the failed reservation but could not restore the physical pool limit; contained the pool"
                );
            }
        }
        Ok(None) => {
            let containment = crate::api::instances::containment::contain_locked(
                state,
                runtime,
                "failed tenant creation released capacity but its shared runtime disappeared",
            )
            .await;
            tracing::error!(
                event = "audit shared_runtime_limit_cleanup_failed",
                %instance_id,
                runtime_id = %runtime.runtime_id,
                containment = %containment.summary(),
                contained = containment.contained(),
                "removed the failed reservation but its physical runtime disappeared"
            );
        }
        Err(error) => {
            let containment = crate::api::instances::containment::contain_locked(
                state,
                runtime,
                "failed tenant creation released capacity but its shared runtime could not be reloaded",
            )
            .await;
            tracing::error!(
                event = "audit shared_runtime_limit_cleanup_failed",
                %instance_id,
                runtime_id = %runtime.runtime_id,
                %error,
                containment = %containment.summary(),
                contained = containment.contained(),
                "removed the failed reservation but could not reload its physical runtime"
            );
        }
    }
}

pub(crate) fn placement_error(error: PlacementRepositoryError) -> ApiError {
    match error {
        PlacementRepositoryError::CapacityUnavailable(_) => ApiError::Conflict("shared_pool_full: the server pool has reached its disk or database-count limit; resize it explicitly".into()),
        PlacementRepositoryError::DatabaseInUse { .. } | PlacementRepositoryError::UsernameInUse { .. } | PlacementRepositoryError::AlreadyReserved(_) => ApiError::Conflict(error.to_string()),
        _ => ApiError::Runtime(format!("shared runtime storage failed: {error}")),
    }
}

fn same_created_tenant(stored: &InstanceMetadata, expected: &InstanceMetadata) -> bool {
    let same_public = match (serde_json::to_value(stored), serde_json::to_value(expected)) {
        (Ok(stored), Ok(expected)) => stored == expected,
        _ => false,
    };
    same_public
        && stored.desired_state == expected.desired_state
        && stored.disk_limit_blocked == expected.disk_limit_blocked
        && stored.mariadb_native_password_sha1_stage2
            == expected.mariadb_native_password_sha1_stage2
        && stored.mariadb_root_password == expected.mariadb_root_password
        && stored.mysql_native_password_sha1_stage2 == expected.mysql_native_password_sha1_stage2
        && stored.mysql_root_password == expected.mysql_root_password
        && stored.mongodb_root_password == expected.mongodb_root_password
        && stored.postgres_admin_password == expected.postgres_admin_password
        && stored.tenant_password == expected.tenant_password
}

fn fail(state: &AppState, instance_id: &str, error: impl std::fmt::Display) -> ApiError {
    let error = ApiError::Runtime(error.to_string());
    state
        .install_progress
        .fail_api_error(instance_id, "shared instance creation", &error);
    error
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lost_create_ack_only_adopts_exact_metadata_and_secrets() {
        let mut expected: InstanceMetadata = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "instance_id": "tenant-a",
            "deployment_mode": "shared",
            "runtime_id": "pool-a",
            "protocol": "postgres",
            "status": "running",
            "public": {"host": "db.example.com", "port": 5432},
            "backend": {"kind": "unix_socket", "socket_path": "/run/pool-a.sock"},
            "runtime": {"kind": "docker", "container_name": "pool-a", "network_mode": "none"},
            "database": {"name": "database_a", "username": "user_a"},
            "limits": {
                "cpu_cores": 1.0,
                "memory_mib": 1024,
                "disk_mib": 4096,
                "disk_enforced": false,
                "disk_enforcement_method": "shared_pool_reservation"
            },
            "created_at": "2026-08-27T00:00:00Z",
            "updated_at": "2026-08-27T00:00:00Z"
        }))
        .unwrap();
        expected.tenant_password = Some("tenant-secret".to_string());
        let mut stored = expected.clone();
        assert!(same_created_tenant(&stored, &expected));

        stored.tenant_password = Some("different-secret".to_string());
        assert!(!same_created_tenant(&stored, &expected));
        stored = expected.clone();
        stored.public.port += 1;
        assert!(!same_created_tenant(&stored, &expected));
    }
}
