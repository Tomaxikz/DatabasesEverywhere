use secrecy::SecretString;
use tokio::sync::OwnedMutexGuard;

use super::{
    backend_endpoint, docker_error, launch_container_from_spec, prepare_instance_container_user,
    protocol_pids_limit, resolve_image,
};
use crate::{
    api::{
        http::{response::ApiError, router::AppState},
        instances::requests::CreateInstanceRequest,
    },
    databases,
    disk::DiskLimiter,
    instances::{
        metadata::{
            DatabaseIdentity, DesiredInstanceState, InstanceDatabaseVersion, InstanceImageStatus,
            InstanceMetadata, InstanceStatus, PublicEndpoint, RuntimeKind, RuntimeMetadata,
            SCHEMA_VERSION,
        },
        paths::InstancePaths,
    },
    placement::{
        DeploymentMode, ENGINE_RUNTIME_SCHEMA_VERSION, EngineRuntime, EngineRuntimeStatus,
        PlacementRepositoryError, ReserveTenant, RuntimeReservation, policy,
        runtime as shared_runtime,
        tenant::{self, TenantTarget},
    },
    runtime::docker::DockerInstanceSpec,
    shared::{limits::InstanceLimits, protocol::Protocol, time::now_rfc3339},
};

pub(super) async fn create(
    state: &AppState,
    request: CreateInstanceRequest,
    creation: OwnedMutexGuard<()>,
) -> Result<InstanceMetadata, ApiError> {
    let mut creation = Some(creation);
    let image = resolve_image(state, &request)?;
    state
        .install_progress
        .begin(&request.instance_id, request.protocol, &image);
    state.install_progress.stage(
        &request.instance_id,
        "select_pool",
        "selecting a compatible shared database runtime",
    );

    let mut tenant_limits = request
        .limits
        .as_ref()
        .map(super::limits_from_request)
        .unwrap_or_default();
    tenant_limits.disk_enforced = false;
    tenant_limits.disk_enforcement_method = "shared_pool_reservation".to_string();

    let requested_pool_limits = request
        .limits
        .as_ref()
        .map(super::limits_from_request)
        .unwrap_or_default();
    let (claimed_runtime, created_pool, _runtime_operation) = claim_runtime(
        state,
        &request,
        &image,
        requested_pool_limits,
        &tenant_limits,
        &mut creation,
    )
    .await
    .map_err(|error| fail(state, &request.instance_id, error))?;
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
            created_pool,
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
        release_claim(state, &runtime, &request.instance_id, created_pool).await;
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
            created_pool,
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
            created_pool,
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
                created_pool,
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
            created_pool,
        )
        .await;
        return Err(fail(
            state,
            &request.instance_id,
            format!("failed to persist shared tenant provisioning: {error}"),
        ));
    }

    let metadata = build_shared_metadata(state, &request, &runtime, tenant_limits, &image);
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
                    created_pool,
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
        created_pool,
    );
    Ok(metadata)
}

pub(crate) async fn claim_runtime(
    state: &AppState,
    request: &CreateInstanceRequest,
    image: &str,
    limits: InstanceLimits,
    tenant_limits: &InstanceLimits,
    creation: &mut Option<OwnedMutexGuard<()>>,
) -> Result<(EngineRuntime, bool, OwnedMutexGuard<()>), ApiError> {
    let protocol = request.protocol;
    for candidate in state
        .placements
        .find_shared(protocol, image, &limits)
        .await
        .map_err(placement_error)?
    {
        let candidate_operation = state.instance_locks.lock(&candidate.runtime_id).await;
        let Some(runtime) = state
            .placements
            .get(&candidate.runtime_id)
            .await
            .map_err(placement_error)?
        else {
            continue;
        };
        if runtime.status != EngineRuntimeStatus::Running {
            continue;
        }
        match state
            .placements
            .check_tenant_identity(&runtime.runtime_id, &request.database, &request.username)
            .await
        {
            Ok(()) => {}
            Err(
                PlacementRepositoryError::DatabaseInUse { .. }
                | PlacementRepositoryError::UsernameInUse { .. },
            ) => continue,
            Err(error) => return Err(placement_error(error)),
        }
        let mut admission = limits.clone();
        admission.disk_mib =
            policy::pool_disk_growth_mib(protocol, runtime.reserved.disk_mib, limits.disk_mib)
                .ok_or_else(|| {
                    ApiError::BadRequest(format!("{protocol} cannot use shared deployment"))
                })?;
        super::enforce_node_allocation_policy(state, &admission, None).await?;
        match state
            .placements
            .reserve(ReserveTenant {
                instance_id: &request.instance_id,
                runtime_id: &runtime.runtime_id,
                database: &request.database,
                username: &request.username,
                limits: tenant_limits,
            })
            .await
        {
            Ok(runtime) => {
                // The durable reservation is the node-capacity commit. Release
                // global admission before any Docker or tenant-engine work.
                drop(creation.take());
                return Ok((runtime, false, candidate_operation));
            }
            Err(PlacementRepositoryError::CapacityUnavailable(_)) => continue,
            Err(error) => return Err(placement_error(error)),
        }
    }

    let pool_limits = policy::pool_limits(protocol, &limits)
        .ok_or_else(|| ApiError::BadRequest(format!("{protocol} cannot use shared deployment")))?;
    crate::shared::limits::validate_runtime_limits(pool_limits.cpu_cores, pool_limits.memory_mib)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    super::enforce_node_allocation_policy(state, &pool_limits, None).await?;
    let (runtime, runtime_operation) =
        create_runtime(state, request, image, pool_limits, tenant_limits, creation).await?;
    Ok((runtime, true, runtime_operation))
}

async fn create_runtime(
    state: &AppState,
    request: &CreateInstanceRequest,
    image: &str,
    mut limits: InstanceLimits,
    tenant_limits: &InstanceLimits,
    creation: &mut Option<OwnedMutexGuard<()>>,
) -> Result<(EngineRuntime, OwnedMutexGuard<()>), ApiError> {
    let protocol = request.protocol;
    let runtime_id = policy::runtime_id(protocol);
    // Container events use this same lock before reading and persisting pool
    // state. Holding it across the first durable row, bootstrap, and any
    // cleanup prevents an early event from reviving a failed pool from a stale
    // snapshot.
    let runtime_operation = state.instance_locks.lock(&runtime_id).await;
    let admin_password = format!(
        "dbe-pool-{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let paths = InstancePaths::new(&state.config.paths, &runtime_id)
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    // Resolve every fallible identity value before creating the pool's
    // filesystem namespace. From create_dirs onward there is no durable row
    // for boot recovery until the initial placement save succeeds.
    let backend = backend_endpoint(state, protocol, &runtime_id)?;
    let container_name = state
        .docker
        .container_name(protocol, &runtime_id)
        .map_err(docker_error)?;
    let max_tenants = policy::max_tenants(protocol)
        .ok_or_else(|| ApiError::BadRequest(format!("{protocol} cannot use shared deployment")))?;
    let disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
            .for_protocol(protocol);
    let effective_disk_method = disk_limiter.mode().method().to_string();
    if let Err(error) = paths.create_dirs().await {
        return Err(cleanup_unpersisted_runtime(
            state,
            &paths,
            protocol,
            &effective_disk_method,
            ApiError::Runtime(error.to_string()),
        )
        .await);
    }
    let user = match prepare_instance_container_user(&state.docker, &paths, protocol).await {
        Ok(user) => user,
        Err(error) => {
            return Err(cleanup_unpersisted_runtime(
                state,
                &paths,
                protocol,
                &effective_disk_method,
                ApiError::Runtime(error.to_string()),
            )
            .await);
        }
    };
    let disk = match disk_limiter
        .apply_instance_limit(&runtime_id, &paths.data, limits.disk_mib)
        .await
    {
        Ok(disk) => disk,
        Err(error) => {
            return Err(cleanup_unpersisted_runtime(
                state,
                &paths,
                protocol,
                &effective_disk_method,
                ApiError::Runtime(error.to_string()),
            )
            .await);
        }
    };
    limits.disk_enforced = disk.enforced;
    limits.disk_enforcement_method = disk.method.clone();
    let data_path = disk.container_data_path.unwrap_or(paths.data.clone());
    let mut spec = match shared_spec(
        protocol,
        &runtime_id,
        image,
        &admin_password,
        &paths,
        data_path,
    )
    .await
    {
        Ok(spec) => spec,
        Err(error) => {
            return Err(cleanup_unpersisted_runtime(
                state,
                &paths,
                protocol,
                &limits.disk_enforcement_method,
                error,
            )
            .await);
        }
    };
    spec.user = Some(user);
    spec.cpu_cores = limits.cpu_cores;
    spec.memory_mib = limits.memory_mib;
    spec.disk_mib = limits.disk_mib;
    spec.pids_limit = Some(protocol_pids_limit(state, protocol));

    let now = now_rfc3339();
    let mut runtime = EngineRuntime {
        schema_version: ENGINE_RUNTIME_SCHEMA_VERSION,
        runtime_id: runtime_id.clone(),
        protocol,
        deployment_mode: DeploymentMode::Shared,
        status: EngineRuntimeStatus::Creating,
        backend,
        runtime: RuntimeMetadata {
            kind: RuntimeKind::from(state.config.daemon.engine),
            container_name,
            network_mode: "none".to_string(),
        },
        limits,
        image: image.to_string(),
        database_version: None,
        compatibility: None,
        compatibility_key: policy::compatibility_key(protocol, image),
        max_tenants,
        reserved: RuntimeReservation::default(),
        admin_secret: Some(admin_password.clone()),
        created_at: now.clone(),
        updated_at: now,
    };
    if let Err(error) = state.placements.save(&runtime).await {
        let save_error = placement_error(error);
        match state.placements.get(&runtime_id).await {
            Ok(Some(persisted)) if same_initial_runtime(&persisted, &runtime) => {
                tracing::warn!(
                    event = "audit shared_runtime_create_commit_ack_lost",
                    runtime_id = %runtime_id,
                    %protocol,
                    error = %save_error,
                    "initial shared runtime placement was committed despite a lost SQLite acknowledgement"
                );
            }
            Ok(None) => {
                return Err(cleanup_unpersisted_runtime(
                    state,
                    &paths,
                    protocol,
                    &runtime.limits.disk_enforcement_method,
                    save_error,
                )
                .await);
            }
            Ok(Some(_)) => {
                tracing::error!(
                    event = "audit shared_runtime_create_commit_ambiguous",
                    runtime_id = %runtime_id,
                    %protocol,
                    error = %save_error,
                    durable_state = "mismatched",
                    "retained provisional shared runtime paths because placement persistence became ambiguous"
                );
                return Err(ApiError::Runtime(format!(
                    "initial shared runtime placement returned {save_error}, but runtime {runtime_id} contains different durable state; retained its physical state for boot recovery"
                )));
            }
            Err(read_error) => {
                tracing::error!(
                    event = "audit shared_runtime_create_commit_ambiguous",
                    runtime_id = %runtime_id,
                    %protocol,
                    error = %save_error,
                    durable_state = "unreadable",
                    durable_read_error = %read_error,
                    "retained provisional shared runtime paths because placement persistence became ambiguous"
                );
                return Err(ApiError::Runtime(format!(
                    "initial shared runtime placement returned {save_error}, and durable state for runtime {runtime_id} could not be read ({read_error}); retained its physical state for boot recovery"
                )));
            }
        }
    }
    runtime = match state
        .placements
        .reserve_starting(ReserveTenant {
            instance_id: &request.instance_id,
            runtime_id: &runtime.runtime_id,
            database: &request.database,
            username: &request.username,
            limits: tenant_limits,
        })
        .await
    {
        Ok(runtime) => runtime,
        Err(error) => {
            destroy_empty_runtime(state, &runtime).await;
            return Err(placement_error(error));
        }
    };
    // The creating runtime and its first tenant reservation are one durable
    // physical-capacity commit. Other admissions count it while Docker work
    // runs, but find_shared excludes it until launch succeeds.
    drop(creation.take());

    state.install_progress.stage(
        &request.instance_id,
        "create_pool",
        "starting a new shared database runtime",
    );
    let progress = state.install_progress.clone();
    let progress_id = request.instance_id.clone();
    let pull_progress = move |event| progress.docker_pull(&progress_id, event);
    let launch = launch_container_from_spec(
        state,
        &spec,
        protocol,
        &runtime_id,
        &pull_progress,
        false,
        || async {
            if protocol == Protocol::Mongodb {
                super::bootstrap_mongodb_root(state, &runtime_id, &admin_password).await?;
            }
            Ok(())
        },
    )
    .await;
    if let Err(error) = launch {
        cleanup_starting_runtime(state, &runtime, &request.instance_id).await;
        return Err(error.into_api_error());
    }

    if let Err(error) = tenant::secure_pool(&state.docker, &runtime).await {
        cleanup_starting_runtime(state, &runtime, &request.instance_id).await;
        return Err(ApiError::Conflict(format!(
            "shared runtime isolation bootstrap failed: {error}"
        )));
    }

    let probe = match shared_runtime::probe_compatibility(&state.docker, &runtime).await {
        Ok(probe) => probe,
        Err(error) => {
            cleanup_starting_runtime(state, &runtime, &request.instance_id).await;
            return Err(ApiError::Conflict(error));
        }
    };
    runtime.database_version = Some(probe.version.clone());
    runtime.compatibility = Some(probe.compatibility);
    runtime.status = EngineRuntimeStatus::Running;
    runtime.updated_at = now_rfc3339();
    if let Err(error) = state
        .placements
        .save(&runtime)
        .await
        .map_err(placement_error)
    {
        cleanup_starting_runtime(state, &runtime, &request.instance_id).await;
        return Err(error);
    }
    tracing::info!(
        event = "audit shared_runtime_created",
        runtime_id = %runtime.runtime_id,
        %protocol,
        image,
        version = %probe.version,
        max_tenants = runtime.max_tenants,
    );
    Ok((runtime, runtime_operation))
}

async fn cleanup_unpersisted_runtime(
    state: &AppState,
    paths: &InstancePaths,
    protocol: Protocol,
    disk_enforcement_method: &str,
    error: ApiError,
) -> ApiError {
    let physical_cleanup = crate::api::instances::purge_provisional_runtime_paths(
        state,
        &paths.instance_id,
        protocol,
        Some(disk_enforcement_method),
    )
    .await;
    // purge_provisional_runtime_paths deliberately preserves logical instance
    // artifacts for deployment rollback. A brand-new pool has no logical
    // owner, so remove the artifacts directory created by create_dirs too.
    let artifact_cleanup =
        crate::api::instances::major_upgrade::remove_path_if_exists(&paths.artifacts).await;
    let cleanup_error = match (physical_cleanup, artifact_cleanup) {
        (Ok(()), Ok(())) => None,
        (Err(physical), Ok(())) => Some(physical.to_string()),
        (Ok(()), Err(artifacts)) => Some(artifacts.to_string()),
        (Err(physical), Err(artifacts)) => Some(format!(
            "physical cleanup failed: {physical}; artifact cleanup failed: {artifacts}"
        )),
    };
    match cleanup_error {
        None => {
            tracing::info!(
                event = "audit shared_runtime_create_failed_cleaned",
                runtime_id = %paths.instance_id,
                %protocol,
                disk_enforcement_method,
                error = %error,
                "removed an unpersisted shared runtime after creation failed"
            );
            error
        }
        Some(cleanup_error) => {
            tracing::error!(
                event = "audit shared_runtime_create_cleanup_incomplete",
                runtime_id = %paths.instance_id,
                %protocol,
                disk_enforcement_method,
                error = %error,
                %cleanup_error,
                "an unpersisted shared runtime could not be cleaned completely"
            );
            ApiError::Runtime(format!(
                "{error}; cleanup of unpersisted shared runtime {} using disk method {disk_enforcement_method} also failed: {cleanup_error}",
                paths.instance_id
            ))
        }
    }
}

async fn cleanup_starting_runtime(state: &AppState, runtime: &EngineRuntime, instance_id: &str) {
    if let Err(error) = state.placements.release(instance_id).await {
        tracing::error!(
            event = "audit shared_runtime_initial_reservation_cleanup_failed",
            %instance_id,
            runtime_id = %runtime.runtime_id,
            %error,
            "could not release a failed new pool's initial reservation"
        );
        return;
    }
    destroy_empty_runtime(state, runtime).await;
}

async fn shared_spec(
    protocol: Protocol,
    runtime_id: &str,
    image: &str,
    admin_password: &str,
    paths: &InstancePaths,
    data_path: std::path::PathBuf,
) -> Result<DockerInstanceSpec, ApiError> {
    let password = || SecretString::from(admin_password.to_string());
    let spec = match protocol {
        Protocol::Postgres => databases::postgres::docker::shared_spec(
            runtime_id,
            image,
            password(),
            data_path,
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mysql => databases::mysql::docker::shared_spec(
            runtime_id,
            image,
            password(),
            data_path,
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mariadb => databases::mariadb::docker::shared_spec(
            runtime_id,
            image,
            password(),
            data_path,
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mongodb => databases::mongodb::docker::shared_spec(
            runtime_id,
            image,
            password(),
            data_path,
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Clickhouse => {
            let config =
                databases::clickhouse::docker::write_shared_hosted_config(&paths.runtime_config)
                    .await
                    .map_err(|error| ApiError::Runtime(error.to_string()))?;
            databases::clickhouse::docker::shared_spec(
                runtime_id,
                image,
                password(),
                data_path,
                paths.logs.clone(),
                config,
                paths.sockets.clone(),
                paths.socket_bridge_binary.clone(),
            )
        }
        protocol => {
            return Err(ApiError::BadRequest(format!(
                "{protocol} cannot use shared deployment"
            )));
        }
    };
    Ok(spec)
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
    created_pool: bool,
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
    release_claim(state, runtime, instance_id, created_pool).await;
}

async fn release_claim(
    state: &AppState,
    runtime: &EngineRuntime,
    instance_id: &str,
    created_pool: bool,
) {
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
    if created_pool {
        destroy_empty_runtime(state, runtime).await;
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

pub(crate) async fn destroy_empty_runtime(state: &AppState, runtime: &EngineRuntime) {
    if let Err(error) = crate::api::instances::delete_empty_pool(state, &runtime.runtime_id).await {
        let containment = crate::api::instances::containment::contain_locked(
            state,
            runtime,
            "empty shared runtime cleanup failed",
        )
        .await;
        tracing::error!(
            event = "audit empty_shared_runtime_cleanup_failed",
            runtime_id = %runtime.runtime_id,
            %error,
            containment = %containment.summary(),
            contained = containment.contained(),
            "retained the empty runtime after physical cleanup failed"
        );
    }
}

fn placement_error(error: impl std::fmt::Display) -> ApiError {
    ApiError::Runtime(format!("shared runtime storage failed: {error}"))
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

fn same_initial_runtime(stored: &EngineRuntime, expected: &EngineRuntime) -> bool {
    let Some(persisted_disk_mib) =
        policy::pool_disk_mib(expected.protocol, expected.reserved.disk_mib)
    else {
        return false;
    };
    // PlacementRepository::save persists a shared runtime's disk limit from
    // its durable reservation total. Before reserve_starting, that total is
    // zero even though the effective quota was prepared for the first tenant.
    let mut normalized_expected = expected.clone();
    normalized_expected.limits.disk_mib = persisted_disk_mib;
    let same_public = match (
        serde_json::to_value(stored),
        serde_json::to_value(&normalized_expected),
    ) {
        (Ok(stored), Ok(expected)) => stored == expected,
        _ => false,
    };
    same_public && stored.admin_secret == normalized_expected.admin_secret
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

    fn initial_runtime() -> EngineRuntime {
        let mut runtime = crate::placement::test_support::runtime(
            "pool_postgres_initial",
            Protocol::Postgres,
            "postgres:18.4",
        );
        runtime.status = EngineRuntimeStatus::Creating;
        runtime.backend = crate::shared::backend::BackendEndpoint::UnixSocket {
            socket_path: "/run/dbe/pool_postgres_initial/.s.PGSQL.5432".to_string(),
        };
        runtime.limits = InstanceLimits {
            cpu_cores: 1.25,
            memory_mib: 1280,
            disk_mib: 8192,
            disk_enforced: true,
            disk_enforcement_method: "fuse_quota".to_string(),
        };
        runtime.max_tenants = policy::max_tenants(Protocol::Postgres).unwrap();
        runtime.admin_secret = Some("pool-admin-secret".to_string());
        runtime.created_at = "2026-09-08T00:00:00Z".to_string();
        runtime.updated_at = runtime.created_at.clone();
        runtime
    }

    #[test]
    fn lost_initial_save_ack_only_adopts_exact_creating_runtime() {
        let expected = initial_runtime();
        let mut persisted = expected.clone();
        persisted.limits.disk_mib = policy::pool_disk_mib(Protocol::Postgres, 0).unwrap();
        assert!(same_initial_runtime(&persisted, &expected));

        persisted.admin_secret = Some("different-secret".to_string());
        assert!(!same_initial_runtime(&persisted, &expected));
        persisted = expected.clone();
        persisted.limits.disk_mib = policy::pool_disk_mib(Protocol::Postgres, 0).unwrap();
        persisted.runtime.container_name.push_str("-different");
        assert!(!same_initial_runtime(&persisted, &expected));
    }

    #[tokio::test]
    async fn unpersisted_runtime_cleanup_removes_every_created_pool_path() {
        let namespace = tempfile::tempdir().unwrap();
        let root = namespace.path();
        let path = |name: &str| root.join(name).display().to_string();
        let mut config = crate::config::Config::default();
        config.disk.mode = crate::config::DiskLimitMode::SoftScanner;
        config.paths.data = path("data");
        config.paths.metadata = path("metadata");
        config.paths.volumes = path("volumes");
        config.paths.backups = path("backups");
        config.paths.sockets = path("sockets");
        config.paths.locks = path("locks");
        config.paths.logs = path("logs");
        config.paths.artifacts = path("artifacts");
        config.paths.exports = path("exports");
        config.paths.imports = path("imports");
        config.paths.fuse = path("fuse");
        config.paths.tmp = path("tmp");
        let (state, _database) = super::super::tests::test_state(config).await;
        let paths = InstancePaths::new(&state.config.paths, "pool_postgres_unpersisted").unwrap();
        paths.create_dirs().await.unwrap();
        for path in [
            &paths.data,
            &paths.logs,
            &paths.sockets,
            &paths.artifacts,
            &paths.runtime_config,
        ] {
            tokio::fs::write(path.join("partial-create"), b"orphan")
                .await
                .unwrap();
        }

        let error = cleanup_unpersisted_runtime(
            &state,
            &paths,
            Protocol::Postgres,
            "soft_scanner",
            ApiError::Runtime("injected pre-durable failure".to_string()),
        )
        .await;

        assert!(error.to_string().contains("injected pre-durable failure"));
        for path in [
            &paths.data,
            &paths.logs,
            &paths.sockets,
            &paths.artifacts,
            &paths.runtime_config,
        ] {
            assert!(
                tokio::fs::symlink_metadata(path).await.is_err(),
                "{} survived cleanup",
                path.display()
            );
        }
    }

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
