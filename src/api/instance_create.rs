use std::{future::Future, time::Duration};

use secrecy::SecretString;
use tokio::time::sleep;

use crate::{
    api::{
        api_response::ApiError,
        images::{ensure_image_allowed, validate_image},
        instance_requests::{CreateInstanceRequest, limits_from_request, validate_create_request},
        instances::docker_error,
        resources::{mib_to_bytes, read_host_cpu_cores, read_host_disk, read_host_memory},
        routes::AppState,
        security_policy::DestructiveActionPolicy,
    },
    databases,
    disk::DiskLimiter,
    instances::{
        metadata::{
            DatabaseIdentity, InstanceMetadata, InstanceStatus, PublicEndpoint, RuntimeKind,
            RuntimeMetadata, SCHEMA_VERSION,
        },
        paths::InstancePaths,
    },
    runtime::docker::{DockerImagePullProgress, DockerInstanceSpec, DockerRuntime},
    shared::{
        backend::BackendEndpoint, logs::summarize_failure_logs, protocol::Protocol, redaction,
        shell::sh_quote, time::now_rfc3339,
    },
};

mod mysql_hardening;

#[cfg(test)]
use mysql_hardening::mysql_auth_failed_metadata;
pub(crate) use mysql_hardening::{
    harden_mysql_accounts_on_boot, harden_mysql_tenant_auth, verify_mysql_root_auth,
};

pub async fn create_instance_from_request(
    state: &AppState,
    request: CreateInstanceRequest,
) -> Result<InstanceMetadata, ApiError> {
    validate_create_request(&request)?;
    let _creation = state.instance_locks.lock_creation().await;
    let _operation = state.instance_locks.lock(&request.instance_id).await;
    reject_duplicate_instance(state, &request).await?;
    handle_stale_instance_resources(state, &request).await?;
    let requested_limits = request
        .limits
        .as_ref()
        .map(limits_from_request)
        .unwrap_or_default();
    enforce_node_allocation_policy(state, &requested_limits, None).await?;

    let cleanup = CreateFailureCleanup::new(state, request.protocol, request.instance_id.clone());
    match create_instance_from_validated_request(state, request).await {
        Ok(metadata) => Ok(metadata),
        Err(error) => {
            cleanup.run(&error).await;
            Err(error)
        }
    }
}

pub(crate) async fn prepare_instance_container_user(
    docker: &DockerRuntime,
    paths: &InstancePaths,
    protocol: Protocol,
) -> Result<String, crate::instances::paths::InstancePathError> {
    if let Some(user) = docker.rootless_podman_container_user(protocol) {
        let (uid, gid) = docker
            .rootless_podman_host_owner()
            .ok_or(crate::instances::paths::InstancePathError::MissingRuntimeOwner)?;
        paths.apply_rootless_podman_owner(uid, gid).await?;
        Ok(user.to_string())
    } else {
        paths.apply_container_owner().await?;
        paths.container_user().await
    }
}

pub(crate) async fn enforce_node_allocation_policy(
    state: &AppState,
    requested: &crate::shared::limits::InstanceLimits,
    previous: Option<&crate::shared::limits::InstanceLimits>,
) -> Result<(), ApiError> {
    let previous_cpu_cores = previous.map(|limits| limits.cpu_cores).unwrap_or_default();
    let previous_memory_bytes = previous
        .map(|limits| mib_to_bytes(limits.memory_mib))
        .unwrap_or_default();
    let previous_disk_bytes = previous
        .map(|limits| mib_to_bytes(limits.disk_mib))
        .unwrap_or_default();
    let requested_memory_bytes = mib_to_bytes(requested.memory_mib);
    let requested_disk_bytes = mib_to_bytes(requested.disk_mib);
    let allocation = &state.config.allocation;
    let check_cpu =
        allocation.prevent_cpu_overallocation && requested.cpu_cores > previous_cpu_cores;
    let check_memory =
        allocation.prevent_memory_overallocation && requested_memory_bytes > previous_memory_bytes;
    let check_disk =
        allocation.prevent_disk_overallocation && requested_disk_bytes > previous_disk_bytes;

    // Decreases are always safe, and disabled guards must not retain hidden
    // host-probe failure modes or overhead.
    if !check_cpu && !check_memory && !check_disk {
        return Ok(());
    }

    let instances = state.instances.list().await;
    let allocated_cpu_cores = check_cpu.then(|| {
        instances
            .iter()
            .map(|metadata| metadata.limits.cpu_cores)
            .sum::<f64>()
    });
    let allocated_memory_bytes = check_memory.then(|| {
        instances.iter().fold(0_u64, |total, metadata| {
            total.saturating_add(mib_to_bytes(metadata.limits.memory_mib))
        })
    });
    let allocated_disk_bytes = check_disk.then(|| {
        instances.iter().fold(0_u64, |total, metadata| {
            total.saturating_add(mib_to_bytes(metadata.limits.disk_mib))
        })
    });
    let volumes_root = state.config.paths.volumes_root();
    let (host_cpu_cores, host_memory, host_disk) = tokio::join!(
        async {
            if check_cpu {
                read_host_cpu_cores().await.map(Some)
            } else {
                Ok(None)
            }
        },
        async {
            if check_memory {
                read_host_memory().await.map(Some)
            } else {
                Ok(None)
            }
        },
        async {
            if check_disk {
                read_host_disk(&volumes_root).await.map(Some)
            } else {
                Ok(None)
            }
        },
    );

    if let (Some(allocated), Some(total)) = (
        allocated_cpu_cores,
        host_cpu_cores.map_err(|error| {
            ApiError::Runtime(format!(
                "failed to sample host CPU for allocation admission: {error}"
            ))
        })?,
    ) {
        enforce_cpu_allocation(allocated, previous_cpu_cores, requested.cpu_cores, total)?;
    }
    if let (Some(allocated), Some(host)) = (
        allocated_memory_bytes,
        host_memory.map_err(|error| {
            ApiError::Runtime(format!(
                "failed to sample host memory for allocation admission: {error}"
            ))
        })?,
    ) {
        enforce_resource_allocation(
            "memory",
            allocated,
            previous_memory_bytes,
            requested_memory_bytes,
            allocation.effective_memory_limit_bytes(host.total_bytes),
            host.available_bytes,
            allocation.reserved_memory_bytes(),
        )?;
    }
    if let (Some(allocated), Some(host)) = (
        allocated_disk_bytes,
        host_disk.map_err(|error| {
            ApiError::Runtime(format!(
                "failed to sample host disk for allocation admission: {error}"
            ))
        })?,
    ) {
        enforce_resource_allocation(
            "disk",
            allocated,
            previous_disk_bytes,
            requested_disk_bytes,
            allocation.effective_disk_limit_bytes(host.total_bytes),
            host.available_bytes,
            allocation.reserved_disk_bytes(),
        )?;
    }

    Ok(())
}

fn enforce_cpu_allocation(
    allocated_cores: f64,
    previous_cores: f64,
    requested_cores: f64,
    host_cores: u64,
) -> Result<(), ApiError> {
    if requested_cores <= previous_cores {
        return Ok(());
    }
    let projected_cores = (allocated_cores - previous_cores).max(0.0) + requested_cores;
    if projected_cores > host_cores as f64 {
        return Err(ApiError::ServiceUnavailable(format!(
            "node CPU allocation capacity exhausted: projected allocation {projected_cores:.2} cores exceeds the detected {host_cores}-core capacity"
        )));
    }
    Ok(())
}

fn enforce_resource_allocation(
    resource: &str,
    allocated_bytes: u64,
    previous_bytes: u64,
    requested_bytes: u64,
    allocation_limit_bytes: u64,
    available_bytes: u64,
    reserved_bytes: u64,
) -> Result<(), ApiError> {
    let additional_bytes = requested_bytes.saturating_sub(previous_bytes);
    if additional_bytes == 0 {
        return Ok(());
    }

    let projected_bytes = allocated_bytes
        .saturating_sub(previous_bytes)
        .saturating_add(requested_bytes);
    if projected_bytes > allocation_limit_bytes {
        return Err(allocation_unavailable(
            resource,
            projected_bytes,
            allocation_limit_bytes,
        ));
    }
    if additional_bytes.saturating_add(reserved_bytes) > available_bytes {
        return Err(available_capacity_unavailable(
            resource,
            additional_bytes,
            available_bytes,
            reserved_bytes,
        ));
    }

    Ok(())
}

fn allocation_unavailable(resource: &str, projected_bytes: u64, limit_bytes: u64) -> ApiError {
    ApiError::ServiceUnavailable(format!(
        "node {resource} allocation capacity exhausted: projected allocation {} MiB exceeds the {} MiB limit",
        bytes_to_mib_ceil(projected_bytes),
        bytes_to_mib_ceil(limit_bytes),
    ))
}

fn available_capacity_unavailable(
    resource: &str,
    additional_bytes: u64,
    available_bytes: u64,
    reserved_bytes: u64,
) -> ApiError {
    ApiError::ServiceUnavailable(format!(
        "node {resource} safety reserve would be breached: allocation increase requires {} MiB, {} MiB is available, and {} MiB must remain reserved",
        bytes_to_mib_ceil(additional_bytes),
        bytes_to_mib_ceil(available_bytes),
        bytes_to_mib_ceil(reserved_bytes),
    ))
}

fn bytes_to_mib_ceil(bytes: u64) -> u64 {
    bytes.saturating_add((1024 * 1024) - 1) / (1024 * 1024)
}

async fn create_instance_from_validated_request(
    state: &AppState,
    request: CreateInstanceRequest,
) -> Result<InstanceMetadata, ApiError> {
    let image = requested_or_configured_image(state, &request)?;
    state
        .install_progress
        .begin(&request.instance_id, request.protocol, &image);
    state.install_progress.stage(
        &request.instance_id,
        "prepare",
        "preparing instance metadata and directories",
    );

    let mut limits = request
        .limits
        .as_ref()
        .map(limits_from_request)
        .unwrap_or_default();
    let container_name = state
        .docker
        .container_name(request.protocol, &request.instance_id)
        .map_err(docker_error)?;
    let paths = InstancePaths::new(&state.config.paths, &request.instance_id)
        .map_err(|error| fail_bad_request(state, &request.instance_id, error))?;
    paths
        .create_dirs()
        .await
        .map_err(|error| fail_runtime(state, &request.instance_id, error))?;
    let password = SecretString::from(request.password.clone());
    let postgres_admin_password = (request.protocol == Protocol::Postgres)
        .then(|| format!("dbe-admin-{}", uuid::Uuid::new_v4().simple()));
    let mariadb_root_password = (request.protocol == Protocol::Mariadb)
        .then(|| format!("dbe-root-{}", uuid::Uuid::new_v4()));
    let mysql_root_password =
        (request.protocol == Protocol::Mysql).then(|| format!("dbe-root-{}", uuid::Uuid::new_v4()));
    let mongodb_root_password = (request.protocol == Protocol::Mongodb)
        .then(|| format!("dbe-root-{}", uuid::Uuid::new_v4()));

    match request.protocol {
        Protocol::Redis => {
            state.install_progress.stage(
                &request.instance_id,
                "provision",
                "writing Redis ACL configuration",
            );
            databases::redis::provision::write_acl_file(&paths.data, &request.username, &password)
                .await
                .map_err(|error| fail_bad_request(state, &request.instance_id, error))?;
        }
        Protocol::Valkey => {
            state.install_progress.stage(
                &request.instance_id,
                "provision",
                "writing Valkey ACL configuration",
            );
            databases::valkey::provision::write_acl_file(&paths.data, &request.username, &password)
                .await
                .map_err(|error| fail_bad_request(state, &request.instance_id, error))?;
        }
        Protocol::Postgres
        | Protocol::Mariadb
        | Protocol::Mysql
        | Protocol::Mongodb
        | Protocol::Clickhouse
        | Protocol::Qdrant => {}
    }
    state.install_progress.stage(
        &request.instance_id,
        "permissions",
        "applying container file ownership",
    );
    if let Some(user) = state
        .docker
        .rootless_podman_container_user(request.protocol)
    {
        tracing::debug!(
            instance_id = request.instance_id,
            protocol = %request.protocol,
            user,
            "rootless podman detected; using protocol-specific container user for bind mount ownership mapping"
        );
    }
    let container_user = prepare_instance_container_user(&state.docker, &paths, request.protocol)
        .await
        .map_err(|error| fail_runtime(state, &request.instance_id, error))?;

    state
        .install_progress
        .stage(&request.instance_id, "disk_limit", "applying disk limit");
    let disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
            .for_protocol(request.protocol);
    let disk = disk_limiter
        .apply_instance_limit(&request.instance_id, &paths.data, limits.disk_mib)
        .await
        .map_err(|error| fail_runtime(state, &request.instance_id, error))?;
    let container_data_path = disk
        .container_data_path
        .clone()
        .unwrap_or(paths.data.clone());
    limits.disk_enforced = disk.enforced;
    limits.disk_enforcement_method = disk.method;

    let mut spec = match request.protocol {
        Protocol::Postgres => databases::postgres::docker::instance_spec(
            &request.instance_id,
            &image,
            &request.database,
            &request.username,
            password,
            SecretString::from(postgres_admin_password.clone().ok_or_else(|| {
                fail_runtime(
                    state,
                    &request.instance_id,
                    "internal PostgreSQL administrator password was not generated",
                )
            })?),
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Redis => databases::redis::docker::instance_spec(
            &request.instance_id,
            &image,
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Valkey => databases::valkey::docker::instance_spec(
            &request.instance_id,
            &image,
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mariadb => databases::mariadb::docker::instance_spec(
            &request.instance_id,
            &image,
            &request.database,
            &request.username,
            password,
            SecretString::from(mariadb_root_password.clone().ok_or_else(|| {
                fail_runtime(
                    state,
                    &request.instance_id,
                    "internal mariadb root password was not generated",
                )
            })?),
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mysql => databases::mysql::docker::instance_spec(
            &request.instance_id,
            &image,
            &request.database,
            SecretString::from(mysql_root_password.clone().ok_or_else(|| {
                fail_runtime(
                    state,
                    &request.instance_id,
                    "internal mysql root password was not generated",
                )
            })?),
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mongodb => databases::mongodb::docker::instance_spec(
            &request.instance_id,
            &image,
            &request.database,
            databases::mongodb::docker::MongodbAuth {
                username: request.username.clone(),
                password,
                root_password: SecretString::from(mongodb_root_password.clone().ok_or_else(
                    || {
                        fail_runtime(
                            state,
                            &request.instance_id,
                            "internal mongodb root password was not generated",
                        )
                    },
                )?),
            },
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Clickhouse => {
            let hosted_config_path =
                databases::clickhouse::docker::write_hosted_config(&paths.runtime_config)
                    .await
                    .map_err(|error| fail_runtime(state, &request.instance_id, error))?;
            databases::clickhouse::docker::instance_spec(
                &request.instance_id,
                &image,
                &request.database,
                &request.username,
                password,
                container_data_path,
                paths.logs.clone(),
                hosted_config_path,
                paths.sockets.clone(),
                paths.socket_bridge_binary.clone(),
            )
        }
        Protocol::Qdrant => databases::qdrant::docker::instance_spec(
            &request.instance_id,
            &image,
            password,
            container_data_path,
            paths.logs.clone(),
            paths.sockets.clone(),
            paths.socket_bridge_binary.clone(),
        ),
    };
    spec.project_id = request.project_id.clone();
    spec.user = Some(container_user);
    spec.cpu_cores = limits.cpu_cores;
    spec.memory_mib = limits.memory_mib;
    spec.disk_mib = limits.disk_mib;
    spec.pids_limit = Some(protocol_pids_limit(state, request.protocol));

    let progress = state.install_progress.clone();
    let progress_instance_id = request.instance_id.clone();
    let pull_progress = move |event| progress.docker_pull(&progress_instance_id, event);
    let mongodb_after_start = || async {
        if request.protocol == Protocol::Mongodb {
            state.install_progress.stage(
                &request.instance_id,
                "provision",
                "creating MongoDB tenant user",
            );
            provision_mongodb_tenant_user(
                state,
                &request.instance_id,
                &request.database,
                &request.username,
                &request.password,
                mongodb_root_password.as_deref().ok_or_else(|| {
                    fail_runtime(
                        state,
                        &request.instance_id,
                        "internal mongodb root password was not generated",
                    )
                })?,
            )
            .await?;
        }
        Ok(())
    };
    if let Err(error) = launch_container_from_spec(
        state,
        &spec,
        request.protocol,
        &request.instance_id,
        &pull_progress,
        true,
        mongodb_after_start,
    )
    .await
    {
        let api_error = error.into_api_error();
        state.install_progress.fail_api_error(
            &request.instance_id,
            "instance creation",
            &api_error,
        );
        return Err(api_error);
    }
    if request.protocol == Protocol::Mariadb {
        state.install_progress.stage(
            &request.instance_id,
            "provision",
            "creating or updating MariaDB tenant user",
        );
        if let Err(error) = provision_mariadb_tenant_user(
            state,
            &request.instance_id,
            &request.database,
            &request.username,
            &request.password,
            mariadb_root_password.as_deref().ok_or_else(|| {
                fail_runtime(
                    state,
                    &request.instance_id,
                    "internal mariadb root password was not generated",
                )
            })?,
        )
        .await
        {
            state.install_progress.fail_api_error(
                &request.instance_id,
                "mariadb provisioning",
                &error,
            );
            return Err(error);
        }
    }
    if request.protocol == Protocol::Mysql {
        state.install_progress.stage(
            &request.instance_id,
            "provision",
            "creating or updating MySQL tenant user",
        );
        if let Err(error) = provision_mysql_tenant_user(
            state,
            &request.instance_id,
            &request.database,
            &request.username,
            &request.password,
            mysql_root_password.as_deref().ok_or_else(|| {
                fail_runtime(
                    state,
                    &request.instance_id,
                    "internal mysql root password was not generated",
                )
            })?,
        )
        .await
        {
            state.install_progress.fail_api_error(
                &request.instance_id,
                "mysql provisioning",
                &error,
            );
            return Err(error);
        }
    }
    if request.protocol == Protocol::Postgres {
        state.install_progress.stage(
            &request.instance_id,
            "provision",
            "restricting PostgreSQL tenant role",
        );
        if let Err(error) = provision_postgres_tenant_role(
            state,
            &request.instance_id,
            &request.database,
            &request.username,
            &request.password,
            postgres_admin_password.as_deref().ok_or_else(|| {
                fail_runtime(
                    state,
                    &request.instance_id,
                    "internal PostgreSQL administrator password was not generated",
                )
            })?,
        )
        .await
        {
            state.install_progress.fail_api_error(
                &request.instance_id,
                "postgres provisioning",
                &error,
            );
            return Err(error);
        }
    }
    state.install_progress.stage(
        &request.instance_id,
        "socket",
        "registering private backend socket",
    );
    let backend = match backend_endpoint_for_instance(state, request.protocol, &request.instance_id)
    {
        Ok(backend) => backend,
        Err(error) => {
            state.install_progress.fail_api_error(
                &request.instance_id,
                "instance socket setup",
                &error,
            );
            return Err(error);
        }
    };

    let now = now_rfc3339();
    let metadata = InstanceMetadata {
        schema_version: SCHEMA_VERSION,
        instance_id: request.instance_id,
        protocol: request.protocol,
        status: InstanceStatus::Running,
        desired_state: crate::instances::metadata::DesiredInstanceState::Running,
        disk_limit_blocked: false,
        public: PublicEndpoint {
            host: request.public_host,
            port: request
                .public_port
                .unwrap_or_else(|| public_port(state, request.protocol)),
        },
        backend,
        runtime: RuntimeMetadata {
            kind: RuntimeKind::from(state.config.daemon.engine),
            container_name,
            network_mode: "none".to_string(),
        },
        database: DatabaseIdentity {
            name: request.database,
            username: request.username,
        },
        route_key_sha256: (request.protocol == Protocol::Qdrant)
            .then(|| crate::protocols::qdrant::route_key_sha256(&request.password)),
        mariadb_native_password_sha1_stage2: (request.protocol == Protocol::Mariadb)
            .then(|| crate::protocols::mariadb::native_password_sha1_stage2_hex(&request.password)),
        mariadb_root_password,
        mysql_native_password_sha1_stage2: (request.protocol == Protocol::Mysql)
            .then(|| crate::protocols::mariadb::native_password_sha1_stage2_hex(&request.password)),
        mysql_root_password,
        mongodb_root_password,
        postgres_admin_password,
        tenant_password: Some(request.password),
        limits,
        image: None,
        database_version: None,
        created_at: now.clone(),
        updated_at: now,
    };

    state
        .manager
        .upsert(metadata.clone())
        .await
        .map_err(|error| {
            state.install_progress.fail_internal(
                &metadata.instance_id,
                "instance metadata persistence",
                &error,
            );
            ApiError::Runtime(format!(
                "created container but failed to persist instance metadata: {error}"
            ))
        })?;
    // IDs are normally unique, but clear any in-memory scanner history before
    // publishing a newly created instance defensively.
    state.soft_disk_limiter.remove(&metadata.instance_id).await;
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;

    tracing::info!(
        event = "audit instance_created",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        database = %metadata.database.name,
        username = %metadata.database.username,
    );

    state
        .install_progress
        .complete(&metadata.instance_id, "database instance is running");

    Ok(metadata)
}

pub(crate) enum ContainerLaunchError {
    Create(ApiError),
    AfterCreate(ApiError),
}

impl ContainerLaunchError {
    pub(crate) fn into_api_error(self) -> ApiError {
        match self {
            Self::Create(error) | Self::AfterCreate(error) => error,
        }
    }
}

pub(crate) async fn launch_container_from_spec<F, H, Fut>(
    state: &AppState,
    spec: &DockerInstanceSpec,
    protocol: Protocol,
    instance_id: &str,
    pull_progress: &F,
    report_install_progress: bool,
    after_start: H,
) -> Result<(), ContainerLaunchError>
where
    F: Fn(DockerImagePullProgress) + Send + Sync,
    H: FnOnce() -> Fut,
    Fut: Future<Output = Result<(), ApiError>>,
{
    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ContainerLaunchError::Create(ApiError::BadRequest(error.to_string())))?;
    paths
        .clear_socket_dir()
        .await
        .map_err(|error| ContainerLaunchError::Create(ApiError::Runtime(error.to_string())))?;
    if report_install_progress {
        state
            .install_progress
            .stage(instance_id, "create_container", "creating Docker container");
    }
    state
        .docker
        .create_with_progress(spec, pull_progress)
        .await
        .map_err(docker_error)
        .map_err(ContainerLaunchError::Create)?;

    if report_install_progress {
        state
            .install_progress
            .stage(instance_id, "start", "starting container");
    }
    state
        .docker
        .start(protocol, instance_id)
        .await
        .map_err(docker_error)
        .map_err(ContainerLaunchError::AfterCreate)?;

    after_start()
        .await
        .map_err(ContainerLaunchError::AfterCreate)?;

    if report_install_progress {
        state.install_progress.stage(
            instance_id,
            "healthcheck",
            "confirming one-time database startup readiness",
        );
    }
    if let Err(error) = state
        .docker
        .wait_until_ready(protocol, instance_id, Duration::from_secs(120))
        .await
    {
        return Err(ContainerLaunchError::AfterCreate(
            docker_error_with_logs(state, protocol, instance_id, error).await,
        ));
    }
    Ok(())
}

pub(crate) async fn provision_mariadb_tenant_user(
    state: &AppState,
    instance_id: &str,
    database: &str,
    username: &str,
    password: &str,
    root_password: &str,
) -> Result<(), ApiError> {
    wait_for_mariadb_localhost(state, instance_id).await?;
    let verifier = crate::protocols::mariadb::native_password_sha1_stage2_hex(password);
    let sql = databases::mariadb::provision::tenant_user_sql(database, username, &verifier)
        .map_err(|error| fail_bad_request(state, instance_id, error))?;
    let script = format!(
        "set -eu\nexport MYSQL_PWD={}\nprintf %s {} | mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -hlocalhost -uroot\n",
        sh_quote(root_password),
        sh_quote(&sql)
    );
    state
        .docker
        .exec_shell(Protocol::Mariadb, instance_id, &script)
        .await
        .map_err(|error| fail_runtime(state, instance_id, error))?;
    Ok(())
}

pub(crate) async fn provision_mysql_tenant_user(
    state: &AppState,
    instance_id: &str,
    database: &str,
    username: &str,
    password: &str,
    root_password: &str,
) -> Result<(), ApiError> {
    let root_password_secret = SecretString::from(root_password.to_string());
    mysql_hardening::verify_mysql_root_auth_with_timeout(
        state,
        instance_id,
        &root_password_secret,
        Duration::from_secs(120),
    )
    .await?;
    let sql = databases::mysql::provision::tenant_user_sql(database, username);
    mysql_hardening::execute_mysql_protected_sql(state, instance_id, &sql, password, root_password)
        .await
}

pub(crate) async fn provision_postgres_tenant_role(
    state: &AppState,
    instance_id: &str,
    database: &str,
    tenant_username: &str,
    tenant_password: &str,
    admin_password: &str,
) -> Result<(), ApiError> {
    databases::postgres::hardening::provision_tenant_role(
        &state.docker,
        instance_id,
        database,
        tenant_username,
        &SecretString::from(tenant_password.to_string()),
        &SecretString::from(admin_password.to_string()),
    )
    .await
    .map_err(|error| fail_runtime(state, instance_id, error))
}

pub(crate) async fn harden_postgres_instance_auth(
    state: &AppState,
    instance_id: &str,
    tenant_username: &str,
    tenant_password: &str,
    admin_password: &str,
) -> Result<bool, ApiError> {
    databases::postgres::hardening::harden_instance_auth(
        &state.docker,
        instance_id,
        tenant_username,
        &SecretString::from(tenant_password.to_string()),
        &SecretString::from(admin_password.to_string()),
    )
    .await
    .map_err(|error| fail_runtime(state, instance_id, error))
}

async fn wait_for_mariadb_localhost(state: &AppState, instance_id: &str) -> Result<(), ApiError> {
    state.install_progress.stage(
        instance_id,
        "readiness",
        "waiting for MariaDB local socket to become available",
    );
    wait_for_container_shell_command(
        state,
        Protocol::Mariadb,
        instance_id,
        "test \"$(cat /proc/1/comm)\" = mariadbd || exit 1; root_password=\"${DBE_MARIADB_ROOT_PASSWORD:-${MARIADB_ROOT_PASSWORD:-}}\"; MYSQL_PWD=\"$root_password\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -hlocalhost -u root -N -B -e 'SELECT 1' >/dev/null",
        Duration::from_secs(120),
    )
    .await
}

async fn wait_for_container_shell_command(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
    command: &str,
    timeout: Duration,
) -> Result<(), ApiError> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_error = String::new();
    while tokio::time::Instant::now() < deadline {
        match state
            .docker
            .exec_shell(protocol, instance_id, command)
            .await
        {
            Ok(_) => return Ok(()),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_secs(1)).await;
            }
        }
    }

    let message = format!("database local readiness did not succeed before timeout: {last_error}");
    state
        .install_progress
        .fail_internal(instance_id, "database readiness", &message);
    Err(ApiError::Runtime(message))
}

pub(crate) async fn provision_mongodb_tenant_user(
    state: &AppState,
    instance_id: &str,
    database: &str,
    username: &str,
    password: &str,
    root_password: &str,
) -> Result<(), ApiError> {
    wait_for_mongodb_localhost(state, instance_id).await?;
    let root_username = "dbe_root";
    let root_script =
        databases::mongodb::provision::create_root_user_script(root_username, root_password)
            .map_err(|error| fail_bad_request(state, instance_id, error))?;
    state
        .docker
        .exec(
            Protocol::Mongodb,
            instance_id,
            vec![
                "mongosh".to_string(),
                "--quiet".to_string(),
                "mongodb://127.0.0.1/admin?directConnection=true".to_string(),
                "--eval".to_string(),
                root_script,
            ],
        )
        .await
        .map_err(|error| fail_runtime(state, instance_id, error))?;

    let tenant_script =
        databases::mongodb::provision::create_user_script(database, username, password)
            .map_err(|error| fail_bad_request(state, instance_id, error))?;
    let uri = format!(
        "mongodb://{root_username}:{root_password}@127.0.0.1/admin?authSource=admin&directConnection=true"
    );
    state
        .docker
        .exec(
            Protocol::Mongodb,
            instance_id,
            vec![
                "mongosh".to_string(),
                "--quiet".to_string(),
                uri,
                "--eval".to_string(),
                tenant_script,
            ],
        )
        .await
        .map_err(|error| fail_runtime(state, instance_id, error))?;
    Ok(())
}

async fn wait_for_mongodb_localhost(state: &AppState, instance_id: &str) -> Result<(), ApiError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut last_error = String::new();
    while tokio::time::Instant::now() < deadline {
        match state
            .docker
            .exec(
                Protocol::Mongodb,
                instance_id,
                vec![
                    "mongosh".to_string(),
                    "--quiet".to_string(),
                    "mongodb://127.0.0.1/admin?directConnection=true".to_string(),
                    "--eval".to_string(),
                    "db.adminCommand({ ping: 1 }).ok".to_string(),
                ],
            )
            .await
        {
            Ok(_) => return Ok(()),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_secs(1)).await;
            }
        }
    }
    let message = format!("mongodb localhost bootstrap did not become ready: {last_error}");
    state
        .install_progress
        .fail_internal(instance_id, "mongodb bootstrap", &message);
    Err(ApiError::Runtime(message))
}

fn image_for_protocol(state: &AppState, protocol: Protocol) -> &str {
    match protocol {
        Protocol::Postgres => &state.config.images.postgres,
        Protocol::Redis => &state.config.images.redis,
        Protocol::Valkey => &state.config.images.valkey,
        Protocol::Mariadb => &state.config.images.mariadb,
        Protocol::Mysql => &state.config.images.mysql,
        Protocol::Mongodb => &state.config.images.mongodb,
        Protocol::Clickhouse => &state.config.images.clickhouse,
        Protocol::Qdrant => &state.config.images.qdrant,
    }
}

pub(crate) fn requested_or_configured_image(
    state: &AppState,
    request: &CreateInstanceRequest,
) -> Result<String, ApiError> {
    let image = request
        .image
        .as_deref()
        .map(validate_image)
        .transpose()?
        .map(str::to_string)
        .unwrap_or_else(|| image_for_protocol(state, request.protocol).to_string());
    ensure_image_allowed(state, request.protocol, &image)?;
    Ok(image)
}

fn fail_bad_request(
    state: &AppState,
    instance_id: &str,
    error: impl std::fmt::Display,
) -> ApiError {
    state
        .install_progress
        .fail_public(instance_id, "bad_request", error.to_string());
    ApiError::BadRequest(error.to_string())
}

fn fail_runtime(state: &AppState, instance_id: &str, error: impl std::fmt::Display) -> ApiError {
    state
        .install_progress
        .fail_internal(instance_id, "instance creation", &error);
    ApiError::Runtime(error.to_string())
}

async fn reject_duplicate_instance(
    state: &AppState,
    request: &CreateInstanceRequest,
) -> Result<(), ApiError> {
    if state.instances.get(&request.instance_id).await.is_some() {
        return Err(ApiError::Conflict(format!(
            "instance_id {} already exists",
            request.instance_id
        )));
    }

    let instances = state.instances.list().await;
    let route_exists = instances.iter().any(|metadata| match request.protocol {
        Protocol::Postgres
        | Protocol::Mariadb
        | Protocol::Mysql
        | Protocol::Mongodb
        | Protocol::Clickhouse => {
            metadata.protocol == request.protocol
                && metadata.database.username == request.username
                && metadata.database.name == request.database
        }
        Protocol::Qdrant => {
            let route_key_sha256 = crate::protocols::qdrant::route_key_sha256(&request.password);
            metadata.protocol == request.protocol
                && metadata.route_key_sha256.as_deref() == Some(route_key_sha256.as_str())
        }
        Protocol::Redis | Protocol::Valkey => {
            metadata.protocol == request.protocol && metadata.database.username == request.username
        }
    });

    if route_exists {
        return Err(ApiError::Conflict(format!(
            "{} route already exists for username {} and database {}; choose different credentials or delete the existing database first",
            request.protocol, request.username, request.database
        )));
    }

    Ok(())
}

async fn handle_stale_instance_resources(
    state: &AppState,
    request: &CreateInstanceRequest,
) -> Result<(), ApiError> {
    let mut stale_containers = Vec::new();
    for protocol in Protocol::ALL {
        if let Some(container) = state
            .docker
            .verified_managed_container_name(protocol, &request.instance_id)
            .await
            .map_err(docker_error)?
        {
            stale_containers.push((protocol, container));
        }
    }

    let paths = InstancePaths::new(&state.config.paths, &request.instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let stale_paths = stale_persistent_paths(&paths)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    if stale_containers.is_empty() && stale_paths.is_empty() {
        return Ok(());
    }

    if !request.purge_stale_resources {
        let resources = stale_containers
            .iter()
            .map(|(_, container)| format!("container {container}"))
            .chain(stale_paths.iter().cloned())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(stale_resources_conflict(request, resources));
    }

    let authorization = DestructiveActionPolicy::authorize(
        "stale resource purge",
        request
            .purge_stale_resources_confirmation
            .as_ref()
            .ok_or_else(|| {
                ApiError::BadRequest(
                    "stale resource purge requires purge_stale_resources_confirmation".to_string(),
                )
            })?,
    )?;

    let stale_container_count = stale_containers.len();
    for (protocol, _) in stale_containers {
        cleanup_created_container(state, protocol, &request.instance_id).await?;
    }
    if !stale_paths.is_empty() {
        cleanup_created_paths(state, &paths).await?;
    }
    tracing::warn!(
        event = "audit stale_instance_resources_purged",
        instance_id = %request.instance_id,
        protocol = %request.protocol,
        stale_container_count,
        stale_path_count = stale_paths.len(),
        reason = authorization.reason(),
        "explicitly purged stale resources before retrying instance creation"
    );
    Ok(())
}

fn stale_resources_conflict(request: &CreateInstanceRequest, resources: String) -> ApiError {
    ApiError::Conflict(format!(
        "stale resources already exist for instance_id {} and will not be reused with new credentials: {resources}. Recover the data manually, use a different instance_id, or explicitly retry creation with purge_stale_resources=true to irreversibly remove them",
        request.instance_id
    ))
}

async fn stale_persistent_paths(paths: &InstancePaths) -> Result<Vec<String>, std::io::Error> {
    let mut stale = Vec::new();
    for path in [
        &paths.data,
        &paths.logs,
        &paths.artifacts,
        &paths.exports,
        &paths.imports,
        &paths.backups,
        &paths.runtime_config,
    ] {
        if !path_has_entries(path).await? {
            continue;
        }
        stale.push(path.display().to_string());
    }
    for path in crate::api::instances::retained_instance_volume_paths(&paths.data).await? {
        stale.push(path.display().to_string());
    }
    Ok(stale)
}

async fn path_has_entries(path: &std::path::Path) -> Result<bool, std::io::Error> {
    let metadata = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    if !metadata.is_dir() {
        return Ok(true);
    }

    let mut entries = tokio::fs::read_dir(path).await?;
    Ok(entries.next_entry().await?.is_some())
}

async fn cleanup_created_container(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
) -> Result<(), ApiError> {
    if let Err(error) = state.docker.delete(protocol, instance_id).await {
        if error.is_not_found() {
            tracing::debug!(%instance_id, %protocol, "container already absent during create failure cleanup");
            return Ok(());
        }
        return Err(ApiError::Runtime(format!(
            "failed to clean up container after create failure: {error}"
        )));
    }
    Ok(())
}

struct CreateFailureCleanup<'a> {
    state: &'a AppState,
    protocol: Protocol,
    instance_id: String,
}

impl<'a> CreateFailureCleanup<'a> {
    fn new(state: &'a AppState, protocol: Protocol, instance_id: String) -> Self {
        Self {
            state,
            protocol,
            instance_id,
        }
    }

    async fn run(self, error: &ApiError) {
        self.state.install_progress.stage(
            &self.instance_id,
            "cleanup",
            "cleaning failed installation",
        );

        let cleanup_result = self.cleanup_resources().await;
        if cleanup_result.is_ok() {
            if let Err(cleanup_error) = self.state.manager.delete(&self.instance_id).await {
                tracing::warn!(
                    error = %cleanup_error,
                    instance_id = %self.instance_id,
                    "failed to delete metadata after create failure"
                );
            } else {
                self.state.instances.remove(&self.instance_id).await;
                self.state.soft_disk_limiter.remove(&self.instance_id).await;
            }
        }

        self.state
            .install_progress
            .fail_api_error(&self.instance_id, "instance creation", error);
        match cleanup_result {
            Ok(()) => tracing::info!(
                event = "audit instance_create_failed_cleaned",
                instance_id = %self.instance_id,
                protocol = %self.protocol,
                error = %error,
            ),
            Err(cleanup_error) => tracing::error!(
                event = "audit instance_create_cleanup_incomplete",
                instance_id = %self.instance_id,
                protocol = %self.protocol,
                error = %error,
                cleanup_error = %cleanup_error,
            ),
        }
    }

    async fn cleanup_resources(&self) -> Result<(), ApiError> {
        cleanup_created_container(self.state, self.protocol, &self.instance_id).await?;
        let paths = InstancePaths::new(&self.state.config.paths, &self.instance_id)
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        cleanup_created_paths(self.state, &paths).await
    }
}

async fn cleanup_created_paths(state: &AppState, paths: &InstancePaths) -> Result<(), ApiError> {
    crate::api::instances::purge_instance_paths(state, &paths.instance_id).await
}

pub(crate) async fn docker_error_with_logs(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
    error: crate::runtime::docker::DockerError,
) -> ApiError {
    let logs = match state.docker.logs(protocol, instance_id, None).await {
        Ok(output) => {
            let combined = format!("{}{}", output.stdout, output.stderr);
            summarize_failure_logs(&redaction::redact_connection_url(&combined), 4_000)
        }
        Err(log_error) => format!("failed to read container logs: {log_error}"),
    };

    ApiError::Runtime(format!("{error}; recent container logs: {logs}"))
}

fn public_port(state: &AppState, protocol: Protocol) -> u16 {
    let bind = match protocol {
        Protocol::Postgres => &state.config.postgres.bind,
        Protocol::Redis => &state.config.redis.bind,
        Protocol::Valkey => &state.config.valkey.bind,
        Protocol::Mariadb => &state.config.mariadb.bind,
        Protocol::Mysql => &state.config.mysql.bind,
        Protocol::Mongodb => &state.config.mongodb.bind,
        Protocol::Clickhouse => &state.config.clickhouse.bind,
        Protocol::Qdrant => &state.config.qdrant.bind,
    };
    bind.rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .unwrap_or_else(|| protocol.default_container_port())
}

pub(crate) fn protocol_pids_limit(state: &AppState, protocol: Protocol) -> i64 {
    let overrides = &state.config.security.pids_limits;
    match protocol {
        Protocol::Postgres => overrides.postgres,
        Protocol::Redis => overrides.redis,
        Protocol::Valkey => overrides.valkey,
        Protocol::Mariadb => overrides.mariadb,
        Protocol::Mysql => overrides.mysql,
        Protocol::Mongodb => overrides.mongodb,
        Protocol::Clickhouse => overrides.clickhouse,
        Protocol::Qdrant => overrides.qdrant,
    }
    .unwrap_or(state.config.security.pids_limit)
}

pub(crate) fn backend_endpoint_for_instance(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
) -> Result<BackendEndpoint, ApiError> {
    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    Ok(BackendEndpoint::UnixSocket {
        socket_path: crate::shared::backend::backend_socket_path(&paths.sockets, protocol)
            .display()
            .to_string(),
    })
}

#[cfg(test)]
mod tests;
