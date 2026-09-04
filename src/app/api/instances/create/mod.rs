use std::{future::Future, time::Duration};

use secrecy::SecretString;
use tokio::time::sleep;

use crate::{
    api::{
        http::{policy::DestructiveActionPolicy, response::ApiError, router::AppState},
        instances::{
            docker_error,
            images::{check_image_allowed, validate_image},
            requests::{
                CreateInstanceRequest, limits_from_request, validate_create_config,
                validate_create_request,
            },
        },
        monitoring::resources::{read_host_cpu_cores, read_host_disk, read_host_memory},
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
    runtime::docker::{DockerImagePullProgress, DockerInstanceSpec, DockerRuntime, ExecRecovery},
    shared::{
        backend::BackendEndpoint,
        limits::{bytes_to_mib_ceil, mib_to_bytes},
        logs::summarize_failure_logs,
        protocol::Protocol,
        redaction,
        shell::sh_quote,
        time::now_rfc3339,
    },
};

pub(crate) mod dedicated;
mod mongodb;
mod mysql_hardening;
mod shared;

pub(crate) use dedicated::{
    attest as attest_dedicated_target, build as build_dedicated_target,
    launch as launch_dedicated_target,
};
pub(crate) use shared::{
    build_shared_metadata, claim_runtime as claim_shared_runtime,
    destroy_empty_runtime as destroy_empty_shared_runtime,
};

pub(crate) use mongodb::bootstrap_root as bootstrap_mongodb_root;
pub(crate) use mongodb::provision_tenant as provision_mongodb_tenant_user;

#[cfg(test)]
use mysql_hardening::failed_auth_metadata;
pub(crate) use mysql_hardening::{
    harden_mysql_accounts, harden_mysql_tenant_auth, verify_mysql_root_auth,
};

pub async fn create_instance_from_request(
    state: &AppState,
    request: CreateInstanceRequest,
) -> Result<InstanceMetadata, ApiError> {
    validate_create_request(&request)?;
    validate_create_config(&state.config, &request)?;
    if request.deployment_mode == crate::placement::DeploymentMode::Shared
        && !state.gateway_supervisor.is_ready()
    {
        return Err(ApiError::ServiceUnavailable(
            "shared tenant creation is unavailable until database gateway recovery completes"
                .to_string(),
        ));
    }
    let creation = state.instance_locks.lock_creation().await;
    let _operation = state.instance_locks.lock(&request.instance_id).await;
    reject_duplicate_instance(state, &request).await?;
    handle_stale_instance_resources(state, &request).await?;
    let requested_limits = request
        .limits
        .as_ref()
        .map(limits_from_request)
        .unwrap_or_default();
    if request.deployment_mode == crate::placement::DeploymentMode::Shared {
        return shared::create(state, request, creation).await;
    }
    enforce_node_allocation_policy(state, &requested_limits, None).await?;

    let cleanup = CreateFailureCleanup::new(state, request.protocol, request.instance_id.clone());
    match dedicated::create(state, request).await {
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
        paths.apply_rootless_owner(uid, gid).await?;
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

    let runtimes = state.placements.list().await.map_err(|error| {
        ApiError::Runtime(format!("failed to load runtime allocation: {error}"))
    })?;
    let allocated = crate::placement::policy::sum_runtime_limits(
        runtimes.iter().map(|runtime| &runtime.limits),
    );
    let allocated_cpu_cores = check_cpu.then_some(allocated.cpu_cores);
    let allocated_memory_bytes = check_memory.then_some(mib_to_bytes(allocated.memory_mib));
    let allocated_disk_bytes = check_disk.then_some(mib_to_bytes(allocated.disk_mib));
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
            allocation.memory_allocation_cap_bytes(host.total_bytes),
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
            allocation.disk_allocation_cap_bytes(host.total_bytes),
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
        return Err(capacity_unavailable(
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

fn capacity_unavailable(
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
        "set -eu\nprintf %s {} | MYSQL_PWD=\"$DBE_MARIADB_ROOT_PASSWORD\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -hlocalhost -uroot\n",
        sh_quote(&sql)
    );
    let root_password = SecretString::from(root_password.to_string());
    state
        .docker
        .exec_shell_with_secrets(
            Protocol::Mariadb,
            instance_id,
            &script,
            &[("DBE_MARIADB_ROOT_PASSWORD", &root_password)],
        )
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
    mysql_hardening::probe_mysql_root_auth(
        state,
        instance_id,
        &root_password_secret,
        Duration::from_secs(120),
    )
    .await?;
    let sql = databases::mysql::provision::tenant_user_sql(database, username);
    mysql_hardening::run_protected_mysql_sql(state, instance_id, &sql, password, root_password)
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
        ExecRecovery::RestartRuntime,
    )
    .await
    .map_err(|error| fail_runtime(state, instance_id, error))
}

pub(crate) async fn harden_postgres_instance_auth(
    state: &AppState,
    instance_id: &str,
    database: &str,
    tenant_username: &str,
    tenant_password: &str,
    admin_password: &str,
) -> Result<bool, ApiError> {
    let metadata = state.instances.get(instance_id).await.filter(|metadata| {
        metadata.protocol == Protocol::Postgres
            && metadata.database.name == database
            && metadata.database.username == tenant_username
            && metadata.tenant_password.as_deref() == Some(tenant_password)
            && metadata.postgres_admin_password.as_deref() == Some(admin_password)
    });
    let attestation = if let Some(metadata) = metadata.as_ref() {
        match crate::instances::auth_hardening::begin_attestation(
            &state.manager,
            &state.docker,
            metadata,
        )
        .await
        {
            Ok(check) if check.current => return Ok(false),
            Ok(check) => {
                if let Some(error) = check.cache_warning.as_deref() {
                    tracing::warn!(
                        event = "audit auth_hardening_attestation_check_failed",
                        instance_id,
                        protocol = %Protocol::Postgres,
                        %error,
                        "could not validate the cached hardening attestation; running full PostgreSQL hardening"
                    );
                }
                Some(check)
            }
            Err(error) => return Err(fail_runtime(state, instance_id, error)),
        }
    } else {
        None
    };
    let changed = databases::postgres::hardening::harden_instance_auth(
        &state.docker,
        instance_id,
        database,
        tenant_username,
        &SecretString::from(tenant_password.to_string()),
        &SecretString::from(admin_password.to_string()),
        ExecRecovery::RestartRuntime,
    )
    .await
    .map_err(|error| fail_runtime(state, instance_id, error))?;
    if let (Some(metadata), Some(attestation)) = (metadata.as_ref(), attestation.as_ref())
        && let Err(error) = crate::instances::auth_hardening::complete_attestation(
            &state.manager,
            &state.docker,
            metadata,
            attestation.generation(),
        )
        .await
    {
        if error.is_storage() {
            tracing::warn!(
                event = "audit auth_hardening_attestation_write_failed",
                instance_id,
                protocol = %Protocol::Postgres,
                %error,
                "PostgreSQL hardening succeeded, but its optimization attestation could not be persisted"
            );
        } else {
            return Err(fail_runtime(state, instance_id, error));
        }
    }
    Ok(changed)
}

async fn wait_for_mariadb_localhost(state: &AppState, instance_id: &str) -> Result<(), ApiError> {
    state.install_progress.stage(
        instance_id,
        "readiness",
        "waiting for MariaDB local socket to become available",
    );
    wait_for_shell_command(
        state,
        Protocol::Mariadb,
        instance_id,
        "test \"$(cat /proc/1/comm)\" = mariadbd || exit 1; root_password=\"${DBE_MARIADB_ROOT_PASSWORD:-${MARIADB_ROOT_PASSWORD:-}}\"; MYSQL_PWD=\"$root_password\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -hlocalhost -u root -N -B -e 'SELECT 1' >/dev/null",
        Duration::from_secs(120),
    )
    .await
}

async fn wait_for_shell_command(
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

pub(crate) fn resolve_image(
    state: &AppState,
    request: &CreateInstanceRequest,
) -> Result<String, ApiError> {
    let image = request
        .image
        .as_deref()
        .map(validate_image)
        .transpose()?
        .map(str::to_string)
        .unwrap_or_else(|| {
            state
                .config
                .images
                .configured_for_protocol(request.protocol)
                .to_string()
        });
    check_image_allowed(state, request.protocol, &image)?;
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

    // Instance ids and physical runtime ids share container and filesystem
    // namespaces. A generated shared-pool id must therefore never be treated
    // as an unowned, stale instance id: an explicitly authorized stale purge
    // would otherwise be able to remove a live pool before creation reaches
    // the metadata transaction that rejects the collision.
    if state
        .placements
        .get(&request.instance_id)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?
        .is_some()
    {
        return Err(ApiError::Conflict(format!(
            "instance_id {} is already reserved by a managed database runtime",
            request.instance_id
        )));
    }
    if state
        .placements
        .get_reservation(&request.instance_id)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?
        .is_some()
    {
        return Err(ApiError::Conflict(format!(
            "instance_id {} is already reserved by an unfinished shared tenant operation",
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
            let route_key_sha256 = crate::protocols::qdrant::route_key_fingerprint(
                state.config.websocket_jwt_secret(),
                &request.password,
            );
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

pub(crate) fn backend_endpoint(
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
