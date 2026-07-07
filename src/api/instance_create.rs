use std::{future::Future, time::Duration};

use secrecy::SecretString;
use tokio::{net::TcpListener, time::sleep};

use crate::{
    api::{
        handlers::ApiError,
        instance_requests::{CreateInstanceRequest, limits_from_request, validate_create_request},
        instances::docker_error,
        routes::AppState,
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
    runtime::docker::{DockerImagePullProgress, DockerInstanceSpec},
    shared::{
        backend::BackendEndpoint, logs::truncate_log_tail, protocol::Protocol, shell::sh_quote,
        time::now_rfc3339,
    },
};

pub async fn create_instance_from_request(
    state: &AppState,
    request: CreateInstanceRequest,
) -> Result<InstanceMetadata, ApiError> {
    validate_create_request(&request)?;
    reject_duplicate_instance(state, &request).await?;
    reject_stale_instance_resources(state, &request).await?;

    let cleanup = CreateFailureCleanup::new(state, request.protocol, request.instance_id.clone());
    match create_instance_from_validated_request(state, request).await {
        Ok(metadata) => Ok(metadata),
        Err(error) => {
            cleanup.run(&error).await;
            Err(error)
        }
    }
}

async fn create_instance_from_validated_request(
    state: &AppState,
    request: CreateInstanceRequest,
) -> Result<InstanceMetadata, ApiError> {
    let image = image_for_protocol(state, request.protocol).to_string();
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
    let mariadb_root_password = (request.protocol == Protocol::Mariadb)
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
        Protocol::Postgres
        | Protocol::Mariadb
        | Protocol::Mongodb
        | Protocol::Clickhouse
        | Protocol::Qdrant => {}
    }
    state.install_progress.stage(
        &request.instance_id,
        "permissions",
        "applying container file ownership",
    );
    let container_user = if let Some(user) = state
        .docker
        .rootless_podman_container_user(request.protocol)
    {
        tracing::debug!(
            instance_id = request.instance_id,
            protocol = %request.protocol,
            user,
            "rootless podman detected; using protocol-specific container user for bind mount ownership mapping"
        );
        user.to_string()
    } else {
        paths
            .apply_container_owner()
            .await
            .map_err(|error| fail_runtime(state, &request.instance_id, error))?;
        paths
            .container_user()
            .await
            .map_err(|error| fail_runtime(state, &request.instance_id, error))?
    };

    state
        .install_progress
        .stage(&request.instance_id, "disk_limit", "applying disk limit");
    let disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root());
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
            &state.config.images.postgres,
            &request.database,
            &request.username,
            password,
            container_data_path.clone(),
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Redis => databases::redis::docker::instance_spec(
            &request.instance_id,
            &state.config.images.redis,
            container_data_path.clone(),
            paths.logs.clone(),
        ),
        Protocol::Mariadb => databases::mariadb::docker::instance_spec(
            &request.instance_id,
            &state.config.images.mariadb,
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
        Protocol::Mongodb => databases::mongodb::docker::instance_spec(
            &request.instance_id,
            &state.config.images.mongodb,
            &request.database,
            &request.username,
            password,
            container_data_path.clone(),
            paths.logs.clone(),
        ),
        Protocol::Clickhouse => {
            let hosted_config_path =
                databases::clickhouse::docker::write_hosted_config(&paths.logs)
                    .await
                    .map_err(|error| fail_runtime(state, &request.instance_id, error))?;
            databases::clickhouse::docker::instance_spec(
                &request.instance_id,
                &state.config.images.clickhouse,
                &request.database,
                &request.username,
                password,
                container_data_path,
                paths.logs.clone(),
                hosted_config_path,
            )
        }
        Protocol::Qdrant => databases::qdrant::docker::instance_spec(
            &request.instance_id,
            &state.config.images.qdrant,
            password,
            container_data_path,
            paths.logs.clone(),
        ),
    };
    spec.project_id = request.project_id.clone();
    spec.user = Some(container_user);
    spec.cpu_cores = limits.cpu_cores;
    spec.memory_mib = limits.memory_mib;
    spec.disk_mib = limits.disk_mib;
    spec.pids_limit = Some(protocol_pids_limit(state, request.protocol));
    let rootless_podman_backend_port = if state.docker.uses_rootless_podman() {
        let port = allocate_loopback_backend_port()
            .await
            .map_err(|error| fail_runtime(state, &request.instance_id, error))?;
        spec.public_backend_port = Some(port);
        tracing::debug!(
            instance_id = request.instance_id,
            port,
            "allocated rootless podman loopback backend port"
        );
        Some(port)
    } else {
        None
    };

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
        match &error {
            ContainerLaunchError::Create(_) => cleanup_created_paths(state, &paths).await,
            ContainerLaunchError::AfterCreate(_) => {
                cleanup_created_resources(state, request.protocol, &request.instance_id, &paths)
                    .await;
            }
        }
        let api_error = error.into_api_error();
        state
            .install_progress
            .fail(&request.instance_id, api_error.to_string());
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
            cleanup_created_resources(state, request.protocol, &request.instance_id, &paths).await;
            state
                .install_progress
                .fail(&request.instance_id, error.to_string());
            return Err(error);
        }
    }
    state.install_progress.stage(
        &request.instance_id,
        "network",
        "resolving container network endpoint",
    );
    let backend = match backend_endpoint_for_instance(
        state,
        request.protocol,
        &request.instance_id,
        rootless_podman_backend_port,
    )
    .await
    {
        Ok(backend) => backend,
        Err(error) => {
            cleanup_created_resources(state, request.protocol, &request.instance_id, &paths).await;
            state
                .install_progress
                .fail(&request.instance_id, error.to_string());
            return Err(error);
        }
    };

    let now = now_rfc3339();
    let metadata = InstanceMetadata {
        schema_version: SCHEMA_VERSION,
        instance_id: request.instance_id,
        protocol: request.protocol,
        status: InstanceStatus::Running,
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
            network: state.config.daemon.network.clone(),
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
        limits,
        created_at: now.clone(),
        updated_at: now,
    };

    state
        .manager
        .upsert(metadata.clone())
        .await
        .map_err(|error| {
            state
                .install_progress
                .fail(&metadata.instance_id, error.to_string());
            ApiError::Runtime(format!(
                "created container but failed to persist instance metadata: {error}"
            ))
        })?;

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
            "waiting for database healthcheck",
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
    if state.docker.uses_rootless_podman() {
        wait_for_rootless_podman_service(state, protocol, instance_id)
            .await
            .map_err(ContainerLaunchError::AfterCreate)?;
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
        "set -eu\nexport MYSQL_PWD={}\nprintf %s {} | mariadb --protocol=socket -uroot\n",
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

pub(crate) async fn wait_for_rootless_podman_service(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
) -> Result<(), ApiError> {
    let (message, command) = match protocol {
        Protocol::Postgres => (
            "waiting for PostgreSQL to accept local connections",
            "pg_isready -h 127.0.0.1 -U \"$POSTGRES_USER\"",
        ),
        Protocol::Redis => (
            "waiting for Redis to accept local connections",
            "redis-cli --user dbe_health -a healthcheck --no-auth-warning ping",
        ),
        Protocol::Mariadb => (
            "waiting for MariaDB to accept local connections",
            "mariadb-admin ping -h 127.0.0.1 -u \"$MARIADB_USER\" -p\"$MARIADB_PASSWORD\"",
        ),
        Protocol::Mongodb => return wait_for_mongodb_localhost(state, instance_id).await,
        Protocol::Clickhouse => (
            "waiting for ClickHouse to accept local connections",
            "clickhouse-client --user \"$CLICKHOUSE_USER\" --password \"$CLICKHOUSE_PASSWORD\" --database \"$CLICKHOUSE_DB\" --query 'SELECT 1'",
        ),
        Protocol::Qdrant => return Ok(()),
    };

    state
        .install_progress
        .stage(instance_id, "readiness", message);
    wait_for_container_shell_command(
        state,
        protocol,
        instance_id,
        command,
        Duration::from_secs(120),
    )
    .await
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
        "mariadb-admin ping --protocol=socket -u root -p\"$MARIADB_ROOT_PASSWORD\"",
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
    state.install_progress.fail(instance_id, &message);
    Err(ApiError::Runtime(message))
}

async fn provision_mongodb_tenant_user(
    state: &AppState,
    instance_id: &str,
    database: &str,
    username: &str,
    password: &str,
) -> Result<(), ApiError> {
    wait_for_mongodb_localhost(state, instance_id).await?;
    let root_username = "dbe_root";
    let root_password = uuid::Uuid::new_v4().to_string();
    let root_script =
        databases::mongodb::provision::create_root_user_script(root_username, &root_password)
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
    state.install_progress.fail(instance_id, &message);
    Err(ApiError::Runtime(message))
}

fn image_for_protocol(state: &AppState, protocol: Protocol) -> &str {
    match protocol {
        Protocol::Postgres => &state.config.images.postgres,
        Protocol::Redis => &state.config.images.redis,
        Protocol::Mariadb => &state.config.images.mariadb,
        Protocol::Mongodb => &state.config.images.mongodb,
        Protocol::Clickhouse => &state.config.images.clickhouse,
        Protocol::Qdrant => &state.config.images.qdrant,
    }
}

fn fail_bad_request(
    state: &AppState,
    instance_id: &str,
    error: impl std::fmt::Display,
) -> ApiError {
    state.install_progress.fail(instance_id, error.to_string());
    ApiError::BadRequest(error.to_string())
}

fn fail_runtime(state: &AppState, instance_id: &str, error: impl std::fmt::Display) -> ApiError {
    state.install_progress.fail(instance_id, error.to_string());
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
        Protocol::Postgres | Protocol::Mariadb | Protocol::Mongodb | Protocol::Clickhouse => {
            metadata.protocol == request.protocol
                && metadata.database.username == request.username
                && metadata.database.name == request.database
        }
        Protocol::Qdrant => {
            let route_key_sha256 = crate::protocols::qdrant::route_key_sha256(&request.password);
            metadata.protocol == request.protocol
                && (metadata.route_key_sha256.as_deref() == Some(route_key_sha256.as_str())
                    || (metadata.database.username == request.username
                        && metadata.database.name == request.database))
        }
        Protocol::Redis => {
            metadata.protocol == request.protocol && metadata.database.username == request.username
        }
    });

    if route_exists {
        return Err(ApiError::Conflict(format!(
            "{} route already exists for username {} and database {}",
            request.protocol, request.username, request.database
        )));
    }

    Ok(())
}

async fn reject_stale_instance_resources(
    state: &AppState,
    request: &CreateInstanceRequest,
) -> Result<(), ApiError> {
    let container_name = state
        .docker
        .container_name(request.protocol, &request.instance_id)
        .map_err(docker_error)?;
    match state
        .docker
        .inspect(request.protocol, &request.instance_id)
        .await
    {
        Ok(_) => {
            return Err(ApiError::Conflict(format!(
                "stale container {container_name} already exists for instance_id {}; delete it with purge=true before recreating this database",
                request.instance_id
            )));
        }
        Err(error) if error.is_not_found() => {}
        Err(error) => return Err(docker_error(error)),
    }

    let paths = InstancePaths::new(&state.config.paths, &request.instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let stale_paths = stale_persistent_paths(&paths)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    if stale_paths.is_empty() {
        return Ok(());
    }

    Err(ApiError::Conflict(format!(
        "stale persistent files already exist for instance_id {}; DBE will not reuse them with new credentials because that can break database auth. Purge the old instance first or restore/import the data into a new instance. Stale paths: {}",
        request.instance_id,
        stale_paths.join(", ")
    )))
}

async fn stale_persistent_paths(paths: &InstancePaths) -> Result<Vec<String>, std::io::Error> {
    let mut stale = Vec::new();
    for path in [&paths.data, &paths.logs, &paths.artifacts] {
        if !path_has_entries(path).await? {
            continue;
        }
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

async fn cleanup_created_container(state: &AppState, protocol: Protocol, instance_id: &str) {
    if let Err(error) = state.docker.delete(protocol, instance_id).await {
        if error.is_not_found() {
            tracing::debug!(%instance_id, %protocol, "container already absent during create failure cleanup");
            return;
        }
        tracing::warn!(%error, %instance_id, %protocol, "failed to clean up container after create failure");
    }
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

        if let Err(cleanup_error) = self.state.manager.delete(&self.instance_id).await {
            tracing::warn!(
                error = %cleanup_error,
                instance_id = %self.instance_id,
                "failed to delete metadata after create failure"
            );
        }
        self.state.instances.remove(&self.instance_id).await;

        cleanup_created_container(self.state, self.protocol, &self.instance_id).await;
        match InstancePaths::new(&self.state.config.paths, &self.instance_id) {
            Ok(paths) => cleanup_created_paths(self.state, &paths).await,
            Err(cleanup_error) => {
                tracing::warn!(
                    error = %cleanup_error,
                    instance_id = %self.instance_id,
                    "failed to resolve instance paths after create failure"
                );
            }
        }

        self.state.install_progress.fail(
            &self.instance_id,
            format!("{error}; failed installation was cleaned up"),
        );
        tracing::info!(
            event = "audit instance_create_failed_cleaned",
            instance_id = %self.instance_id,
            protocol = %self.protocol,
            error = %error,
        );
    }
}

async fn cleanup_created_resources(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
    paths: &InstancePaths,
) {
    cleanup_created_container(state, protocol, instance_id).await;
    cleanup_created_paths(state, paths).await;
}

async fn cleanup_created_paths(state: &AppState, paths: &InstancePaths) {
    if let Err(error) =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
            .purge_instance_data(&paths.data)
            .await
    {
        tracing::warn!(
            %error,
            instance_id = %paths.instance_id,
            "failed to purge instance data after create failure"
        );
    }

    for path in [&paths.data, &paths.logs, &paths.sockets, &paths.artifacts] {
        match tokio::fs::remove_dir_all(path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(
                    %error,
                    instance_id = %paths.instance_id,
                    path = %path.display(),
                    "failed to remove instance path after create failure"
                );
            }
        }
    }
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
            truncate_log_tail(combined.trim(), 4_000)
        }
        Err(log_error) => format!("failed to read container logs: {log_error}"),
    };

    ApiError::Runtime(format!("{error}; recent container logs: {logs}"))
}

fn public_port(state: &AppState, protocol: Protocol) -> u16 {
    let bind = match protocol {
        Protocol::Postgres => &state.config.postgres.bind,
        Protocol::Redis => &state.config.redis.bind,
        Protocol::Mariadb => &state.config.mariadb.bind,
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
        Protocol::Mariadb => overrides.mariadb,
        Protocol::Mongodb => overrides.mongodb,
        Protocol::Clickhouse => overrides.clickhouse,
        Protocol::Qdrant => overrides.qdrant,
    }
    .unwrap_or(state.config.security.pids_limit)
}

pub(crate) async fn allocate_loopback_backend_port() -> Result<u16, std::io::Error> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

pub(crate) async fn backend_endpoint_for_instance(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
    rootless_podman_backend_port: Option<u16>,
) -> Result<BackendEndpoint, ApiError> {
    if state.docker.uses_rootless_podman() {
        let port = rootless_podman_backend_port.ok_or_else(|| {
            ApiError::Runtime("rootless podman backend port was not allocated".to_string())
        })?;
        return Ok(BackendEndpoint::DockerTcp {
            host: "127.0.0.1".to_string(),
            port,
        });
    }

    let backend_host = state
        .docker
        .container_ip(protocol, instance_id)
        .await
        .map_err(docker_error)?;
    Ok(BackendEndpoint::DockerTcp {
        host: backend_host,
        port: protocol.default_container_port(),
    })
}
