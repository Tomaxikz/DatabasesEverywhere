use std::{future::Future, time::Duration};

use secrecy::SecretString;
use tokio::time::sleep;

use crate::{
    api::{
        api_response::ApiError,
        images::{ensure_image_allowed, validate_image},
        instance_requests::{CreateInstanceRequest, limits_from_request, validate_create_request},
        instances::docker_error,
        routes::AppState,
        security_policy::DestructiveActionPolicy,
    },
    databases,
    disk::DiskLimiter,
    instances::{
        manager::InstanceManager,
        metadata::{
            DatabaseIdentity, InstanceMetadata, InstanceStatus, PublicEndpoint, RuntimeKind,
            RuntimeMetadata, SCHEMA_VERSION,
        },
        paths::InstancePaths,
    },
    runtime::docker::{DockerError, DockerImagePullProgress, DockerInstanceSpec, DockerRuntime},
    shared::{
        backend::BackendEndpoint, logs::summarize_failure_logs, protocol::Protocol, redaction,
        shell::sh_quote, time::now_rfc3339,
    },
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
    let mariadb_root_password = (request.protocol == Protocol::Mariadb)
        .then(|| format!("dbe-root-{}", uuid::Uuid::new_v4()));
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
            &image,
            &request.database,
            &request.username,
            password,
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
        mongodb_root_password,
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

pub(crate) async fn provision_postgres_tenant_role(
    state: &AppState,
    instance_id: &str,
    database: &str,
    tenant_username: &str,
) -> Result<(), ApiError> {
    let script = postgres_tenant_provision_script(database, tenant_username);
    let output = state
        .docker
        .exec_shell(Protocol::Postgres, instance_id, &script)
        .await
        .map_err(|error| fail_runtime(state, instance_id, error))?;
    match output.stdout.lines().last() {
        Some("provisioned") => Ok(()),
        Some("legacy_bootstrap_superuser") => Err(fail_runtime(
            state,
            instance_id,
            DockerError::LegacyPostgresBootstrapSuperuser {
                instance_id: instance_id.to_string(),
                username: tenant_username.to_string(),
            },
        )),
        _ => Err(fail_runtime(
            state,
            instance_id,
            DockerError::UnexpectedPostgresProvisioningOutput {
                instance_id: instance_id.to_string(),
            },
        )),
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PostgresRoleHardeningSummary {
    pub checked: usize,
    pub hardened: usize,
}

pub(crate) async fn harden_postgres_roles_on_boot(
    manager: &InstanceManager,
    docker: &DockerRuntime,
    instance_locks: &crate::instances::locks::InstanceLocks,
) -> Result<PostgresRoleHardeningSummary, DockerError> {
    let instances = manager.store().list().await;
    let mut checked = 0_usize;
    let mut hardened = 0_usize;
    for snapshot in instances {
        if snapshot.protocol != Protocol::Postgres {
            continue;
        }
        let _operation = instance_locks.lock(&snapshot.instance_id).await;
        let Some(metadata) = manager.store().get(&snapshot.instance_id).await else {
            continue;
        };
        if metadata.protocol != Protocol::Postgres || metadata.status != InstanceStatus::Running {
            continue;
        }
        checked += 1;
        if ensure_postgres_tenant_role_restricted(
            docker,
            &metadata.instance_id,
            &metadata.database.username,
        )
        .await?
        {
            hardened += 1;
        }
    }
    Ok(PostgresRoleHardeningSummary { checked, hardened })
}

async fn ensure_postgres_tenant_role_restricted(
    docker: &DockerRuntime,
    instance_id: &str,
    tenant_username: &str,
) -> Result<bool, DockerError> {
    let script = postgres_tenant_hardening_script(tenant_username);
    let output = docker
        .exec_shell(Protocol::Postgres, instance_id, &script)
        .await?;
    match output.stdout.lines().last() {
        Some("hardened") => Ok(true),
        Some("already_restricted") => Ok(false),
        Some("legacy_bootstrap_superuser") => Err(DockerError::LegacyPostgresBootstrapSuperuser {
            instance_id: instance_id.to_string(),
            username: tenant_username.to_string(),
        }),
        Some("missing_tenant_role") => Err(DockerError::MissingPostgresTenantRole {
            instance_id: instance_id.to_string(),
            username: tenant_username.to_string(),
        }),
        _ => Err(DockerError::UnexpectedPostgresProvisioningOutput {
            instance_id: instance_id.to_string(),
        }),
    }
}

fn postgres_tenant_provision_script(database: &str, tenant_username: &str) -> String {
    let role_state = databases::postgres::provision::tenant_role_state_sql(tenant_username);
    let provision_role =
        databases::postgres::provision::provision_tenant_role_sql(database, tenant_username);
    format!(
        "set -eu\nadmin_user=$POSTGRES_USER\nif ! psql -U \"$admin_user\" -d \"$POSTGRES_DB\" -Atqc 'SELECT 1' >/dev/null 2>&1; then\n  admin_user=${{DBE_POSTGRES_USER:-$POSTGRES_USER}}\nfi\nrole_state=$(psql -U \"$admin_user\" -d \"$POSTGRES_DB\" -Atq -c {})\ncase \"$role_state\" in\n  10:*) printf 'legacy_bootstrap_superuser\\n'; exit 0 ;;\nesac\nprintf %s {} | psql -U \"$admin_user\" -d \"$POSTGRES_DB\" -v ON_ERROR_STOP=1 -v tenant_password=\"$DBE_POSTGRES_PASSWORD\"\nprintf 'provisioned\\n'\n",
        sh_quote(&role_state),
        sh_quote(&provision_role),
    )
}

fn postgres_tenant_hardening_script(tenant_username: &str) -> String {
    let role_state = databases::postgres::provision::tenant_role_state_sql(tenant_username);
    let restrict_role = databases::postgres::provision::restrict_tenant_role_sql(tenant_username);
    format!(
        "set -eu\nadmin_user=$POSTGRES_USER\nif ! psql -U \"$admin_user\" -d \"$POSTGRES_DB\" -Atqc 'SELECT 1' >/dev/null 2>&1; then\n  admin_user=${{DBE_POSTGRES_USER:-$POSTGRES_USER}}\nfi\nrole_state=$(psql -U \"$admin_user\" -d \"$POSTGRES_DB\" -Atq -c {})\ncase \"$role_state\" in\n  '') printf 'missing_tenant_role\\n' ;;\n  10:*) printf 'legacy_bootstrap_superuser\\n' ;;\n  *:1) printf %s {} | psql -U \"$admin_user\" -d \"$POSTGRES_DB\" -v ON_ERROR_STOP=1; printf 'hardened\\n' ;;\n  *) printf 'already_restricted\\n' ;;\nesac\n",
        sh_quote(&role_state),
        sh_quote(&restrict_role),
    )
}

pub(crate) async fn wait_for_rootless_podman_service(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
) -> Result<(), ApiError> {
    let (message, command) = match protocol {
        Protocol::Postgres => (
            "waiting for PostgreSQL to accept local connections",
            "psql -X -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -Atqc 'SELECT 1' >/dev/null",
        ),
        Protocol::Redis => (
            "waiting for Redis to accept local connections",
            "redis-cli -s /run/dbev/redis.sock --user dbe_health -a healthcheck --no-auth-warning ping",
        ),
        Protocol::Mariadb => (
            "waiting for MariaDB to accept local connections",
            "mariadb-admin ping --protocol=socket --socket=/run/mysqld/mysqld.sock -u \"$MARIADB_USER\" -p\"$MARIADB_PASSWORD\"",
        ),
        Protocol::Mongodb => return wait_for_mongodb_localhost(state, instance_id).await,
        Protocol::Clickhouse => (
            "waiting for ClickHouse to accept local connections",
            "clickhouse-client --user \"$CLICKHOUSE_USER\" --password \"$CLICKHOUSE_PASSWORD\" --database \"$CLICKHOUSE_DB\" --query 'SELECT 1'",
        ),
        Protocol::Qdrant => (
            "waiting for Qdrant gRPC to accept local connections",
            "/opt/dbev/dbev-socket-bridge __socket-bridge-healthcheck 127.0.0.1:6334",
        ),
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
        Protocol::Mariadb => &state.config.images.mariadb,
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
        Protocol::Postgres | Protocol::Mariadb | Protocol::Mongodb | Protocol::Clickhouse => {
            metadata.protocol == request.protocol
                && metadata.database.username == request.username
                && metadata.database.name == request.database
        }
        Protocol::Qdrant => {
            let route_key_sha256 = crate::protocols::qdrant::route_key_sha256(&request.password);
            metadata.protocol == request.protocol
                && metadata.route_key_sha256.as_deref() == Some(route_key_sha256.as_str())
        }
        Protocol::Redis => {
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
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        auth::api_token::ApiToken,
        config::{Config, ImageAllowlistConfig, ImageConfig},
        instances::{manager::InstanceManager, state::InstanceStore},
        jobs::import_export::ImportExportJobs,
        runtime::docker::DockerRuntime,
        storage::{repositories::InstanceRepository, sqlite},
    };

    #[tokio::test]
    async fn create_request_allows_configured_image_override() {
        let state = test_state(Config {
            images: ImageConfig {
                postgres: "postgres:18.4".to_string(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
        let mut request = create_request(Protocol::Postgres);
        request.image = Some("postgres:18.4".to_string());

        let image = requested_or_configured_image(&state, &request).unwrap();

        assert_eq!(image, "postgres:18.4");
    }

    #[tokio::test]
    async fn create_request_allows_protocol_allowlisted_image_override() {
        let state = test_state(Config {
            images: ImageConfig {
                postgres: "postgres:18.4".to_string(),
                allowed: ImageAllowlistConfig {
                    postgres: vec!["postgres:18.5".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
        let mut request = create_request(Protocol::Postgres);
        request.image = Some("postgres:18.5".to_string());

        let image = requested_or_configured_image(&state, &request).unwrap();

        assert_eq!(image, "postgres:18.5");
    }

    #[tokio::test]
    async fn create_request_rejects_unlisted_image_override_before_pull() {
        let state = test_state(Config {
            images: ImageConfig {
                postgres: "postgres:18.4".to_string(),
                allowed: ImageAllowlistConfig {
                    postgres: vec!["postgres:18.5".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
        let mut request = create_request(Protocol::Postgres);
        request.image = Some("postgres:18.6".to_string());

        let error = requested_or_configured_image(&state, &request).unwrap_err();

        assert!(error.to_string().contains("is not allowed"));
    }

    #[tokio::test]
    async fn create_request_allows_same_database_name_for_a_distinct_route_user() {
        let state = test_state(Config::default()).await;
        state
            .instances
            .upsert(sample_metadata(
                "inst_existing_pg",
                Protocol::Postgres,
                "shared_db",
                "first_user",
            ))
            .await;
        let mut request = create_request(Protocol::Postgres);
        request.instance_id = "inst_new_pg".to_string();
        request.database = "shared_db".to_string();
        request.username = "second_user".to_string();

        reject_duplicate_instance(&state, &request).await.unwrap();
    }

    #[tokio::test]
    async fn create_request_rejects_existing_redis_route_for_username() {
        let state = test_state(Config::default()).await;
        state
            .instances
            .upsert(sample_metadata(
                "inst_existing_redis",
                Protocol::Redis,
                "first_cache",
                "shared_user",
            ))
            .await;
        let mut request = create_request(Protocol::Redis);
        request.instance_id = "inst_new_redis".to_string();
        request.database = "second_cache".to_string();
        request.username = "shared_user".to_string();

        let error = reject_duplicate_instance(&state, &request)
            .await
            .unwrap_err();

        assert!(matches!(error, ApiError::Conflict(_)));
        assert!(
            error
                .to_string()
                .contains("redis route already exists for username shared_user")
        );
    }

    #[test]
    fn postgres_provisioning_uses_internal_admin_and_tenant_secret_env() {
        let script = postgres_tenant_provision_script("app_db", "tenant_user");

        assert!(script.contains("BEGIN;"));
        assert!(script.contains("CREATE ROLE \"tenant_user\" LOGIN"));
        assert!(script.contains("\"tenant_user\" LOGIN NOSUPERUSER"));
        assert!(script.contains("ALTER DATABASE \"app_db\""));
        assert!(script.contains("COMMIT;"));
        assert_eq!(script.matches("| psql").count(), 1);
        assert!(script.contains("DBE_POSTGRES_PASSWORD"));
        assert!(script.contains("legacy_bootstrap_superuser"));
        assert!(!script.contains("dbe_admin_test"));
    }

    #[test]
    fn postgres_hardening_rejects_legacy_bootstrap_tenants() {
        let script = postgres_tenant_hardening_script("tenant_user");

        assert!(script.contains("10:*"));
        assert!(script.contains("legacy_bootstrap_superuser"));
        assert!(script.contains("missing_tenant_role"));
        assert!(script.contains("already_restricted"));
    }

    fn create_request(protocol: Protocol) -> CreateInstanceRequest {
        CreateInstanceRequest {
            instance_id: "inst_test_pg".to_string(),
            protocol,
            database: "test_db".to_string(),
            username: "test_user".to_string(),
            password: "test-password".to_string(),
            public_host: "127.0.0.1".to_string(),
            public_port: None,
            project_id: None,
            image: None,
            limits: None,
            purge_stale_resources: false,
            purge_stale_resources_confirmation: None,
        }
    }

    fn sample_metadata(
        instance_id: &str,
        protocol: Protocol,
        database: &str,
        username: &str,
    ) -> InstanceMetadata {
        InstanceMetadata {
            schema_version: SCHEMA_VERSION,
            instance_id: instance_id.to_string(),
            protocol,
            status: InstanceStatus::Running,
            public: PublicEndpoint {
                host: "127.0.0.1".to_string(),
                port: 5432,
            },
            backend: BackendEndpoint::UnixSocket {
                socket_path: format!("/run/dbev/sockets/{instance_id}/.s.PGSQL.5432"),
            },
            runtime: RuntimeMetadata {
                kind: RuntimeKind::Docker,
                container_name: format!("dbe-{}-{instance_id}", protocol.as_str()),
                network_mode: "none".to_string(),
            },
            database: DatabaseIdentity {
                name: database.to_string(),
                username: username.to_string(),
            },
            route_key_sha256: None,
            mariadb_native_password_sha1_stage2: None,
            mariadb_root_password: None,
            mongodb_root_password: None,
            limits: crate::shared::limits::InstanceLimits::default(),
            image: None,
            database_version: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    async fn test_state(config: Config) -> AppState {
        let dir = tempfile::tempdir().unwrap();
        let pool = sqlite::connect(dir.path()).await.unwrap();
        let store = InstanceStore::default();
        let manager = InstanceManager::new(store.clone(), InstanceRepository::new(pool));
        AppState {
            config: Arc::new(config),
            config_path: dir.path().join("config.yml"),
            config_patches: crate::api::config_admin::ConfigPatchCoordinator::default(),
            api_token: ApiToken::new("secret"),
            instances: store,
            manager,
            docker: DockerRuntime::new(&Default::default(), false).unwrap(),
            import_export_jobs: ImportExportJobs::default(),
            api_rate_limiter: crate::api::security::ApiRateLimiter::default(),
            install_progress: crate::api::progress::InstallProgressStore::default(),
            artifact_downloads: crate::api::artifacts::ArtifactDownloadTickets::default(),
            resource_cache: crate::api::resources::ResourceCache::default(),
            instance_runtime_cache: crate::api::instances::InstanceRuntimeInfoCache::default(),
            gateway_supervisor: crate::gateway::supervisor::GatewaySupervisor::default(),
            instance_locks: crate::instances::locks::InstanceLocks::default(),
        }
    }
}
