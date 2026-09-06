//! Canonical dedicated-runtime preparation, launch, and publication.
//!
//! Preparation deliberately stops before the container is created. Deployment
//! migration can therefore persist the generated maintenance credential before
//! launch and keep the provisional runtime out of the gateway route store.

use super::*;

pub(crate) struct DedicatedTarget {
    pub(crate) metadata: InstanceMetadata,
    spec: DockerInstanceSpec,
    image: String,
    report_progress: bool,
}

impl DedicatedTarget {
    pub(crate) fn runtime(&self) -> crate::placement::EngineRuntime {
        crate::placement::EngineRuntime {
            pending_image: None,
            desired_state: crate::instances::metadata::DesiredInstanceState::Running,
            owner: self.metadata.owner.clone(),
            schema_version: crate::placement::ENGINE_RUNTIME_SCHEMA_VERSION,
            runtime_id: self.metadata.instance_id.clone(),
            protocol: self.metadata.protocol,
            deployment_mode: crate::placement::DeploymentMode::Dedicated,
            status: crate::placement::EngineRuntimeStatus::Creating,
            backend: self.metadata.backend.clone(),
            runtime: self.metadata.runtime.clone(),
            limits: self.metadata.limits.clone(),
            image: self.image.clone(),
            database_version: None,
            compatibility: None,

            max_tenants: 1,
            reserved: crate::placement::RuntimeReservation::default(),
            admin_secret: maintenance_secret(&self.metadata).map(str::to_string),
            created_at: self.metadata.created_at.clone(),
            updated_at: self.metadata.updated_at.clone(),
        }
    }
}

fn maintenance_secret(metadata: &InstanceMetadata) -> Option<&str> {
    match metadata.protocol {
        Protocol::Postgres => metadata.postgres_admin_password.as_deref(),
        Protocol::Mariadb => metadata.mariadb_root_password.as_deref(),
        Protocol::Mysql => metadata.mysql_root_password.as_deref(),
        Protocol::Mongodb => metadata.mongodb_root_password.as_deref(),
        Protocol::Clickhouse => metadata.tenant_password.as_deref(),
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => None,
    }
}

pub(super) async fn create(
    state: &AppState,
    request: CreateInstanceRequest,
) -> Result<InstanceMetadata, ApiError> {
    let target = build(state, request, true).await?;
    launch(state, &target).await?;
    publish(state, target.metadata).await
}

pub(crate) async fn build(
    state: &AppState,
    request: CreateInstanceRequest,
    report_progress: bool,
) -> Result<DedicatedTarget, ApiError> {
    let image = resolve_image(state, &request)?;
    if report_progress {
        state
            .install_progress
            .begin(&request.instance_id, request.protocol, &image);
        stage(
            state,
            true,
            &request.instance_id,
            "prepare",
            "preparing instance metadata and directories",
        );
    }

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

    let postgres_admin_password = (request.protocol == Protocol::Postgres)
        .then(|| format!("dbe-admin-{}", uuid::Uuid::new_v4().simple()));
    let mariadb_root_password = (request.protocol == Protocol::Mariadb)
        .then(|| format!("dbe-root-{}", uuid::Uuid::new_v4()));
    let mysql_root_password =
        (request.protocol == Protocol::Mysql).then(|| format!("dbe-root-{}", uuid::Uuid::new_v4()));
    let mongodb_root_password = (request.protocol == Protocol::Mongodb)
        .then(|| format!("dbe-root-{}", uuid::Uuid::new_v4()));

    match request.protocol {
        Protocol::Redis | Protocol::Valkey => {
            let message = if request.protocol == Protocol::Redis {
                "writing Redis ACL configuration"
            } else {
                "writing Valkey ACL configuration"
            };
            stage(
                state,
                report_progress,
                &request.instance_id,
                "provision",
                message,
            );
            databases::resp::write_acl_file(
                &paths.data,
                &request.username,
                &SecretString::from(request.password.clone()),
            )
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

    stage(
        state,
        report_progress,
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

    stage(
        state,
        report_progress,
        &request.instance_id,
        "disk_limit",
        "applying disk limit",
    );
    let disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
            .for_protocol(request.protocol);
    let disk = disk_limiter
        .apply_instance_limit(&request.instance_id, &paths.data, limits.disk_mib)
        .await
        .map_err(|error| fail_runtime(state, &request.instance_id, error))?;
    let data_path = disk
        .container_data_path
        .clone()
        .unwrap_or(paths.data.clone());
    limits.disk_enforced = disk.enforced;
    limits.disk_enforcement_method = disk.method;

    let mut spec = build_spec(
        state,
        &request,
        &paths,
        &image,
        data_path,
        postgres_admin_password.as_deref(),
        mariadb_root_password.as_deref(),
        mysql_root_password.as_deref(),
        mongodb_root_password.as_deref(),
    )
    .await?;
    spec.project_id = request.project_id.clone();
    spec.user = Some(container_user);
    spec.cpu_cores = limits.cpu_cores;
    spec.memory_mib = limits.memory_mib;
    spec.disk_mib = limits.disk_mib;
    spec.pids_limit = Some(protocol_pids_limit(state, request.protocol));

    let backend = backend_endpoint(state, request.protocol, &request.instance_id)?;
    let now = now_rfc3339();
    let metadata = InstanceMetadata {
        owner: request.owner.clone(),
        schema_version: SCHEMA_VERSION,
        instance_id: request.instance_id.clone(),
        deployment_mode: crate::placement::DeploymentMode::Dedicated,
        runtime_id: request.instance_id,
        protocol: request.protocol,
        status: InstanceStatus::Booting,
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
        route_key_sha256: (request.protocol == Protocol::Qdrant).then(|| {
            crate::protocols::qdrant::route_key_fingerprint(
                state.config.websocket_jwt_secret(),
                &request.password,
            )
        }),
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
    Ok(DedicatedTarget {
        metadata,
        spec,
        image,
        report_progress,
    })
}

#[allow(clippy::too_many_arguments)]
async fn build_spec(
    state: &AppState,
    request: &CreateInstanceRequest,
    paths: &InstancePaths,
    image: &str,
    data_path: std::path::PathBuf,
    postgres_admin_password: Option<&str>,
    mariadb_root_password: Option<&str>,
    mysql_root_password: Option<&str>,
    mongodb_root_password: Option<&str>,
) -> Result<DockerInstanceSpec, ApiError> {
    let password = || SecretString::from(request.password.clone());
    Ok(match request.protocol {
        Protocol::Postgres => databases::postgres::docker::instance_spec(
            &request.instance_id,
            image,
            &request.database,
            &request.username,
            password(),
            SecretString::from(required_secret(
                state,
                &request.instance_id,
                postgres_admin_password,
                "PostgreSQL administrator",
            )?),
            data_path,
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Redis | Protocol::Valkey => databases::resp::instance_spec(
            request.protocol,
            &request.instance_id,
            image,
            data_path,
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mariadb => databases::mariadb::docker::instance_spec(
            &request.instance_id,
            image,
            &request.database,
            &request.username,
            password(),
            SecretString::from(required_secret(
                state,
                &request.instance_id,
                mariadb_root_password,
                "MariaDB root",
            )?),
            data_path,
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mysql => databases::mysql::docker::instance_spec(
            &request.instance_id,
            image,
            &request.database,
            SecretString::from(required_secret(
                state,
                &request.instance_id,
                mysql_root_password,
                "MySQL root",
            )?),
            data_path,
            paths.logs.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mongodb => databases::mongodb::docker::instance_spec(
            &request.instance_id,
            image,
            &request.database,
            databases::mongodb::docker::MongodbAuth {
                username: request.username.clone(),
                password: password(),
                root_password: SecretString::from(required_secret(
                    state,
                    &request.instance_id,
                    mongodb_root_password,
                    "MongoDB root",
                )?),
            },
            data_path,
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
                image,
                &request.database,
                &request.username,
                password(),
                data_path,
                paths.logs.clone(),
                hosted_config_path,
                paths.sockets.clone(),
                paths.socket_bridge_binary.clone(),
            )
        }
        Protocol::Qdrant => databases::qdrant::docker::instance_spec(
            &request.instance_id,
            image,
            password(),
            data_path,
            paths.logs.clone(),
            paths.sockets.clone(),
            paths.socket_bridge_binary.clone(),
        ),
    })
}

fn required_secret(
    state: &AppState,
    instance_id: &str,
    secret: Option<&str>,
    name: &str,
) -> Result<String, ApiError> {
    secret.map(str::to_string).ok_or_else(|| {
        fail_runtime(
            state,
            instance_id,
            format!("internal {name} password was not generated"),
        )
    })
}

pub(crate) async fn launch(state: &AppState, target: &DedicatedTarget) -> Result<(), ApiError> {
    let metadata = &target.metadata;
    let progress = state.install_progress.clone();
    let progress_instance_id = metadata.instance_id.clone();
    let pull_progress = move |event| progress.docker_pull(&progress_instance_id, event);
    let mongodb_after_start = || async {
        if metadata.protocol == Protocol::Mongodb {
            stage(
                state,
                target.report_progress,
                &metadata.instance_id,
                "provision",
                "creating MongoDB tenant user",
            );
            provision_mongodb_tenant_user(
                state,
                &metadata.instance_id,
                &metadata.database.name,
                &metadata.database.username,
                tenant_password(metadata)?,
                required_metadata_secret(
                    metadata.mongodb_root_password.as_deref(),
                    "MongoDB root",
                )?,
            )
            .await?;
        }
        Ok(())
    };
    if let Err(error) = launch_container_from_spec(
        state,
        &target.spec,
        metadata.protocol,
        &metadata.instance_id,
        &pull_progress,
        target.report_progress,
        mongodb_after_start,
    )
    .await
    {
        let error = error.into_api_error();
        if target.report_progress {
            state.install_progress.fail_api_error(
                &metadata.instance_id,
                "instance creation",
                &error,
            );
        }
        return Err(error);
    }
    provision_sql_tenant(state, metadata, target.report_progress).await
}

async fn provision_sql_tenant(
    state: &AppState,
    metadata: &InstanceMetadata,
    report_progress: bool,
) -> Result<(), ApiError> {
    let result = match metadata.protocol {
        Protocol::Mariadb => {
            stage(
                state,
                report_progress,
                &metadata.instance_id,
                "provision",
                "creating or updating MariaDB tenant user",
            );
            provision_mariadb_tenant_user(
                state,
                &metadata.instance_id,
                &metadata.database.name,
                &metadata.database.username,
                tenant_password(metadata)?,
                required_metadata_secret(
                    metadata.mariadb_root_password.as_deref(),
                    "MariaDB root",
                )?,
            )
            .await
        }
        Protocol::Mysql => {
            stage(
                state,
                report_progress,
                &metadata.instance_id,
                "provision",
                "creating or updating MySQL tenant user",
            );
            provision_mysql_tenant_user(
                state,
                &metadata.instance_id,
                &metadata.database.name,
                &metadata.database.username,
                tenant_password(metadata)?,
                required_metadata_secret(metadata.mysql_root_password.as_deref(), "MySQL root")?,
            )
            .await
        }
        Protocol::Postgres => {
            stage(
                state,
                report_progress,
                &metadata.instance_id,
                "provision",
                "restricting PostgreSQL tenant role",
            );
            provision_postgres_tenant_role(
                state,
                &metadata.instance_id,
                &metadata.database.name,
                &metadata.database.username,
                tenant_password(metadata)?,
                required_metadata_secret(
                    metadata.postgres_admin_password.as_deref(),
                    "PostgreSQL administrator",
                )?,
            )
            .await
        }
        _ => Ok(()),
    };
    if let Err(error) = &result
        && report_progress
    {
        state.install_progress.fail_api_error(
            &metadata.instance_id,
            "database tenant provisioning",
            error,
        );
    }
    result
}

fn tenant_password(metadata: &InstanceMetadata) -> Result<&str, ApiError> {
    required_metadata_secret(metadata.tenant_password.as_deref(), "tenant")
}

fn required_metadata_secret<'a>(secret: Option<&'a str>, name: &str) -> Result<&'a str, ApiError> {
    secret.ok_or_else(|| ApiError::Runtime(format!("internal {name} password is missing")))
}

pub(crate) async fn attest(state: &AppState, metadata: &InstanceMetadata) -> Result<(), ApiError> {
    let compatibility = crate::compatibility::probe_instance_compatibility(
        &state.manager,
        &state.docker,
        metadata,
        true,
    )
    .await
    .map_err(|error| {
        ApiError::Runtime(format!(
            "created database container but its compatibility probe failed: {error}"
        ))
    })?;
    if compatibility.compatible {
        Ok(())
    } else {
        Err(ApiError::Conflict(compatibility.diagnostic.unwrap_or_else(
            || "database engine version is unsupported".to_string(),
        )))
    }
}

async fn publish(
    state: &AppState,
    mut metadata: InstanceMetadata,
) -> Result<InstanceMetadata, ApiError> {
    stage(
        state,
        true,
        &metadata.instance_id,
        "socket",
        "registering private backend socket",
    );
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
    stage(
        state,
        true,
        &metadata.instance_id,
        "compatibility",
        "attesting database engine compatibility",
    );
    attest(state, &metadata).await?;
    metadata.status = InstanceStatus::Running;
    metadata.updated_at = now_rfc3339();
    state
        .manager
        .upsert(metadata.clone())
        .await
        .map_err(|error| {
            state.install_progress.fail_internal(
                &metadata.instance_id,
                "verified instance metadata publication",
                &error,
            );
            ApiError::Runtime(format!(
                "attested the created container but failed to publish its route: {error}"
            ))
        })?;
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

fn stage(
    state: &AppState,
    enabled: bool,
    instance_id: &str,
    name: &'static str,
    message: &'static str,
) {
    if enabled {
        state.install_progress.stage(instance_id, name, message);
    }
}
