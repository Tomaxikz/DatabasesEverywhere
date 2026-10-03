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
    pub(crate) fn runtime(&self) -> crate::instance::placement::EngineRuntime {
        crate::instance::placement::EngineRuntime {
            pending_image: None,
            desired_state: crate::instance::metadata::DesiredInstanceState::Running,
            owner: self.metadata.owner.clone(),
            schema_version: crate::instance::placement::ENGINE_RUNTIME_SCHEMA_VERSION,
            runtime_id: self.metadata.instance_id.clone(),
            protocol: self.metadata.protocol,
            deployment_mode: crate::instance::placement::DeploymentMode::Dedicated,
            status: crate::instance::placement::EngineRuntimeStatus::Creating,
            backend: self.metadata.backend.clone(),
            runtime: self.metadata.runtime.clone(),
            limits: self.metadata.limits.clone(),
            image: self.image.clone(),
            database_version: None,
            compatibility: None,

            max_tenants: 1,
            reserved: crate::instance::placement::RuntimeReservation::default(),
            admin_secret: maintenance_secret(&self.metadata).map(str::to_string),
            created_at: self.metadata.created_at.clone(),
            updated_at: self.metadata.updated_at.clone(),
        }
    }
}

fn maintenance_secret(metadata: &InstanceMetadata) -> Option<&str> {
    metadata.protocol.engine().runtime_admin_secret(metadata)
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

    let engine = request.protocol.engine();
    let maintenance_password = engine.generate_maintenance_password();

    if let Some(message) = engine.acl_file_stage() {
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
        maintenance_password.as_deref(),
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
    let mut metadata = InstanceMetadata {
        owner: request.owner.clone(),
        schema_version: SCHEMA_VERSION,
        instance_id: request.instance_id.clone(),
        deployment_mode: crate::instance::placement::DeploymentMode::Dedicated,
        runtime_id: request.instance_id,
        protocol: request.protocol,
        status: InstanceStatus::Booting,
        desired_state: crate::instance::metadata::DesiredInstanceState::Running,
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
        route_key_sha256: engine
            .route_key_fingerprint(state.config.websocket_jwt_secret(), &request.password),
        mariadb_native_password_sha1_stage2: None,
        mariadb_root_password: None,
        mysql_native_password_sha1_stage2: None,
        mysql_root_password: None,
        mongodb_root_password: None,
        postgres_admin_password: None,
        tenant_password: Some(request.password.clone()),
        limits,
        image: None,
        database_version: None,
        created_at: now.clone(),
        updated_at: now,
    };
    engine.refresh_native_password_verifier(&mut metadata, &request.password);
    engine.store_maintenance_password(&mut metadata, maintenance_password);
    Ok(DedicatedTarget {
        metadata,
        spec,
        image,
        report_progress,
    })
}

async fn build_spec(
    state: &AppState,
    request: &CreateInstanceRequest,
    paths: &InstancePaths,
    image: &str,
    data_path: std::path::PathBuf,
    maintenance_password: Option<&str>,
) -> Result<DockerInstanceSpec, ApiError> {
    let engine = request.protocol.engine();
    let maintenance_password = match engine.maintenance_secret_label() {
        Some(label) => SecretString::from(required_secret(
            state,
            &request.instance_id,
            maintenance_password,
            label,
        )?),
        None => SecretString::from(String::new()),
    };
    let hosted_config = engine
        .write_hosted_config(&paths.runtime_config, false)
        .await
        .map_err(|error| fail_runtime(state, &request.instance_id, error))?;
    Ok(engine.dedicated_spec(DedicatedSpecInput {
        instance_id: &request.instance_id,
        image,
        database: &request.database,
        username: &request.username,
        password: SecretString::from(request.password.clone()),
        maintenance_password,
        data_path,
        sockets: paths.sockets.clone(),
        hosted_config,
        socket_bridge_binary: paths.socket_bridge_binary.clone(),
    }))
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
    let engine = metadata.protocol.engine();
    let after_start = || async {
        if let Some(plan) = engine.post_launch_plan(LifecycleFlow::Create) {
            if let Some(message) = plan.stage {
                stage(
                    state,
                    target.report_progress,
                    &metadata.instance_id,
                    "provision",
                    message,
                );
            }
            match plan.step {
                PostLaunchStep::ProvisionTenantUser => {
                    provision_mongodb_tenant_user(
                        state,
                        &metadata.instance_id,
                        &metadata.database.name,
                        &metadata.database.username,
                        tenant_password(metadata)?,
                        maintenance_password(metadata)?,
                    )
                    .await?;
                }
                PostLaunchStep::BootstrapRoot => {}
            }
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
        after_start,
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
    let result = match metadata
        .protocol
        .engine()
        .tenant_auth_plan(LifecycleFlow::Create)
    {
        Some(plan) => {
            if let Some(message) = plan.stage {
                stage(
                    state,
                    report_progress,
                    &metadata.instance_id,
                    "provision",
                    message,
                );
            }
            run_tenant_auth_step(
                state,
                metadata,
                plan.step,
                tenant_password(metadata)?,
                maintenance_password(metadata)?,
            )
            .await
        }
        None => Ok(()),
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

fn maintenance_password(metadata: &InstanceMetadata) -> Result<&str, ApiError> {
    let engine = metadata.protocol.engine();
    required_metadata_secret(
        engine.stored_maintenance_password(metadata),
        engine.maintenance_secret_label().unwrap_or("maintenance"),
    )
}

fn tenant_password(metadata: &InstanceMetadata) -> Result<&str, ApiError> {
    required_metadata_secret(metadata.tenant_password.as_deref(), "tenant")
}

fn required_metadata_secret<'a>(secret: Option<&'a str>, name: &str) -> Result<&'a str, ApiError> {
    secret.ok_or_else(|| ApiError::Runtime(format!("internal {name} password is missing")))
}

pub(crate) async fn attest(state: &AppState, metadata: &InstanceMetadata) -> Result<(), ApiError> {
    let compatibility = crate::instance::compatibility::probe_instance_compatibility(
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
