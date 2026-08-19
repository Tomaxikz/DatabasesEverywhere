use super::*;

pub(super) fn log_boot_configuration(config: &Config, config_path: &Path) {
    tracing::info!(
        config = %config_path.display(),
        data = %config.paths.data,
        metadata = %config.paths.metadata_root(),
        logs = %config.paths.logs,
        sockets = %config.paths.sockets,
        artifacts = %config.paths.artifacts,
        "configured paths"
    );
    tracing::info!(
        api_bind = %config.api.bind_addr(),
        api_host = %config.api.host,
        api_fqdn = config.api.fqdn().unwrap_or("<unset>"),
        api_port = config.api.port,
        remote = %config.remote,
        cors_allowed_origins = ?config.cors_allowed_origins(),
        body_limit_bytes = config.security.api_body_limit_bytes,
        api_rate_limit_per_minute = config.security.api_rate_limit_per_minute,
        "api configuration"
    );
    log_api_host_resolution(config);
    log_tls_configuration(config);
    tracing::info!(
        default_pids_limit = config.security.pids_limit,
        postgres = ?config.security.pids_limits.postgres,
        redis = ?config.security.pids_limits.redis,
        valkey = ?config.security.pids_limits.valkey,
        mariadb = ?config.security.pids_limits.mariadb,
        mysql = ?config.security.pids_limits.mysql,
        mongodb = ?config.security.pids_limits.mongodb,
        clickhouse = ?config.security.pids_limits.clickhouse,
        qdrant = ?config.security.pids_limits.qdrant,
        "container pid limits configured"
    );
    tracing::info!(
        postgres = %config.images.postgres,
        redis = %config.images.redis,
        valkey = %config.images.valkey,
        mariadb = %config.images.mariadb,
        mysql = %config.images.mysql,
        mongodb = %config.images.mongodb,
        clickhouse = %config.images.clickhouse,
        qdrant = %config.images.qdrant,
        "database images configured"
    );
    let mutable_images: Vec<&str> = [
        config.images.postgres.as_str(),
        config.images.redis.as_str(),
        config.images.valkey.as_str(),
        config.images.mariadb.as_str(),
        config.images.mysql.as_str(),
        config.images.mongodb.as_str(),
        config.images.clickhouse.as_str(),
        config.images.qdrant.as_str(),
    ]
    .into_iter()
    .filter(|image| !has_sha256_digest(image))
    .collect();
    if !mutable_images.is_empty() {
        tracing::warn!(
            images = ?mutable_images,
            "database image tags are mutable; version tags are accepted, while sha256 digests provide stronger reproducibility"
        );
    }
    tracing::info!(
        mode = %config.disk.mode.method(),
        enforced = config.disk.mode.enforced(),
        project_id_base = config.disk.project_id_base,
        fuse_quota_binary = %config.disk.fuse_quota_binary(),
        "disk limiter configured"
    );
    if config.security.remote_import.enabled {
        tracing::info!(
            allow_plaintext = config.security.remote_import.allow_plaintext,
            allowed_private_hosts = config.security.remote_import.allowed_private_hosts.len(),
            max_concurrent_jobs = config.security.remote_import.max_concurrent_jobs,
            "remote credential imports enabled by node policy; target database containers remain network-isolated"
        );
    } else {
        tracing::info!("remote credential imports disabled by node policy");
    }
}

pub(super) fn log_api_host_resolution(config: &Config) {
    if config.api.host == "0.0.0.0" || config.api.host == "::" {
        tracing::info!(
            host = %config.api.host,
            fqdn = config.api.fqdn().unwrap_or("<unset>"),
            port = config.api.port,
            "api binds all local interfaces; clients must use the configured canonical fqdn"
        );
        return;
    }
    if config.api.host.parse::<IpAddr>().is_ok() {
        tracing::info!(
            host = %config.api.host,
            port = config.api.port,
            "api binds explicit local IP"
        );
        return;
    }

    let target = config.api.bind_addr();
    match target.to_socket_addrs() {
        Ok(addrs) => {
            let resolved: Vec<String> = addrs.map(|addr| addr.to_string()).collect();
            tracing::warn!(
                host = %config.api.host,
                port = config.api.port,
                resolved = ?resolved,
                "api host is a DNS name; bind succeeds only if it resolves to an address assigned to this server"
            );
        }
        Err(error) => {
            tracing::warn!(
                host = %config.api.host,
                port = config.api.port,
                %error,
                "api host DNS resolution failed; use 0.0.0.0 when exposing the daemon by domain"
            );
        }
    }
}

pub(super) fn log_tls_configuration(config: &Config) {
    if config.api.ssl.enabled {
        log_tls_file("api tls certificate", &config.api.ssl.cert);
        log_tls_file("api tls private key", &config.api.ssl.key);
        tracing::info!(
            require_client_cert = config.api.ssl.require_client_cert,
            client_ca = %empty_as_unset(&config.api.ssl.client_ca),
            "api tls enabled"
        );
        if config.api.ssl.require_client_cert {
            log_tls_file("api tls client ca", &config.api.ssl.client_ca);
        }
    } else {
        let host = config.api.host.trim();
        let loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback());
        if loopback {
            tracing::info!(
                bind = %config.api.bind_addr(),
                "api tls disabled on loopback"
            );
        } else {
            tracing::warn!(
                bind = %config.api.bind_addr(),
                "api serves plaintext HTTP on a non-loopback interface; bearer tokens, credentials, requests, and responses are not protected from network interception"
            );
        }
    }

    if any_database_listener_tls_enabled(config) {
        log_tls_file("database listener tls certificate", &config.tls.cert);
        log_tls_file("database listener tls private key", &config.tls.key);
        tracing::info!("database gateway tls enabled for at least one protocol");
    } else {
        tracing::info!("database gateway tls disabled for all protocols");
    }
}

pub(super) fn log_tls_file(label: &'static str, path: &str) {
    if path.trim().is_empty() {
        tracing::warn!(label, "tls path is empty");
        return;
    }
    match fs::metadata(path) {
        Ok(metadata) => {
            tracing::info!(
                label,
                path,
                bytes = metadata.len(),
                readonly = metadata.permissions().readonly(),
                "tls file accessible"
            );
        }
        Err(error) => {
            tracing::error!(label, path, %error, "tls file is not accessible");
        }
    }
}

pub(super) fn any_database_listener_tls_enabled(config: &Config) -> bool {
    config.postgres.tls
        || config.redis.tls
        || config.valkey.tls
        || config.mariadb.tls
        || config.mysql.tls
        || config.mongodb.tls
        || config.clickhouse.tls
        || config.qdrant.tls
}

pub(super) fn empty_as_unset(value: &str) -> &str {
    if value.trim().is_empty() {
        "<unset>"
    } else {
        value
    }
}

pub(super) fn log_gateway_listener_summary(config: &Config) {
    log_listener(
        "postgres",
        &config.postgres.bind,
        config.postgres.enabled,
        config.postgres.tls,
    );
    log_listener(
        "redis",
        &config.redis.bind,
        config.redis.enabled,
        config.redis.tls,
    );
    log_listener(
        "valkey",
        &config.valkey.bind,
        config.valkey.enabled,
        config.valkey.tls,
    );
    log_listener(
        "mariadb",
        &config.mariadb.bind,
        config.mariadb.enabled,
        config.mariadb.tls,
    );
    log_listener(
        "mysql",
        &config.mysql.bind,
        config.mysql.enabled,
        config.mysql.tls,
    );
    log_listener(
        "mongodb",
        &config.mongodb.bind,
        config.mongodb.enabled,
        config.mongodb.tls,
    );
    log_listener(
        "clickhouse native",
        &config.clickhouse.bind,
        config.clickhouse.enabled,
        config.clickhouse.tls,
    );
    log_listener(
        "clickhouse http",
        &config.clickhouse.http_bind,
        config.clickhouse.enabled,
        config.clickhouse.tls,
    );
    log_listener(
        "qdrant",
        &config.qdrant.bind,
        config.qdrant.enabled,
        config.qdrant.tls,
    );
}

pub(super) fn log_listener(protocol: &'static str, bind: &str, enabled: bool, tls: bool) {
    if enabled {
        let publicly_reachable = bind
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|address| !address.ip().is_loopback());
        if !tls && publicly_reachable {
            tracing::warn!(
                protocol,
                bind,
                "gateway listener accepts authenticated database traffic without transport encryption"
            );
        } else {
            tracing::info!(protocol, bind, tls, "gateway listener configured");
        }
    } else {
        tracing::info!(protocol, bind, "gateway listener disabled");
    }
}

pub(super) async fn reapply_instance_disk_limits(
    config: &Config,
    manager: &InstanceManager,
    docker: &DockerRuntime,
    disk_limiter: &DiskLimiter,
) -> anyhow::Result<()> {
    let instances = manager.store().list().await;
    let outcomes = futures::stream::iter(instances)
        .map(|metadata| async move {
            let outcome = async {
                let paths = InstancePaths::new(&config.paths, &metadata.instance_id).with_context(
                    || format!("failed to build paths for {}", metadata.instance_id),
                )?;
                if let Some((uid, gid)) = docker.rootless_podman_host_owner() {
                    paths.create_dirs().await.with_context(|| {
                        format!(
                            "failed to create rootless Podman paths for {}",
                            metadata.instance_id
                        )
                    })?;
                    paths
                        .apply_rootless_podman_owner(uid, gid)
                        .await
                        .with_context(|| {
                            format!(
                                "failed to apply rootless Podman ownership for {}",
                                metadata.instance_id
                            )
                        })?;
                }
                let legacy_qdrant_fuse_retained = if metadata.protocol == Protocol::Qdrant {
                    !migrate_legacy_qdrant_fuse_storage(
                        config,
                        docker,
                        disk_limiter,
                        &metadata,
                        &paths,
                    )
                    .await?
                } else {
                    false
                };
                let effective_limiter = if legacy_qdrant_fuse_retained {
                    // Migration was deliberately deferred or rolled back. The
                    // existing container is still bound to FuseQuota, even if
                    // the operator has since selected soft/native enforcement.
                    disk_limiter.legacy_fuse_limiter()
                } else {
                    disk_limiter.for_protocol(metadata.protocol)
                };
                effective_limiter.validate_persisted_method_transition(
                    &metadata.limits.disk_enforcement_method,
                )?;
                ensure_container_uses_effective_disk_path(
                    docker,
                    &metadata,
                    &paths,
                    &effective_limiter,
                )
                .await?;
                if !effective_limiter
                    .instance_runtime_is_healthy(&paths.data)
                    .await
                    .with_context(|| {
                        format!(
                            "failed to inspect disk-limit runtime for {}",
                            metadata.instance_id
                        )
                    })?
                {
                    match docker.stop(metadata.protocol, &metadata.instance_id).await {
                        Ok(_) => tracing::warn!(
                            instance_id = %metadata.instance_id,
                            protocol = %metadata.protocol,
                            "stopped managed instance to recover an unavailable disk-limit runtime"
                        ),
                        Err(error) if error.is_not_found() || error.is_not_running() => {}
                        Err(error) => {
                            return Err(error).with_context(|| {
                                format!(
                                    "failed to stop {} before recovering its disk-limit runtime",
                                    metadata.instance_id
                                )
                            });
                        }
                    }
                }
                let enforcement = effective_limiter
                    .apply_instance_limit(
                        &metadata.instance_id,
                        &paths.data,
                        metadata.limits.disk_mib,
                    )
                    .await
                    .with_context(|| {
                        format!("failed to apply disk limit for {}", metadata.instance_id)
                    })?;
                Ok::<(crate::config::DiskLimitMode, crate::disk::DiskEnforcement), anyhow::Error>((
                    effective_limiter.mode(),
                    enforcement,
                ))
            }
            .await;
            (metadata, outcome)
        })
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut failed = 0_usize;
    for (mut metadata, outcome) in outcomes {
        if let Ok((_effective_mode, enforcement)) = outcome.as_ref() {
            if metadata.limits.disk_enforced != enforcement.enforced
                || metadata.limits.disk_enforcement_method != enforcement.method
            {
                metadata.limits.disk_enforced = enforcement.enforced;
                metadata.limits.disk_enforcement_method = enforcement.method.clone();
                metadata.updated_at = now_rfc3339();
                manager.upsert(metadata).await?;
            }
            continue;
        }
        let error = outcome.expect_err("disk-limit error checked above");
        failed += 1;
        tracing::error!(
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            %error,
            "instance disk-limit reconciliation failed; isolating this instance and continuing daemon boot"
        );
        let stop_failed = match docker.stop(metadata.protocol, &metadata.instance_id).await {
            Ok(_) => false,
            Err(error) if error.is_not_found() || error.is_not_running() => false,
            Err(stop_error) => {
                tracing::error!(
                    event = "audit disk_limit_recovery_stop_failed",
                    instance_id = %metadata.instance_id,
                    protocol = %metadata.protocol,
                    %stop_error,
                    "failed to stop an instance whose disk-limit runtime could not be reconciled; quarantining it fail-closed"
                );
                true
            }
        };
        isolate_disk_reconciliation_failure(&mut metadata, stop_failed);
        metadata.updated_at = now_rfc3339();
        manager.upsert(metadata).await?;
    }
    if failed > 0 {
        tracing::warn!(
            failed,
            "one or more instance disk limits could not be reconciled; affected instances were isolated while daemon startup continues"
        );
    }
    Ok(())
}

pub(super) fn isolate_disk_reconciliation_failure(
    metadata: &mut crate::instances::metadata::InstanceMetadata,
    stop_failed: bool,
) {
    // A Failed+desired-running instance is automatically retried later in the
    // same boot. Persist explicit stopped intent for every reconciliation or
    // bind-source failure so activation cannot immediately bypass the mode we
    // failed to establish.
    metadata.desired_state = crate::instances::metadata::DesiredInstanceState::Stopped;
    metadata.status = if metadata.status == InstanceStatus::Quarantined || stop_failed {
        InstanceStatus::Quarantined
    } else {
        InstanceStatus::Failed
    };
}

async fn ensure_container_uses_effective_disk_path(
    docker: &DockerRuntime,
    metadata: &crate::instances::metadata::InstanceMetadata,
    paths: &InstancePaths,
    effective_limiter: &DiskLimiter,
) -> anyhow::Result<()> {
    let expected_source = effective_limiter.container_data_path(&paths.data)?;
    match docker
        .verify_container_data_bind(metadata.protocol, &metadata.instance_id, &expected_source)
        .await
    {
        Ok(()) => Ok(()),
        // A missing container can be recreated later with the selected mode.
        // There is no running bind source that could bypass enforcement.
        Err(error) if error.is_not_found() => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Move a pre-exclusion Qdrant instance from its FuseQuota bind source to the
/// raw backing directory. Every destructive runtime step has a remount/recreate
/// rollback; the backing data directory is never renamed or deleted.
async fn migrate_legacy_qdrant_fuse_storage(
    config: &Config,
    docker: &DockerRuntime,
    disk_limiter: &DiskLimiter,
    metadata: &crate::instances::metadata::InstanceMetadata,
    paths: &InstancePaths,
) -> anyhow::Result<bool> {
    let legacy_mount = disk_limiter.legacy_fuse_container_path(&paths.data)?;
    let legacy_mount_present = disk_limiter.legacy_fuse_mount_is_present(&paths.data)?;
    let bound_source = match docker
        .container_bind_source(metadata.protocol, &metadata.instance_id, "/dbe-qdrant")
        .await
    {
        Ok(source) => source,
        Err(error) if error.is_not_found() => None,
        Err(error) => return Err(error.into()),
    };
    if !legacy_qdrant_container_uses_fuse(bound_source.as_deref(), &legacy_mount) {
        if legacy_mount_present {
            disk_limiter.teardown_legacy_fuse_mount(&paths.data).await?;
            tracing::info!(
                event = "audit qdrant_stale_fuse_mount_removed",
                instance_id = %metadata.instance_id,
                bound_source = bound_source.as_ref().map(|path| path.display().to_string()),
                legacy_mount = %legacy_mount.display(),
                "removed a stale legacy Qdrant FuseQuota mount without recreating a container that did not use it"
            );
        }
        return Ok(true);
    }
    let migration_target_mode = disk_limiter.mode_for_protocol(metadata.protocol);
    if !qdrant_fuse_migration_target_is_safe(migration_target_mode) {
        tracing::error!(
            event = "audit qdrant_fuse_migration_deferred",
            instance_id = %metadata.instance_id,
            target_mode = migration_target_mode.method(),
            "legacy Qdrant FuseQuota storage cannot be adopted transactionally by a native project-quota backend; temporarily select disk.mode=soft_scanner to migrate it to raw storage, or use a backup/create/import migration"
        );
        return Ok(false);
    }
    let Some(api_key) = metadata.tenant_password.clone() else {
        tracing::error!(
            event = "audit qdrant_fuse_migration_deferred",
            instance_id = %metadata.instance_id,
            "legacy Qdrant FuseQuota mount was retained because encrypted tenant credential metadata is unavailable; reset the instance password, then restart dbev to retry safe migration"
        );
        return Ok(false);
    };
    let image = match docker
        .container_immutable_image_id(metadata.protocol, &metadata.instance_id)
        .await
    {
        Ok(Some(image)) => image,
        Ok(None) => {
            tracing::error!(
                event = "audit qdrant_fuse_migration_deferred",
                instance_id = %metadata.instance_id,
                "legacy Qdrant FuseQuota mount was retained because its immutable container image ID is unavailable"
            );
            return Ok(false);
        }
        Err(error) if error.is_not_found() => {
            tracing::error!(
                event = "audit qdrant_fuse_migration_deferred",
                instance_id = %metadata.instance_id,
                "legacy Qdrant FuseQuota mount was retained because its managed container is missing"
            );
            return Ok(false);
        }
        Err(error) => return Err(error.into()),
    };
    let inspection = docker
        .inspect_instance(metadata.protocol, &metadata.instance_id)
        .await?;
    let (stop_existing, should_run) =
        qdrant_migration_runtime_actions(inspection.status, metadata.desired_state);
    let container_user = crate::api::instance_create::prepare_instance_container_user(
        docker,
        paths,
        metadata.protocol,
    )
    .await?;
    let project_id = docker
        .container_project_id(metadata.protocol, &metadata.instance_id)
        .await?;
    let raw_spec = qdrant_migration_spec(
        config,
        metadata,
        paths,
        QdrantMigrationContainer {
            data_path: paths.data.clone(),
            image: &image,
            api_key: &api_key,
            container_user: &container_user,
            project_id: project_id.clone(),
        },
    );
    let legacy_spec = qdrant_migration_spec(
        config,
        metadata,
        paths,
        QdrantMigrationContainer {
            data_path: legacy_mount,
            image: &image,
            api_key: &api_key,
            container_user: &container_user,
            project_id,
        },
    );

    if stop_existing {
        docker
            .stop(metadata.protocol, &metadata.instance_id)
            .await?;
    }

    let migration = async {
        // Deletion is part of the rollback-covered transaction. An engine
        // response can be lost after it removed the container; either outcome
        // is safe because rollback tolerates not-found and recreates exactly
        // the immutable image/spec captured above.
        docker
            .delete(metadata.protocol, &metadata.instance_id)
            .await?;
        disk_limiter.teardown_legacy_fuse_mount(&paths.data).await?;
        disk_limiter
            .for_protocol(metadata.protocol)
            .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
            .await?;
        docker.create(&raw_spec).await?;
        if should_run {
            docker
                .start(metadata.protocol, &metadata.instance_id)
                .await?;
            docker
                .wait_until_ready(
                    metadata.protocol,
                    &metadata.instance_id,
                    Duration::from_secs(120),
                )
                .await?;
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;

    if let Err(migration_error) = migration {
        let rollback = async {
            match docker
                .delete(metadata.protocol, &metadata.instance_id)
                .await
            {
                Ok(_) => {}
                Err(error) if error.is_not_found() => {}
                Err(error) => return Err(anyhow::Error::from(error)),
            }
            disk_limiter
                .apply_legacy_fuse_limit(&paths.data, metadata.limits.disk_mib)
                .await?;
            docker.create(&legacy_spec).await?;
            if should_run {
                docker
                    .start(metadata.protocol, &metadata.instance_id)
                    .await?;
                docker
                    .wait_until_ready(
                        metadata.protocol,
                        &metadata.instance_id,
                        Duration::from_secs(120),
                    )
                    .await?;
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        match rollback {
            Ok(()) => {
                tracing::error!(
                    event = "audit qdrant_fuse_migration_rolled_back",
                    instance_id = %metadata.instance_id,
                    error = %migration_error,
                    "Qdrant migration to native storage failed; restored its previous FuseQuota container and retained truthful hard-enforcement metadata"
                );
                return Ok(false);
            }
            Err(rollback_error) => {
                anyhow::bail!(
                    "Qdrant FuseQuota migration failed ({migration_error}) and rollback failed ({rollback_error})"
                );
            }
        }
    }

    tracing::info!(
        event = "audit qdrant_fuse_migration_completed",
        instance_id = %metadata.instance_id,
        running = should_run,
        "migrated legacy Qdrant storage from FuseQuota to raw filesystem storage governed by the selected non-FUSE enforcement"
    );
    Ok(true)
}

pub(super) fn qdrant_migration_runtime_actions(
    observed: DockerContainerStatus,
    desired: crate::instances::metadata::DesiredInstanceState,
) -> (bool, bool) {
    let stop_existing = matches!(
        observed,
        DockerContainerStatus::Running | DockerContainerStatus::Starting
    );
    let start_replacement = desired == crate::instances::metadata::DesiredInstanceState::Running;
    (stop_existing, start_replacement)
}

pub(super) fn qdrant_fuse_migration_target_is_safe(mode: crate::config::DiskLimitMode) -> bool {
    mode != crate::config::DiskLimitMode::ProjectQuota
}

pub(super) fn legacy_qdrant_container_uses_fuse(
    bound_source: Option<&Path>,
    legacy_mount: &Path,
) -> bool {
    bound_source == Some(legacy_mount)
}

pub(super) struct QdrantMigrationContainer<'a> {
    pub(super) data_path: PathBuf,
    pub(super) image: &'a str,
    pub(super) api_key: &'a str,
    pub(super) container_user: &'a str,
    pub(super) project_id: Option<String>,
}

pub(super) fn qdrant_migration_spec(
    config: &Config,
    metadata: &crate::instances::metadata::InstanceMetadata,
    paths: &InstancePaths,
    container: QdrantMigrationContainer<'_>,
) -> crate::runtime::docker::DockerInstanceSpec {
    let mut spec = crate::databases::qdrant::docker::instance_spec(
        &metadata.instance_id,
        container.image,
        secrecy::SecretString::from(container.api_key.to_string()),
        container.data_path,
        paths.logs.clone(),
        paths.sockets.clone(),
        paths.socket_bridge_binary.clone(),
    );
    spec.project_id = container.project_id;
    spec.user = Some(container.container_user.to_string());
    spec.cpu_cores = metadata.limits.cpu_cores;
    spec.memory_mib = metadata.limits.memory_mib;
    spec.disk_mib = metadata.limits.disk_mib;
    spec.pids_limit = Some(
        config
            .security
            .pids_limits
            .qdrant
            .unwrap_or(config.security.pids_limit),
    );
    spec
}

pub(super) async fn start_known_instances_on_boot(
    config: &Config,
    manager: &InstanceManager,
    docker: &DockerRuntime,
    instance_locks: &crate::instances::locks::InstanceLocks,
) -> anyhow::Result<()> {
    let instances = manager.store().list().await;
    let outcomes = futures::stream::iter(instances)
        .map(|snapshot| async move {
            start_known_instance_on_boot(config, manager, docker, instance_locks, snapshot).await
        })
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut attempted = 0_usize;
    let mut running = 0_usize;
    let mut stopped = 0_usize;
    let mut failed = 0_usize;
    let mut errors = 0_usize;

    for outcome in outcomes {
        let status = match outcome {
            Ok(Some(status)) => status,
            Ok(None) => continue,
            Err(error) => {
                errors += 1;
                tracing::error!(
                    %error,
                    "managed instance failed background activation during daemon boot; continuing with other instances"
                );
                continue;
            }
        };
        attempted += 1;
        match status {
            InstanceStatus::Booting => {}
            InstanceStatus::Running => running += 1,
            InstanceStatus::Stopped => stopped += 1,
            InstanceStatus::Failed | InstanceStatus::Quarantined => failed += 1,
            InstanceStatus::Creating | InstanceStatus::Deleting => {}
        }
    }

    tracing::info!(
        attempted,
        running,
        stopped,
        failed,
        errors,
        concurrency = MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY,
        "daemon boot managed instance auto-start complete"
    );
    Ok(())
}

pub(super) async fn reconcile_running_cpu_burst_limits(
    manager: &InstanceManager,
    docker: &DockerRuntime,
) {
    let instances = manager
        .store()
        .list()
        .await
        .into_iter()
        .filter(|metadata| metadata.status == InstanceStatus::Running)
        .collect::<Vec<_>>();
    let checked = instances.len();
    let outcomes = futures::stream::iter(instances)
        .map(|metadata| async move {
            let result = docker
                .apply_cpu_burst_policy(metadata.protocol, &metadata.instance_id)
                .await;
            (metadata, result)
        })
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut applied = 0_usize;
    let mut already_configured = 0_usize;
    let mut inactive = 0_usize;
    let mut unsupported = 0_usize;
    let mut failed = 0_usize;
    for (metadata, result) in outcomes {
        match result {
            Ok(CpuBurstPolicyStatus::Applied) => applied += 1,
            Ok(CpuBurstPolicyStatus::AlreadyConfigured) => already_configured += 1,
            Ok(CpuBurstPolicyStatus::Inactive) => inactive += 1,
            Ok(CpuBurstPolicyStatus::Unsupported) => unsupported += 1,
            Err(error) => {
                failed += 1;
                tracing::warn!(
                    event = "cpu_burst_policy_reconciliation_failed",
                    instance_id = %metadata.instance_id,
                    protocol = %metadata.protocol,
                    %error,
                    "failed to reconcile CPU burst credit; the normal CPU quota remains active"
                );
            }
        }
    }
    if unsupported > 0 {
        tracing::warn!(
            unsupported,
            "host cgroups do not expose CFS burst control for some running instances; their normal CPU quotas remain active"
        );
    }
    tracing::info!(
        checked,
        applied,
        already_configured,
        inactive,
        unsupported,
        failed,
        "managed container CPU burst policy reconciliation complete"
    );
}

pub(super) async fn start_known_instance_on_boot(
    config: &Config,
    manager: &InstanceManager,
    docker: &DockerRuntime,
    instance_locks: &crate::instances::locks::InstanceLocks,
    snapshot: crate::instances::metadata::InstanceMetadata,
) -> anyhow::Result<Option<InstanceStatus>> {
    let Some(snapshot_action) = managed_boot_action(snapshot.status, snapshot.desired_state) else {
        return Ok(None);
    };

    let _operation = instance_locks.lock(&snapshot.instance_id).await;
    let Some(mut metadata) = manager.store().get(&snapshot.instance_id).await else {
        return Ok(None);
    };
    let Some(action) = managed_boot_action(metadata.status, metadata.desired_state) else {
        return Ok(None);
    };
    if action != snapshot_action {
        tracing::debug!(
            instance_id = %metadata.instance_id,
            snapshot_action = snapshot_action.as_str(),
            action = action.as_str(),
            "managed instance boot action changed after acquiring its operation lock"
        );
    }

    tracing::info!(
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        previous_status = ?metadata.status,
        action = action.as_str(),
        "activating managed instance on daemon boot"
    );

    let mut boot_failed = false;
    let mut disk_blocked = false;
    let mut disk_bind_blocked = false;
    if let Err(error) =
        ensure_instance_runtime_paths(config, docker, metadata.protocol, &metadata.instance_id)
            .await
    {
        boot_failed = true;
        tracing::warn!(
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            %error,
            "failed to prepare managed instance runtime directories during daemon boot; skipping container start"
        );
    } else {
        let paths = InstancePaths::new(&config.paths, &metadata.instance_id)
            .with_context(|| format!("failed to build paths for {}", metadata.instance_id))?;
        let disk_limiter =
            DiskLimiter::with_fuse_root(config.disk.clone(), config.paths.fuse_root())
                .for_persisted_protocol(
                    metadata.protocol,
                    &metadata.limits.disk_enforcement_method,
                );
        let expected_data_source = disk_limiter.container_data_path(&paths.data)?;
        if let Err(error) = docker
            .verify_container_data_bind(
                metadata.protocol,
                &metadata.instance_id,
                &expected_data_source,
            )
            .await
        {
            boot_failed = true;
            disk_bind_blocked = true;
            tracing::error!(
                event = "audit disk_limit_bind_boot_blocked",
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                %error,
                "refused to activate an instance whose container data bind does not match the selected disk enforcement"
            );
        }
        let scanner_required = crate::disk::soft::SoftDiskLimiter::enforcement_required(
            config.disk.mode,
            metadata.protocol,
        ) || (metadata.protocol == Protocol::Qdrant
            && metadata.limits.disk_enforcement_method == "fuse_quota");
        if !disk_bind_blocked && scanner_required {
            let soft_limiter =
                crate::disk::soft::SoftDiskLimiter::new(config.disk.soft_scanner.clone());
            match soft_limiter
                .ensure_start_allowed(&crate::disk::soft::SoftDiskTarget {
                    instance_id: metadata.instance_id.clone(),
                    created_at: metadata.created_at.clone(),
                    protocol: metadata.protocol,
                    data_path: paths.data.clone(),
                    limit_bytes: metadata.limits.disk_mib.saturating_mul(1024 * 1024),
                    durable_blocked: metadata.disk_limit_blocked,
                })
                .await
            {
                Ok(snapshot) => {
                    if metadata.disk_limit_blocked && !snapshot.blocked {
                        metadata.disk_limit_blocked = false;
                        metadata.updated_at = now_rfc3339();
                    }
                }
                Err(error) => {
                    boot_failed = true;
                    disk_blocked = true;
                    metadata.disk_limit_blocked = true;
                    tracing::error!(
                        event = "audit soft_disk_boot_blocked",
                        instance_id = %metadata.instance_id,
                        protocol = %metadata.protocol,
                        %error,
                        "refused to activate an instance whose data is above the soft disk threshold or could not be measured safely"
                    );
                }
            }
        }
        if disk_bind_blocked || disk_blocked {
            // The preflight already emitted an actionable audit event and the
            // durable stopped state is persisted below.
        } else if let Err(error) = disk_limiter
            .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
            .await
        {
            boot_failed = true;
            tracing::warn!(
                instance_id = %metadata.instance_id,
                protocol = %metadata.protocol,
                %error,
                "failed to prepare managed instance disk limit during daemon boot; skipping container activation"
            );
        } else {
            let activation = match action {
                ManagedBootAction::Start => {
                    docker.start(metadata.protocol, &metadata.instance_id).await
                }
                ManagedBootAction::Restart => {
                    docker
                        .restart(metadata.protocol, &metadata.instance_id)
                        .await
                }
            };
            match activation {
                Ok(_) => {
                    if let Err(error) = docker
                        .wait_until_ready(
                            metadata.protocol,
                            &metadata.instance_id,
                            Duration::from_secs(180),
                        )
                        .await
                    {
                        boot_failed = true;
                        log_boot_container_failure(
                            docker,
                            metadata.protocol,
                            &metadata.instance_id,
                            "managed instance did not become ready during daemon boot",
                            error.to_string(),
                        )
                        .await;
                    }
                }
                Err(error) => {
                    boot_failed = true;
                    log_boot_container_failure(
                        docker,
                        metadata.protocol,
                        &metadata.instance_id,
                        "failed to activate managed instance during daemon boot",
                        error.to_string(),
                    )
                    .await;
                }
            }
        }
    }

    if boot_failed
        && let Err(error) = docker.stop(metadata.protocol, &metadata.instance_id).await
        && !error.is_not_running()
        && !error.is_not_found()
    {
        tracing::error!(
            event = "audit boot_activation_cleanup_failed",
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            %error,
            "database activation failed during daemon boot and the container could not be stopped"
        );
    }

    let mut reconciled = reconcile::reconcile_one(metadata, docker).await;
    if disk_bind_blocked {
        reconciled.desired_state = crate::instances::metadata::DesiredInstanceState::Stopped;
        reconciled.status = InstanceStatus::Failed;
        reconciled.updated_at = now_rfc3339();
    } else if disk_blocked {
        reconciled.desired_state = crate::instances::metadata::DesiredInstanceState::Stopped;
        reconciled.status = InstanceStatus::Stopped;
        reconciled.updated_at = now_rfc3339();
    } else if boot_failed {
        reconciled.status = InstanceStatus::Failed;
        reconciled.updated_at = now_rfc3339();
    }
    let status = reconciled.status;
    manager.upsert(reconciled).await?;
    Ok(Some(status))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ManagedBootAction {
    Start,
    Restart,
}

impl ManagedBootAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Restart => "restart",
        }
    }
}

pub(super) fn managed_boot_action(
    status: InstanceStatus,
    desired_state: crate::instances::metadata::DesiredInstanceState,
) -> Option<ManagedBootAction> {
    if desired_state == crate::instances::metadata::DesiredInstanceState::Stopped {
        return None;
    }
    match status {
        InstanceStatus::Stopped => Some(ManagedBootAction::Start),
        InstanceStatus::Failed => Some(ManagedBootAction::Restart),
        InstanceStatus::Creating
        | InstanceStatus::Booting
        | InstanceStatus::Running
        | InstanceStatus::Quarantined
        | InstanceStatus::Deleting => None,
    }
}

pub(super) async fn log_boot_container_failure(
    docker: &DockerRuntime,
    protocol: Protocol,
    instance_id: &str,
    message: &'static str,
    error: String,
) {
    let recent_container_logs = match docker.logs(protocol, instance_id, None).await {
        Ok(output) => {
            let combined = format!("{}{}", output.stdout, output.stderr);
            truncate_log_tail(combined.trim(), 4_000)
        }
        Err(log_error) => format!("failed to read container logs: {log_error}"),
    };

    tracing::warn!(
        instance_id,
        protocol = %protocol,
        reason = message,
        %error,
        %recent_container_logs,
        "managed instance boot start failed"
    );
}
