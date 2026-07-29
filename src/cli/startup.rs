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
        api_port = config.api.port,
        remote = %config.remote,
        cors_allowed_hosts = ?config.cors_allowed_hosts(),
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
            port = config.api.port,
            "api binds all local interfaces; clients should use the configured DNS name or server IP"
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
        tracing::warn!(
            "api tls disabled; use this only behind a trusted TLS reverse proxy or on a private network"
        );
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
            let paths = InstancePaths::new(&config.paths, &metadata.instance_id)
                .with_context(|| format!("failed to build paths for {}", metadata.instance_id))?;
            if !disk_limiter
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
            disk_limiter
                .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
                .await
                .with_context(|| {
                    format!("failed to apply disk limit for {}", metadata.instance_id)
                })?;
            Ok::<(), anyhow::Error>(())
        })
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    for outcome in outcomes {
        outcome?;
    }
    Ok(())
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

    for outcome in outcomes {
        let Some(status) = outcome? else {
            continue;
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
        concurrency = MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY,
        "daemon boot managed instance auto-start complete"
    );
    Ok(())
}

pub(super) async fn start_known_instance_on_boot(
    config: &Config,
    manager: &InstanceManager,
    docker: &DockerRuntime,
    instance_locks: &crate::instances::locks::InstanceLocks,
    snapshot: crate::instances::metadata::InstanceMetadata,
) -> anyhow::Result<Option<InstanceStatus>> {
    let Some(snapshot_action) = managed_boot_action(snapshot.status) else {
        return Ok(None);
    };

    let _operation = instance_locks.lock(&snapshot.instance_id).await;
    let Some(metadata) = manager.store().get(&snapshot.instance_id).await else {
        return Ok(None);
    };
    let Some(action) = managed_boot_action(metadata.status) else {
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
    let mut startup_readiness_failed = false;
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
                    startup_readiness_failed = true;
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

    if startup_readiness_failed
        && let Err(error) = docker.stop(metadata.protocol, &metadata.instance_id).await
        && !error.is_not_running()
        && !error.is_not_found()
    {
        tracing::error!(
            event = "audit boot_readiness_cleanup_failed",
            instance_id = %metadata.instance_id,
            protocol = %metadata.protocol,
            %error,
            "database failed startup readiness during daemon boot and could not be stopped"
        );
    }

    let mut reconciled = reconcile::reconcile_one(metadata, docker).await;
    if boot_failed {
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

pub(super) fn managed_boot_action(status: InstanceStatus) -> Option<ManagedBootAction> {
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
