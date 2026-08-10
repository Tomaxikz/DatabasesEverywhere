use super::*;

pub(super) async fn run_daemon(config_path: PathBuf) -> anyhow::Result<()> {
    let mut config = load_config(&config_path)?;
    let runtime_directories = ensure_runtime_directories(&config)
        .await
        .context("failed to create runtime directories")?;
    let _daemon_lock = acquire_configured_daemon_lock(&config).await?;
    init_configured_logging(&config)?;
    warn_if_memory_overcommit_disabled();
    detect_and_log_disk_mode(&mut config)?;
    let config = Arc::new(config);
    let socket_bridge_helper = crate::runtime::socket_bridge::install_helper(&config.paths)
        .await
        .context("failed to install the container socket bridge helper")?;
    tracing::info!("\n{}", startup_banner());
    for directory in runtime_directories {
        tracing::info!(
            path = %directory.path,
            existed = directory.existed,
            "runtime directory ready"
        );
    }
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %config_path.display(),
        logs = %config.paths.logs,
        uuid = %config.uuid,
        token_id = %config.token_id,
        remote = %config.remote,
        api_bind = %config.api.bind_addr(),
        api_host = %config.api.host,
        api_port = config.api.port,
        api_ssl = config.api.ssl.enabled,
        "DatabasesEverywhere daemon starting"
    );
    tracing::info!(
        path = %Path::new(&config.paths.locks).join(DAEMON_LOCK_FILE).display(),
        "exclusive daemon lock acquired"
    );
    tracing::info!(
        path = %socket_bridge_helper.display(),
        "private container socket bridge helper ready"
    );
    log_boot_configuration(&config, &config_path);
    ensure_fuse_quota_host_config(&config)
        .context("failed to prepare fuse quota host configuration")?;
    tracing::info!("runtime preflight starting");
    validate_runtime_support(&config).await?;
    tracing::info!(
        mode = %config.disk.mode.method(),
        enforced = config.disk.mode.enforced(),
        data_path = %config.paths.data,
        "disk limiter preflight ok"
    );
    let backup_storage = crate::backups::BackupStorage::from_config(&config)
        .context("failed to configure backup storage")?;
    backup_storage
        .preflight()
        .await
        .context("backup storage preflight failed")?;
    let backups_root = config.paths.backups_root();
    if crate::backups::cleanup_staging(Path::new(&backups_root))
        .await
        .context("failed to clean incomplete backup staging")?
    {
        tracing::info!("removed incomplete backup staging from an earlier daemon run");
    }
    let tmp_root = config.paths.tmp_root();
    let removed_materialization_roots =
        crate::backups::cleanup_materializations(Path::new(&tmp_root))
            .await
            .context("failed to clean incomplete backup materializations")?;
    if removed_materialization_roots > 0 {
        tracing::info!(
            removed_materialization_roots,
            "removed incomplete backup materializations from an earlier daemon run"
        );
    }
    tracing::info!(
        driver = backup_storage.kind().as_str(),
        "backup storage preflight ok"
    );

    let store = InstanceStore::default();
    let pool = sqlite::connect(std::path::Path::new(&config.paths.metadata_root()))
        .await
        .context("failed to initialize sqlite storage")?;
    let metadata_root = config.paths.metadata_root();
    tracing::info!(path = %metadata_root, "sqlite metadata storage ready");
    let repository = InstanceRepository::encrypted(pool.clone(), Path::new(&metadata_root))
        .context("failed to initialize encrypted metadata secret storage")?;
    let job_repository = ImportExportJobRepository::new(pool.clone());
    let interrupted_running_import_instances =
        job_repository
            .running_import_instance_ids()
            .await
            .context("failed to identify interrupted running import jobs")?;
    let failed_jobs = job_repository
        .fail_unfinished(
            "daemon restarted before import/export job completed",
            &crate::jobs::import_export::now_rfc3339(),
        )
        .await
        .context("failed to reconcile import/export jobs")?;
    if failed_jobs > 0 {
        tracing::warn!(failed_jobs, "marked unfinished import/export jobs failed");
    }
    let job_repository_for_prune = job_repository.clone();
    let import_export_jobs = ImportExportJobs::with_repository(job_repository);
    let import_uploads = crate::api::import_export::ImportUploadService::new(
        ImportUploadRepository::new(pool.clone()),
        config.artifacts.import_upload_max_concurrent,
    );
    let manager = InstanceManager::new(store.clone(), repository);
    manager
        .load_from_storage()
        .await
        .context("failed to load local instance metadata from sqlite")?;
    let quarantined_interrupted_instances =
        quarantine_interrupted_job_instances(&manager, &interrupted_running_import_instances)
            .await?;
    if quarantined_interrupted_instances > 0 {
        tracing::warn!(
            quarantined_interrupted_instances,
            "quarantined instances with mutating import jobs interrupted by an unclean shutdown"
        );
    }
    let volumes_root = config.paths.volumes_root();
    let quarantined_physical_restore_instances =
        quarantine_retained_physical_restore_workspaces(&manager, Path::new(&volumes_root))
            .await
            .context("failed to quarantine instances with retained physical restore workspaces")?;
    if quarantined_physical_restore_instances > 0 {
        tracing::warn!(
            quarantined_physical_restore_instances,
            "quarantined instances with retained physical restore rollback state"
        );
    }
    let quarantined_recovery_instances = quarantine_retained_import_recovery_manifests(
        &manager,
        Path::new(&config.paths.tmp_root()),
    )
    .await
    .context("failed to quarantine instances with retained import recovery manifests")?;
    if quarantined_recovery_instances > 0 {
        tracing::warn!(
            quarantined_recovery_instances,
            "quarantined instances with retained import recovery manifests"
        );
    }
    let import_temp_cleanup =
        cleanup_orphaned_import_export_staging(Path::new(&config.paths.tmp_root()))
            .await
            .context("failed to clean orphaned logical import staging")?;
    tracing::info!(
        scanned_entries = import_temp_cleanup.scanned_entries,
        removed_files = import_temp_cleanup.removed_files,
        removed_directories = import_temp_cleanup.removed_directories,
        protected_rollbacks = import_temp_cleanup.protected_rollbacks,
        skipped_entries = import_temp_cleanup.skipped_entries,
        "orphaned logical import staging cleanup complete"
    );

    let mut docker = DockerRuntime::new(&config.daemon, false)
        .context("failed to connect to container engine API")?
        .with_node_id(config.uuid.clone());
    docker
        .refresh_engine_info()
        .await
        .context("failed to negotiate and validate the configured container engine")?;
    let docker_ping = docker
        .ping()
        .await
        .context("failed to ping container engine API")?;
    prepare_rootless_podman_runtime_paths(&config, &docker)
        .context("failed to prepare rootless Podman bind-mount paths")?;
    reconcile::validate_configured_runtime(&manager, &docker)
        .await
        .context("configured container engine is incompatible with stored instances")?;
    let remote_import_helper_reconciliation = docker.reconcile_remote_import_helpers().await;
    match &remote_import_helper_reconciliation {
        Ok(reconciled_remote_import_helpers) if *reconciled_remote_import_helpers > 0 => {
            tracing::warn!(
                reconciled_remote_import_helpers = *reconciled_remote_import_helpers,
                "removed stale remote import helper containers"
            );
        }
        Ok(_) => {}
        Err(error) => {
            tracing::error!(
                %error,
                "failed to reconcile stale remote import helper containers; credential cleanup will still run before startup aborts"
            );
        }
    }
    let remote_import_tmp_root = PathBuf::from(config.paths.tmp_root());
    let remove_orphaned_remote_import_staging = remote_import_helper_reconciliation.is_ok();
    let stale_credential_cleanup =
        crate::api::remote_import::cleanup_stale_remote_import_credentials(
            &remote_import_tmp_root,
            remove_orphaned_remote_import_staging,
        )
        .await;
    if stale_credential_cleanup.errors > 0 {
        tracing::warn!(
            scanned_entries = stale_credential_cleanup.scanned_entries,
            job_directories = stale_credential_cleanup.job_directories,
            removed_files = stale_credential_cleanup.removed_files,
            removed_directories = stale_credential_cleanup.removed_directories,
            skipped_entries = stale_credential_cleanup.skipped_entries,
            errors = stale_credential_cleanup.errors,
            limit_reached = stale_credential_cleanup.limit_reached,
            "stale remote import credential cleanup completed with errors"
        );
    } else {
        tracing::info!(
            scanned_entries = stale_credential_cleanup.scanned_entries,
            job_directories = stale_credential_cleanup.job_directories,
            removed_files = stale_credential_cleanup.removed_files,
            removed_directories = stale_credential_cleanup.removed_directories,
            skipped_entries = stale_credential_cleanup.skipped_entries,
            "stale remote import credential cleanup completed"
        );
    }
    remote_import_helper_reconciliation
        .context("failed to reconcile stale remote import helper containers")?;
    tracing::info!(
        engine = %docker.engine_name(),
        socket = %docker.socket_path(),
        rootless_podman = docker.uses_rootless_podman(),
        engine_version = docker.engine_version().unwrap_or("unknown"),
        engine_api_version = docker.engine_api_version().unwrap_or("unknown"),
        cgroup_version = docker.cgroup_version().unwrap_or("unknown"),
        response = %docker_ping,
        "container engine api reachable"
    );
    tracing::info!(
        engine = %docker.engine_name(),
        "database containers will run with network_mode=none and private Unix sockets"
    );
    let disk_limiter = DiskLimiter::with_fuse_root(config.disk.clone(), config.paths.fuse_root());
    disk_limiter
        .verify_startup(std::path::Path::new(&volumes_root))
        .await
        .context("failed to verify disk limiter support")?;
    reapply_instance_disk_limits(&config, &manager, &docker, &disk_limiter)
        .await
        .context("failed to reapply instance disk limits")?;
    tracing::info!("instance disk limits reconciled");
    let reconcile_summary = reconcile::reconcile_all(&manager, &docker)
        .await
        .context("failed to reconcile instance metadata")?;
    tracing::info!(
        checked = reconcile_summary.checked,
        booting = reconcile_summary.booting,
        running = reconcile_summary.running,
        stopped = reconcile_summary.stopped,
        failed = reconcile_summary.failed,
        quarantined = reconcile_summary.quarantined,
        "instance metadata reconciled"
    );
    let shutdown_jobs = import_export_jobs.clone();
    let install_progress = InstallProgressStore::default();
    let shutdown_creations = install_progress.clone();
    let instance_locks = crate::instances::locks::InstanceLocks::default();
    let state = AppState::new(AppStateData {
        config: config.clone(),
        config_path: config_path.clone(),
        config_patches: crate::api::config_admin::ConfigPatchCoordinator::default(),
        api_token: ApiToken::from_config(&config),
        instances: store,
        manager,
        docker,
        import_export_jobs,
        import_uploads,
        instance_locks,
        api_rate_limiter: crate::api::security::ApiRateLimiter::new(
            config.security.api_rate_limit_per_minute,
        ),
        install_progress,
        artifact_downloads: crate::api::artifacts::ArtifactDownloadTickets::default(),
        resource_cache: crate::api::resources::ResourceCache::default(),
        soft_disk_limiter: crate::disk::soft::SoftDiskLimiter::new(
            config.disk.soft_scanner.clone(),
        ),
        monitoring_cache: crate::api::websocket::MonitoringSnapshotCache::default(),
        instance_runtime_cache: crate::api::instances::InstanceRuntimeInfoCache::default(),
        gateway_supervisor: GatewaySupervisor::new(),
        daemon_shutdown: crate::api::routes::DaemonShutdown::default(),
    });
    let upload_recovery = crate::api::import_export::reconcile_import_uploads_once(&state)
        .await
        .context("failed to reconcile temporary import uploads")?;
    if upload_recovery.examined > 0 || upload_recovery.failures > 0 {
        tracing::info!(
            examined = upload_recovery.examined,
            restored_ready = upload_recovery.restored_ready,
            blocked = upload_recovery.blocked,
            deleted = upload_recovery.deleted,
            failures = upload_recovery.failures,
            "temporary import upload recovery completed"
        );
    }
    let pruned_jobs = job_repository_for_prune
        .prune_completed(10_000)
        .await
        .context("failed to prune completed import/export jobs during startup")?;
    if pruned_jobs > 0 {
        tracing::info!(pruned_jobs, "pruned old completed import/export jobs");
    }
    crate::api::resources::start_resource_sampler(state.clone());
    let import_upload_sweeper = tokio::spawn(crate::api::import_export::run_import_upload_sweeper(
        state.clone(),
    ));
    let soft_disk_limits = tokio::spawn(monitor_soft_disk_limits(state.clone()));
    tracing::info!(
        "critical startup complete; API will accept requests while managed instances start in the background"
    );
    let managed_container_events = tokio::spawn(monitor_managed_container_events(state.clone()));
    let managed_runtime_boot = tokio::spawn(complete_managed_runtime_boot(state.clone()));
    let gateway_supervisor = state.gateway_supervisor.clone();
    let daemon_shutdown = state.daemon_shutdown.clone();
    let server_result = serve_api(
        &config,
        build_router(state.clone()),
        shutdown_jobs.clone(),
        shutdown_creations.clone(),
        state.api_rate_limiter.clone(),
        daemon_shutdown.clone(),
        gateway_supervisor.clone(),
    )
    .await;
    let shutdown_started = std::time::Instant::now();
    daemon_shutdown.trigger();
    shutdown_jobs.close_admission();
    shutdown_creations.close_creation_admission();
    gateway_supervisor.shutdown();
    tracing::info!(
        phase = "background_stop",
        api_server_error = server_result.is_err(),
        active_import_export_jobs = shutdown_jobs.active_count(),
        active_instance_creations = shutdown_creations.active_creation_count(),
        active_mutations = daemon_shutdown.active_mutation_count(),
        active_websockets = state.api_rate_limiter.active_websocket_count(),
        active_gateway_connections = gateway_supervisor.active_connections(),
        "API listener stopped; shutting down daemon-owned background tasks"
    );
    managed_container_events.abort();
    let _ = managed_container_events.await;
    soft_disk_limits.abort();
    let _ = soft_disk_limits.await;
    import_upload_sweeper.abort();
    let _ = import_upload_sweeper.await;
    managed_runtime_boot.abort();
    let _ = managed_runtime_boot.await;
    let (jobs_drained, creations_drained, mutations_drained, websocket_drained, gateway_drain) = tokio::join!(
        shutdown_jobs.wait_for_drain(ACTIVE_OPERATION_DRAIN_TIMEOUT),
        shutdown_creations.wait_for_creation_drain(ACTIVE_OPERATION_DRAIN_TIMEOUT),
        daemon_shutdown.wait_for_mutation_drain(API_MUTATION_DRAIN_TIMEOUT),
        state
            .api_rate_limiter
            .wait_for_websocket_drain(WEBSOCKET_DRAIN_TIMEOUT),
        gateway_supervisor.drain_connections(
            GATEWAY_CONNECTION_DRAIN_TIMEOUT,
            GATEWAY_CONNECTION_FORCE_CLOSE_TIMEOUT,
        ),
    );
    tracing::info!(
        phase = "drain_complete",
        elapsed_ms = shutdown_started.elapsed().as_millis(),
        jobs_drained,
        creations_drained,
        mutations_drained,
        websocket_drained,
        gateway_connections_at_start = gateway_drain.active_at_start,
        gateway_connections_remaining = gateway_drain.remaining,
        gateway_connections_gracefully_drained = gateway_drain.gracefully_drained,
        "daemon shutdown drain finished; managed database containers were not stopped"
    );
    if !jobs_drained {
        anyhow::bail!(
            "timed out after {} seconds waiting for import/export jobs to finish safely",
            ACTIVE_OPERATION_DRAIN_TIMEOUT.as_secs()
        );
    }
    if !creations_drained {
        anyhow::bail!(
            "timed out after {} seconds waiting for instance creations to finish safely",
            ACTIVE_OPERATION_DRAIN_TIMEOUT.as_secs()
        );
    }
    if !mutations_drained {
        anyhow::bail!(
            "timed out after {} seconds waiting for active API mutations to finish",
            API_MUTATION_DRAIN_TIMEOUT.as_secs()
        );
    }
    tracing::info!("active import/export jobs drained");
    tracing::info!("active instance creations drained");
    server_result
}
