use super::*;

pub(super) async fn update_instance_image_by_major_migration(
    state: &AppState,
    mut metadata: InstanceMetadata,
    current_image: String,
    image: String,
    password: Option<String>,
) -> Result<UpdateInstanceImageResponse, ApiError> {
    ensure_major_upgrade_supported(metadata.protocol)
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    let password = password.ok_or_else(|| {
        fail_image_update_api(
            state,
            &metadata.instance_id,
            ApiError::BadRequest(
                "password is required for major upgrade migration because DBE does not store tenant database passwords".to_string(),
            ),
        )
    })?;
    state
        .install_progress
        .begin_major_upgrade(&metadata.instance_id, metadata.protocol, &image);
    let precheck = precheck_major_upgrade(state, &metadata, &current_image, &image)
        .await
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    state.install_progress.stage(
        &metadata.instance_id,
        "export",
        "exporting old database before major upgrade",
    );
    let export_artifact = crate::api::import_export::export_instance_to_default_artifact(
        state,
        &metadata.instance_id,
    )
    .await
    .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    metadata.runtime.network_mode = "none".to_string();

    let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
        .map_err(|error| fail_image_update_bad_request(state, &metadata.instance_id, error))?;
    let rollback = MajorUpgradeRollback {
        metadata: metadata.clone(),
        old_image: current_image.clone(),
        password: password.clone(),
        paths: paths.clone(),
    };

    let staged =
        create_staged_replacement_and_import(state, &metadata, &image, &password, &export_artifact)
            .await
            .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;

    state.install_progress.stage(
        &metadata.instance_id,
        "cutover",
        "validated replacement; stopping old container for final cutover",
    );
    let old_volume_backup = old_volume_backup_path(&paths.data)?;
    stop_and_delete_container(state, metadata.protocol, &metadata.instance_id)
        .await
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    rename_path(&paths.data, &old_volume_backup)
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
        .purge_instance_data(&paths.data)
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    if let Err(error) =
        move_staged_replacement_into_place(state, &metadata, &paths, &staged, &image, &password)
            .await
    {
        let rollback_error = rollback
            .restore(state, &old_volume_backup)
            .await
            .err()
            .map(|rollback_error| rollback_error.to_string());
        let message = match rollback_error {
            Some(rollback_error) => {
                format!("major upgrade failed: {error}; rollback also failed: {rollback_error}")
            }
            None => format!("major upgrade failed and old container was restored: {error}"),
        };
        return Err(fail_image_update_runtime(
            state,
            &metadata.instance_id,
            message,
        ));
    }
    metadata.backend =
        backend_endpoint_for_instance(state, metadata.protocol, &metadata.instance_id)
            .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    metadata.runtime.network_mode = "none".to_string();
    if metadata.protocol == Protocol::Mariadb {
        metadata.mariadb_native_password_sha1_stage2 = Some(
            crate::protocols::mariadb::native_password_sha1_stage2_hex(&password),
        );
    }
    if metadata.protocol == Protocol::Mysql {
        metadata.mysql_native_password_sha1_stage2 = Some(
            crate::protocols::mariadb::native_password_sha1_stage2_hex(&password),
        );
    }

    metadata.status = InstanceStatus::Running;
    metadata.updated_at = now_rfc3339();
    state
        .manager
        .upsert(metadata.clone())
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    state
        .instance_runtime_cache
        .remove(&metadata.instance_id)
        .await;
    state.install_progress.complete(
        &metadata.instance_id,
        "major upgrade migration completed; old volume retained for rollback",
    );

    tracing::info!(
        event = "audit instance_major_upgrade_completed",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        from_image = %current_image,
        to_image = %image,
        export_artifact = %export_artifact.display(),
        old_volume_backup = %old_volume_backup.display(),
    );

    Ok(UpdateInstanceImageResponse {
        instance: metadata,
        image,
        recreated: true,
        strategy: ImageUpdateStrategy::MajorUpgradeMigration,
        warnings: {
            let mut warnings = precheck.warnings;
            warnings.extend([
                "major upgrade used export/import migration instead of reusing the old data volume"
                    .to_string(),
                "old volume backup was kept on disk for manual rollback until the admin removes it"
                    .to_string(),
            ]);
            warnings
        },
        export_artifact_id: export_artifact
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string),
        old_volume_backup_retained: true,
    })
}

pub(super) async fn precheck_major_upgrade(
    state: &AppState,
    metadata: &InstanceMetadata,
    current_image: &str,
    requested_image: &str,
) -> Result<MajorUpgradePrecheck, ApiError> {
    state.install_progress.stage(
        &metadata.instance_id,
        "precheck",
        "checking major upgrade compatibility",
    );
    ensure_major_upgrade_supported(metadata.protocol)?;
    let inspection = state
        .docker
        .inspect_instance(metadata.protocol, &metadata.instance_id)
        .await
        .map_err(docker_error)?;
    if inspection.status != DockerContainerStatus::Running {
        return Err(ApiError::BadRequest(format!(
            "major upgrade requires a running healthy source container; current status is {:?}, health={:?}",
            inspection.status, inspection.health
        )));
    }

    let current_major = image_major_version(current_image).ok_or_else(|| {
        ApiError::BadRequest(format!(
            "{} major upgrade cannot compare current image tag {current_image:?}; use pinned semver-like tags for existing instances",
            metadata.protocol
        ))
    })?;
    let requested_major = image_major_version(requested_image).ok_or_else(|| {
        ApiError::BadRequest(format!(
            "{} major upgrade cannot compare requested image tag {requested_image:?}; use pinned semver-like tags for existing instances",
            metadata.protocol
        ))
    })?;
    validate_major_upgrade_path(metadata.protocol, current_major, requested_major)?;

    let mut warnings = Vec::new();
    if current_major == requested_major {
        warnings.push(format!(
            "requested image has the same major version as current image ({current_major}); DBE still rebuilt the instance because major_upgrade=true"
        ));
    }
    if metadata.protocol == Protocol::Mongodb {
        precheck_mongodb_major_upgrade(state, metadata, current_major, requested_major).await?;
    } else {
        warnings.push(format!(
            "{} major upgrade uses logical dump/import; test application compatibility before upgrading production workloads",
            metadata.protocol
        ));
    }

    tracing::info!(
        event = "audit instance_major_upgrade_precheck_passed",
        instance_id = %metadata.instance_id,
        protocol = %metadata.protocol,
        current_image,
        requested_image,
        current_major,
        requested_major,
    );
    Ok(MajorUpgradePrecheck { warnings })
}

pub(super) fn validate_major_upgrade_path(
    protocol: Protocol,
    current_major: u64,
    requested_major: u64,
) -> Result<(), ApiError> {
    if requested_major < current_major {
        return Err(ApiError::BadRequest(format!(
            "{protocol} image downgrade is blocked: current major is {current_major}, requested major is {requested_major}. Restore an older-version backup into a new instance instead."
        )));
    }
    if protocol == Protocol::Mongodb && requested_major > current_major + 1 {
        return Err(ApiError::BadRequest(format!(
            "mongodb major upgrade cannot skip versions: current major is {current_major}, requested major is {requested_major}. Upgrade one major version at a time."
        )));
    }
    Ok(())
}

pub(super) async fn precheck_mongodb_major_upgrade(
    state: &AppState,
    metadata: &InstanceMetadata,
    current_major: u64,
    requested_major: u64,
) -> Result<(), ApiError> {
    if metadata.mongodb_root_password.is_none() {
        return Err(ApiError::BadRequest(
            "mongodb internal root password is missing; this instance was created before DBE stored MongoDB maintenance credentials, so automatic major upgrades cannot safely dump protected internal collections. Recreate the instance or restore from a manual admin dump.".to_string(),
        ));
    }
    let fcv = mongodb_feature_compatibility_major(state, metadata).await?;
    if requested_major > fcv + 1 {
        return Err(ApiError::BadRequest(format!(
            "mongodb featureCompatibilityVersion blocks this upgrade: FCV major is {fcv}, requested image major is {requested_major}. Upgrade one major version at a time and let FCV advance before the next major upgrade."
        )));
    }
    if fcv > current_major {
        return Err(ApiError::BadRequest(format!(
            "mongodb featureCompatibilityVersion {fcv} is newer than current image major {current_major}; refusing upgrade because the source state is inconsistent"
        )));
    }
    Ok(())
}

pub(super) async fn mongodb_feature_compatibility_major(
    state: &AppState,
    metadata: &InstanceMetadata,
) -> Result<u64, ApiError> {
    let output = state
        .docker
        .exec_shell(
            Protocol::Mongodb,
            &metadata.instance_id,
            r#"mongosh --quiet --host 127.0.0.1 --username "$DBE_MONGO_ROOT_USER" --password "$DBE_MONGO_ROOT_PASSWORD" --authenticationDatabase admin admin --eval 'const f=db.adminCommand({getParameter:1, featureCompatibilityVersion:1}).featureCompatibilityVersion || {}; print(f.version || f.targetVersion || "")'"#,
        )
        .await
        .map_err(|error| {
            ApiError::BadRequest(format!(
                "failed to read mongodb featureCompatibilityVersion with DBE maintenance credentials: {error}"
            ))
        })?;
    parse_major_version_value(output.stdout.trim()).ok_or_else(|| {
        ApiError::BadRequest(
            "failed to parse mongodb featureCompatibilityVersion from source container".to_string(),
        )
    })
}

pub(super) async fn create_empty_replacement_and_import(
    state: &AppState,
    metadata: &mut InstanceMetadata,
    paths: &InstancePaths,
    image: &str,
    password: &str,
    export_artifact: &std::path::Path,
) -> Result<(), ApiError> {
    state.install_progress.stage(
        &metadata.instance_id,
        "prepare_replacement",
        "creating fresh data directory for target major version",
    );
    paths
        .create_dirs()
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    let container_user = prepare_instance_container_user(&state.docker, paths, metadata.protocol)
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;

    let disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root());
    let disk = disk_limiter
        .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    let container_data_path = disk.container_data_path.unwrap_or(paths.data.clone());
    let mut spec = instance_image_update_spec(
        metadata,
        paths,
        container_data_path,
        image,
        Some(password.to_string()),
        protocol_pids_limit(state, metadata.protocol),
    )
    .await
    .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    spec.user = Some(container_user);
    let progress = state.install_progress.clone();
    let progress_instance_id = metadata.instance_id.clone();
    let pull_progress = move |event| progress.docker_pull(&progress_instance_id, event);
    state
        .docker
        .pull_image_with_progress(image, &pull_progress)
        .await
        .map_err(docker_error)
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    launch_container_from_spec(
        state,
        &spec,
        metadata.protocol,
        &metadata.instance_id,
        &pull_progress,
        true,
        || async {
            if metadata.protocol == Protocol::Mongodb {
                provision_mongodb_tenant_user(
                    state,
                    &metadata.instance_id,
                    &metadata.database.name,
                    &metadata.database.username,
                    password,
                    metadata.mongodb_root_password.as_deref().ok_or_else(|| {
                        ApiError::BadRequest(
                            "mongodb internal root password is missing; this instance was created before DBE stored MongoDB maintenance credentials, so automatic major upgrades cannot dump protected internal collections. Recreate the instance or restore from a manually created admin dump.".to_string(),
                        )
                    })?,
                )
                .await?;
            }
            Ok(())
        },
    )
    .await
    .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error.into_api_error()))?;

    if metadata.protocol == Protocol::Postgres {
        provision_postgres_tenant_role(
            state,
            &metadata.instance_id,
            &metadata.database.name,
            &metadata.database.username,
        )
        .await
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    }
    if metadata.protocol == Protocol::Mysql {
        provision_mysql_tenant_user(
            state,
            &metadata.instance_id,
            &metadata.database.name,
            &metadata.database.username,
            password,
            metadata.mysql_root_password.as_deref().ok_or_else(|| {
                ApiError::BadRequest(
                    "mysql internal root password is missing; automatic major upgrades require an instance created with MySQL maintenance credentials".to_string(),
                )
            })?,
        )
        .await
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    }

    state.install_progress.stage(
        &metadata.instance_id,
        "import",
        "importing exported data into replacement container",
    );
    crate::api::import_export::import_default_artifact_into_metadata(
        state,
        metadata,
        export_artifact,
    )
    .await
    .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    validate_replacement_instance(state, metadata, password).await?;
    metadata.backend =
        backend_endpoint_for_instance(state, metadata.protocol, &metadata.instance_id)
            .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    if metadata.protocol == Protocol::Mariadb {
        metadata.mariadb_native_password_sha1_stage2 = Some(
            crate::protocols::mariadb::native_password_sha1_stage2_hex(password),
        );
    }
    if metadata.protocol == Protocol::Mysql {
        metadata.mysql_native_password_sha1_stage2 = Some(
            crate::protocols::mariadb::native_password_sha1_stage2_hex(password),
        );
    }
    Ok(())
}

pub(super) struct StagedMajorUpgrade {
    metadata: InstanceMetadata,
    paths: InstancePaths,
}

pub(super) async fn create_staged_replacement_and_import(
    state: &AppState,
    metadata: &InstanceMetadata,
    image: &str,
    password: &str,
    export_artifact: &std::path::Path,
) -> Result<StagedMajorUpgrade, ApiError> {
    state.install_progress.stage(
        &metadata.instance_id,
        "prepare_replacement",
        "creating temporary target-version database for major upgrade",
    );
    let temporary_instance_id = temporary_major_upgrade_instance_id(&metadata.instance_id);
    let staged_paths = InstancePaths::new(&state.config.paths, &temporary_instance_id)
        .map_err(|error| fail_image_update_bad_request(state, &metadata.instance_id, error))?;
    cleanup_temporary_replacement(
        state,
        metadata.protocol,
        &temporary_instance_id,
        &staged_paths,
    )
    .await;

    let mut staged_metadata = metadata.clone();
    staged_metadata.instance_id = temporary_instance_id.clone();
    staged_metadata.status = InstanceStatus::Creating;
    staged_metadata.runtime.container_name = state
        .docker
        .container_name(metadata.protocol, &temporary_instance_id)
        .map_err(docker_error)
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    staged_metadata.updated_at = now_rfc3339();

    match create_empty_replacement_and_import(
        state,
        &mut staged_metadata,
        &staged_paths,
        image,
        password,
        export_artifact,
    )
    .await
    {
        Ok(()) => Ok(StagedMajorUpgrade {
            metadata: staged_metadata,
            paths: staged_paths,
        }),
        Err(error) => {
            cleanup_temporary_replacement(
                state,
                metadata.protocol,
                &temporary_instance_id,
                &staged_paths,
            )
            .await;
            Err(error)
        }
    }
}

pub(super) async fn move_staged_replacement_into_place(
    state: &AppState,
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    staged: &StagedMajorUpgrade,
    image: &str,
    password: &str,
) -> Result<(), ApiError> {
    stop_and_delete_container(
        state,
        staged.metadata.protocol,
        &staged.metadata.instance_id,
    )
    .await
    .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
        .purge_instance_data(&staged.paths.data)
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    cleanup_path_if_exists(&paths.data).await?;
    rename_path(&staged.paths.data, &paths.data)
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    cleanup_temporary_side_paths(&staged.paths).await;
    create_empty_replacement_and_import_without_import(state, metadata, paths, image, password)
        .await
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    Ok(())
}

pub(super) struct MajorUpgradeRollback {
    metadata: InstanceMetadata,
    old_image: String,
    password: String,
    paths: InstancePaths,
}

impl MajorUpgradeRollback {
    async fn restore(
        self,
        state: &AppState,
        old_volume_backup: &std::path::Path,
    ) -> Result<(), ApiError> {
        tracing::warn!(
            event = "audit instance_major_upgrade_rollback_started",
            instance_id = %self.metadata.instance_id,
            protocol = %self.metadata.protocol,
        );
        let _ =
            stop_and_delete_container(state, self.metadata.protocol, &self.metadata.instance_id)
                .await;
        let disk_limiter =
            DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root());
        let _ = disk_limiter.purge_instance_data(&self.paths.data).await;
        cleanup_path_if_exists(&self.paths.data).await?;
        rename_path(old_volume_backup, &self.paths.data)
            .await
            .map_err(|error| ApiError::Runtime(format!("failed to restore old volume: {error}")))?;
        create_empty_replacement_and_import_without_import(
            state,
            &self.metadata,
            &self.paths,
            &self.old_image,
            &self.password,
        )
        .await?;
        state
            .manager
            .upsert(self.metadata.clone())
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        tracing::warn!(
            event = "audit instance_major_upgrade_rollback_completed",
            instance_id = %self.metadata.instance_id,
            protocol = %self.metadata.protocol,
        );
        Ok(())
    }
}

pub(super) async fn create_empty_replacement_and_import_without_import(
    state: &AppState,
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    image: &str,
    password: &str,
) -> Result<(), ApiError> {
    let container_user = prepare_instance_container_user(&state.docker, paths, metadata.protocol)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root());
    let disk = disk_limiter
        .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let container_data_path = disk.container_data_path.unwrap_or(paths.data.clone());
    let mut spec = instance_image_update_spec(
        metadata,
        paths,
        container_data_path,
        image,
        Some(password.to_string()),
        protocol_pids_limit(state, metadata.protocol),
    )
    .await?;
    spec.user = Some(container_user);
    let progress = state.install_progress.clone();
    let progress_instance_id = metadata.instance_id.clone();
    let pull_progress = move |event| progress.docker_pull(&progress_instance_id, event);
    launch_container_from_spec(
        state,
        &spec,
        metadata.protocol,
        &metadata.instance_id,
        &pull_progress,
        true,
        || async { Ok(()) },
    )
    .await
    .map_err(|error| error.into_api_error())?;
    if metadata.protocol == Protocol::Mysql {
        provision_mysql_tenant_user(
            state,
            &metadata.instance_id,
            &metadata.database.name,
            &metadata.database.username,
            password,
            metadata.mysql_root_password.as_deref().ok_or_else(|| {
                ApiError::BadRequest(
                    "mysql internal root password is missing; container recreation requires maintenance credentials".to_string(),
                )
            })?,
        )
        .await?;
    }
    Ok(())
}

pub(super) fn temporary_major_upgrade_instance_id(instance_id: &str) -> String {
    format!(
        "dbe_upgrade_tmp_{}_{}",
        uuid::Uuid::new_v4().simple(),
        instance_id
    )
}

pub(super) async fn cleanup_temporary_replacement(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
    paths: &InstancePaths,
) {
    let _ = stop_and_delete_container(state, protocol, instance_id).await;
    let disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root());
    let _ = disk_limiter.purge_instance_data(&paths.data).await;
    let _ = cleanup_path_if_exists(&paths.data).await;
    cleanup_temporary_side_paths(paths).await;
}

pub(super) async fn cleanup_temporary_side_paths(paths: &InstancePaths) {
    for path in [
        &paths.logs,
        &paths.sockets,
        &paths.artifacts,
        &paths.exports,
        &paths.imports,
        &paths.backups,
        &paths.runtime_config,
    ] {
        let _ = cleanup_path_if_exists(path).await;
    }
}

pub(super) async fn validate_replacement_instance(
    state: &AppState,
    metadata: &InstanceMetadata,
    password: &str,
) -> Result<(), ApiError> {
    state.install_progress.stage(
        &metadata.instance_id,
        "validate",
        "validating replacement database",
    );
    let command = replacement_validation_command(
        metadata.protocol,
        &metadata.database.username,
        &metadata.database.name,
    )?;
    let script = format!(
        "set -eu\nexport DBE_UPGRADE_PASSWORD={}\n{command}",
        crate::shared::shell::sh_quote(password)
    );
    state
        .docker
        .exec_shell(metadata.protocol, &metadata.instance_id, &script)
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    Ok(())
}

pub(super) fn replacement_validation_command(
    protocol: Protocol,
    username: &str,
    database: &str,
) -> Result<String, ApiError> {
    let command = match protocol {
        Protocol::Postgres => "PGPASSWORD=\"${DBE_POSTGRES_PASSWORD:-$POSTGRES_PASSWORD}\" psql -h /var/run/postgresql -U \"${DBE_POSTGRES_USER:-$POSTGRES_USER}\" -d \"$POSTGRES_DB\" -v ON_ERROR_STOP=1 -c 'select 1' >/dev/null".to_string(),
        Protocol::Mariadb => "mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -u \"$MARIADB_USER\" -p\"$MARIADB_PASSWORD\" \"$MARIADB_DATABASE\" -e 'select 1' >/dev/null".to_string(),
        Protocol::Mysql => format!(
            "MYSQL_PWD=\"$DBE_UPGRADE_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u {} {} -e 'select 1' >/dev/null",
            crate::shared::shell::sh_quote(username),
            crate::shared::shell::sh_quote(database),
        ),
        Protocol::Mongodb => "mongosh --quiet --host 127.0.0.1 --username \"$DBE_MONGO_USER\" --password \"$DBE_MONGO_PASSWORD\" --authenticationDatabase \"$DBE_MONGO_DATABASE\" \"$DBE_MONGO_DATABASE\" --eval 'db.runCommand({ ping: 1 }).ok' >/dev/null".to_string(),
        Protocol::Clickhouse => "clickhouse-client --host 127.0.0.1 --user \"$CLICKHOUSE_USER\" --password \"$CLICKHOUSE_PASSWORD\" --database \"$CLICKHOUSE_DB\" --query 'SELECT 1' >/dev/null".to_string(),
        Protocol::Redis | Protocol::Qdrant => {
            return Err(ApiError::BadRequest(format!(
                "{} major upgrade migration is not supported",
                protocol
            )));
        }
    };
    Ok(command)
}

pub(super) async fn stop_and_delete_container(
    state: &AppState,
    protocol: Protocol,
    instance_id: &str,
) -> Result<(), ApiError> {
    match state.docker.stop(protocol, instance_id).await {
        Ok(_) => {}
        Err(error) if error.is_not_found() => {}
        Err(error) => return Err(docker_error(error)),
    }
    match state.docker.delete(protocol, instance_id).await {
        Ok(_) => Ok(()),
        Err(error) if error.is_not_found() => Ok(()),
        Err(error) => Err(docker_error(error)),
    }
}

pub(super) async fn rename_path(
    from: &std::path::Path,
    to: &std::path::Path,
) -> Result<(), std::io::Error> {
    if let Some(parent) = to.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::rename(from, to).await
}

pub(super) async fn cleanup_path_if_exists(path: &std::path::Path) -> Result<(), ApiError> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.is_dir() => tokio::fs::remove_dir_all(path).await,
        Ok(_) => tokio::fs::remove_file(path).await,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => Err(error),
    }
    .map_err(|error| ApiError::Runtime(format!("failed to remove {}: {error}", path.display())))
}

pub(super) fn old_volume_backup_path(data_path: &std::path::Path) -> Result<PathBuf, ApiError> {
    let parent = data_path
        .parent()
        .ok_or_else(|| ApiError::Runtime("instance data path has no parent".to_string()))?;
    let name = data_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ApiError::Runtime("instance data path has no valid name".to_string()))?;
    Ok(parent.join(format!(
        ".dbe-major-upgrade-old-{name}-{}",
        uuid::Uuid::new_v4()
    )))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ImageVersionChange {
    SameMajorOrUnknown,
    Major,
}

pub(super) fn classify_image_update(
    protocol: Protocol,
    current_image: &str,
    requested_image: &str,
) -> Result<ImageVersionChange, ApiError> {
    if current_image == requested_image {
        return Ok(ImageVersionChange::SameMajorOrUnknown);
    }
    let Some(current_major) = image_major_version(current_image) else {
        return Err(ApiError::BadRequest(format!(
            "{} image update cannot compare current image tag {current_image:?}; use pinned semver-like tags for existing instances",
            protocol
        )));
    };
    let Some(requested_major) = image_major_version(requested_image) else {
        return Err(ApiError::BadRequest(format!(
            "{} image update cannot compare requested image tag {requested_image:?}; use pinned semver-like tags for existing instances",
            protocol
        )));
    };
    if current_major == requested_major {
        Ok(ImageVersionChange::SameMajorOrUnknown)
    } else {
        Ok(ImageVersionChange::Major)
    }
}

pub(super) fn image_major_version(image: &str) -> Option<u64> {
    let image = image.split('@').next().unwrap_or(image);
    let slash_index = image.rfind('/').map(|index| index + 1).unwrap_or(0);
    let tag_index = image[slash_index..].rfind(':')? + slash_index;
    let tag = &image[tag_index + 1..];
    parse_major_version_value(tag)
}

pub(super) fn parse_major_version_value(value: &str) -> Option<u64> {
    let major = value
        .split(|character: char| !character.is_ascii_digit())
        .next()?;
    if major.is_empty() {
        None
    } else {
        major.parse().ok()
    }
}

pub(super) fn major_upgrade_required_error(
    protocol: Protocol,
    current_image: &str,
    requested_image: &str,
) -> ApiError {
    ApiError::BadRequest(format!(
        "{protocol} major image upgrade is blocked for normal image updates. Current image is {current_image}, requested image is {requested_image}. Retry with major_upgrade=true to run DBE's export/import migration workflow, or create a fresh instance and import a dump manually."
    ))
}

pub(super) fn ensure_major_upgrade_supported(protocol: Protocol) -> Result<(), ApiError> {
    match protocol {
        Protocol::Postgres
        | Protocol::Mariadb
        | Protocol::Mysql
        | Protocol::Mongodb
        | Protocol::Clickhouse => Ok(()),
        Protocol::Redis => Err(ApiError::BadRequest(
            "redis major upgrades are blocked because Redis uses physical archive restore here; create a fresh Redis instance or use a dedicated Redis migration workflow".to_string(),
        )),
        Protocol::Qdrant => Err(ApiError::BadRequest(
            "qdrant major upgrades are blocked because Qdrant snapshot compatibility is version-specific; create a fresh Qdrant instance or use a dedicated Qdrant migration workflow".to_string(),
        )),
    }
}
