use super::rollback::{
    cleanup_temp_paths, cleanup_temp_replacement, remove_container, remove_path_if_exists,
    rename_path, upgrade_temp_instance_id,
};
use super::*;
use secrecy::SecretString;

#[derive(Debug, PartialEq, Eq)]
pub(in crate::api::instances) enum MajorUpgradeCommitResolution {
    Committed,
    NotCommitted,
    Uncertain(String),
}

pub(super) async fn resolve_upgrade_commit(
    state: &AppState,
    previous: &InstanceMetadata,
    intended: &InstanceMetadata,
) -> MajorUpgradeCommitResolution {
    match state.manager.get_persisted(&intended.instance_id).await {
        Ok(Some(persisted)) => classify_upgrade_commit(&persisted, previous, intended),
        Ok(None) => MajorUpgradeCommitResolution::Uncertain(
            "the durable instance metadata row is missing".to_string(),
        ),
        Err(error) => MajorUpgradeCommitResolution::Uncertain(format!(
            "the durable metadata read failed: {error}"
        )),
    }
}

pub(in crate::api::instances) fn classify_upgrade_commit(
    persisted: &InstanceMetadata,
    previous: &InstanceMetadata,
    intended: &InstanceMetadata,
) -> MajorUpgradeCommitResolution {
    if durable_metadata_matches(persisted, intended) {
        MajorUpgradeCommitResolution::Committed
    } else if durable_metadata_matches(persisted, previous) {
        MajorUpgradeCommitResolution::NotCommitted
    } else {
        MajorUpgradeCommitResolution::Uncertain(format!(
            "durable metadata has update marker {:?}, expected committed marker {:?} or previous marker {:?}",
            persisted.updated_at, intended.updated_at, previous.updated_at
        ))
    }
}

fn durable_metadata_matches(left: &InstanceMetadata, right: &InstanceMetadata) -> bool {
    left.schema_version == right.schema_version
        && left.instance_id == right.instance_id
        && left.protocol == right.protocol
        && left.status == right.status
        && left.desired_state == right.desired_state
        && left.disk_limit_blocked == right.disk_limit_blocked
        && left.public.host == right.public.host
        && left.public.port == right.public.port
        && left.backend == right.backend
        && left.runtime.kind == right.runtime.kind
        && left.runtime.container_name == right.runtime.container_name
        && left.runtime.network_mode == right.runtime.network_mode
        && left.database.name == right.database.name
        && left.database.username == right.database.username
        && left.route_key_sha256 == right.route_key_sha256
        && left.mariadb_native_password_sha1_stage2 == right.mariadb_native_password_sha1_stage2
        && left.mariadb_root_password == right.mariadb_root_password
        && left.mysql_native_password_sha1_stage2 == right.mysql_native_password_sha1_stage2
        && left.mysql_root_password == right.mysql_root_password
        && left.mongodb_root_password == right.mongodb_root_password
        && left.postgres_admin_password == right.postgres_admin_password
        && left.tenant_password == right.tenant_password
        && left.limits.cpu_cores.to_bits() == right.limits.cpu_cores.to_bits()
        && left.limits.memory_mib == right.limits.memory_mib
        && left.limits.disk_mib == right.limits.disk_mib
        && left.limits.disk_enforced == right.limits.disk_enforced
        && left.limits.disk_enforcement_method == right.limits.disk_enforcement_method
        && left.created_at == right.created_at
        && left.updated_at == right.updated_at
}

async fn replace_and_import(
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
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
            .for_persisted_protocol(metadata.protocol, &metadata.limits.disk_enforcement_method);
    let disk = disk_limiter
        .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    let container_data_path = disk.container_data_path.unwrap_or(paths.data.clone());
    let mut spec = image_update_spec(
        metadata,
        paths,
        container_data_path,
        image,
        Some(secrecy::SecretString::from(password.to_string())),
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
            password,
            metadata.postgres_admin_password.as_deref().ok_or_else(|| {
                ApiError::Conflict(
                    "the encrypted PostgreSQL administrator credential is missing; restart the daemon to migrate this legacy instance before a major upgrade".to_string(),
                )
            })?,
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
    crate::api::import_export::register_default_artifact(state, metadata, export_artifact)
        .await
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    validate_replacement(state, metadata, password).await?;
    metadata.backend = backend_endpoint(state, metadata.protocol, &metadata.instance_id)
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
    pub(super) metadata: InstanceMetadata,
    pub(super) paths: InstancePaths,
}

pub(super) async fn stage_replacement(
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
    let temporary_instance_id = upgrade_temp_instance_id(&metadata.instance_id);
    let staged_paths = InstancePaths::new(&state.config.paths, &temporary_instance_id)
        .map_err(|error| fail_image_update_bad_request(state, &metadata.instance_id, error))?;
    cleanup_temp_replacement(
        state,
        metadata.protocol,
        &metadata.limits.disk_enforcement_method,
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

    match replace_and_import(
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
            cleanup_temp_replacement(
                state,
                metadata.protocol,
                &metadata.limits.disk_enforcement_method,
                &temporary_instance_id,
                &staged_paths,
            )
            .await;
            Err(error)
        }
    }
}

pub(super) async fn commit_staged_replacement(
    state: &AppState,
    metadata: &InstanceMetadata,
    paths: &InstancePaths,
    staged: &StagedMajorUpgrade,
    image: &str,
    password: &str,
) -> Result<(), ApiError> {
    remove_container(
        state,
        staged.metadata.protocol,
        &staged.metadata.instance_id,
    )
    .await
    .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    // Only detach transient runtime state before moving the validated volume.
    // `purge_instance_data` is deliberately destructive for Btrfs subvolumes
    // and ZFS datasets and would erase the imported replacement here.
    DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
        .for_persisted_protocol(metadata.protocol, &metadata.limits.disk_enforcement_method)
        .teardown_instance_mount(&staged.paths.data)
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    remove_path_if_exists(&paths.data).await?;
    rename_path(&staged.paths.data, &paths.data)
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    cleanup_temp_paths(&staged.paths).await;
    recreate_empty_instance(state, metadata, paths, image, password)
        .await
        .map_err(|error| fail_image_update_api(state, &metadata.instance_id, error))?;
    Ok(())
}

pub(super) async fn recreate_empty_instance(
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
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
            .for_persisted_protocol(metadata.protocol, &metadata.limits.disk_enforcement_method);
    let disk = disk_limiter
        .apply_instance_limit(&metadata.instance_id, &paths.data, metadata.limits.disk_mib)
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    let container_data_path = disk.container_data_path.unwrap_or(paths.data.clone());
    let mut spec = image_update_spec(
        metadata,
        paths,
        container_data_path,
        image,
        Some(secrecy::SecretString::from(password.to_string())),
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

async fn validate_replacement(
    state: &AppState,
    metadata: &InstanceMetadata,
    password: &str,
) -> Result<(), ApiError> {
    state.install_progress.stage(
        &metadata.instance_id,
        "validate",
        "validating replacement database",
    );
    let command = replacement_check_command(
        metadata.protocol,
        &metadata.database.username,
        &metadata.database.name,
    )?;
    let password = SecretString::from(password.to_string());
    let script = format!("set -eu\n{command}");
    state
        .docker
        .exec_shell_with_secrets(
            metadata.protocol,
            &metadata.instance_id,
            &script,
            &[("DBE_UPGRADE_PASSWORD", &password)],
        )
        .await
        .map_err(|error| fail_image_update_runtime(state, &metadata.instance_id, error))?;
    Ok(())
}

pub(in crate::api::instances) fn replacement_check_command(
    protocol: Protocol,
    username: &str,
    database: &str,
) -> Result<String, ApiError> {
    let command = match protocol {
        Protocol::Postgres => format!(
            "PGPASSWORD=\"$DBE_UPGRADE_PASSWORD\" psql -X -h /var/run/postgresql -U {} -d {} -v ON_ERROR_STOP=1 -c 'select 1' >/dev/null",
            crate::shared::shell::sh_quote(username),
            crate::shared::shell::sh_quote(database),
        ),
        Protocol::Mariadb => "MYSQL_PWD=\"$DBE_UPGRADE_PASSWORD\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -u \"$MARIADB_USER\" \"$MARIADB_DATABASE\" -N -B -e 'select 1' >/dev/null".to_string(),
        Protocol::Mysql => format!(
            "MYSQL_PWD=\"$DBE_UPGRADE_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u {} {} -e 'select 1' >/dev/null",
            crate::shared::shell::sh_quote(username),
            crate::shared::shell::sh_quote(database),
        ),
        Protocol::Mongodb => format!(
            "mongosh --quiet --host 127.0.0.1 --username {} --password \"$DBE_UPGRADE_PASSWORD\" --authenticationDatabase {} {} --eval 'db.runCommand({{ ping: 1 }}).ok' >/dev/null",
            crate::shared::shell::sh_quote(username),
            crate::shared::shell::sh_quote(database),
            crate::shared::shell::sh_quote(database),
        ),
        Protocol::Clickhouse => format!(
            "clickhouse-client --host 127.0.0.1 --user {} --password \"$DBE_UPGRADE_PASSWORD\" --database {} --query 'SELECT 1' >/dev/null",
            crate::shared::shell::sh_quote(username),
            crate::shared::shell::sh_quote(database),
        ),
        Protocol::Redis | Protocol::Valkey | Protocol::Qdrant => {
            return Err(ApiError::BadRequest(format!(
                "{} major upgrade migration is not supported",
                protocol
            )));
        }
    };
    Ok(command)
}
