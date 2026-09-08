use crate::api::instances::create::shared::placement_error;
use crate::api::instances::docker_error;
use crate::{
    api::{
        http::{response::ApiError, router::AppState},
        instances::create::{
            backend_endpoint, launch_container_from_spec, prepare_instance_container_user,
            protocol_pids_limit,
        },
    },
    databases,
    disk::DiskLimiter,
    instances::{
        metadata::{RuntimeKind, RuntimeMetadata},
        paths::InstancePaths,
    },
    placement::{
        DeploymentMode, ENGINE_RUNTIME_SCHEMA_VERSION, EngineRuntime, EngineRuntimeStatus,
        RuntimeReservation, runtime as shared_runtime, tenant,
    },
    runtime::docker::DockerInstanceSpec,
    shared::{protocol::Protocol, time::now_rfc3339},
};
use secrecy::SecretString;
use tokio::sync::OwnedMutexGuard;

pub(crate) async fn provision_pool(
    state: &AppState,
    pool: &crate::placement::PoolSpec,
    runtime_id: &str,
    creation: &mut Option<OwnedMutexGuard<()>>,
) -> Result<(EngineRuntime, OwnedMutexGuard<()>), ApiError> {
    let protocol = pool.protocol;
    let image = pool.image.as_str();
    let mut limits = pool.limits.limits();
    let runtime_id = runtime_id.to_string();
    // Container events use this same lock before reading and persisting pool
    // state. Holding it across the first durable row, bootstrap, and any
    // cleanup prevents an early event from reviving a failed pool from a stale
    // snapshot.
    let runtime_operation = state.instance_locks.lock(&runtime_id).await;
    let admin_password = format!(
        "dbe-pool-{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let paths = InstancePaths::new(&state.config.paths, &runtime_id)
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
    // Resolve every fallible identity value before creating the pool's
    // filesystem namespace. From create_dirs onward there is no durable row
    // for boot recovery until the initial placement save succeeds.
    let backend = backend_endpoint(state, protocol, &runtime_id)?;
    let container_name = state
        .docker
        .container_name(protocol, &runtime_id)
        .map_err(docker_error)?;
    let max_tenants = pool.limits.max_tenants;
    let disk_limiter =
        DiskLimiter::with_fuse_root(state.config.disk.clone(), state.config.paths.fuse_root())
            .for_protocol(protocol);
    let effective_disk_method = disk_limiter.mode().method().to_string();
    if let Err(error) = paths.create_dirs().await {
        return Err(cleanup_unpersisted_runtime(
            state,
            &paths,
            protocol,
            &effective_disk_method,
            ApiError::Runtime(error.to_string()),
        )
        .await);
    }
    let user = match prepare_instance_container_user(&state.docker, &paths, protocol).await {
        Ok(user) => user,
        Err(error) => {
            return Err(cleanup_unpersisted_runtime(
                state,
                &paths,
                protocol,
                &effective_disk_method,
                ApiError::Runtime(error.to_string()),
            )
            .await);
        }
    };
    let disk = match disk_limiter
        .apply_instance_limit(&runtime_id, &paths.data, limits.disk_mib)
        .await
    {
        Ok(disk) => disk,
        Err(error) => {
            return Err(cleanup_unpersisted_runtime(
                state,
                &paths,
                protocol,
                &effective_disk_method,
                ApiError::Runtime(error.to_string()),
            )
            .await);
        }
    };
    limits.disk_enforced = disk.enforced;
    limits.disk_enforcement_method = disk.method.clone();
    let data_path = disk.container_data_path.unwrap_or(paths.data.clone());
    let mut spec = match shared_spec(
        protocol,
        &runtime_id,
        image,
        &admin_password,
        &paths,
        data_path,
    )
    .await
    {
        Ok(spec) => spec,
        Err(error) => {
            return Err(cleanup_unpersisted_runtime(
                state,
                &paths,
                protocol,
                &limits.disk_enforcement_method,
                error,
            )
            .await);
        }
    };
    spec.user = Some(user);
    spec.cpu_cores = limits.cpu_cores;
    spec.memory_mib = limits.memory_mib;
    spec.disk_mib = limits.disk_mib;
    spec.pids_limit = Some(protocol_pids_limit(state, protocol));

    let now = now_rfc3339();
    let mut runtime = EngineRuntime {
        pending_image: None,
        desired_state: crate::instances::metadata::DesiredInstanceState::Running,
        owner: Some(pool.owner.clone()),
        schema_version: ENGINE_RUNTIME_SCHEMA_VERSION,
        runtime_id: runtime_id.clone(),
        protocol,
        deployment_mode: DeploymentMode::Shared,
        status: EngineRuntimeStatus::Creating,
        backend,
        runtime: RuntimeMetadata {
            kind: RuntimeKind::from(state.config.daemon.engine),
            container_name,
            network_mode: "none".to_string(),
        },
        limits,
        image: image.to_string(),
        database_version: None,
        compatibility: None,

        max_tenants,
        reserved: RuntimeReservation::default(),
        admin_secret: Some(admin_password.clone()),
        created_at: now.clone(),
        updated_at: now,
    };
    if let Err(error) = state.placements.save(&runtime).await {
        let save_error = placement_error(error);
        match state.placements.get(&runtime_id).await {
            Ok(Some(persisted)) if same_initial_runtime(&persisted, &runtime) => {
                tracing::warn!(
                    event = "audit shared_runtime_create_commit_ack_lost",
                    runtime_id = %runtime_id,
                    %protocol,
                    error = %save_error,
                    "initial shared runtime placement was committed despite a lost SQLite acknowledgement"
                );
            }
            Ok(None) => {
                return Err(cleanup_unpersisted_runtime(
                    state,
                    &paths,
                    protocol,
                    &runtime.limits.disk_enforcement_method,
                    save_error,
                )
                .await);
            }
            Ok(Some(_)) => {
                tracing::error!(
                    event = "audit shared_runtime_create_commit_ambiguous",
                    runtime_id = %runtime_id,
                    %protocol,
                    error = %save_error,
                    durable_state = "mismatched",
                    "retained provisional shared runtime paths because placement persistence became ambiguous"
                );
                return Err(ApiError::Runtime(format!(
                    "initial shared runtime placement returned {save_error}, but runtime {runtime_id} contains different durable state; retained its physical state for boot recovery"
                )));
            }
            Err(read_error) => {
                tracing::error!(
                    event = "audit shared_runtime_create_commit_ambiguous",
                    runtime_id = %runtime_id,
                    %protocol,
                    error = %save_error,
                    durable_state = "unreadable",
                    durable_read_error = %read_error,
                    "retained provisional shared runtime paths because placement persistence became ambiguous"
                );
                return Err(ApiError::Runtime(format!(
                    "initial shared runtime placement returned {save_error}, and durable state for runtime {runtime_id} could not be read ({read_error}); retained its physical state for boot recovery"
                )));
            }
        }
    }
    drop(creation.take());

    state.install_progress.stage(
        &runtime_id,
        "create_pool",
        "starting a new shared database runtime",
    );
    let progress = state.install_progress.clone();
    let progress_id = runtime_id.clone();
    let pull_progress = move |event| progress.docker_pull(&progress_id, event);
    let launch = launch_container_from_spec(
        state,
        &spec,
        protocol,
        &runtime_id,
        &pull_progress,
        false,
        || async {
            if protocol == Protocol::Mongodb {
                crate::api::instances::create::bootstrap_mongodb_root(
                    state,
                    &runtime_id,
                    &admin_password,
                )
                .await?;
            }
            Ok(())
        },
    )
    .await;
    if let Err(error) = launch {
        fail_pool_start(state, &runtime).await;
        return Err(error.into_api_error());
    }

    if let Err(error) = tenant::secure_pool(&state.docker, &runtime).await {
        fail_pool_start(state, &runtime).await;
        return Err(ApiError::Conflict(format!(
            "shared runtime isolation bootstrap failed: {error}"
        )));
    }

    let probe = match shared_runtime::probe_compatibility(&state.docker, &runtime).await {
        Ok(probe) => probe,
        Err(error) => {
            fail_pool_start(state, &runtime).await;
            return Err(ApiError::Conflict(error));
        }
    };
    runtime.database_version = Some(probe.version.clone());
    runtime.compatibility = Some(probe.compatibility);
    runtime.status = EngineRuntimeStatus::Running;
    runtime.updated_at = now_rfc3339();
    if let Err(error) = state
        .placements
        .save(&runtime)
        .await
        .map_err(placement_error)
    {
        fail_pool_start(state, &runtime).await;
        return Err(error);
    }
    tracing::info!(
        event = "audit shared_runtime_created",
        runtime_id = %runtime.runtime_id,
        %protocol,
        image,
        version = %probe.version,
        max_tenants = runtime.max_tenants,
    );
    Ok((runtime, runtime_operation))
}

async fn cleanup_unpersisted_runtime(
    state: &AppState,
    paths: &InstancePaths,
    protocol: Protocol,
    disk_enforcement_method: &str,
    error: ApiError,
) -> ApiError {
    let physical_cleanup = crate::api::instances::purge_provisional_runtime_paths(
        state,
        &paths.instance_id,
        protocol,
        Some(disk_enforcement_method),
    )
    .await;
    // purge_provisional_runtime_paths deliberately preserves logical instance
    // artifacts for deployment rollback. A brand-new pool has no logical
    // owner, so remove the artifacts directory created by create_dirs too.
    let artifact_cleanup =
        crate::api::instances::major_upgrade::remove_path_if_exists(&paths.artifacts).await;
    let cleanup_error = match (physical_cleanup, artifact_cleanup) {
        (Ok(()), Ok(())) => None,
        (Err(physical), Ok(())) => Some(physical.to_string()),
        (Ok(()), Err(artifacts)) => Some(artifacts.to_string()),
        (Err(physical), Err(artifacts)) => Some(format!(
            "physical cleanup failed: {physical}; artifact cleanup failed: {artifacts}"
        )),
    };
    match cleanup_error {
        None => {
            tracing::info!(
                event = "audit shared_runtime_create_failed_cleaned",
                runtime_id = %paths.instance_id,
                %protocol,
                disk_enforcement_method,
                error = %error,
                "removed an unpersisted shared runtime after creation failed"
            );
            error
        }
        Some(cleanup_error) => {
            tracing::error!(
                event = "audit shared_runtime_create_cleanup_incomplete",
                runtime_id = %paths.instance_id,
                %protocol,
                disk_enforcement_method,
                error = %error,
                %cleanup_error,
                "an unpersisted shared runtime could not be cleaned completely"
            );
            ApiError::Runtime(format!(
                "{error}; cleanup of unpersisted shared runtime {} using disk method {disk_enforcement_method} also failed: {cleanup_error}",
                paths.instance_id
            ))
        }
    }
}

async fn fail_pool_start(state: &AppState, runtime: &EngineRuntime) {
    crate::api::instances::containment::contain_locked(state, runtime, "pool creation failed")
        .await;
}

pub(crate) async fn shared_spec(
    protocol: Protocol,
    runtime_id: &str,
    image: &str,
    admin_password: &str,
    paths: &InstancePaths,
    data_path: std::path::PathBuf,
) -> Result<DockerInstanceSpec, ApiError> {
    let password = || SecretString::from(admin_password.to_string());
    let spec = match protocol {
        Protocol::Postgres => databases::postgres::docker::shared_spec(
            runtime_id,
            image,
            password(),
            data_path,
            paths.sockets.clone(),
        ),
        Protocol::Mysql => databases::mysql::docker::shared_spec(
            runtime_id,
            image,
            password(),
            data_path,
            paths.sockets.clone(),
        ),
        Protocol::Mariadb => databases::mariadb::docker::shared_spec(
            runtime_id,
            image,
            password(),
            data_path,
            paths.sockets.clone(),
        ),
        Protocol::Mongodb => databases::mongodb::docker::shared_spec(
            runtime_id,
            image,
            password(),
            data_path,
            paths.sockets.clone(),
        ),
        Protocol::Clickhouse => {
            let config =
                databases::clickhouse::docker::write_shared_hosted_config(&paths.runtime_config)
                    .await
                    .map_err(|error| ApiError::Runtime(error.to_string()))?;
            databases::clickhouse::docker::shared_spec(
                runtime_id,
                image,
                password(),
                data_path,
                config,
                paths.sockets.clone(),
                paths.socket_bridge_binary.clone(),
            )
        }
        protocol => {
            return Err(ApiError::BadRequest(format!(
                "{protocol} cannot use shared deployment"
            )));
        }
    };
    Ok(spec)
}

fn same_initial_runtime(stored: &EngineRuntime, expected: &EngineRuntime) -> bool {
    let same_public = match (serde_json::to_value(stored), serde_json::to_value(expected)) {
        (Ok(stored), Ok(expected)) => stored == expected,
        _ => false,
    };
    same_public
        && stored.admin_secret == expected.admin_secret
        && stored.desired_state == expected.desired_state
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::limits::InstanceLimits;
    fn initial_runtime() -> EngineRuntime {
        let mut runtime = crate::placement::test_support::runtime(
            "pool_postgres_initial",
            Protocol::Postgres,
            "postgres:18.4",
        );
        runtime.status = EngineRuntimeStatus::Creating;
        runtime.backend = crate::shared::backend::BackendEndpoint::UnixSocket {
            socket_path: "/run/dbe/pool_postgres_initial/.s.PGSQL.5432".to_string(),
        };
        runtime.limits = InstanceLimits {
            cpu_cores: 1.25,
            memory_mib: 1280,
            disk_mib: 8192,
            disk_enforced: true,
            disk_enforcement_method: "fuse_quota".to_string(),
        };
        runtime.max_tenants = 64;
        runtime.admin_secret = Some("pool-admin-secret".to_string());
        runtime.created_at = "2026-09-08T00:00:00Z".to_string();
        runtime.updated_at = runtime.created_at.clone();
        runtime
    }

    #[test]
    fn lost_initial_save_ack_only_adopts_exact_creating_runtime() {
        let expected = initial_runtime();
        let mut persisted = expected.clone();
        assert!(same_initial_runtime(&persisted, &expected));

        persisted.admin_secret = Some("different-secret".to_string());
        assert!(!same_initial_runtime(&persisted, &expected));
        persisted = expected.clone();
        persisted.limits.disk_mib =
            crate::placement::policy::pool_disk_mib(Protocol::Postgres, 0).unwrap();
        persisted.runtime.container_name.push_str("-different");
        assert!(!same_initial_runtime(&persisted, &expected));
    }

    #[tokio::test]
    async fn unpersisted_runtime_cleanup_removes_every_created_pool_path() {
        let namespace = tempfile::tempdir().unwrap();
        let root = namespace.path();
        let path = |name: &str| root.join(name).display().to_string();
        let mut config = crate::config::Config::default();
        config.disk.mode = crate::config::DiskLimitMode::SoftScanner;
        config.paths.data = path("data");
        config.paths.metadata = path("metadata");
        config.paths.volumes = path("volumes");
        config.paths.backups = path("backups");
        config.paths.sockets = path("sockets");
        config.paths.locks = path("locks");
        config.paths.logs = path("logs");
        config.paths.artifacts = path("artifacts");
        config.paths.exports = path("exports");
        config.paths.imports = path("imports");
        config.paths.fuse = path("fuse");
        config.paths.tmp = path("tmp");
        let (state, _database) = crate::api::test_support::database(config).await;
        let paths = InstancePaths::new(&state.config.paths, "pool_postgres_unpersisted").unwrap();
        paths.create_dirs().await.unwrap();
        // Old installations may still have a log directory to purge.
        tokio::fs::create_dir_all(&paths.logs).await.unwrap();
        for path in [
            &paths.data,
            &paths.logs,
            &paths.sockets,
            &paths.artifacts,
            &paths.runtime_config,
        ] {
            tokio::fs::write(path.join("partial-create"), b"orphan")
                .await
                .unwrap();
        }

        let error = cleanup_unpersisted_runtime(
            &state,
            &paths,
            Protocol::Postgres,
            "soft_scanner",
            ApiError::Runtime("injected pre-durable failure".to_string()),
        )
        .await;

        assert!(error.to_string().contains("injected pre-durable failure"));
        for path in [
            &paths.data,
            &paths.logs,
            &paths.sockets,
            &paths.artifacts,
            &paths.runtime_config,
        ] {
            assert!(
                tokio::fs::symlink_metadata(path).await.is_err(),
                "{} survived cleanup",
                path.display()
            );
        }
    }
}
