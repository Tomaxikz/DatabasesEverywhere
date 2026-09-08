use crate::{
    api::{
        http::{
            policy::{ApiRequestContext, DestructiveActionConfirmation, DestructiveActionPolicy},
            response::{ApiError, ApiJson, ApiPath, ApiResponse, ApiResult},
            router::AppState,
        },
        instances,
    },
    auth::scopes,
    disk::DiskLimiter,
    instances::{metadata::DesiredInstanceState, paths::InstancePaths},
    placement::{EngineRuntimeStatus, lifecycle},
    shared::{protocol::Protocol, time::now_rfc3339},
};
use axum::extract::State;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImageRequest {
    image: String,
    confirm: bool,
    reason: String,
}

pub(crate) async fn update(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(id): ApiPath<String>,
    ApiJson(request): ApiJson<ImageRequest>,
) -> ApiResult<serde_json::Value> {
    auth.require_scope(scopes::POOLS_WRITE)?;
    auth.require_scope(scopes::IMAGES_ADMIN)?;
    DestructiveActionPolicy::authorize(
        "pool image update (all databases affected; take backups first)",
        &DestructiveActionConfirmation {
            confirm: request.confirm,
            reason: request.reason,
        },
    )?;
    let (mut pool, guard) = super::power::PoolGuard::acquire(&state, &id).await?;
    instances::images::validate_image(&request.image)?;
    instances::images::check_image_allowed(&state, pool.protocol, &request.image)?;
    if matches!(
        pool.status,
        EngineRuntimeStatus::Creating | EngineRuntimeStatus::Deleting
    ) || (pool.status == EngineRuntimeStatus::Quarantined && pool.pending_image.is_none())
    {
        return Err(ApiError::Conflict(
            "pool requires recovery before its image can change".into(),
        ));
    }
    let previous_version = pool
        .database_version
        .clone()
        .ok_or_else(|| ApiError::Conflict("pool engine version is not attested".into()))?;
    state
        .install_progress
        .begin_image_update(&id, pool.protocol, &request.image);
    let location = format!("/api/pools/{id}/status");
    let response = ApiResponse::accepted_at(
        serde_json::json!({"runtime_id":id,"status":"updating","status_url":location}),
        location,
    );
    instances::spawn_owned_mutation_task(async move {
        let _guard = guard;
        let _ =
            replace_image_locked(&state, &mut pool, request.image, previous_version, None).await;
    });
    Ok(response)
}

/// Caller owns PoolGuard. Boot configuration repair and API image updates use
/// the same journal, readiness checks, tenant fencing, and failure handling.
pub(crate) async fn replace_image_locked(
    state: &AppState,
    pool: &mut crate::placement::EngineRuntime,
    image: String,
    previous_version: String,
    expected_image: Option<String>,
) -> Result<(), ApiError> {
    let mut replaced = false;
    let result = async {
        let progress = state.install_progress.clone();
        let progress_id = pool.runtime_id.clone();
        state
            .docker
            .pull_image_with_progress(&image, &move |event| {
                progress.docker_pull(&progress_id, event)
            })
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        state.install_progress.stage(
            &pool.runtime_id,
            "probe_image",
            "checking the image without mounting database data",
        );
        let (image_id, version) = state
            .docker
            .probe_image_version(pool.protocol, &image)
            .await
            .map_err(ApiError::Runtime)?;
        if expected_image.as_ref().is_some_and(|expected| expected != &image_id) {
            return Err(ApiError::Conflict("console-policy repair would change the installed image; update the image explicitly first".into()));
        }
        check_version(pool.protocol, &previous_version, &version)?;
        if pool
            .pending_image
            .as_ref()
            .is_some_and(|pending| pending != &image_id)
        {
            return Err(ApiError::Conflict(
                "retry the exact pending image before selecting a different one".into(),
            ));
        }
        let was_running = pool.desired_state == DesiredInstanceState::Running;
        let paths = InstancePaths::new(&state.config.paths, &pool.runtime_id)
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        let user = instances::create::prepare_instance_container_user(
            &state.docker,
            &paths,
            pool.protocol,
        )
        .await
        .map_err(|error| ApiError::Runtime(error.to_string()))?;
        let limiter = DiskLimiter::with_fuse_root(
            state.config.disk.clone(),
            state.config.paths.fuse_root(),
        )
        .for_persisted_protocol(pool.protocol, &pool.limits.disk_enforcement_method);
        let data = limiter
            .container_data_path(&paths.data)
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        let mut spec = super::provision::shared_spec(
            pool.protocol,
            &pool.runtime_id,
            &image_id,
            pool.admin_secret.as_deref().ok_or_else(|| {
                ApiError::Conflict("pool administrator credential is missing".into())
            })?,
            &paths,
            data,
        )
        .await?;
        spec.user = Some(user);
        spec.cpu_cores = pool.limits.cpu_cores;
        spec.memory_mib = pool.limits.memory_mib;
        spec.disk_mib = pool.limits.disk_mib;
        spec.pids_limit = Some(instances::create::protocol_pids_limit(
            state,
            pool.protocol,
        ));
        // Record intent before stopping/removing anything. Boot quarantines
        // an unfinished image operation instead of starting an ambiguous engine.
        replaced = true;
        pool.pending_image = Some(image_id.clone());
        pool.status = EngineRuntimeStatus::Booting;
        pool.updated_at = now_rfc3339();
        lifecycle::fence_runtime(state, &pool.runtime_id).await;
        lifecycle::save_runtime(&state.placements, &state.manager, pool.clone())
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        state.install_progress.stage(
            &pool.runtime_id,
            "replace_image",
            "replacing the pool container; database volumes are retained",
        );
        state
            .docker
            .stop(pool.protocol, &pool.runtime_id)
            .await
            .or_else(|error| {
                if error.is_not_running() || error.is_not_found() {
                    Ok(crate::runtime::docker::CommandOutput::empty())
                } else {
                    Err(error)
                }
            })
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        state
            .docker
            .delete(pool.protocol, &pool.runtime_id)
            .await
            .or_else(|error| {
                if error.is_not_found() {
                    Ok(crate::runtime::docker::CommandOutput::empty())
                } else {
                    Err(error)
                }
            })
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        paths
            .clear_socket_dir()
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        state
            .docker
            .create_with_progress(&spec, &|_| {})
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        // activate_locked intentionally leaves tenant routes fenced while
        // pending_image exists, even after readiness and credential checks.
        lifecycle::activate_locked(state, pool, false)
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        if pool.database_version.as_deref() != Some(&version)
            || pool
                .compatibility
                .as_ref()
                .is_none_or(|identity| identity.image_id != image_id)
        {
            return Err(ApiError::Conflict(
                "replacement engine does not match the attested image".into(),
            ));
        }
        pool.image = image;
        pool.pending_image = None;
        pool.desired_state = if was_running {
            DesiredInstanceState::Running
        } else {
            DesiredInstanceState::Stopped
        };
        pool.updated_at = now_rfc3339();
        lifecycle::save_runtime(&state.placements, &state.manager, pool.clone())
            .await
            .map_err(|error| ApiError::Runtime(error.to_string()))?;
        if was_running {
            let recovered =
                crate::placement::tenant::recovery::reconcile_runtime_tenants_locked(
                    state, pool,
                )
                .await
                .map_err(|error| ApiError::Runtime(error.to_string()))?;
            if recovered.pools_contained != 0 {
                return Err(ApiError::Conflict("pool failed tenant recovery".into()));
            }
        } else {
            lifecycle::honor_stop(state, pool)
                .await
                .map_err(|error| ApiError::Runtime(error.to_string()))?;
        }
        lifecycle::clear_runtime_caches(state, &pool.runtime_id).await;
        Ok::<_, ApiError>(())
    }
    .await;
    match &result {
        Ok(()) => state
            .install_progress
            .complete(&pool.runtime_id, "pool image update completed"),
        Err(error) => {
            if replaced || pool.pending_image.is_some() {
                instances::containment::contain_locked(state, pool, "pool image update failed")
                    .await;
            }
            state
                .install_progress
                .fail_api_error(&pool.runtime_id, "pool image update", error);
        }
    }
    result
}

pub(crate) async fn refresh_logging(state: &AppState, runtime_id: &str) -> Result<bool, ApiError> {
    let current = super::load(state, runtime_id).await?;
    if current.status != EngineRuntimeStatus::Running
        || current.desired_state != DesiredInstanceState::Running
        || current.pending_image.is_some()
        || state
            .docker
            .log_policy_is_current(current.protocol, runtime_id)
            .await
            .map_err(instances::docker_error)?
    {
        return Ok(false);
    }
    let (mut pool, guard) = super::power::PoolGuard::acquire(state, runtime_id).await?;
    if pool.status != EngineRuntimeStatus::Running
        || pool.desired_state != DesiredInstanceState::Running
    {
        return Ok(false);
    }
    let state = state.clone();
    instances::spawn_owned_mutation_task(async move {
        let _guard = guard;
        refresh_logging_locked(&state, &mut pool).await
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("pool console-policy worker failed: {error}")))?
}

pub(super) async fn refresh_logging_locked(
    state: &AppState,
    pool: &mut crate::placement::EngineRuntime,
) -> Result<bool, ApiError> {
    let runtime_id = pool.runtime_id.clone();
    if pool.pending_image.is_some()
        || state
            .docker
            .log_policy_is_current(pool.protocol, &runtime_id)
            .await
            .map_err(instances::docker_error)?
    {
        return Ok(false);
    }
    let installed = state
        .docker
        .container_immutable_image_id(pool.protocol, &runtime_id)
        .await
        .map_err(instances::docker_error)?
        .ok_or_else(|| ApiError::Conflict("pool image identity is unavailable".into()))?;
    let previous_version = match &pool.database_version {
        Some(version) => version.clone(),
        None => {
            crate::placement::runtime::probe_compatibility(&state.docker, pool)
                .await
                .map_err(ApiError::Runtime)?
                .version
        }
    };
    let image = pool.image.clone();
    tracing::info!(
        event = "audit pool_console_policy_upgrade",
        runtime_id,
        "recreating pool container with bounded console history; database volumes are retained"
    );
    state
        .install_progress
        .begin_image_update(&runtime_id, pool.protocol, &image);
    replace_image_locked(state, pool, image, previous_version, Some(installed)).await?;
    Ok(true)
}

fn check_version(protocol: Protocol, current: &str, next: &str) -> Result<(), ApiError> {
    let parse = |value: &str| {
        value
            .split('.')
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
    };
    let current = parse(current)
        .map_err(|_| ApiError::Conflict("current version cannot be compared".into()))?;
    let next =
        parse(next).map_err(|_| ApiError::Conflict("image version cannot be compared".into()))?;
    let series = if protocol == Protocol::Postgres { 1 } else { 2 };
    if current.len() < series
        || next.len() < series
        || current[..series] != next[..series]
        || next < current
    {
        return Err(ApiError::Conflict("pool image changes must stay on the same engine release line without downgrading; use a planned data migration for a major/release-line change".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn console_policy_boot_repair_never_activates_stopped_or_unhealthy_pools() {
        let (state, _directory) =
            crate::api::test_support::database(crate::config::Config::default()).await;
        for (status, desired) in [
            (EngineRuntimeStatus::Stopped, DesiredInstanceState::Stopped),
            (
                EngineRuntimeStatus::Quarantined,
                DesiredInstanceState::Stopped,
            ),
            (EngineRuntimeStatus::Creating, DesiredInstanceState::Running),
            (EngineRuntimeStatus::Deleting, DesiredInstanceState::Stopped),
            (EngineRuntimeStatus::Running, DesiredInstanceState::Stopped),
        ] {
            let mut pool = crate::placement::test_support::runtime(
                "pool",
                Protocol::Postgres,
                "postgres:18.4",
            );
            pool.status = status;
            pool.desired_state = desired;
            state.placements.save(&pool).await.unwrap();
            // The deliberately offline engine would fail if repair inspected
            // or started a container before checking durable power intent.
            assert!(!refresh_logging(&state, "pool").await.unwrap());
            let stored = state.placements.get("pool").await.unwrap().unwrap();
            assert_eq!(stored.status, status);
            assert_eq!(stored.desired_state, desired);
            assert!(stored.pending_image.is_none());
        }
    }
    #[test]
    fn only_forward_same_release_line_images_are_accepted() {
        for (protocol, current, next, allowed) in [
            (Protocol::Postgres, "18.4", "18.5", true),
            (Protocol::Postgres, "18.4", "19.0", false),
            (Protocol::Mysql, "8.4.5", "8.4.6", true),
            (Protocol::Mysql, "8.4.5", "9.4.0", false),
            (Protocol::Mariadb, "11.8.1", "11.8.2", true),
            (Protocol::Mongodb, "8.0.1", "8.0.2", true),
            (Protocol::Clickhouse, "26.4.4.38", "26.4.5.1", true),
            (Protocol::Mysql, "8.4.5", "8.4.4", false),
        ] {
            assert_eq!(check_version(protocol, current, next).is_ok(), allowed);
        }
    }
}
