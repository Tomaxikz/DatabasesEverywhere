use futures::FutureExt;

use super::*;

async fn lock_shared_runtime(
    state: &AppState,
    migration: &DeploymentMigration,
) -> Result<Option<OwnedMutexGuard<()>>, ApiError> {
    let runtime_id = if migration.source_mode == DeploymentMode::Shared {
        Some(migration.source_runtime_id.clone())
    } else if let Some(runtime_id) = migration.target_runtime_id.as_ref() {
        Some(runtime_id.clone())
    } else {
        let temp_id = temp_instance_id(&migration.migration_id)?;
        state
            .placements
            .reservation_runtime(&temp_id)
            .await
            .map_err(runtime_error)?
            .map(|runtime| runtime.runtime_id)
    };
    Ok(match runtime_id {
        Some(runtime_id) if runtime_id != migration.instance_id => {
            Some(state.instance_locks.lock(&runtime_id).await)
        }
        _ => None,
    })
}

/// Finishes records classified during early boot before shared quota priming
/// or gateway publication can consume provisional reservations.
pub(crate) async fn recover_on_boot(state: &AppState) -> Result<(), ApiError> {
    let active = state
        .placements
        .migrations()
        .list_active()
        .await
        .map_err(migration_error)?;
    for migration in active {
        crate::api::instances::route_fence::fence(state, &migration.instance_id).await;
        if migration.stage == MigrationStage::ManualIntervention {
            tracing::error!(
                event = "audit deployment_migration_manual_intervention_retained",
                migration_id = %migration.migration_id,
                instance_id = %migration.instance_id,
                "deployment migration requires manual intervention; its route remains fenced while other boot recovery continues"
            );
            continue;
        }
        if !automatic_boot_recovery_stage(migration.stage) {
            tracing::warn!(
                event = "audit deployment_migration_unclassified_boot_stage",
                migration_id = %migration.migration_id,
                instance_id = %migration.instance_id,
                stage = migration.stage.as_str(),
                "active deployment migration was not classified for automatic boot recovery; its route remains fenced"
            );
            continue;
        }
        let result = match std::panic::AssertUnwindSafe(recover_one_on_boot(state, &migration))
            .catch_unwind()
            .await
        {
            Ok(result) => result,
            Err(_) => Err(ApiError::Runtime(
                "deployment migration boot recovery panicked".to_string(),
            )),
        };
        if let Err(error) = result {
            // Recovery can briefly republish the authoritative source or target
            // while verifying it. Any incomplete record must finish this attempt
            // fenced, even when a later boot pass refreshes its cached metadata.
            crate::api::instances::route_fence::fence(state, &migration.instance_id).await;
            tracing::error!(
                event = "audit deployment_migration_boot_recovery_failed",
                migration_id = %migration.migration_id,
                instance_id = %migration.instance_id,
                error = %redaction::redact_connection_url(&error.to_string()),
                "isolated deployment migration recovery failure; its route remains fenced while boot recovery continues"
            );
        }
    }
    Ok(())
}

async fn recover_one_on_boot(
    state: &AppState,
    migration: &DeploymentMigration,
) -> Result<(), ApiError> {
    let admission = state
        .import_export_jobs
        .try_admit_exclusive(&migration.instance_id)
        .map_err(|error| migration_admission_error(&migration.instance_id, error))?;
    let creation = state.instance_locks.lock_creation().await;
    let _operation = state.instance_locks.lock(&migration.instance_id).await;
    let _shared_runtime = lock_shared_runtime(state, migration).await?;
    let result = if migration.stage == MigrationStage::RollingBack {
        let result = finish_rollback(state, migration.clone()).await;
        drop(creation);
        result
    } else {
        drop(creation);
        finish_forward_cleanup(state, migration.clone()).await
    };
    drop(admission);
    result
}

/// Reasserts every durable migration fence immediately before gateway
/// listeners are published. Later boot reconciliation may refresh otherwise
/// route-eligible metadata, so the migration repository remains authoritative.
pub(crate) async fn fence_active_routes_on_boot(state: &AppState) -> Result<usize, ApiError> {
    let active = state
        .placements
        .migrations()
        .list_active()
        .await
        .map_err(migration_error)?;
    for migration in &active {
        crate::api::instances::route_fence::pin(state, &migration.instance_id).await;
    }
    Ok(active.len())
}

fn automatic_boot_recovery_stage(stage: MigrationStage) -> bool {
    matches!(
        stage,
        MigrationStage::RollingBack | MigrationStage::CleanupPending
    )
}

pub(super) async fn recover_failure(state: &AppState, migration_id: &str) -> Result<(), ApiError> {
    let mut migration = state
        .placements
        .migrations()
        .get(migration_id)
        .await
        .map_err(migration_error)?
        .ok_or(ApiError::NotFound)?;
    let _shared_runtime = lock_shared_runtime(state, &migration).await?;
    if migration.cutover_committed || migration.stage.crossed_cutover() {
        if migration.stage != MigrationStage::CleanupPending {
            migration = advance(
                state,
                migration,
                MigrationStage::CleanupPending,
                MigrationPatch {
                    failure: Some(MigrationFailure::PostCutoverFailure),
                    ..MigrationPatch::default()
                },
            )
            .await?;
        }
        return finish_forward_cleanup(state, migration).await;
    }
    if matches!(
        migration.stage,
        MigrationStage::Requested | MigrationStage::Preflight
    ) {
        advance(
            state,
            migration,
            MigrationStage::Failed,
            MigrationPatch {
                failure: Some(MigrationFailure::PreflightFailed),
                ..MigrationPatch::default()
            },
        )
        .await?;
        return Ok(());
    }
    if migration.stage != MigrationStage::RollingBack {
        migration = advance(
            state,
            migration,
            MigrationStage::RollingBack,
            MigrationPatch {
                failure: Some(MigrationFailure::PreCutoverFailure),
                ..MigrationPatch::default()
            },
        )
        .await?;
    }
    finish_rollback(state, migration).await
}

async fn finish_rollback(state: &AppState, migration: DeploymentMigration) -> Result<(), ApiError> {
    let instance_id = migration.instance_id.clone();
    let source_before_cleanup = state
        .manager
        .get_persisted(&migration.instance_id)
        .await
        .map_err(runtime_error)?
        .ok_or(ApiError::NotFound)?;
    match migration.target_mode {
        DeploymentMode::Shared => {
            rollback_shared_target(state, &migration, &source_before_cleanup).await?
        }
        DeploymentMode::Dedicated => rollback_dedicated_target(state, &migration).await?,
    }
    remove_artifact_root(state, &migration.migration_id).await;
    // Reload after cleanup so provisional maintenance secrets can never be
    // copied back into the in-memory source route.
    let mut source = state
        .manager
        .get_persisted(&migration.instance_id)
        .await
        .map_err(runtime_error)?
        .ok_or(ApiError::NotFound)?;
    let source_runtime = state
        .placements
        .get(source.runtime_id())
        .await
        .map_err(runtime_error)?
        .ok_or_else(|| ApiError::Conflict("source runtime is missing during rollback".into()))?;
    ensure_runtime_ready(state, &source_runtime).await?;
    if source.deployment_mode == DeploymentMode::Shared {
        apply_tenant_disk(state, &source_runtime, &mut source).await?;
        runtime_ops::apply_root_disk_limit(&state.config, &state.placements, &source_runtime)
            .await
            .map_err(ApiError::Runtime)?;
        tenant::unfence(&state.docker, &source_runtime, tenant_target(&source))
            .await
            .map_err(|error| {
                ApiError::Runtime(format!("source tenant rollback enable failed: {error}"))
            })?;
    }
    let password = source
        .tenant_password
        .as_deref()
        .ok_or_else(|| ApiError::Conflict("source credential is missing during rollback".into()))?;
    tenant::verify_password(
        &state.docker,
        &source_runtime,
        tenant_target(&source),
        password,
    )
    .await
    .map_err(|error| ApiError::Runtime(format!("source rollback verification failed: {error}")))?;
    let failure = if migration.failure_code.as_deref()
        == Some(MigrationFailure::StructuralValidationTimedOut.code())
    {
        MigrationFailure::StructuralValidationTimedOut
    } else {
        MigrationFailure::RolledBackBeforeCutover
    };
    advance(
        state,
        migration,
        MigrationStage::Failed,
        MigrationPatch {
            failure: Some(failure),
            ..MigrationPatch::default()
        },
    )
    .await?;
    // Boot recovery pins routes so ordinary metadata refreshes cannot reopen
    // them. Clear that pin only after the rollback is durable and the source
    // credential was verified above.
    state.instances.open_routes(source).await;
    clear_caches(state, &instance_id).await;
    Ok(())
}

async fn rollback_shared_target(
    state: &AppState,
    migration: &DeploymentMigration,
    source: &InstanceMetadata,
) -> Result<(), ApiError> {
    let temp_id = temp_instance_id(&migration.migration_id)?;
    let target_runtime = match state
        .placements
        .reservation_runtime(&temp_id)
        .await
        .map_err(runtime_error)?
    {
        Some(runtime) => Some(runtime),
        None => match migration.target_runtime_id.as_deref() {
            Some(runtime_id) => state
                .placements
                .get(runtime_id)
                .await
                .map_err(runtime_error)?,
            None => None,
        },
    };
    if let Some(runtime) = target_runtime {
        ensure_runtime_ready(state, &runtime).await?;
        tenant::disk::prepare_drop(&state.config, &runtime, tenant_target(source))
            .await
            .map_err(|error| {
                ApiError::Runtime(format!(
                    "target rollback storage preparation failed: {error}"
                ))
            })?;
        tenant::drop_tenant(&state.docker, &runtime, tenant_target(source))
            .await
            .map_err(|error| ApiError::Runtime(format!("target rollback failed: {error}")))?;
        tenant::disk::remove(&state.config, &runtime, tenant_target(source))
            .await
            .map_err(|error| {
                ApiError::Runtime(format!("target rollback quota cleanup failed: {error}"))
            })?;
        let _ = state
            .placements
            .release(&temp_id)
            .await
            .map_err(runtime_error)?;
        if let Some(updated) = state
            .placements
            .get(&runtime.runtime_id)
            .await
            .map_err(runtime_error)?
        {
            runtime_ops::apply_limits(&state.docker, &state.config, &state.placements, &updated)
                .await
                .map_err(ApiError::Runtime)?;
        }
    }
    crate::api::instances::purge_shared_tenant_paths(state, &temp_id).await
}

async fn rollback_dedicated_target(
    state: &AppState,
    migration: &DeploymentMigration,
) -> Result<(), ApiError> {
    if let Err(error) = state
        .docker
        .delete(migration.protocol, &migration.instance_id)
        .await
        && !error.is_not_found()
    {
        return Err(ApiError::Runtime(format!(
            "dedicated target rollback failed: {error}"
        )));
    }
    if let Some(runtime) = state
        .placements
        .get(&migration.instance_id)
        .await
        .map_err(runtime_error)?
    {
        crate::api::instances::purge_retired_runtime_paths(state, &runtime).await?;
        state
            .placements
            .delete(&runtime.runtime_id)
            .await
            .map_err(runtime_error)?;
    } else {
        crate::api::instances::purge_provisional_runtime_paths(
            state,
            &migration.instance_id,
            migration.protocol,
            None,
        )
        .await?;
    }
    state
        .manager
        .delete_compatibility(&migration.instance_id)
        .await
        .map_err(runtime_error)?;
    state
        .manager
        .clear_staged_admin_secrets(&migration.instance_id)
        .await
        .map_err(runtime_error)
}

async fn finish_forward_cleanup(
    state: &AppState,
    mut migration: DeploymentMigration,
) -> Result<(), ApiError> {
    let migration_id = migration.migration_id.clone();
    let instance_id = migration.instance_id.clone();
    let mut target = state
        .manager
        .get_persisted(&migration.instance_id)
        .await
        .map_err(runtime_error)?
        .ok_or(ApiError::NotFound)?;
    let target_runtime = state
        .placements
        .get(target.runtime_id())
        .await
        .map_err(runtime_error)?
        .ok_or_else(|| ApiError::Conflict("committed target runtime is missing".into()))?;
    ensure_runtime_ready(state, &target_runtime).await?;
    if target.deployment_mode == DeploymentMode::Shared {
        apply_tenant_disk(state, &target_runtime, &mut target).await?;
        runtime_ops::apply_root_disk_limit(&state.config, &state.placements, &target_runtime)
            .await
            .map_err(ApiError::Runtime)?;
    }
    let password = target
        .tenant_password
        .as_deref()
        .ok_or_else(|| ApiError::Conflict("committed target credential is missing".into()))?;
    if let Err(error) = tenant::verify_password(
        &state.docker,
        &target_runtime,
        tenant_target(&target),
        password,
    )
    .await
    {
        let summary = "committed target could not be verified; source retained for manual recovery";
        let _ = advance(
            state,
            migration,
            MigrationStage::ManualIntervention,
            MigrationPatch {
                failure: Some(MigrationFailure::TargetVerificationFailed),
                ..MigrationPatch::default()
            },
        )
        .await;
        tracing::error!(
            event = "audit deployment_migration_target_verification_failed",
            %migration_id,
            error = %redaction::redact_connection_url(&error.to_string()),
        );
        return Err(ApiError::Runtime(summary.to_string()));
    }
    migration = advance(
        state,
        migration,
        MigrationStage::CleaningSource,
        MigrationPatch::default(),
    )
    .await?;
    if let Some(source_runtime) = state
        .placements
        .get(&migration.source_runtime_id)
        .await
        .map_err(runtime_error)?
    {
        match migration.source_mode {
            DeploymentMode::Dedicated => retire_dedicated_source(state, &source_runtime).await?,
            DeploymentMode::Shared => {
                retire_shared_source(state, &source_runtime, &target, &migration.migration_id)
                    .await?
            }
        }
    }
    advance(
        state,
        migration,
        MigrationStage::Completed,
        MigrationPatch::default(),
    )
    .await?;
    // Keep a boot-pinned route closed until source retirement and the terminal
    // migration record are both durable. The target credential was verified
    // before cleanup, so it is now safe to publish.
    state.instances.open_routes(target).await;
    clear_caches(state, &instance_id).await;
    remove_artifact_root(state, &migration_id).await;
    Ok(())
}

pub(super) async fn retire_dedicated_source(
    state: &AppState,
    runtime: &EngineRuntime,
) -> Result<(), ApiError> {
    if let Err(error) = state
        .docker
        .delete(runtime.protocol, &runtime.runtime_id)
        .await
        && !error.is_not_found()
    {
        return Err(ApiError::Runtime(format!(
            "source container cleanup failed: {error}"
        )));
    }
    crate::api::instances::purge_retired_runtime_paths(state, runtime).await?;
    state
        .manager
        .delete_compatibility(&runtime.runtime_id)
        .await
        .map_err(runtime_error)?;
    state
        .placements
        .delete(&runtime.runtime_id)
        .await
        .map_err(runtime_error)?;
    Ok(())
}

pub(super) async fn retire_shared_source(
    state: &AppState,
    runtime: &EngineRuntime,
    source: &InstanceMetadata,
    migration_id: &str,
) -> Result<(), ApiError> {
    ensure_runtime_ready(state, runtime).await?;
    tenant::disk::prepare_drop(&state.config, runtime, tenant_target(source))
        .await
        .map_err(|error| {
            ApiError::Runtime(format!("shared source storage preparation failed: {error}"))
        })?;
    tenant::drop_tenant(&state.docker, runtime, tenant_target(source))
        .await
        .map_err(|error| ApiError::Runtime(format!("shared source cleanup failed: {error}")))?;
    tenant::disk::remove(&state.config, runtime, tenant_target(source))
        .await
        .map_err(|error| {
            ApiError::Runtime(format!("shared source quota cleanup failed: {error}"))
        })?;
    let reservation_id = temp_instance_id(migration_id)?;
    state
        .placements
        .release(&reservation_id)
        .await
        .map_err(runtime_error)?;
    if let Some(updated) = state
        .placements
        .get(&runtime.runtime_id)
        .await
        .map_err(runtime_error)?
    {
        runtime_ops::apply_limits(&state.docker, &state.config, &state.placements, &updated)
            .await
            .map_err(ApiError::Runtime)?;
    }
    Ok(())
}

async fn apply_tenant_disk(
    state: &AppState,
    runtime: &EngineRuntime,
    metadata: &mut InstanceMetadata,
) -> Result<(), ApiError> {
    let disk = tenant::disk::set_limit(
        &state.config,
        &state.docker,
        runtime,
        tenant_target(metadata),
        metadata.limits.disk_mib,
    )
    .await
    .map_err(|error| ApiError::Runtime(format!("shared tenant disk limit failed: {error}")))?;
    let changed = tenant::disk::update_state(
        &mut metadata.limits,
        &mut metadata.disk_limit_blocked,
        &disk,
    )
    .map_err(|error| {
        ApiError::Runtime(format!(
            "shared tenant disk boundary could not be restored during migration recovery: {error}"
        ))
    })?;
    if changed {
        metadata.updated_at = now_rfc3339();
        state
            .manager
            .upsert_fenced(metadata.clone())
            .await
            .map_err(runtime_error)?;
    }
    Ok(())
}

async fn ensure_runtime_ready(state: &AppState, runtime: &EngineRuntime) -> Result<(), ApiError> {
    if !recovery_can_activate_runtime(runtime.status) {
        return Err(ApiError::Conflict(format!(
            "runtime {} is {} and cannot be activated for deployment migration recovery",
            runtime.runtime_id,
            runtime.status.as_str()
        )));
    }
    let inspection = state
        .docker
        .inspect_instance(runtime.protocol, &runtime.runtime_id)
        .await
        .map_err(runtime_error)?;
    match inspection.status {
        DockerContainerStatus::Running | DockerContainerStatus::Starting => {}
        DockerContainerStatus::Created | DockerContainerStatus::Stopped => {
            state
                .docker
                .start(runtime.protocol, &runtime.runtime_id)
                .await
                .map_err(runtime_error)?;
        }
        DockerContainerStatus::Failed => {
            return Err(ApiError::Conflict(format!(
                "runtime {} is failed and cannot complete migration recovery",
                runtime.runtime_id
            )));
        }
    }
    state
        .docker
        .wait_until_ready(
            runtime.protocol,
            &runtime.runtime_id,
            Duration::from_secs(180),
        )
        .await
        .map_err(runtime_error)?;
    Ok(())
}

fn recovery_can_activate_runtime(status: EngineRuntimeStatus) -> bool {
    !matches!(
        status,
        EngineRuntimeStatus::Failed
            | EngineRuntimeStatus::Quarantined
            | EngineRuntimeStatus::Deleting
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_intervention_is_isolated_instead_of_automatically_replayed() {
        assert!(automatic_boot_recovery_stage(MigrationStage::RollingBack));
        assert!(automatic_boot_recovery_stage(
            MigrationStage::CleanupPending
        ));
        assert!(!automatic_boot_recovery_stage(
            MigrationStage::ManualIntervention
        ));
    }

    #[test]
    fn recovery_never_activates_failed_or_destructive_runtime_states() {
        for status in [
            EngineRuntimeStatus::Failed,
            EngineRuntimeStatus::Quarantined,
            EngineRuntimeStatus::Deleting,
        ] {
            assert!(!recovery_can_activate_runtime(status));
        }
        for status in [
            EngineRuntimeStatus::Creating,
            EngineRuntimeStatus::Booting,
            EngineRuntimeStatus::Running,
            EngineRuntimeStatus::Stopped,
        ] {
            assert!(recovery_can_activate_runtime(status));
        }
    }
}
