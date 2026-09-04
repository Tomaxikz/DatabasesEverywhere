use super::copy::{admit_logical_copy, copy_logical_data, validate_target};
use super::recovery::{retire_dedicated_source, retire_shared_source};
use super::*;

const SESSION_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) async fn run_dedicated_to_shared(
    state: &AppState,
    source: InstanceMetadata,
    mut migration: DeploymentMigration,
    creation: OwnedMutexGuard<()>,
) -> Result<(), ApiError> {
    let mut creation = Some(creation);
    migration = advance(
        state,
        migration,
        MigrationStage::Preflight,
        MigrationPatch::default(),
    )
    .await?;
    let source_runtime = state
        .placements
        .get(source.runtime_id())
        .await
        .map_err(runtime_error)?
        .ok_or_else(|| ApiError::Conflict("source runtime disappeared during preflight".into()))?;
    let password = source
        .tenant_password
        .as_deref()
        .ok_or_else(|| ApiError::Conflict("source tenant credential disappeared".into()))?;
    migration = advance(
        state,
        migration,
        MigrationStage::TargetPreparing,
        MigrationPatch::default(),
    )
    .await?;
    let temp_id = temp_instance_id(&migration.migration_id)?;
    let temp_password = temporary_password();
    let request = target_request(&source, &source_runtime, &temp_id, &temp_password);
    let image = resolve_image(state, &request)?;
    let mut tenant_limits = source.limits.clone();
    tenant_limits.disk_enforced = false;
    tenant_limits.disk_enforcement_method = "shared_pool_reservation".to_string();
    let (target_runtime, created_pool, _target_runtime_operation) = claim_shared_runtime(
        state,
        &request,
        &image,
        source.limits.clone(),
        &tenant_limits,
        &mut creation,
    )
    .await?;
    tenant::verify_password(
        &state.docker,
        &source_runtime,
        tenant_target(&source),
        password,
    )
    .await
    .map_err(|error| ApiError::Conflict(format!("source credential check failed: {error}")))?;
    if let Err(error) = runtime_ops::apply_limits(
        &state.docker,
        &state.config,
        &state.placements,
        &target_runtime,
    )
    .await
    {
        let _ = state.placements.release(&temp_id).await;
        if created_pool {
            destroy_empty_shared_runtime(state, &target_runtime).await;
        } else if let Ok(Some(current)) = state.placements.get(&target_runtime.runtime_id).await {
            let _ = runtime_ops::apply_limits(
                &state.docker,
                &state.config,
                &state.placements,
                &current,
            )
            .await;
        }
        return Err(ApiError::Runtime(error));
    }
    tenant::disk::prepare(
        &state.config,
        &state.docker,
        &target_runtime,
        tenant_target(&source),
        tenant_limits.disk_mib,
    )
    .await
    .map_err(|error| {
        ApiError::Runtime(format!("target tenant storage preparation failed: {error}"))
    })?;
    tenant::create(
        &state.docker,
        &target_runtime,
        tenant_target(&source),
        &temp_password,
        &tenant_limits,
    )
    .await
    .map_err(|error| ApiError::Runtime(format!("target tenant creation failed: {error}")))?;
    let disk = tenant::disk::set_limit(
        &state.config,
        &state.docker,
        &target_runtime,
        tenant_target(&source),
        tenant_limits.disk_mib,
    )
    .await
    .map_err(|error| ApiError::Runtime(format!("target tenant disk limit failed: {error}")))?;
    tenant_limits.disk_enforced = disk.enforced;
    tenant_limits.disk_enforcement_method = disk.method;
    state
        .placements
        .mark_provisioned(&temp_id)
        .await
        .map_err(runtime_error)?;
    migration = advance(
        state,
        migration,
        MigrationStage::TargetPrepared,
        MigrationPatch {
            target_runtime_id: Some(&target_runtime.runtime_id),
            ..MigrationPatch::default()
        },
    )
    .await?;
    // Acquire execution capacity while the source route is still open. The
    // permit then covers both structural scans, export, import, and target
    // validation; no expensive manifest phase may bypass the scheduler.
    let copy_admission = admit_logical_copy(state, &source).await?;
    migration = advance(
        state,
        migration,
        MigrationStage::SourceFencing,
        MigrationPatch::default(),
    )
    .await?;
    let drained = crate::instances::sessions::fence_and_wait(
        &state.instances,
        &state.gateway_supervisor.tenant_sessions(),
        &source.instance_id,
        SESSION_DRAIN_TIMEOUT,
    )
    .await;
    if !drained {
        return Err(ApiError::Conflict(
            "source gateway sessions did not drain before the migration deadline".to_string(),
        ));
    }
    migration = advance(
        state,
        migration,
        MigrationStage::SourceFenced,
        MigrationPatch {
            source_fenced: Some(true),
            ..MigrationPatch::default()
        },
    )
    .await?;

    let mut provisional =
        build_shared_metadata(state, &request, &target_runtime, tenant_limits, &image);
    provisional.tenant_password = Some(temp_password.clone());
    let copied = copy_logical_data(
        state,
        &source,
        &source_runtime,
        &provisional,
        migration,
        password,
        copy_admission,
    )
    .await?;
    migration = copied.migration;

    migration = advance(
        state,
        migration,
        MigrationStage::Validating,
        MigrationPatch::default(),
    )
    .await?;
    validate_target(
        state,
        &mut migration,
        &target_runtime,
        &provisional,
        &temp_password,
        &copied.source_manifest,
        copied.manifest_timeout,
    )
    .await?;
    drop(copied.execution);
    tenant::rotate_password(
        &state.docker,
        &target_runtime,
        tenant_target(&source),
        password,
    )
    .await
    .map_err(|error| ApiError::Runtime(format!("target credential adoption failed: {error}")))?;
    tenant::verify_password(
        &state.docker,
        &target_runtime,
        tenant_target(&source),
        password,
    )
    .await
    .map_err(|error| {
        ApiError::Runtime(format!("target credential verification failed: {error}"))
    })?;

    let mut final_metadata = provisional;
    final_metadata.instance_id.clone_from(&source.instance_id);
    final_metadata.public = source.public.clone();
    final_metadata.tenant_password = Some(password.to_string());
    final_metadata.created_at.clone_from(&source.created_at);
    final_metadata.updated_at = now_rfc3339();
    final_metadata.mariadb_native_password_sha1_stage2 =
        source.mariadb_native_password_sha1_stage2.clone();
    final_metadata.mysql_native_password_sha1_stage2 =
        source.mysql_native_password_sha1_stage2.clone();
    migration = advance(
        state,
        migration,
        MigrationStage::CutoverPending,
        MigrationPatch::default(),
    )
    .await?;
    migration = state
        .placements
        .migrations()
        .commit_dedicated_to_shared(
            &migration.migration_id,
            migration.revision,
            &temp_id,
            &final_metadata,
        )
        .await
        .map_err(migration_error)?;

    // The cutover transaction attached the hard tenant metadata. Until that
    // commit the provisional reservation remained charged to the root; only
    // now is it safe to lower the root quota around the child project.
    runtime_ops::apply_root_disk_limit(&state.config, &state.placements, &target_runtime)
        .await
        .map_err(ApiError::Runtime)?;

    // The target route becomes visible only after durable cutover and a live
    // check with the adopted source credential.
    tenant::verify_password(
        &state.docker,
        &target_runtime,
        tenant_target(&source),
        password,
    )
    .await
    .map_err(|error| ApiError::Runtime(format!("cutover target verification failed: {error}")))?;
    state.instances.upsert(final_metadata).await;
    clear_caches(state, &source.instance_id).await;
    migration = advance(
        state,
        migration,
        MigrationStage::VerifyingCutover,
        MigrationPatch::default(),
    )
    .await?;
    migration = advance(
        state,
        migration,
        MigrationStage::CleaningSource,
        MigrationPatch::default(),
    )
    .await?;
    retire_dedicated_source(state, &source_runtime).await?;
    let completed = advance(
        state,
        migration,
        MigrationStage::Completed,
        MigrationPatch::default(),
    )
    .await?;
    remove_artifact_root(state, &completed.migration_id).await;
    tracing::info!(
        event = "audit deployment_migration_completed",
        migration_id = %completed.migration_id,
        instance_id = %completed.instance_id,
        source_mode = completed.source_mode.as_str(),
        target_mode = completed.target_mode.as_str(),
        target_runtime_id = %target_runtime.runtime_id,
    );
    Ok(())
}

pub(super) async fn run_shared_to_dedicated(
    state: &AppState,
    source: InstanceMetadata,
    mut migration: DeploymentMigration,
    creation: OwnedMutexGuard<()>,
) -> Result<(), ApiError> {
    migration = advance(
        state,
        migration,
        MigrationStage::Preflight,
        MigrationPatch::default(),
    )
    .await?;
    let source_runtime = state
        .placements
        .get(source.runtime_id())
        .await
        .map_err(runtime_error)?
        .ok_or_else(|| ApiError::Conflict("source runtime disappeared during preflight".into()))?;
    let _source_runtime_operation = state.instance_locks.lock(&source_runtime.runtime_id).await;
    let password = source
        .tenant_password
        .as_deref()
        .ok_or_else(|| ApiError::Conflict("source tenant credential disappeared".into()))?;
    // The provisional dedicated engine exists at the same time as the source
    // pool, so admit its full temporary footprint rather than treating this as
    // an in-place resize.
    enforce_node_allocation_policy(state, &source.limits, None).await?;

    migration = advance(
        state,
        migration,
        MigrationStage::TargetPreparing,
        MigrationPatch::default(),
    )
    .await?;
    // This private engine has no gateway route until cutover. Bootstrap with
    // the durable credential: changing it later would reapply shared grants
    // and cannot work for ClickHouse's XML-managed dedicated account.
    let request = dedicated_target_request(&source, &source_runtime)?;
    let target = build_dedicated_target(state, request, false).await?;

    // Persist maintenance credentials before the first container process is
    // launched. This updates only encrypted route-auth columns and leaves the
    // authoritative shared placement and route untouched.
    state
        .manager
        .stage_dedicated_admin_secrets(&target.metadata)
        .await
        .map_err(runtime_error)?;
    let mut target_runtime = target.runtime();
    let mut runtime_record = target_runtime.clone();
    runtime_record.admin_secret = None;
    state
        .placements
        .save(&runtime_record)
        .await
        .map_err(runtime_error)?;
    // The provisional engine row is the durable node-capacity commit. Release
    // global admission before credential probes and container launch.
    drop(creation);
    tenant::verify_password(
        &state.docker,
        &source_runtime,
        tenant_target(&source),
        password,
    )
    .await
    .map_err(|error| ApiError::Conflict(format!("source credential check failed: {error}")))?;
    launch_dedicated_target(state, &target).await?;
    attest_dedicated_target(state, &target.metadata).await?;
    target_runtime.status = EngineRuntimeStatus::Running;
    target_runtime.updated_at = now_rfc3339();
    runtime_record = target_runtime.clone();
    runtime_record.admin_secret = None;
    state
        .placements
        .save(&runtime_record)
        .await
        .map_err(runtime_error)?;
    migration = advance(
        state,
        migration,
        MigrationStage::TargetPrepared,
        MigrationPatch {
            target_runtime_id: Some(&target_runtime.runtime_id),
            ..MigrationPatch::default()
        },
    )
    .await?;
    // Wait for scheduler capacity before making the shared source
    // unavailable. The permit remains held through target validation.
    let copy_admission = admit_logical_copy(state, &source).await?;
    migration = advance(
        state,
        migration,
        MigrationStage::SourceFencing,
        MigrationPatch::default(),
    )
    .await?;
    let drained = crate::instances::sessions::fence_and_wait(
        &state.instances,
        &state.gateway_supervisor.tenant_sessions(),
        &source.instance_id,
        SESSION_DRAIN_TIMEOUT,
    )
    .await;
    if !drained {
        return Err(ApiError::Conflict(
            "source gateway sessions did not drain before the migration deadline".to_string(),
        ));
    }
    // Kill live tenant sessions at the engine too. Re-enable the role only for
    // DBE's private export connection; the gateway route remains fenced.
    tenant::fence(&state.docker, &source_runtime, tenant_target(&source))
        .await
        .map_err(|error| ApiError::Runtime(format!("source tenant fence failed: {error}")))?;
    tenant::unfence(&state.docker, &source_runtime, tenant_target(&source))
        .await
        .map_err(|error| {
            ApiError::Runtime(format!("source tenant export enable failed: {error}"))
        })?;
    migration = advance(
        state,
        migration,
        MigrationStage::SourceFenced,
        MigrationPatch {
            source_fenced: Some(true),
            ..MigrationPatch::default()
        },
    )
    .await?;

    let copied = copy_logical_data(
        state,
        &source,
        &source_runtime,
        &target.metadata,
        migration,
        password,
        copy_admission,
    )
    .await?;
    migration = copied.migration;
    migration = advance(
        state,
        migration,
        MigrationStage::Validating,
        MigrationPatch::default(),
    )
    .await?;
    validate_target(
        state,
        &mut migration,
        &target_runtime,
        &target.metadata,
        password,
        &copied.source_manifest,
        copied.manifest_timeout,
    )
    .await?;
    drop(copied.execution);

    let mut final_metadata = target.metadata;
    final_metadata.status = crate::instances::metadata::InstanceStatus::Running;
    final_metadata.public = source.public.clone();
    final_metadata.tenant_password = Some(password.to_string());
    final_metadata.created_at.clone_from(&source.created_at);
    final_metadata.updated_at = now_rfc3339();
    final_metadata.mariadb_native_password_sha1_stage2 =
        source.mariadb_native_password_sha1_stage2.clone();
    final_metadata.mysql_native_password_sha1_stage2 =
        source.mysql_native_password_sha1_stage2.clone();
    tenant::verify_password(
        &state.docker,
        &target_runtime,
        tenant_target(&final_metadata),
        password,
    )
    .await
    .map_err(|error| {
        ApiError::Runtime(format!("target credential verification failed: {error}"))
    })?;

    migration = advance(
        state,
        migration,
        MigrationStage::CutoverPending,
        MigrationPatch::default(),
    )
    .await?;
    let source_reservation_id = temp_instance_id(&migration.migration_id)?;
    migration = state
        .placements
        .migrations()
        .commit_shared_to_dedicated(
            &migration.migration_id,
            migration.revision,
            &source_reservation_id,
            &final_metadata,
        )
        .await
        .map_err(migration_error)?;

    tenant::verify_password(
        &state.docker,
        &target_runtime,
        tenant_target(&final_metadata),
        password,
    )
    .await
    .map_err(|error| ApiError::Runtime(format!("cutover target verification failed: {error}")))?;
    state.instances.upsert(final_metadata).await;
    clear_caches(state, &source.instance_id).await;
    migration = advance(
        state,
        migration,
        MigrationStage::VerifyingCutover,
        MigrationPatch::default(),
    )
    .await?;
    migration = advance(
        state,
        migration,
        MigrationStage::CleaningSource,
        MigrationPatch::default(),
    )
    .await?;
    retire_shared_source(state, &source_runtime, &source, &migration.migration_id).await?;
    let completed = advance(
        state,
        migration,
        MigrationStage::Completed,
        MigrationPatch::default(),
    )
    .await?;
    remove_artifact_root(state, &completed.migration_id).await;
    tracing::info!(
        event = "audit deployment_migration_completed",
        migration_id = %completed.migration_id,
        instance_id = %completed.instance_id,
        source_mode = completed.source_mode.as_str(),
        target_mode = completed.target_mode.as_str(),
        target_runtime_id = %target_runtime.runtime_id,
    );
    Ok(())
}
