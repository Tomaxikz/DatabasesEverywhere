use super::*;

const GIB: u64 = 1024 * 1024 * 1024;
const MANIFEST_BASE_TIMEOUT_SECONDS: u64 = 3 * 60;
const MANIFEST_SECONDS_PER_GIB: u64 = 2 * 60;
const MANIFEST_TIMEOUT_MESSAGE: &str =
    "deployment structural validation timed out before cutover; migration was not cut over";

pub(super) struct LogicalCopy {
    pub(super) migration: DeploymentMigration,
    pub(super) source_manifest: tenant::TenantManifest,
    pub(super) manifest_timeout: Duration,
    pub(super) execution: ExecutionPermit,
}

pub(super) struct LogicalCopyAdmission {
    export_bytes: u64,
    execution: ExecutionPermit,
}

pub(super) async fn admit_logical_copy(
    state: &AppState,
    source: &InstanceMetadata,
) -> Result<LogicalCopyAdmission, ApiError> {
    let export_bytes = import_export::jobs::measure_export_bytes(state, source)
        .await?
        .max(1);
    let execution = state
        .import_export_jobs
        .acquire_execution(JobResourceCost::estimate(JobEstimateInput {
            protocol: source.protocol,
            input_size_bytes: export_bytes,
            // `export_bytes` is already a 2x/4x database-size bound plus the
            // fixed logical allowance. Feeding that conservative bound into
            // the import model covers the sequential manifest/export/import
            // pipeline without falsely charging in-place rollback memory.
            rollback_size_bytes: 0,
            wipe: false,
            compressed: crate::jobs::import_export::protocol_uses_native_compression(
                source.protocol,
            ),
            export: false,
        }))
        .await
        .map_err(scheduler_error)?;
    Ok(LogicalCopyAdmission {
        export_bytes,
        execution,
    })
}

pub(super) async fn copy_logical_data(
    state: &AppState,
    source: &InstanceMetadata,
    source_runtime: &EngineRuntime,
    target: &InstanceMetadata,
    mut migration: DeploymentMigration,
    source_password: &str,
    admission: LogicalCopyAdmission,
) -> Result<LogicalCopy, ApiError> {
    let LogicalCopyAdmission {
        export_bytes,
        execution,
    } = admission;
    let manifest_timeout = manifest_timeout(export_bytes);
    let manifest_challenge = tenant::ManifestChallenge::random();
    let source_manifest = match tenant::measure_manifest(
        &state.docker,
        source_runtime,
        tenant_target(source),
        source_password,
        manifest_challenge,
        import_export::MAX_UNARCHIVED_BYTES,
        manifest_timeout,
    )
    .await
    {
        Ok(manifest) => manifest,
        Err(error) if error.is_timeout() => {
            advance(
                state,
                migration,
                MigrationStage::RollingBack,
                MigrationPatch {
                    failure: Some(MigrationFailure::StructuralValidationTimedOut),
                    ..MigrationPatch::default()
                },
            )
            .await?;
            return Err(ApiError::Conflict(MANIFEST_TIMEOUT_MESSAGE.to_string()));
        }
        Err(error) => {
            return Err(ApiError::Runtime(format!(
                "source structural manifest collection failed: {error}"
            )));
        }
    };
    let artifact = artifact_path(state, &migration.migration_id)?;
    // The daemon-owned artifact and its pinned restore snapshot coexist on
    // the migration filesystem. Reserve both before writing either file so
    // concurrent migrations cannot overcommit the host between phases.
    let staging_bytes = migration_staging_bytes(export_bytes)?;
    let capacity = state
        .import_uploads
        .reserve_output_capacity(
            std::path::Path::new(&state.config.paths.tmp_root()),
            staging_bytes,
        )
        .await?;
    migration = advance(
        state,
        migration,
        MigrationStage::Exporting,
        MigrationPatch::default(),
    )
    .await?;
    import_export::logical::export_for_deployment_migration(
        state,
        source,
        artifact.clone(),
        export_bytes,
    )
    .await?;
    let artifact_bytes = tokio::fs::metadata(&artifact)
        .await
        .map_err(runtime_error)?
        .len();
    if artifact_bytes == 0 {
        return Err(ApiError::Conflict(
            "logical export produced an empty migration artifact".to_string(),
        ));
    }
    let stable_source_manifest = match tenant::measure_manifest(
        &state.docker,
        source_runtime,
        tenant_target(source),
        source_password,
        manifest_challenge,
        import_export::MAX_UNARCHIVED_BYTES,
        manifest_timeout,
    )
    .await
    {
        Ok(manifest) => manifest,
        Err(error) if error.is_timeout() => {
            return Err(ApiError::Conflict(MANIFEST_TIMEOUT_MESSAGE.to_string()));
        }
        Err(error) => {
            return Err(ApiError::Runtime(format!(
                "source integrity manifest recheck failed: {error}"
            )));
        }
    };
    ensure_source_stable(&source_manifest, &stable_source_manifest)?;
    migration = advance(
        state,
        migration,
        MigrationStage::Exported,
        MigrationPatch::default(),
    )
    .await?;
    migration = advance(
        state,
        migration,
        MigrationStage::Importing,
        MigrationPatch::default(),
    )
    .await?;
    import_export::logical::import_for_deployment_migration(state, target, &artifact).await?;
    migration = advance(
        state,
        migration,
        MigrationStage::Imported,
        MigrationPatch::default(),
    )
    .await?;
    drop(capacity);
    Ok(LogicalCopy {
        migration,
        source_manifest: stable_source_manifest,
        manifest_timeout,
        execution,
    })
}

pub(super) async fn validate_target(
    state: &AppState,
    migration: &mut DeploymentMigration,
    runtime: &EngineRuntime,
    metadata: &InstanceMetadata,
    password: &str,
    source_manifest: &tenant::TenantManifest,
    manifest_timeout: Duration,
) -> Result<(), ApiError> {
    tenant::verify_password(&state.docker, runtime, tenant_target(metadata), password)
        .await
        .map_err(|error| ApiError::Runtime(format!("target reachability failed: {error}")))?;
    let target_manifest = match tenant::measure_manifest(
        &state.docker,
        runtime,
        tenant_target(metadata),
        password,
        source_manifest.challenge,
        import_export::MAX_UNARCHIVED_BYTES,
        manifest_timeout,
    )
    .await
    {
        Ok(manifest) => manifest,
        Err(error) if error.is_timeout() => {
            *migration = advance(
                state,
                migration.clone(),
                MigrationStage::RollingBack,
                MigrationPatch {
                    failure: Some(MigrationFailure::StructuralValidationTimedOut),
                    ..MigrationPatch::default()
                },
            )
            .await?;
            return Err(ApiError::Conflict(MANIFEST_TIMEOUT_MESSAGE.to_string()));
        }
        Err(error) => {
            return Err(ApiError::Runtime(format!(
                "target structural validation failed: {error}"
            )));
        }
    };
    compare_manifests(source_manifest, &target_manifest)
}

fn manifest_timeout(export_bytes: u64) -> Duration {
    let bounded = export_bytes.clamp(1, import_export::MAX_UNARCHIVED_BYTES);
    let gib = bounded.div_ceil(GIB);
    Duration::from_secs(
        MANIFEST_BASE_TIMEOUT_SECONDS.saturating_add(gib.saturating_mul(MANIFEST_SECONDS_PER_GIB)),
    )
}

fn compare_manifests(
    source: &tenant::TenantManifest,
    target: &tenant::TenantManifest,
) -> Result<(), ApiError> {
    if source == target {
        return Ok(());
    }
    tracing::error!(
        event = "audit deployment_migration_manifest_mismatch",
        source_objects = source.object_count,
        target_objects = target.object_count,
        source_counted_objects = source.counted_object_count,
        target_counted_objects = target.counted_object_count,
        source_rows = source.row_count,
        target_rows = target.row_count,
        source_fingerprint = %source.fingerprint_sha256,
        target_fingerprint = %target.fingerprint_sha256,
        "deployment migration target differs from its fenced source"
    );
    Err(ApiError::Conflict(
        "target structural manifest does not match the fenced source; migration was not cut over"
            .to_string(),
    ))
}

fn ensure_source_stable(
    before: &tenant::TenantManifest,
    after: &tenant::TenantManifest,
) -> Result<(), ApiError> {
    if before == after {
        return Ok(());
    }
    tracing::warn!(
        event = "audit deployment_migration_source_changed",
        before_schema = %before.schema_sha256,
        after_schema = %after.schema_sha256,
        before_data = %before.data_sha256,
        after_data = %after.data_sha256,
        "deployment migration source changed while its logical export was being captured"
    );
    Err(ApiError::Conflict(
        "source schema or data changed during export; migration was not cut over".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(
        objects: u64,
        counted: u64,
        rows: u64,
        fingerprint: &str,
    ) -> tenant::TenantManifest {
        tenant::TenantManifest {
            challenge: tenant::ManifestChallenge([7; 32]),
            object_count: objects,
            counted_object_count: counted,
            row_count: rows,
            schema_sha256: format!("schema-{fingerprint}"),
            data_sha256: format!("data-{fingerprint}"),
            fingerprint_sha256: fingerprint.to_string(),
        }
    }

    #[test]
    fn target_manifest_must_exactly_match_the_fenced_source() {
        let source = manifest(4, 2, 50, "source");
        assert!(compare_manifests(&source, &source).is_ok());

        for target in [
            manifest(3, 2, 50, "source"),
            manifest(4, 1, 50, "source"),
            manifest(4, 2, 49, "source"),
            manifest(4, 2, 50, "different"),
        ] {
            let error = compare_manifests(&source, &target).unwrap_err();
            assert!(matches!(error, ApiError::Conflict(_)));
            assert!(error.to_string().contains("was not cut over"));
        }
    }

    #[test]
    fn manifest_timeout_scales_with_the_bounded_export_estimate() {
        assert_eq!(manifest_timeout(1), Duration::from_secs(5 * 60));
        assert_eq!(manifest_timeout(GIB), Duration::from_secs(5 * 60));
        assert_eq!(manifest_timeout(GIB + 1), Duration::from_secs(7 * 60));
        assert_eq!(manifest_timeout(u64::MAX), Duration::from_secs(19 * 60));
    }

    #[test]
    fn source_must_remain_stable_while_exporting() {
        let before = manifest(4, 2, 50, "before");
        assert!(ensure_source_stable(&before, &before).is_ok());
        let after = manifest(4, 2, 50, "after");
        let error = ensure_source_stable(&before, &after).unwrap_err();
        assert!(matches!(error, ApiError::Conflict(_)));
        assert!(error.to_string().contains("changed during export"));
    }
}
