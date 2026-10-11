use super::PHYSICAL_BACKUP_HEADROOM_BYTES;
use super::catalog::backup_info;
use super::checks::{
    admit_backup, backup_layout, check_backup_ready, check_backup_service,
    intentionally_stopped_backup, physical_restore_capacity, scheduler_error, store_error,
};
use super::online::{
    CaptureBudget, ValidatedCapture, capture_online, finish_publication, staging_budget,
};
use super::publication;
use super::storage::{backup_storage, prune_instance_backups};
use super::types::{BackupAttempt, BackupIssue};
use crate::config::DedicatedBackupMode;
use crate::databases::protocol::Protocol;
use crate::routes::http::response::ApiError;
use crate::routes::http::router::AppState;
use crate::server::backup::catalog::BackupCatalog;
use crate::server::backup::manifest::{
    CaptureInterval, ConsistencyLevel, EngineRecord, ManifestDetails,
};
use crate::server::backup::{
    BackupBundle, BackupLayout, BackupStorage, StoredBackup, build_manifest, new_backup_id,
};
use crate::server::jobs::import_export::{
    DataArchiveSourcePolicy, ExecutionPermit, ImportExportJobPermit, JobEstimateInput,
    JobResourceCost, create_bounded_archive_with_policy,
};
use crate::server::metadata::{InstanceMetadata, InstanceStatus};
use crate::server::placement::DeploymentMode;
use crate::utils::limits::mib_to_bytes;
use crate::utils::time::now_unix;
use std::path::Path as FsPath;
use std::path::PathBuf;

/// `mode` overrides `backups.dedicated_mode` for one request. An explicit or
/// configured `online` never falls back to a cold copy.
pub(super) async fn backup_instance(
    state: &AppState,
    instance_id: &str,
    mode: Option<DedicatedBackupMode>,
) -> Result<BackupAttempt, ApiError> {
    let admission = admit_backup(state, instance_id)?;
    let state = state.clone();
    let instance_id = instance_id.to_string();
    tokio::spawn(async move { run_backup(state, instance_id, mode, admission).await })
        .await
        .map_err(|error| ApiError::Runtime(format!("backup task failed: {error}")))?
}

/// A complete local artifact that no longer depends on the source.
struct PreparedBackup {
    storage: BackupStorage,
    bundle: BackupBundle,
    manifest: StoredBackup,
    protocol: Protocol,
    online_job: Option<String>,
    // Scheduler budget stays charged through upload.
    _execution: ExecutionPermit,
}

enum Prepared {
    Ready(Box<PreparedBackup>),
    Skipped(BackupIssue),
}

pub(super) async fn run_backup(
    state: AppState,
    instance_id: String,
    mode: Option<DedicatedBackupMode>,
    // The exclusive admission pins this instance's backup slot (and so the
    // staged artifact) until publication finishes.
    _admission: ImportExportJobPermit,
) -> Result<BackupAttempt, ApiError> {
    let prepared = match prepare_backup(&state, &instance_id, mode).await? {
        Prepared::Ready(prepared) => prepared,
        Prepared::Skipped(issue) => return Ok(BackupAttempt::Skipped(issue)),
    };
    // Management locks are released here: stop, delete or upgrade may proceed
    // while the finished artifact uploads.
    let PreparedBackup {
        storage,
        bundle,
        manifest,
        protocol,
        online_job,
        _execution,
    } = *prepared;
    let backup_id = manifest.backup_id.clone();
    // Journal the storage target before any object exists, so recovery can
    // remove an interrupted or orphaned upload by backup id.
    if let Err(error) = publication::begin(
        &state,
        &storage,
        &instance_id,
        &backup_id,
        online_job.as_deref(),
    )
    .await
    {
        if let Some(job_id) = &online_job {
            finish_publication(&state, job_id, Err(&error), false).await;
        }
        bundle.cleanup().await;
        return Err(error);
    }
    let committed = storage
        .commit(
            &bundle,
            &manifest,
            &publication::journal(&state, &backup_id),
        )
        .await
        .map_err(store_error);
    bundle.cleanup().await;
    // Reacquires the instance lock to serialize the final existence check
    // with deletion; a deleted instance's upload is removed.
    publication::finish(
        &state,
        &storage,
        &instance_id,
        &backup_id,
        online_job.as_deref(),
        committed,
    )
    .await?;
    if let Err(error) = prune_instance_backups(&state, &storage, &instance_id).await {
        tracing::warn!(
            event = "audit backup_retention_failed",
            instance_id,
            backup_id,
            %error,
            "backup completed but retention could not be fully applied"
        );
    }
    tracing::info!(
        event = "audit backup_completed",
        instance_id,
        protocol = protocol.as_str(),
        layout = ?manifest.layout,
        backup_id,
        storage = storage.kind().as_str(),
        catalog = manifest.catalog_available,
        consistency = manifest.consistency().map(ConsistencyLevel::as_str),
    );
    Ok(BackupAttempt::Completed(backup_info(manifest)))
}

/// Captures and validates a backup under the instance (and shared runtime)
/// management locks, which are released when this returns.
async fn prepare_backup(
    state: &AppState,
    instance_id: &str,
    mode: Option<DedicatedBackupMode>,
) -> Result<Prepared, ApiError> {
    let _operation = state.instance_locks.lock(instance_id).await;
    check_backup_service(state)?;
    let mut metadata =
        crate::subsystems::instances::reconcile_instance_locked(state, instance_id).await?;
    if let Some(issue) = intentionally_stopped_backup(&metadata) {
        return Ok(Prepared::Skipped(issue));
    }
    check_backup_ready(&metadata)?;
    super::recovery::recover_instance_publications(state, instance_id).await;
    let online = metadata.deployment_mode == DeploymentMode::Dedicated
        && mode.unwrap_or(state.config.backups.dedicated_mode) == DedicatedBackupMode::Online;
    // Strict online requests fail before any resource is reserved when the
    // engine has no certified strategy; they never fall back to a cold copy.
    let strategy = if online {
        let strategy = super::registry::strategy_for(&metadata).map_err(ApiError::from)?;
        super::recovery::recover_instance_jobs(state, instance_id).await?;
        Some(strategy)
    } else {
        None
    };
    let backup_source_bytes = if metadata.deployment_mode == DeploymentMode::Shared {
        crate::subsystems::import_export::jobs::measure_shared_database_bytes(state, &metadata)
            .await?
    } else {
        mib_to_bytes(metadata.limits.disk_mib)
    };
    let execution = state
        .import_export_jobs
        .acquire_execution(JobResourceCost::estimate(JobEstimateInput {
            protocol: metadata.protocol,
            input_size_bytes: backup_source_bytes.max(1),
            rollback_size_bytes: 0,
            wipe: false,
            compressed: true,
            export: true,
        }))
        .await
        .map_err(scheduler_error)?;
    let _runtime_operation = if metadata.deployment_mode == DeploymentMode::Shared {
        Some(state.instance_locks.lock(metadata.runtime_id()).await)
    } else {
        None
    };
    if metadata.deployment_mode == DeploymentMode::Shared {
        metadata =
            crate::subsystems::instances::reload_after_runtime_lock(state, &metadata).await?;
        check_backup_ready(&metadata)?;
    }
    let storage = backup_storage(state)?;
    let layout = backup_layout(metadata.deployment_mode);
    let backup_id = new_backup_id(layout);
    let catalog = if state.config.backups.browsing.enabled {
        Some(
            BackupCatalog::capture(
                &state.docker,
                &metadata,
                &backup_id,
                &state.config.backups.browsing,
            )
            .await
            .encode_bounded(state.config.backups.browsing.max_catalog_bytes)
            .map_err(|error| {
                ApiError::Runtime(format!("failed to encode backup catalog: {error}"))
            })?,
        )
    } else {
        None
    };
    let backups_root = PathBuf::from(state.config.paths.backups_root());
    let bundle = BackupBundle::create(&backups_root, instance_id, &backup_id)
        .await
        .map_err(store_error)?;
    let output_capacity = if layout == BackupLayout::Logical {
        crate::subsystems::import_export::jobs::measure_export_bytes(state, &metadata).await?
    } else {
        mib_to_bytes(metadata.limits.disk_mib)
            .saturating_add(PHYSICAL_BACKUP_HEADROOM_BYTES)
            .clamp(
                1,
                crate::server::jobs::import_export::MAX_DATA_ARCHIVE_BYTES,
            )
    };
    // Online staging holds the native capture and the packaged archive at
    // once; native verification reads in place. The native budget is what
    // restore extracts, so a larger capture is never published.
    let native_budget = physical_restore_capacity(metadata.limits.disk_mib);
    let reserved_bytes = if strategy.is_some() {
        staging_budget(native_budget, output_capacity)
    } else {
        output_capacity
    };
    let mut output_reservation = match state
        .import_uploads
        .reserve_output_capacity(&backups_root, reserved_bytes)
        .await
    {
        Ok(reservation) => Some(reservation),
        Err(error) => {
            bundle.cleanup().await;
            return Err(error);
        }
    };
    let source = BackupSource {
        metadata: &metadata,
        instance_id,
        backup_id: &backup_id,
        layout,
        catalog: catalog.as_deref(),
        output_capacity,
    };
    let written = match strategy {
        Some(strategy) => {
            write_online_bundle(
                state,
                &bundle,
                &source,
                strategy,
                native_budget,
                &mut output_reservation,
            )
            .await
        }
        None => write_bundle(state, &bundle, &source)
            .await
            .map(|manifest| (manifest, None)),
    };
    // `output_reservation` is released when this returns, after staging is
    // gone, unless a helper's removal was unconfirmed and cleanup took it.
    match written {
        Ok((manifest, online_job)) => Ok(Prepared::Ready(Box::new(PreparedBackup {
            storage,
            bundle,
            manifest,
            protocol: metadata.protocol,
            online_job,
            _execution: execution,
        }))),
        Err(error) => {
            bundle.cleanup().await;
            Err(error)
        }
    }
}

struct BackupSource<'a> {
    metadata: &'a InstanceMetadata,
    instance_id: &'a str,
    backup_id: &'a str,
    layout: BackupLayout,
    catalog: Option<&'a [u8]>,
    output_capacity: u64,
}

async fn write_online_bundle(
    state: &AppState,
    bundle: &BackupBundle,
    source: &BackupSource<'_>,
    strategy: &'static dyn super::strategy::OnlineBackupStrategy,
    native_budget: u64,
    reservation: &mut Option<crate::server::disk::capacity::DiskCapacityReservation>,
) -> Result<(StoredBackup, Option<String>), ApiError> {
    if let Some(catalog) = source.catalog {
        bundle.write_catalog(catalog).await.map_err(store_error)?;
    }
    let ValidatedCapture { job_id, details } = capture_online(
        state,
        source.metadata,
        strategy,
        bundle,
        source.backup_id,
        CaptureBudget {
            native_budget_bytes: native_budget,
            max_archive_bytes: source.output_capacity,
        },
        reservation,
    )
    .await?;
    tracing::info!(
        event = "audit online_backup_captured",
        instance_id = source.instance_id,
        protocol = source.metadata.protocol.as_str(),
        strategy = strategy.id(),
        job_id,
        "online backup captured and verified without stopping the database"
    );
    let manifest = finish_manifest(bundle, source, details).await;
    if let Err(error) = &manifest {
        finish_publication(state, &job_id, Err(error), false).await;
    }
    Ok((manifest?, Some(job_id)))
}

async fn write_bundle(
    state: &AppState,
    bundle: &BackupBundle,
    source: &BackupSource<'_>,
) -> Result<StoredBackup, ApiError> {
    if let Some(catalog) = source.catalog {
        bundle.write_catalog(catalog).await.map_err(store_error)?;
    }
    let engine = engine_record(state, source.metadata).await;
    let started_at_unix = now_unix();
    let consistency = match source.layout {
        BackupLayout::Physical => {
            create_physical_archive(
                state,
                source.metadata,
                &bundle.archive,
                source.output_capacity,
            )
            .await?;
            ConsistencyLevel::StoppedCopy
        }
        BackupLayout::Logical => {
            crate::subsystems::import_export::logical::create_shared_backup(
                state,
                source.metadata,
                bundle.archive.clone(),
                source.output_capacity,
            )
            .await?;
            shared_dump_consistency(source.metadata.protocol)
        }
    };
    let details = ManifestDetails::built_in(
        source.layout,
        consistency,
        CaptureInterval {
            started_at_unix,
            finished_at_unix: now_unix(),
        },
        engine,
    );
    finish_manifest(bundle, source, details).await
}

/// Only PostgreSQL's tenant dump runs in one repeatable-read snapshot; other
/// engines' tenant exports promise no common transactional point.
fn shared_dump_consistency(protocol: Protocol) -> ConsistencyLevel {
    if protocol == Protocol::Postgres {
        ConsistencyLevel::TransactionalSnapshot
    } else {
        ConsistencyLevel::PerObject
    }
}

async fn engine_record(state: &AppState, metadata: &InstanceMetadata) -> EngineRecord {
    let runtime_id = metadata.runtime_id();
    EngineRecord {
        version: None,
        image: state
            .docker
            .container_image(metadata.protocol, runtime_id)
            .await
            .ok()
            .flatten(),
        image_digest: state
            .docker
            .container_immutable_image_id(metadata.protocol, runtime_id)
            .await
            .ok()
            .flatten(),
    }
}

async fn finish_manifest(
    bundle: &BackupBundle,
    source: &BackupSource<'_>,
    details: ManifestDetails,
) -> Result<StoredBackup, ApiError> {
    let manifest = build_manifest(
        source.backup_id.to_string(),
        source.instance_id.to_string(),
        source.metadata.protocol,
        source.layout,
        &bundle.archive,
        source.catalog.is_some(),
        details,
    )
    .await
    .map_err(store_error)?;
    bundle
        .write_metadata(&manifest)
        .await
        .map_err(store_error)?;
    Ok(manifest)
}

/// Explicitly selected offline copy: stops the database, archives its data
/// directory and restarts it.
pub(super) async fn create_physical_archive(
    state: &AppState,
    metadata: &InstanceMetadata,
    archive: &FsPath,
    max_output_bytes: u64,
) -> Result<(), ApiError> {
    let instance_id = &metadata.instance_id;
    let was_running = metadata.status == InstanceStatus::Running;
    if was_running {
        tracing::info!(
            event = "audit physical_backup_pause",
            instance_id,
            protocol = metadata.protocol.as_str(),
            "offline backup mode is stopping the database for a cold archive; clients may disconnect"
        );
        crate::subsystems::instances::change_instance_state_locked(
            state,
            instance_id,
            crate::subsystems::instances::LifecycleAction::Stop,
        )
        .await?;
    }
    let paths = crate::server::paths::InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let archive_policy = if metadata.protocol == Protocol::Mysql {
        DataArchiveSourcePolicy::MysqlDataDirectory
    } else {
        DataArchiveSourcePolicy::Strict
    };
    let result = create_bounded_archive_with_policy(
        paths.data,
        archive.to_path_buf(),
        archive_policy,
        max_output_bytes,
    )
    .await
    .map_err(|error| ApiError::Runtime(error.to_string()));
    if let Err(error) = &result {
        tracing::error!(
            event = "audit backup_archive_failed",
            instance_id,
            protocol = metadata.protocol.as_str(),
            error = %error,
            "failed to archive stopped instance data"
        );
    }
    let result = crate::subsystems::import_export::finish_physical_change(
        state,
        instance_id,
        was_running,
        result,
    )
    .await;
    if was_running && result.is_ok() {
        tracing::info!(
            event = "audit physical_backup_resumed",
            instance_id,
            protocol = metadata.protocol.as_str(),
            "physical backup archive completed and the database was restarted"
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn online_native_budget_is_what_restore_extracts() {
        assert_eq!(physical_restore_capacity(1024), mib_to_bytes(1024));
        assert_eq!(
            physical_restore_capacity(u64::MAX / (1024 * 1024)),
            crate::server::jobs::import_export::MAX_DATA_ARCHIVE_BYTES
        );
        assert_eq!(physical_restore_capacity(0), 1);
    }

    #[test]
    fn only_postgres_tenant_dumps_claim_a_transactional_snapshot() {
        assert_eq!(
            shared_dump_consistency(Protocol::Postgres),
            ConsistencyLevel::TransactionalSnapshot
        );
        for protocol in [Protocol::Mysql, Protocol::Mongodb, Protocol::Clickhouse] {
            assert_eq!(
                shared_dump_consistency(protocol),
                ConsistencyLevel::PerObject
            );
        }
    }
}
