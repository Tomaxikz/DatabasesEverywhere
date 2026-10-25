use super::checks::{
    check_backup_layout, check_backup_protocol, check_backup_ready, check_backup_service,
    physical_restore_capacity, restore_input_bytes, scheduler_error, store_error,
};
use super::registry::strategy_by_id;
use super::storage::backup_storage;
use super::strategy::{
    AfterStartRestoreContext, OnlineBackupStrategy, RestoreContext, RestoreKind,
};
use super::types::RestoreBackupResponse;
use crate::routes::http::response::{ApiError, ApiResponse, ApiResult};
use crate::routes::http::router::AppState;
use crate::server::backup::manifest::{RestoreFormat, RestoreRecipeRef};
use crate::server::backup::{BackupLayout, StoredBackup, prepare_private_dir};
use crate::server::jobs::import_export::{
    ImportExportJobPermit, JobEstimateInput, JobResourceCost,
};
use crate::server::metadata::InstanceStatus;
use crate::server::placement::DeploymentMode;
use crate::subsystems::import_export::StagedDataPreparation;
use std::path::Path as FsPath;
use std::path::PathBuf;
use std::sync::Arc;

pub(super) async fn restore_backup(
    state: AppState,
    instance_id: String,
    backup_id: String,
    reason: String,
    _admission: ImportExportJobPermit,
) -> ApiResult<RestoreBackupResponse> {
    let _operation = state.instance_locks.lock(&instance_id).await;
    check_backup_service(&state)?;
    let mut metadata =
        crate::subsystems::instances::reconcile_instance_locked(&state, &instance_id).await?;
    let storage = backup_storage(&state)?;
    let stored = storage
        .find(&instance_id, &backup_id)
        .await
        .map_err(store_error)?;
    check_backup_protocol(&stored.backup_id, stored.protocol, metadata.protocol)?;
    check_backup_layout(&stored.backup_id, stored.layout, metadata.deployment_mode)?;
    // Resolve the restore recipe from the stored format before anything is
    // stopped or reserved; unknown recipes fail explicitly.
    let recipe = recipe_for(&stored)?;
    // Engine-loaded captures (logical dumps, snapshot APIs) restore into the
    // running instance instead of replacing its data directory.
    let after_start = recipe
        .as_ref()
        .is_some_and(|recipe| recipe.strategy.restore_kind() == RestoreKind::AfterStart);
    if after_start && metadata.status != InstanceStatus::Running {
        return Err(ApiError::Conflict(format!(
            "backup {} is loaded into the running engine; start the instance first",
            stored.backup_id
        )));
    }
    let logical_rollback_bytes = if stored.layout == BackupLayout::Logical {
        Some(crate::subsystems::import_export::jobs::measure_export_bytes(&state, &metadata).await?)
    } else {
        None
    };
    // Physical archives may expand to the complete instance allocation, but a
    // tenant-logical backup is already a bounded database dump. Charging a
    // shared restore for the tenant's full disk allocation makes a tiny dump
    // impossible to restore into a generously sized tenant.
    let restore_size_bytes =
        restore_input_bytes(stored.layout, stored.size_bytes, metadata.limits.disk_mib);
    let _execution = state
        .import_export_jobs
        .acquire_execution(JobResourceCost::estimate(JobEstimateInput {
            protocol: metadata.protocol,
            input_size_bytes: restore_size_bytes.max(1),
            rollback_size_bytes: logical_rollback_bytes.unwrap_or(0),
            wipe: true,
            compressed: true,
            export: false,
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
            crate::subsystems::instances::reload_after_runtime_lock(&state, &metadata).await?;
        check_backup_ready(&metadata)?;
        if metadata.disk_limit_blocked {
            return Err(ApiError::Conflict(
                "shared tenant writes are blocked by its disk limit; restore cannot continue"
                    .to_string(),
            ));
        }
    }
    let extracted_capacity = physical_restore_capacity(metadata.limits.disk_mib);
    check_expansion(&stored, extracted_capacity)?;
    let physical_paths = if stored.layout == BackupLayout::Physical {
        let paths = crate::server::paths::InstancePaths::new(&state.config.paths, &instance_id)
            .map_err(ApiError::bad_request)?;
        crate::subsystems::import_export::check_restore_layout(&state, &metadata, &paths)?;
        Some(paths)
    } else {
        None
    };
    let _extracted_capacity = if after_start {
        let temporary_root = PathBuf::from(state.config.paths.tmp_root());
        prepare_private_dir(&temporary_root, "backup restore workspace")
            .await
            .map_err(store_error)?;
        Some(
            state
                .import_uploads
                .reserve_output_capacity(&temporary_root, extracted_capacity)
                .await?,
        )
    } else if let Some(paths) = physical_paths.as_ref() {
        let data_parent = paths.data.parent().ok_or_else(|| {
            ApiError::Runtime("backup restore data directory has no parent".to_string())
        })?;
        Some(
            state
                .import_uploads
                .reserve_output_capacity(data_parent, extracted_capacity)
                .await?,
        )
    } else {
        None
    };
    let _logical_staging_capacity = if let Some(rollback_bytes) = logical_rollback_bytes {
        let staging_root = crate::subsystems::import_export::logical_staging_root(&state).await?;
        let staging_bytes =
            crate::subsystems::import_export::logical::shared_restore_staging_bytes(
                stored.size_bytes.max(1),
                rollback_bytes,
            )?;
        Some(
            state
                .import_uploads
                .reserve_output_capacity(&staging_root, staging_bytes)
                .await?,
        )
    } else {
        None
    };
    let temporary_capacity = if storage.kind() == crate::config::BackupStorageDriver::Local {
        None
    } else {
        let temporary_root = PathBuf::from(state.config.paths.tmp_root());
        prepare_private_dir(&temporary_root, "backup materialization directory")
            .await
            .map_err(store_error)?;
        Some(
            state
                .import_uploads
                .reserve_output_capacity(&temporary_root, stored.size_bytes.max(1))
                .await?,
        )
    };
    let materialized = storage
        .materialize(
            &instance_id,
            &backup_id,
            FsPath::new(&state.config.paths.tmp_root()),
            temporary_capacity,
            Arc::clone(&state.config.budgets.backup_materializations),
        )
        .await
        .map_err(store_error)?;
    let finished = match stored.layout {
        BackupLayout::Physical => {
            let paths = physical_paths.ok_or_else(|| {
                ApiError::Runtime("physical backup restore paths were unavailable".to_string())
            })?;
            if let Some(recipe) = recipe.as_ref().filter(|_| after_start) {
                let finished = restore_into_running(
                    &state,
                    &metadata,
                    recipe,
                    &materialized.path,
                    extracted_capacity,
                    &paths,
                )
                .await;
                drop(materialized);
                finished?;
                tracing::info!(
                    event = "audit backup_restored",
                    instance_id,
                    backup_id,
                    reason,
                    storage = storage.kind().as_str(),
                );
                return Ok(ApiResponse::ok(RestoreBackupResponse {
                    instance_id,
                    backup_id,
                    restored: true,
                }));
            }
            let was_running = metadata.status == InstanceStatus::Running;
            if was_running
                && let Err(error) = crate::subsystems::instances::change_instance_state_locked(
                    &state,
                    &instance_id,
                    crate::subsystems::instances::LifecycleAction::Stop,
                )
                .await
            {
                drop(materialized);
                return Err(error);
            }
            match &recipe {
                Some(recipe) => {
                    let preparation = StrategyPreparation { recipe };
                    crate::subsystems::import_export::restore_prepared_archive(
                        &state,
                        &instance_id,
                        paths,
                        &materialized.path,
                        was_running,
                        extracted_capacity,
                        &preparation,
                    )
                    .await
                }
                None => {
                    crate::subsystems::import_export::restore_bounded_archive(
                        &state,
                        &instance_id,
                        paths,
                        &materialized.path,
                        was_running,
                        extracted_capacity,
                    )
                    .await
                }
            }
        }
        BackupLayout::Logical => {
            crate::subsystems::import_export::logical::restore_shared_backup(
                &state,
                &metadata,
                &materialized.path,
                stored.size_bytes.max(1),
                logical_rollback_bytes.ok_or_else(|| {
                    ApiError::Runtime(
                        "logical backup rollback capacity was not reserved".to_string(),
                    )
                })?,
            )
            .await
        }
    };
    drop(materialized);
    finished?;
    tracing::info!(
        event = "audit backup_restored",
        instance_id,
        backup_id,
        reason,
        storage = storage.kind().as_str(),
    );
    Ok(ApiResponse::ok(RestoreBackupResponse {
        instance_id,
        backup_id,
        restored: true,
    }))
}

/// Extracts an engine-loaded capture into a private workspace and lets its
/// strategy load it into the running instance. The data directory is never
/// replaced on this path.
async fn restore_into_running(
    state: &AppState,
    metadata: &crate::server::metadata::InstanceMetadata,
    recipe: &StrategyRecipe,
    artifact: &FsPath,
    max_extracted_bytes: u64,
    paths: &crate::server::paths::InstancePaths,
) -> Result<(), ApiError> {
    let root_name = paths
        .data
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ApiError::Runtime("invalid instance data path".to_string()))?
        .to_string();
    let workspace = PathBuf::from(state.config.paths.tmp_root())
        .join(format!(".dbev-restore-{}", uuid::Uuid::new_v4().simple()));
    prepare_private_dir(&workspace, "backup restore workspace")
        .await
        .map_err(store_error)?;
    let result = async {
        crate::server::jobs::import_export::extract_bounded_archive(
            artifact.to_path_buf(),
            workspace.clone(),
            root_name.clone(),
            max_extracted_bytes,
        )
        .await
        .map_err(ApiError::bad_request)?;
        let payload = workspace.join(&root_name).join(&recipe.restore_target);
        let ctx = AfterStartRestoreContext {
            state,
            metadata,
            recipe: &recipe.recipe,
            payload: &payload,
        };
        recipe
            .strategy
            .restore_after_start(&ctx)
            .await
            .map_err(ApiError::from)
    }
    .await;
    if let Err(error) =
        crate::io::files::ignore_missing(tokio::fs::remove_dir_all(&workspace).await)
    {
        tracing::warn!(path = %workspace.display(), %error, "failed to remove backup restore workspace");
    }
    result
}

/// Strategy recipe resolved for an online capture.
struct StrategyRecipe {
    strategy: &'static dyn OnlineBackupStrategy,
    recipe: RestoreRecipeRef,
    restore_target: PathBuf,
}

/// A recorded expansion larger than this instance's extraction cap would
/// fail midway; refuse it before anything is stopped.
fn check_expansion(stored: &StoredBackup, extracted_capacity: u64) -> Result<(), ApiError> {
    match stored
        .details
        .as_ref()
        .and_then(|details| details.expanded_bytes)
    {
        Some(expanded) if expanded > extracted_capacity => Err(ApiError::Conflict(format!(
            "backup {} expands to {expanded} bytes, but restore into this instance extracts at most {extracted_capacity} bytes; raise the instance disk limit first",
            stored.backup_id
        ))),
        _ => Ok(()),
    }
}

/// Maps the stored format to its restore path, independent of placement.
/// Built-in formats need no recipe step but must name a recipe version this
/// build restores; strategy captures need their exact strategy and a recipe
/// version this build can still restore. Runs before anything is stopped.
fn recipe_for(stored: &StoredBackup) -> Result<Option<StrategyRecipe>, ApiError> {
    let (strategy_id, recipe, restore_target) = match stored.restore_format() {
        RestoreFormat::DataDirectoryArchive { .. } | RestoreFormat::LogicalDump { .. } => {
            if let Some(details) = &stored.details
                && !details.built_in_recipe_supported()
            {
                return Err(ApiError::Conflict(format!(
                    "backup {} uses restore recipe {}, which this build cannot restore",
                    stored.backup_id,
                    details.restore_recipe.tag_value()
                )));
            }
            return Ok(None);
        }
        RestoreFormat::StrategyCapture {
            strategy,
            recipe,
            restore_target,
        } => (strategy, recipe, restore_target),
    };
    let strategy = strategy_by_id(strategy_id).ok_or_else(|| {
        ApiError::Conflict(format!(
            "backup {} requires the {strategy_id} restore recipe, which this build does not provide",
            stored.backup_id
        ))
    })?;
    if strategy.restore_recipe().id != recipe.id
        || !strategy
            .restorable_recipe_versions()
            .contains(&recipe.version)
    {
        return Err(ApiError::Conflict(format!(
            "backup {} uses restore recipe {}, which this build cannot restore",
            stored.backup_id,
            recipe.tag_value()
        )));
    }
    Ok(Some(StrategyRecipe {
        strategy,
        recipe: recipe.clone(),
        restore_target: PathBuf::from(restore_target),
    }))
}

struct StrategyPreparation<'a> {
    recipe: &'a StrategyRecipe,
}

impl StagedDataPreparation for StrategyPreparation<'_> {
    fn prepare<'a>(
        &'a self,
        staged_data: &'a FsPath,
    ) -> futures::future::BoxFuture<'a, Result<(), ApiError>> {
        Box::pin(async move {
            let ctx = RestoreContext {
                recipe: &self.recipe.recipe,
                extracted_root: staged_data,
                restore_target: &self.recipe.restore_target,
            };
            self.recipe
                .strategy
                .prepare_restore(&ctx)
                .await
                .map_err(ApiError::from)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::databases::protocol::Protocol;
    use crate::server::backup::manifest::{
        ArtifactFormat, BackupMethod, ConsistencyLevel, ManifestDetails,
    };

    fn stored(details: Option<ManifestDetails>) -> StoredBackup {
        StoredBackup {
            schema_version: if details.is_some() { 2 } else { 1 },
            backup_id: "one.physical.tar.gz".to_string(),
            instance_id: "inst_one".to_string(),
            protocol: Protocol::Postgres,
            layout: BackupLayout::Physical,
            size_bytes: 1,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            created_at_unix: 1_767_225_600,
            sha256: "0".repeat(64),
            catalog_available: false,
            details,
        }
    }

    #[test]
    fn built_in_formats_restore_without_a_recipe_step() {
        assert!(recipe_for(&stored(None)).unwrap().is_none());
        let offline = crate::server::backup::test_details(BackupLayout::Physical);
        assert!(recipe_for(&stored(Some(offline))).unwrap().is_none());
    }

    #[test]
    fn newer_built_in_recipe_versions_are_refused() {
        for layout in [BackupLayout::Physical, BackupLayout::Logical] {
            let mut details = crate::server::backup::test_details(layout);
            details.restore_recipe.version = 2;
            let mut backup = stored(Some(details));
            backup.layout = layout;
            let Err(error) = recipe_for(&backup) else {
                panic!("a newer built-in recipe must not restore as version 1");
            };
            assert!(matches!(error, ApiError::Conflict(message) if message.contains("@2")));
        }
    }

    #[test]
    fn recorded_expansion_must_fit_the_extraction_cap() {
        let mut details = crate::server::backup::test_details(BackupLayout::Physical);
        details.expanded_bytes = Some(2048);
        let backup = stored(Some(details));
        assert!(check_expansion(&backup, 2048).is_ok());
        assert!(matches!(
            check_expansion(&backup, 2047),
            Err(ApiError::Conflict(message)) if message.contains("2048")
        ));
        // Backups without a recorded expansion keep the extraction-time cap.
        assert!(check_expansion(&stored(None), 1).is_ok());
    }

    #[test]
    fn strategy_captures_without_their_recipe_are_refused() {
        let mut details = crate::server::backup::test_details(BackupLayout::Physical);
        details.format = ArtifactFormat::OnlineCapture;
        details.method = BackupMethod::OnlineStrategy;
        details.strategy = Some("example.unknown".to_string());
        details.restore_recipe = RestoreRecipeRef::new("example.unknown", 1);
        details.restore_target = Some("data".to_string());
        details.consistency = ConsistencyLevel::PhysicalRecoveryPoint;
        let Err(error) = recipe_for(&stored(Some(details))) else {
            panic!("an unknown recipe must not restore");
        };
        assert!(
            matches!(error, ApiError::Conflict(message) if message.contains("example.unknown"))
        );
    }
}
