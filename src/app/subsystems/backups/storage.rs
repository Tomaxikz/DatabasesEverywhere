use super::*;

pub(crate) async fn prepare_backup_download(
    state: &AppState,
    instance_id: &str,
    backup_id: &str,
) -> Result<MaterializedBackup, ApiError> {
    let storage = backup_storage(state)?;
    let tmp_root = PathBuf::from(state.config.paths.tmp_root());
    let capacity = if storage.kind() == crate::config::BackupStorageDriver::Local {
        None
    } else {
        let manifest = storage
            .find(instance_id, backup_id)
            .await
            .map_err(store_error)?;
        prepare_private_dir(&tmp_root, "backup materialization directory")
            .await
            .map_err(store_error)?;
        Some(
            state
                .import_uploads
                .reserve_output_capacity(&tmp_root, manifest.size_bytes.max(1))
                .await?,
        )
    };
    storage
        .materialize(
            instance_id,
            backup_id,
            &tmp_root,
            capacity,
            Arc::clone(&state.config.budgets.backup_materializations),
        )
        .await
        .map_err(store_error)
}

pub(crate) async fn require_backup(
    state: &AppState,
    instance_id: &str,
    backup_id: &str,
) -> Result<(), ApiError> {
    backup_storage(state)?
        .find(instance_id, backup_id)
        .await
        .map(|_| ())
        .map_err(store_error)
}

pub(crate) async fn purge_instance_backups(
    state: &AppState,
    instance_id: &str,
) -> Result<usize, ApiError> {
    backup_storage(state)?
        .delete_instance(instance_id)
        .await
        .map_err(store_error)
}

pub(super) fn backup_storage(state: &AppState) -> Result<BackupStorage, ApiError> {
    BackupStorage::from_config(&state.config).map_err(store_error)
}

pub(super) async fn prune_instance_backups(
    state: &AppState,
    storage: &BackupStorage,
    instance_id: &str,
) -> Result<(), ApiError> {
    let keep_latest = state.config.backups.retention_keep_latest_per_instance;
    let max_age_seconds = state
        .config
        .backups
        .retention_max_age_days
        .saturating_mul(SECONDS_PER_DAY);
    let now = now_unix();
    let mut backups = storage.list(instance_id).await.map_err(store_error)?;
    backups.sort_by_key(|backup| std::cmp::Reverse(backup.created_at_unix));
    let mut deleted = 0_usize;
    for (index, backup) in backups.into_iter().enumerate() {
        let expired = max_age_seconds > 0
            && now.saturating_sub(backup.created_at_unix)
                > i64::try_from(max_age_seconds).unwrap_or(i64::MAX);
        if index >= keep_latest || expired {
            storage
                .delete(instance_id, &backup.backup_id)
                .await
                .map_err(store_error)?;
            deleted += 1;
        }
    }
    tracing::info!(
        event = "audit backup_retention_pruned",
        instance_id,
        keep_latest,
        max_age_days = state.config.backups.retention_max_age_days,
        deleted,
        storage = storage.kind().as_str(),
    );
    Ok(())
}
