use super::*;

pub async fn backup_status(
    State(state): State<AppState>,
    auth: ApiRequestContext,
) -> ApiResult<BackupStatusResponse> {
    auth.require_scope(scopes::BACKUPS_ADMIN)?;
    Ok(ApiResponse::ok(BackupStatusResponse {
        enabled: state.config.backups.enabled,
        interval_minutes: state.config.backups.interval_minutes,
        run_on_startup: state.config.backups.run_on_startup,
        retention_keep_latest_per_instance: state.config.backups.retention_keep_latest_per_instance,
        retention_max_age_days: state.config.backups.retention_max_age_days,
        redis_excluded: false,
        storage_driver: state.config.backups.storage.driver.as_str().to_string(),
        browsing_enabled: state.config.backups.browsing.enabled,
    }))
}

pub async fn list_instance_backups(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
) -> ApiResult<Vec<BackupInfo>> {
    auth.require_scope(scopes::BACKUPS_READ)?;
    require_instance(&state, &instance_id).await?;
    let storage = backup_storage(&state)?;
    let backups = storage
        .list(&instance_id)
        .await
        .map_err(store_error)?
        .into_iter()
        .map(backup_info)
        .collect();
    Ok(ApiResponse::ok(backups))
}

pub async fn browse_instance_backup(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, backup_id)): ApiPath<(String, String)>,
    ApiQuery(query): ApiQuery<BackupContentsQuery>,
) -> ApiResult<BackupContentsResponse> {
    auth.require_scope(scopes::BACKUPS_READ)?;
    let metadata = require_instance(&state, &instance_id).await?;
    let limit = query.limit.unwrap_or(DEFAULT_BROWSE_LIMIT);
    if limit == 0 || limit > MAX_BROWSE_LIMIT {
        return Err(ApiError::BadRequest(
            "limit must be between 1 and 100".to_string(),
        ));
    }
    if query
        .object
        .as_ref()
        .is_some_and(|object| object.len() > MAX_BROWSE_OBJECT_ID_BYTES)
    {
        return Err(ApiError::BadRequest(
            "object is longer than 1024 bytes".to_string(),
        ));
    }

    let storage = backup_storage(&state)?;
    let backup = storage
        .find(&instance_id, &backup_id)
        .await
        .map_err(store_error)?;
    check_backup_protocol(&backup.backup_id, backup.protocol, metadata.protocol)?;
    let bytes = storage
        .read_catalog(
            &instance_id,
            &backup_id,
            state.config.backups.browsing.max_catalog_bytes,
            FsPath::new(&state.config.paths.tmp_root()),
        )
        .await
        .map_err(store_error)?;
    let Some(bytes) = bytes else {
        return Ok(ApiResponse::ok(BackupContentsResponse {
            backup_id,
            instance_id,
            protocol: backup.protocol,
            database_name: metadata.database.name,
            captured_at: None,
            consistency: None,
            catalog_available: false,
            truncated: false,
            warnings: vec![
                "this backup predates catalog capture or browsing was disabled when it was created"
                    .to_string(),
            ],
            objects: query.object.is_none().then(Vec::new),
            selection: None,
        }));
    };
    let catalog =
        BackupCatalog::decode(&bytes, &instance_id, &backup_id).map_err(ApiError::Runtime)?;
    if catalog.protocol != metadata.protocol {
        return Err(ApiError::Conflict(format!(
            "backup {backup_id} catalog uses {}, but the target instance uses {}",
            catalog.protocol.as_str(),
            metadata.protocol.as_str()
        )));
    }
    if catalog.database_name != metadata.database.name {
        return Err(ApiError::Conflict(format!(
            "backup {backup_id} catalog belongs to a different database identity"
        )));
    }
    let selection = select_catalog_object(&catalog, query.object.as_deref(), query.offset, limit)?;
    let objects = backup_objects(&catalog, query.object.is_none());
    Ok(ApiResponse::ok(BackupContentsResponse {
        backup_id,
        instance_id,
        protocol: catalog.protocol,
        database_name: catalog.database_name,
        captured_at: Some(catalog.captured_at),
        consistency: Some(catalog.consistency),
        catalog_available: true,
        truncated: catalog.truncated,
        warnings: catalog.warnings,
        objects,
        selection,
    }))
}

pub async fn run_instance_backup(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
) -> ApiResult<BackupInfo> {
    auth.require_scope(scopes::BACKUPS_WRITE)?;
    match backup_instance(&state, &instance_id).await? {
        BackupAttempt::Completed(backup) => Ok(ApiResponse::ok(backup)),
        BackupAttempt::Skipped(issue) => Err(ApiError::BadRequest(issue.reason.message)),
    }
}

pub async fn run_all_backups(
    State(state): State<AppState>,
    auth: ApiRequestContext,
) -> ApiResult<RunBackupResponse> {
    auth.require_scope(scopes::BACKUPS_ADMIN)?;
    Ok(ApiResponse::ok(backup_all_instances(&state).await))
}

pub async fn delete_instance_backup(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, backup_id)): ApiPath<(String, String)>,
) -> ApiResult<DeleteArtifactResponse> {
    auth.require_scope(scopes::BACKUPS_WRITE)?;
    require_instance(&state, &instance_id).await?;
    let storage = backup_storage(&state)?;
    storage
        .delete(&instance_id, &backup_id)
        .await
        .map_err(store_error)?;
    tracing::info!(
        event = "audit backup_deleted",
        instance_id,
        backup_id,
        storage = storage.kind().as_str()
    );
    Ok(ApiResponse::ok(DeleteArtifactResponse {
        id: backup_id,
        deleted: true,
    }))
}

pub async fn restore_instance_backup(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath((instance_id, backup_id)): ApiPath<(String, String)>,
    ApiJson(confirmation): ApiJson<DestructiveActionConfirmation>,
) -> ApiResult<RestoreBackupResponse> {
    auth.require_scope(scopes::RECOVERY_ADMIN)?;
    let authorization = DestructiveActionPolicy::authorize("backup restore", &confirmation)?;
    let admission = admit_backup(&state, &instance_id)?;
    let state = state.clone();
    let reason = authorization.reason().to_string();
    tokio::spawn(
        async move { restore_backup(state, instance_id, backup_id, reason, admission).await },
    )
    .await
    .map_err(|error| ApiError::Runtime(format!("backup restore task failed: {error}")))?
}
