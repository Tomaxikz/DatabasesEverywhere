use super::catalog::{backup_info, backup_objects, select_catalog_object};
use super::checks::{admit_backup, check_backup_protocol, require_instance, store_error};
use super::restore::restore_backup;
use super::run::backup_instance;
use super::scheduler::backup_all_instances;
use super::storage::backup_storage;
use super::types::{BackupAttempt, BackupContentsQuery, RestoreBackupResponse, RunBackupResponse};
use super::types::{BackupContentsResponse, BackupInfo, BackupStatusResponse};
use super::types::{RunBackupQuery, UnsupportedBackupInfo};
use super::{DEFAULT_BROWSE_LIMIT, MAX_BROWSE_LIMIT, MAX_BROWSE_OBJECT_ID_BYTES};
use crate::auth::scopes;
use crate::routes::http::policy::{
    ApiRequestContext, DestructiveActionConfirmation, DestructiveActionPolicy,
};
use crate::routes::http::response::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResponse, ApiResult};
use crate::routes::http::router::AppState;
use crate::server::backup::catalog::BackupCatalog;
use crate::subsystems::artifacts::DeleteArtifactResponse;
use axum::extract::State;
use std::path::Path as FsPath;

#[utoipa::path(
    get,
    path = "/api/admin/backups/status",
    tag = "admin",
    summary = "Get automatic backup configuration status.",
    extensions(("x-required-scope" = json!(scopes::BACKUPS_ADMIN))),
    responses((status = 200, description = "Backup status.", body = BackupStatusResponse))
)]
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
        dedicated_mode: state.config.backups.dedicated_mode.as_str(),
    }))
}

#[utoipa::path(
    get,
    path = "/api/instances/{instance_id}/backups",
    tag = "backups",
    summary = "List backups belonging to one instance.",
    extensions(("x-required-scope" = json!(scopes::BACKUPS_READ))),
    params(("instance_id" = String, Path)),
    responses((status = 200, description = "Backup artifact list.", body = Vec<BackupInfo>))
)]
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

#[utoipa::path(
    get,
    path = "/api/instances/{instance_id}/unsupported-backups",
    tag = "backups",
    summary = "List backups of one instance that this daemon cannot read.",
    description = "Backups written in a format this daemon does not understand, such as a newer manifest schema. They are never restored or removed by retention; upgrade the daemon to use them, or remove one explicitly with DELETE /api/instances/{instance_id}/backups/{backup_id}.",
    extensions(("x-required-scope" = json!(scopes::BACKUPS_READ))),
    params(("instance_id" = String, Path)),
    responses((status = 200, description = "Unsupported backup entries.", body = Vec<UnsupportedBackupInfo>))
)]
/// Backups in formats this daemon cannot read (for example a newer manifest schema). They are never
/// restored or pruned.
pub async fn list_unsupported_backups(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
) -> ApiResult<Vec<UnsupportedBackupInfo>> {
    auth.require_scope(scopes::BACKUPS_READ)?;
    require_instance(&state, &instance_id).await?;
    let entries = backup_storage(&state)?
        .inventory(&instance_id)
        .await
        .map_err(store_error)?
        .unsupported
        .into_iter()
        .map(|entry| UnsupportedBackupInfo {
            id: entry.backup_id,
            instance_id: instance_id.clone(),
            diagnostic: entry.diagnostic,
        })
        .collect();
    Ok(ApiResponse::ok(entries))
}

#[utoipa::path(
    get,
    path = "/api/instances/{instance_id}/backups/{backup_id}/contents",
    tag = "backups",
    summary = "Browse the bounded schema catalog and captured row previews stored with a backup.",
    description = "Existing backups created before catalog capture return catalog_available=false. The endpoint never starts a restored database or executes queries against backup files.",
    extensions(("x-required-scope" = json!(scopes::BACKUPS_READ))),
    params(("instance_id" = String, Path), ("backup_id" = String, Path), BackupContentsQuery),
    responses((status = 200, description = "Backup catalog, with an optional bounded preview selection.", body = BackupContentsResponse))
)]
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

#[utoipa::path(
    post,
    path = "/api/instances/{instance_id}/backups",
    tag = "backups",
    summary = "Run a backup for one instance.",
    description = "Dedicated instances use their protocol's physical backup layout where supported. Shared tenants always use tenant-scoped logical backups and never capture the pool filesystem or another tenant's data.",
    extensions(("x-required-scope" = json!(scopes::BACKUPS_WRITE))),
    params(("instance_id" = String, Path), RunBackupQuery),
    responses((status = 200, description = "Completed backup artifact.", body = BackupInfo))
)]
pub async fn run_instance_backup(
    State(state): State<AppState>,
    auth: ApiRequestContext,
    ApiPath(instance_id): ApiPath<String>,
    ApiQuery(query): ApiQuery<RunBackupQuery>,
) -> ApiResult<BackupInfo> {
    auth.require_scope(scopes::BACKUPS_WRITE)?;
    match backup_instance(&state, &instance_id, query.mode).await? {
        BackupAttempt::Completed(backup) => Ok(ApiResponse::ok(backup)),
        BackupAttempt::Skipped(issue) => Err(ApiError::BadRequest(issue.reason.message)),
    }
}

#[utoipa::path(
    post,
    path = "/api/admin/backups/run",
    tag = "admin",
    summary = "Run backups for all eligible instances.",
    extensions(("x-required-scope" = json!(scopes::BACKUPS_ADMIN))),
    responses((status = 200, description = "Completed backups and skipped instances.", body = RunBackupResponse))
)]
pub async fn run_all_backups(
    State(state): State<AppState>,
    auth: ApiRequestContext,
) -> ApiResult<RunBackupResponse> {
    auth.require_scope(scopes::BACKUPS_ADMIN)?;
    Ok(ApiResponse::ok(backup_all_instances(&state).await))
}

#[utoipa::path(
    delete,
    path = "/api/instances/{instance_id}/backups/{backup_id}",
    tag = "backups",
    summary = "Delete one backup belonging to an instance.",
    description = "Also removes a backup listed under unsupported-backups; that is the only way such a backup is deleted.",
    extensions(("x-required-scope" = json!(scopes::BACKUPS_WRITE))),
    params(("instance_id" = String, Path), ("backup_id" = String, Path)),
    responses((status = 200, description = "Delete result.", body = DeleteArtifactResponse))
)]
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

#[utoipa::path(
    post,
    path = "/api/instances/{instance_id}/backups/{backup_id}/restore",
    tag = "backups",
    summary = "Restore one backup into the same instance that owns it.",
    description = "A backup is bound to the deployment layout that created it. After a dedicated/shared migration, older backups remain downloadable but restore returns 409 until the instance uses the matching physical or logical layout again.",
    extensions(("x-required-scope" = json!(scopes::RECOVERY_ADMIN))),
    params(("instance_id" = String, Path), ("backup_id" = String, Path)),
    request_body = DestructiveActionConfirmation,
    responses(
        (status = 200, description = "Completed restore result.", body = RestoreBackupResponse),
        (status = 409, description = "The backup protocol or physical/logical layout does not match the instance's current protocol and deployment mode, another data operation blocks restore, or the backup is loaded into the running engine (MySQL and Qdrant online backups taken without a volume snapshot) and the instance is stopped; start it first.", body = crate::routes::http::response::ErrorBody),
    )
)]
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
    .map_err(ApiError::runtime_context("backup restore task failed"))?
}
