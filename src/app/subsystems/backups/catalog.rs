use super::types::BackupInfo;
use super::types::{BackupObjectSelection, BackupObjectSummary};
use crate::routes::http::response::ApiError;
use crate::server::backup::StoredBackup;
use crate::server::backup::catalog::BackupCatalog;

pub(super) fn backup_objects(
    catalog: &BackupCatalog,
    include: bool,
) -> Option<Vec<BackupObjectSummary>> {
    include.then(|| {
        catalog
            .objects
            .iter()
            .map(|object| BackupObjectSummary {
                id: object.id.clone(),
                namespace: object.namespace.clone(),
                name: object.name.clone(),
                kind: object.kind.clone(),
                estimated_rows: object.estimated_rows,
                column_count: object.columns.len(),
                captured_preview_rows: object.preview_rows.len(),
                preview_truncated: object.preview_truncated,
            })
            .collect()
    })
}

pub(super) fn select_catalog_object(
    catalog: &BackupCatalog,
    object_id: Option<&str>,
    offset: usize,
    limit: usize,
) -> Result<Option<BackupObjectSelection>, ApiError> {
    let Some(object_id) = object_id else {
        if offset != 0 {
            return Err(ApiError::BadRequest(
                "offset requires an object selection".to_string(),
            ));
        }
        return Ok(None);
    };
    let object = catalog
        .objects
        .iter()
        .find(|object| object.id == object_id)
        .ok_or(ApiError::NotFound)?;
    let rows = object
        .preview_rows
        .iter()
        .skip(offset)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    Ok(Some(BackupObjectSelection {
        columns: object.columns.clone(),
        object_id: object.id.clone(),
        offset,
        limit,
        returned: rows.len(),
        total_captured: object.preview_rows.len(),
        rows,
        truncated: object.preview_truncated
            || offset.saturating_add(limit) < object.preview_rows.len(),
    }))
}

pub(super) fn backup_info(backup: StoredBackup) -> BackupInfo {
    let consistency = backup.consistency();
    let restore_recipe = backup
        .details
        .as_ref()
        .map(|details| details.restore_recipe.tag_value());
    BackupInfo {
        id: backup.backup_id,
        instance_id: backup.instance_id,
        protocol: backup.protocol,
        layout: backup.layout,
        size_bytes: backup.size_bytes,
        modified_at: backup.created_at,
        sha256: backup.sha256,
        manifest_schema_version: backup.schema_version,
        consistency,
        restore_recipe,
    }
}
