use super::*;

#[derive(Serialize)]
pub(super) struct QdrantRecoverySnapshot<'a> {
    pub(super) collection: &'a str,
    pub(super) file: String,
}

#[derive(Serialize)]
pub(super) struct QdrantRecoveryManifest<'a> {
    pub(super) schema_version: u32,
    pub(super) recovery_kind: &'static str,
    pub(super) instance_id: &'a str,
    pub(super) protocol: &'static str,
    pub(super) import_mode: ImportMode,
    pub(super) source_snapshots: Vec<QdrantRecoverySnapshot<'a>>,
    pub(super) rollback_snapshots: Vec<QdrantRecoverySnapshot<'a>>,
    pub(super) target_aliases: &'a [QdrantAlias],
    pub(super) created_at: String,
}

pub(super) async fn write_recovery_manifest(
    path: &Path,
    instance_id: &str,
    mode: ImportMode,
    source_collections: &[String],
    rollback: &[(String, PathBuf)],
    target_aliases: &[QdrantAlias],
) -> Result<(), ApiError> {
    let staging = path.parent().ok_or_else(|| {
        ApiError::Runtime("qdrant recovery manifest has no staging directory".to_string())
    })?;
    for index in 0..source_collections.len() {
        sync_recovery_file(&staging.join(format!("source-{index}.snapshot"))).await?;
    }
    for (_, rollback_path) in rollback {
        sync_recovery_file(rollback_path).await?;
    }
    let manifest = QdrantRecoveryManifest {
        schema_version: 1,
        recovery_kind: "qdrant_remote_import",
        instance_id,
        protocol: "qdrant",
        import_mode: mode,
        source_snapshots: source_collections
            .iter()
            .enumerate()
            .map(|(index, collection)| QdrantRecoverySnapshot {
                collection,
                file: format!("source-{index}.snapshot"),
            })
            .collect(),
        rollback_snapshots: rollback
            .iter()
            .enumerate()
            .map(|(index, (collection, _))| QdrantRecoverySnapshot {
                collection,
                file: format!("rollback-{index}.snapshot"),
            })
            .collect(),
        target_aliases,
        created_at: crate::instance::jobs::import_export::now_rfc3339(),
    };
    let contents = serde_json::to_vec_pretty(&manifest).map_err(|error| {
        ApiError::Runtime(format!(
            "failed to encode qdrant recovery manifest: {error}"
        ))
    })?;
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || crate::io::files::atomic_write_private(&path, &contents))
        .await
        .map_err(|error| {
            ApiError::Runtime(format!("failed to write qdrant recovery manifest: {error}"))
        })?
        .map_err(|error| {
            ApiError::Runtime(format!("failed to write qdrant recovery manifest: {error}"))
        })
}
