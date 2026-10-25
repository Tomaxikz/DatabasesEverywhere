//! Qdrant online backup on any filesystem: per-collection snapshots.
//!
//! Qdrant's snapshot API captures each collection while it keeps serving.
//! The daemon calls it over the instance's always-on HTTP socket, so nothing
//! executes in the serving container. Collections are consistent one by one,
//! not at one common point.
//!
//! Restore wipes the running instance and uploads the snapshots through the
//! remote-import apply path, which first saves rollback snapshots.

use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use futures::future::BoxFuture;

use super::super::registry::QDRANT_COLLECTION_SNAPSHOTS;
use crate::{
    databases::protocol::Protocol,
    routes::http::response::ApiError,
    server::{
        backup::manifest::{ConsistencyLevel, RecoveryCoordinates, RestoreRecipeRef},
        placement::DeploymentMode,
    },
    subsystems::{
        backups::strategy::{
            AfterStartRestoreContext, CaptureResult, OnlineBackupContext, OnlineBackupStrategy,
            OwnedResourceRegistrar, RestoreKind, StagingArea, StrategyError, VerificationCheck,
            blocking, refuse_overlapping_staging,
        },
        import_export::remote::qdrant_backup,
    },
};

const RESTORE_RECIPE_ID: &str = "qdrant.collection_snapshots.upload";
const RESTORE_RECIPE_VERSION: u32 = 1;
const DATA_ROOT: &str = "qdrant";
const RESTORE_TARGET: &str = "qdrant-collections";

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct QdrantSnapshotStrategy;

impl OnlineBackupStrategy for QdrantSnapshotStrategy {
    fn id(&self) -> &'static str {
        QDRANT_COLLECTION_SNAPSHOTS
    }

    fn restore_recipe(&self) -> RestoreRecipeRef {
        RestoreRecipeRef::new(RESTORE_RECIPE_ID, RESTORE_RECIPE_VERSION)
    }

    fn restorable_recipe_versions(&self) -> &'static [u32] {
        &[RESTORE_RECIPE_VERSION]
    }

    fn preflight<'a>(
        &'a self,
        ctx: &'a OnlineBackupContext<'a>,
    ) -> BoxFuture<'a, Result<(), StrategyError>> {
        Box::pin(async move {
            let _ = self;
            static_gate(ctx)
        })
    }

    fn capture<'a>(
        &'a self,
        ctx: &'a OnlineBackupContext<'a>,
        staging: &'a StagingArea,
        _registrar: &'a dyn OwnedResourceRegistrar,
    ) -> BoxFuture<'a, Result<CaptureResult, StrategyError>> {
        Box::pin(async move {
            let _ = self;
            capture_snapshots(ctx, staging).await
        })
    }

    fn verify<'a>(
        &'a self,
        _ctx: &'a OnlineBackupContext<'a>,
        staging: &'a StagingArea,
        capture: &'a CaptureResult,
        _registrar: &'a dyn OwnedResourceRegistrar,
    ) -> BoxFuture<'a, Result<Vec<VerificationCheck>, StrategyError>> {
        Box::pin(async move {
            let _ = self;
            let dir = staging.root.join(&capture.data_root);
            let summary = blocking("check the collection snapshots", move || {
                qdrant_backup::verify_collections(&dir)
            })
            .await?;
            Ok(vec![VerificationCheck {
                check: "qdrant_snapshot_checksums".to_string(),
                passed: true,
                detail: Some(format!(
                    "{} collection snapshots ({} bytes) and {} aliases, each snapshot matching its SHA-256",
                    summary.collections, summary.bytes, summary.aliases
                )),
            }])
        })
    }

    fn restore_kind(&self) -> RestoreKind {
        RestoreKind::AfterStart
    }

    fn restore_after_start<'a>(
        &'a self,
        ctx: &'a AfterStartRestoreContext<'a>,
    ) -> BoxFuture<'a, Result<(), StrategyError>> {
        Box::pin(async move {
            let _ = self;
            ctx.require_recipe(RESTORE_RECIPE_ID, RESTORE_RECIPE_VERSION)?;
            let timeout = Duration::from_secs(ctx.state.config.backups.online_timeout_minutes * 60);
            qdrant_backup::restore_collections(ctx.state, ctx.metadata, ctx.payload, timeout)
                .await
                .map_err(strategy_error)
        })
    }
}

fn strategy_error(error: ApiError) -> StrategyError {
    match error {
        ApiError::Conflict(reason) => StrategyError::Unsupported(reason),
        other => StrategyError::Failed(other.to_string()),
    }
}

fn static_gate(ctx: &OnlineBackupContext<'_>) -> Result<(), StrategyError> {
    if ctx.metadata.deployment_mode == DeploymentMode::Shared
        || ctx.metadata.protocol != Protocol::Qdrant
    {
        return Err(StrategyError::Unsupported(
            "the collection snapshot strategy covers dedicated Qdrant instances".to_string(),
        ));
    }
    Ok(())
}

async fn capture_snapshots(
    ctx: &OnlineBackupContext<'_>,
    staging: &StagingArea,
) -> Result<CaptureResult, StrategyError> {
    static_gate(ctx)?;
    refuse_overlapping_staging(ctx.paths, staging)?;
    let summary = qdrant_backup::capture_collections(
        ctx.state,
        ctx.metadata,
        &staging.root.join(DATA_ROOT),
        staging.native_budget_bytes,
        tokio::time::Instant::from_std(ctx.deadline),
    )
    .await
    .map_err(|error| strategy_error(error).for_tool("qdrant snapshots"))?;
    let mut recovery = BTreeMap::new();
    recovery.insert("collections".to_string(), summary.collections.to_string());
    recovery.insert("aliases".to_string(), summary.aliases.to_string());
    Ok(CaptureResult {
        data_root: PathBuf::from(DATA_ROOT),
        restore_target: PathBuf::from(RESTORE_TARGET),
        // Each collection is its own snapshot point.
        consistency: ConsistencyLevel::PerObject,
        recovery: RecoveryCoordinates(recovery),
        engine_version: Some(summary.qdrant_version),
        tool_versions: BTreeMap::new(),
        exclusions: vec![
            "snapshots stored inside the instance".to_string(),
            "the API key (dbev keeps the instance's own)".to_string(),
        ],
        native_manifest: Some(PathBuf::from(format!(
            "{DATA_ROOT}/{}",
            qdrant_backup::MANIFEST_FILE
        ))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_and_restore_kind() {
        let strategy = QdrantSnapshotStrategy;
        assert_eq!(strategy.id(), QDRANT_COLLECTION_SNAPSHOTS);
        assert_eq!(strategy.restore_recipe().id, RESTORE_RECIPE_ID);
        assert_eq!(strategy.restore_kind(), RestoreKind::AfterStart);
    }

    #[test]
    fn conflicts_are_unsupported_and_the_rest_failed() {
        assert!(matches!(
            strategy_error(ApiError::Conflict("x".to_string())),
            StrategyError::Unsupported(_)
        ));
        assert!(matches!(
            strategy_error(ApiError::Runtime("x".to_string())),
            StrategyError::Failed(_)
        ));
    }
}
