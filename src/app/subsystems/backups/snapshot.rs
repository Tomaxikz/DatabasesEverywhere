//! Online backup through an atomic volume snapshot (Btrfs or ZFS).
//!
//! For engines whose images ship no hot-backup tool (MySQL, MongoDB,
//! ClickHouse, Qdrant), the instance's own subvolume or dataset is snapshotted
//! read-only in one atomic step while the database keeps serving. The
//! snapshot is crash-consistent: data files plus the engine's journal (InnoDB
//! redo, WiredTiger journal, MergeTree part renames, Qdrant WAL) at a single
//! instant, which the engine recovers like after a power loss. No write
//! freeze, no restart.
//!
//! The snapshot is journaled as an owned resource before it is created,
//! copied into coordinator-reserved staging (bounded by the native budget),
//! and destroyed right away; a crash leaves it to [`cleanup_owned`]. Restore
//! installs the copy as the data directory, and the existing restore path
//! starts the engine on it and rolls back if it does not come up, which is
//! where journal recovery is exercised.
//!
//! Instances on directories without atomic snapshots (XFS/ext4 project
//! quotas, FuseQuota, soft limits) are refused here: copying live files one
//! by one would not be a consistent point. The registry sends MySQL,
//! ClickHouse and Qdrant there to their strategies in `native`.

mod copy;

use super::native::mysql_inventory as mysql;

use std::{collections::BTreeMap, path::PathBuf};

use futures::future::BoxFuture;

use super::{
    registry::FILESYSTEM_SNAPSHOT,
    strategy::{
        CaptureResult, CleanupContext, OnlineBackupContext, OnlineBackupStrategy, OwnedResource,
        OwnedResourceKind, OwnedResourceRegistrar, RestoreContext, StagingArea, StrategyError,
        VerificationCheck, blocking, lift_restore_tree, refuse_overlapping_staging,
    },
};
use crate::{
    databases::protocol::Protocol,
    server::{
        backup::manifest::{ConsistencyLevel, RecoveryCoordinates, RestoreRecipeRef},
        disk::snapshot::{self, SnapshotBackend},
        jobs::import_export::{DataArchiveSourcePolicy, MAX_DATA_ARCHIVE_ENTRIES},
        placement::DeploymentMode,
    },
    utils::time::now_unix,
};

use copy::{CopyStats, copy_snapshot};

const RESTORE_RECIPE_ID: &str = "volume.snapshot.directory";
const RESTORE_RECIPE_VERSION: u32 = 1;
/// Capture directory below the staging root.
const DATA_ROOT: &str = "volume";
/// Where the copy sits in the archive; no engine names a data entry like this.
const RESTORE_TARGET: &str = "dbev-volume-snapshot";
const SNAPSHOT_SUFFIX: &str = "snapshot";

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct VolumeSnapshotStrategy;

impl OnlineBackupStrategy for VolumeSnapshotStrategy {
    fn id(&self) -> &'static str {
        FILESYSTEM_SNAPSHOT
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
            static_gate(ctx).map(|_| ())
        })
    }

    fn capture<'a>(
        &'a self,
        ctx: &'a OnlineBackupContext<'a>,
        staging: &'a StagingArea,
        registrar: &'a dyn OwnedResourceRegistrar,
    ) -> BoxFuture<'a, Result<CaptureResult, StrategyError>> {
        Box::pin(async move {
            let _ = self;
            capture_snapshot(ctx, staging, registrar).await
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
            if capture.data_root != std::path::Path::new(DATA_ROOT) {
                return Err(StrategyError::Failed(format!(
                    "capture data root is not {DATA_ROOT}"
                )));
            }
            let root = staging.root.join(DATA_ROOT);
            let files = blocking("recount the staged volume", move || count_files(&root)).await?;
            if files == 0 {
                return Err(StrategyError::Failed(
                    "the snapshot of the volume holds no files".to_string(),
                ));
            }
            Ok(vec![VerificationCheck {
                check: "atomic_volume_snapshot".to_string(),
                passed: true,
                detail: Some(format!(
                    "{files} files copied from one read-only {} snapshot; the engine recovers its journal when a restore starts it, and a restore that does not start is rolled back",
                    capture
                        .recovery
                        .0
                        .get("snapshot_backend")
                        .map_or("volume", String::as_str)
                )),
            }])
        })
    }

    fn cleanup_owned<'a>(
        &'a self,
        ctx: &'a CleanupContext<'a>,
        resource: &'a OwnedResource,
    ) -> BoxFuture<'a, Result<(), StrategyError>> {
        Box::pin(async move {
            let _ = self;
            if resource.kind != OwnedResourceKind::Snapshot || !ctx.job.owns_name(&resource.name) {
                return Err(StrategyError::Failed(format!(
                    "refusing to clean {} {}; this strategy owns only its volume snapshot",
                    resource.kind.as_str(),
                    resource.name
                )));
            }
            let backend = backend_of(ctx.metadata)?;
            let paths = crate::server::paths::InstancePaths::new(
                &ctx.state.config.paths,
                &ctx.metadata.instance_id,
            )
            .map_err(|error| StrategyError::failed("instance paths", error))?;
            snapshot::destroy(backend, &paths.data, &resource.name)
                .await
                .map_err(|error| StrategyError::failed("remove the volume snapshot", error))
        })
    }

    fn prepare_restore<'a>(
        &'a self,
        ctx: &'a RestoreContext<'a>,
    ) -> BoxFuture<'a, Result<(), StrategyError>> {
        Box::pin(async move {
            let _ = self;
            ctx.require_recipe(RESTORE_RECIPE_ID, RESTORE_RECIPE_VERSION)?;
            if ctx.restore_target != std::path::Path::new(RESTORE_TARGET) {
                return Err(StrategyError::Failed(format!(
                    "restore target is not {RESTORE_TARGET}"
                )));
            }
            lift_restore_tree(ctx.extracted_root, RESTORE_TARGET, |tree| {
                if count_files(tree)? == 0 {
                    Err("the snapshot holds no files".to_string())
                } else {
                    Ok(())
                }
            })
            .map_err(StrategyError::Failed)
        })
    }
}

fn backend_of(
    metadata: &crate::server::metadata::InstanceMetadata,
) -> Result<SnapshotBackend, StrategyError> {
    SnapshotBackend::for_enforcement_method(&metadata.limits.disk_enforcement_method).ok_or_else(
        || {
            StrategyError::Unsupported(format!(
                "online {} backup needs the instance volume on Btrfs or ZFS with native quotas (atomic snapshots); this instance uses {}",
                metadata.protocol, metadata.limits.disk_enforcement_method
            ))
        },
    )
}

/// Checks that need no server session.
fn static_gate(ctx: &OnlineBackupContext<'_>) -> Result<SnapshotBackend, StrategyError> {
    if ctx.metadata.deployment_mode == DeploymentMode::Shared {
        return Err(StrategyError::Unsupported(
            "shared tenants keep their logical dump; a volume snapshot would include other tenants"
                .to_string(),
        ));
    }
    let backend = backend_of(ctx.metadata)?;
    if ctx.metadata.protocol == Protocol::Mysql {
        mysql::static_gate(ctx)?;
    }
    Ok(backend)
}

async fn capture_snapshot(
    ctx: &OnlineBackupContext<'_>,
    staging: &StagingArea,
    registrar: &dyn OwnedResourceRegistrar,
) -> Result<CaptureResult, StrategyError> {
    let backend = static_gate(ctx)?;
    let mut engine_version = None;
    if ctx.metadata.protocol == Protocol::Mysql {
        engine_version = Some(mysql::inventory(ctx, staging, registrar).await?.version);
    }
    refuse_overlapping_staging(ctx.paths, staging)?;

    let resource = OwnedResource {
        kind: OwnedResourceKind::Snapshot,
        name: format!("{}_{SNAPSHOT_SUFFIX}", ctx.job.resource_tag()),
        survives_restart: true,
    };
    registrar.register(&resource).await?;
    let taken_at = now_unix();
    let volume = snapshot::create(backend, &ctx.paths.data, &resource.name)
        .await
        .map_err(|error| StrategyError::failed("take the volume snapshot", error))?;

    let policy = DataArchiveSourcePolicy::for_protocol(ctx.metadata.protocol);
    let source = volume.read_root.clone();
    let destination = staging.root.join(DATA_ROOT);
    let budget = staging.native_budget_bytes;
    let copied = blocking("copy the volume snapshot", move || {
        copy_snapshot(
            &source,
            &destination,
            policy,
            budget,
            MAX_DATA_ARCHIVE_ENTRIES,
        )
    })
    .await;

    // The snapshot is no longer needed either way; a failed removal stays
    // journaled and is retried by cleanup.
    match snapshot::destroy(backend, &ctx.paths.data, &resource.name).await {
        Ok(()) => registrar.released(&resource).await?,
        Err(error) => {
            tracing::warn!(snapshot = resource.name, %error, "volume snapshot removal failed; cleanup will retry");
        }
    }
    let stats: CopyStats = copied?;

    let mut recovery = BTreeMap::new();
    recovery.insert("snapshot_backend".to_string(), backend.as_str().to_string());
    recovery.insert("snapshot_taken_at_unix".to_string(), taken_at.to_string());
    recovery.insert("files".to_string(), stats.files.to_string());
    recovery.insert("bytes".to_string(), stats.bytes.to_string());
    Ok(CaptureResult {
        data_root: PathBuf::from(DATA_ROOT),
        restore_target: PathBuf::from(RESTORE_TARGET),
        // Data and journal at one instant, recovered by the engine on start.
        consistency: ConsistencyLevel::PhysicalRecoveryPoint,
        recovery: RecoveryCoordinates(recovery),
        engine_version,
        tool_versions: BTreeMap::new(),
        exclusions: policy
            .omitted_links_note()
            .filter(|_| stats.omitted_links > 0)
            .map(str::to_string)
            .into_iter()
            .collect(),
        native_manifest: None,
    })
}

fn count_files(root: &std::path::Path) -> Result<u64, String> {
    let mut files = 0_u64;
    for (index, entry) in walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .enumerate()
    {
        if index > MAX_DATA_ARCHIVE_ENTRIES {
            return Err(format!("{} has too many entries", root.display()));
        }
        let entry = entry.map_err(|error| error.to_string())?;
        if entry.file_type().is_symlink() {
            return Err(format!("{} is a link", entry.path().display()));
        }
        files += u64::from(entry.file_type().is_file());
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subsystems::backups::strategy::RestoreContext;

    #[test]
    fn identity_matches_the_registry_contract() {
        let strategy = VolumeSnapshotStrategy;
        assert_eq!(strategy.id(), FILESYSTEM_SNAPSHOT);
        assert_eq!(strategy.restore_recipe().id, RESTORE_RECIPE_ID);
        assert_eq!(strategy.restorable_recipe_versions(), &[1]);
        for protocol in [
            Protocol::Mysql,
            Protocol::Mongodb,
            Protocol::Clickhouse,
            Protocol::Qdrant,
        ] {
            assert!(
                matches!(
                    protocol.engine().online_backup(),
                    crate::databases::engine::OnlineBackup::VolumeSnapshot { .. }
                ),
                "{protocol}"
            );
        }
    }

    #[test]
    fn only_snapshot_capable_volumes_qualify() {
        let mut metadata = crate::server::test_support::metadata("inst_one", Protocol::Mongodb);
        for method in ["host_btrfs_qgroup", "host_zfs_refquota"] {
            metadata.limits.disk_enforcement_method = method.to_string();
            assert!(backend_of(&metadata).is_ok(), "{method}");
        }
        for method in ["host_xfs_project", "fuse_quota", "not_supported"] {
            metadata.limits.disk_enforcement_method = method.to_string();
            assert!(
                matches!(backend_of(&metadata), Err(StrategyError::Unsupported(reason)) if reason.contains("Btrfs or ZFS")),
                "{method}"
            );
        }
    }

    #[tokio::test]
    async fn restore_installs_the_copy_as_the_data_directory() {
        let root = tempfile::tempdir().unwrap();
        let tree = root.path().join(RESTORE_TARGET);
        std::fs::create_dir_all(tree.join("journal")).unwrap();
        std::fs::write(tree.join("journal/WiredTigerLog.0000000001"), b"j").unwrap();
        std::fs::write(tree.join("collection-0.wt"), b"d").unwrap();
        let recipe = RestoreRecipeRef::new(RESTORE_RECIPE_ID, RESTORE_RECIPE_VERSION);
        let ctx = RestoreContext {
            recipe: &recipe,
            extracted_root: root.path(),
            restore_target: std::path::Path::new(RESTORE_TARGET),
        };
        VolumeSnapshotStrategy.prepare_restore(&ctx).await.unwrap();
        assert!(root.path().join("collection-0.wt").is_file());
        assert!(
            root.path()
                .join("journal/WiredTigerLog.0000000001")
                .is_file()
        );
        assert!(!tree.exists());

        let empty = tempfile::tempdir().unwrap();
        std::fs::create_dir(empty.path().join(RESTORE_TARGET)).unwrap();
        let ctx = RestoreContext {
            recipe: &recipe,
            extracted_root: empty.path(),
            restore_target: std::path::Path::new(RESTORE_TARGET),
        };
        assert!(VolumeSnapshotStrategy.prepare_restore(&ctx).await.is_err());
    }
}
