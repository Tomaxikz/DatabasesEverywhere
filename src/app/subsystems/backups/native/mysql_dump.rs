//! MySQL online backup on any filesystem: one consistent logical dump.
//!
//! `mysqldump --single-transaction` reads every InnoDB table from a single
//! transaction snapshot while writes continue. It is the same dump dbev's
//! exports produce, run in a helper container from the instance's own image
//! over the socket, so nothing executes in the serving container and nothing
//! can restart it. The inventory first refuses non-InnoDB user tables, which a
//! transaction snapshot does not cover.
//!
//! Restore loads the dump into the running instance through the regular
//! wipe-and-import path, which takes a rollback dump first.

use std::{collections::BTreeMap, path::PathBuf};

use futures::future::BoxFuture;

use super::{super::registry::MYSQL_CONSISTENT_DUMP, mysql_inventory};
use crate::{
    databases::protocol::Protocol,
    routes::http::response::ApiError,
    runtime::docker::{BACKUP_HELPER_STAGING, BackupHelperSocket, BackupHelperSpec, DockerEnv},
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
        import_export::ImportExportSelection,
    },
    utils::shell::sh_quote,
};

const RESTORE_RECIPE_ID: &str = "mysql.logical_dump.import";
const RESTORE_RECIPE_VERSION: u32 = 1;
const DATA_ROOT: &str = "mysql";
const RESTORE_TARGET: &str = "mysql-dump";
/// `.sql` keeps the importer's format detection on plain SQL.
const DUMP_FILE: &str = "backup.mysql.sql";
const SOCKET_DIRECTORY: &str = "/var/run/mysqld";
/// mysqldump ends a complete dump with this comment.
const DUMP_COMPLETED: &[u8] = b"-- Dump completed";
const TAIL_BYTES: u64 = 4096;

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct MysqlDumpStrategy;

impl OnlineBackupStrategy for MysqlDumpStrategy {
    fn id(&self) -> &'static str {
        MYSQL_CONSISTENT_DUMP
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
        registrar: &'a dyn OwnedResourceRegistrar,
    ) -> BoxFuture<'a, Result<CaptureResult, StrategyError>> {
        Box::pin(async move {
            let _ = self;
            capture_dump(ctx, staging, registrar).await
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
            let dump = staging.root.join(&capture.data_root).join(DUMP_FILE);
            let size = blocking("check the dump", move || check_dump(&dump)).await?;
            Ok(vec![VerificationCheck {
                check: "mysqldump_completed".to_string(),
                passed: true,
                detail: Some(format!(
                    "{size}-byte single-transaction dump that mysqldump marked complete"
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
            restore_dump(ctx).await.map_err(|error| match error {
                ApiError::Conflict(reason) => StrategyError::Unsupported(reason),
                other => StrategyError::Failed(other.to_string()),
            })
        })
    }
}

fn static_gate(ctx: &OnlineBackupContext<'_>) -> Result<(), StrategyError> {
    if ctx.metadata.deployment_mode == DeploymentMode::Shared
        || ctx.metadata.protocol != Protocol::Mysql
    {
        return Err(StrategyError::Unsupported(
            "the consistent dump strategy covers dedicated MySQL instances".to_string(),
        ));
    }
    mysql_inventory::static_gate(ctx)
}

/// The export script dbev already uses, writing into staging instead of a
/// stream, behind a umask and the output directory.
fn dump_script(ctx: &OnlineBackupContext<'_>) -> Result<String, StrategyError> {
    let output = format!("{BACKUP_HELPER_STAGING}/{DATA_ROOT}/{DUMP_FILE}");
    let script = ctx
        .metadata
        .protocol
        .engine()
        .logical_export_script(
            ctx.metadata,
            &sh_quote(&output),
            &ImportExportSelection::default(),
            false,
        )
        .map_err(|error| StrategyError::Unsupported(error.to_string()))?;
    let body = script.strip_prefix("set -eu\n").unwrap_or(&script);
    Ok(format!(
        "set -eu\numask 077\nmkdir -p {}\n{body}",
        sh_quote(&format!("{BACKUP_HELPER_STAGING}/{DATA_ROOT}"))
    ))
}

async fn capture_dump(
    ctx: &OnlineBackupContext<'_>,
    staging: &StagingArea,
    registrar: &dyn OwnedResourceRegistrar,
) -> Result<CaptureResult, StrategyError> {
    static_gate(ctx)?;
    let inventory = mysql_inventory::inventory(ctx, staging, registrar).await?;
    refuse_overlapping_staging(ctx.paths, staging)?;
    let spec = BackupHelperSpec {
        name: ctx.job.resource_tag(),
        instance_id: ctx.metadata.instance_id.clone(),
        image: ctx.runtime_image().await?,
        socket: Some(BackupHelperSocket {
            source: ctx.paths.sockets.clone(),
            target: SOCKET_DIRECTORY.to_string(),
        }),
        data: None,
        staging_dir: staging.root.clone(),
        staging_read_only: false,
        script: dump_script(ctx)?,
        environment: vec![
            DockerEnv::new("MYSQL_ROOT_PASSWORD", mysql_inventory::root_password(ctx)?),
            DockerEnv::plain("MYSQL_DATABASE", &ctx.metadata.database.name),
        ],
        timeout: ctx.remaining()?,
        max_staging_bytes: staging.native_budget_bytes,
    };
    ctx.run_helper(registrar, &spec)
        .await
        .map_err(|error| error.for_tool("mysqldump"))?;
    let mut recovery = BTreeMap::new();
    recovery.insert("database".to_string(), ctx.metadata.database.name.clone());
    Ok(CaptureResult {
        data_root: PathBuf::from(DATA_ROOT),
        restore_target: PathBuf::from(RESTORE_TARGET),
        // Every InnoDB table read in one transaction snapshot.
        consistency: ConsistencyLevel::TransactionalSnapshot,
        recovery: RecoveryCoordinates(recovery),
        engine_version: Some(inventory.version),
        tool_versions: BTreeMap::new(),
        exclusions: vec![
            "accounts and grants (dbev recreates them from the instance credentials)".to_string(),
        ],
        native_manifest: None,
    })
}

/// The dump exists, is a regular non-empty file and mysqldump finished it.
fn check_dump(path: &std::path::Path) -> Result<u64, String> {
    use std::io::{Read, Seek, SeekFrom};

    crate::io::files::require_regular_file(path)?;
    let mut file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let size = file.metadata().map_err(|error| error.to_string())?.len();
    if size == 0 {
        return Err("the dump is empty".to_string());
    }
    file.seek(SeekFrom::Start(size.saturating_sub(TAIL_BYTES)))
        .map_err(|error| error.to_string())?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail)
        .map_err(|error| error.to_string())?;
    if !tail
        .windows(DUMP_COMPLETED.len())
        .any(|window| window == DUMP_COMPLETED)
    {
        return Err("mysqldump did not mark the dump complete".to_string());
    }
    Ok(size)
}

async fn restore_dump(ctx: &AfterStartRestoreContext<'_>) -> Result<(), ApiError> {
    let dump = ctx.payload.join(DUMP_FILE);
    let checked = dump.clone();
    let size = tokio::task::spawn_blocking(move || check_dump(&checked))
        .await
        .map_err(ApiError::runtime)?
        .map_err(ApiError::Conflict)?;
    let rollback_bytes =
        crate::subsystems::import_export::jobs::measure_export_bytes(ctx.state, ctx.metadata)
            .await?;
    let staging_root = crate::subsystems::import_export::logical_staging_root(ctx.state).await?;
    let staging_bytes = crate::subsystems::import_export::logical::shared_restore_staging_bytes(
        size,
        rollback_bytes,
    )?;
    let _capacity = ctx
        .state
        .import_uploads
        .reserve_output_capacity(&staging_root, staging_bytes)
        .await?;
    crate::subsystems::import_export::logical::restore_dedicated_backup(
        ctx.state,
        ctx.metadata,
        &dump,
        size,
        rollback_bytes,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_and_restore_kind() {
        let strategy = MysqlDumpStrategy;
        assert_eq!(strategy.id(), MYSQL_CONSISTENT_DUMP);
        assert_eq!(strategy.restore_recipe().id, RESTORE_RECIPE_ID);
        assert_eq!(strategy.restore_kind(), RestoreKind::AfterStart);
    }

    #[test]
    fn only_completed_dumps_pass() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DUMP_FILE);
        std::fs::write(
            &path,
            b"CREATE TABLE t (id int);\n-- Dump completed on 2026-10-25\n",
        )
        .unwrap();
        assert!(check_dump(&path).unwrap() > 0);
        std::fs::write(&path, b"CREATE TABLE t (id int);\nINSERT INTO t VALUES").unwrap();
        assert!(check_dump(&path).unwrap_err().contains("complete"));
        std::fs::write(&path, b"").unwrap();
        assert!(check_dump(&path).is_err());
        assert!(check_dump(&dir.path().join("missing")).is_err());
    }
}
