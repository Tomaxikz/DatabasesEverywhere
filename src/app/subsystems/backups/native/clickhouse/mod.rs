//! ClickHouse online backup on any filesystem: per-table `FREEZE`.
//!
//! `ALTER TABLE ... FREEZE WITH NAME '<job tag>'` hard-links a table's
//! current parts into `shadow/<job tag>` in one step while the server keeps
//! writing; it is the primitive clickhouse-backup builds on. Hard links cost
//! no space up front, only the parts merges retire while the copy runs.
//!
//! Queries go over the instance's always-on HTTP socket, so nothing executes
//! in the serving container. The daemon then builds a data directory on the
//! host: the live volume without its parts, plus every frozen table's parts
//! from the shadow. Each table is consistent at its own freeze; there is no
//! common point across tables. Restore installs that directory like an
//! offline backup and starts ClickHouse on it, rolling back if it does not
//! come up.
//!
//! The shadow is journaled as an owned resource before the first freeze and
//! removed host-side once copied; a crash leaves it to [`cleanup_owned`].

mod copy;
mod http;
mod inventory;

use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
};

use futures::future::BoxFuture;
use secrecy::SecretString;

use super::super::registry::CLICKHOUSE_FROZEN_PARTS;
use crate::{
    databases::{clickhouse::provision::quote_ident, protocol::Protocol},
    server::{
        backup::manifest::{ConsistencyLevel, RecoveryCoordinates, RestoreRecipeRef},
        jobs::import_export::{DataArchiveSourcePolicy, MAX_DATA_ARCHIVE_ENTRIES},
        placement::DeploymentMode,
    },
    subsystems::backups::strategy::{
        CaptureResult, CleanupContext, OnlineBackupContext, OnlineBackupStrategy, OwnedResource,
        OwnedResourceKind, OwnedResourceRegistrar, RestoreContext, StagingArea, StrategyError,
        VerificationCheck, blocking, lift_restore_tree, refuse_overlapping_staging,
    },
    utils::backend::{BackendEndpoint, clickhouse_http_socket_path},
};

use copy::{CopyStats, Limits, copy_frozen, count_parts, remove_shadow};
use http::ClickhouseHttp;
use inventory::{DATABASES_SQL, DatabaseRow, Plan, TABLES_SQL, TableRow};

const RESTORE_RECIPE_ID: &str = "clickhouse.frozen_parts.directory";
const RESTORE_RECIPE_VERSION: u32 = 1;
/// Capture directory below the staging root.
const DATA_ROOT: &str = "clickhouse";
/// Where the copy sits in the archive; ClickHouse names no data entry like this.
const RESTORE_TARGET: &str = "dbev-clickhouse-freeze";
/// UNKNOWN_TABLE and UNKNOWN_DATABASE: dropped since the inventory.
const DROPPED_CODES: [u32; 2] = [60, 81];

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ClickhouseFreezeStrategy;

impl OnlineBackupStrategy for ClickhouseFreezeStrategy {
    fn id(&self) -> &'static str {
        CLICKHOUSE_FROZEN_PARTS
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
            capture_frozen(ctx, staging, registrar).await
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
            if capture.data_root != Path::new(DATA_ROOT) {
                return Err(StrategyError::Failed(format!(
                    "capture data root is not {DATA_ROOT}"
                )));
            }
            let root = staging.root.join(DATA_ROOT);
            let parts = blocking("count the frozen parts", move || count_parts(&root)).await?;
            let recorded = capture
                .recovery
                .0
                .get("parts")
                .and_then(|parts| parts.parse().ok());
            if recorded != Some(parts) {
                return Err(StrategyError::Failed(format!(
                    "staging holds {parts} frozen parts, not the {} copied",
                    recorded.map_or_else(
                        || "unknown number".to_string(),
                        |parts: u64| parts.to_string()
                    )
                )));
            }
            Ok(vec![VerificationCheck {
                check: "clickhouse_frozen_parts".to_string(),
                passed: true,
                detail: Some(format!(
                    "{parts} frozen parts, each with its checksums.txt; ClickHouse checks every part when a restore starts it, and a restore that does not start is rolled back"
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
                    "refusing to clean {} {}; this strategy owns only its freeze shadow",
                    resource.kind.as_str(),
                    resource.name
                )));
            }
            let paths = crate::server::paths::InstancePaths::new(
                &ctx.state.config.paths,
                &ctx.metadata.instance_id,
            )
            .map_err(|error| StrategyError::failed("instance paths", error))?;
            let name = resource.name.clone();
            blocking("remove the freeze shadow", move || {
                remove_shadow(&paths.data, &name)
            })
            .await
        })
    }

    fn prepare_restore<'a>(
        &'a self,
        ctx: &'a RestoreContext<'a>,
    ) -> BoxFuture<'a, Result<(), StrategyError>> {
        Box::pin(async move {
            let _ = self;
            ctx.require_recipe(RESTORE_RECIPE_ID, RESTORE_RECIPE_VERSION)?;
            if ctx.restore_target != Path::new(RESTORE_TARGET) {
                return Err(StrategyError::Failed(format!(
                    "restore target is not {RESTORE_TARGET}"
                )));
            }
            lift_restore_tree(ctx.extracted_root, RESTORE_TARGET, |tree| {
                if tree.join("metadata").is_dir() {
                    Ok(())
                } else {
                    Err("the capture holds no ClickHouse metadata".to_string())
                }
            })
            .map_err(StrategyError::Failed)
        })
    }
}

/// The dedicated user and its password, which owns every privilege.
fn static_gate(ctx: &OnlineBackupContext<'_>) -> Result<SecretString, StrategyError> {
    if ctx.metadata.deployment_mode == DeploymentMode::Shared
        || ctx.metadata.protocol != Protocol::Clickhouse
    {
        return Err(StrategyError::Unsupported(
            "the freeze strategy covers dedicated ClickHouse instances".to_string(),
        ));
    }
    ctx.metadata
        .tenant_password
        .as_deref()
        .filter(|password| !password.is_empty())
        .map(|password| SecretString::from(password.to_string()))
        .ok_or_else(|| {
            StrategyError::Unsupported("the ClickHouse credential is missing".to_string())
        })
}

fn connect(
    ctx: &OnlineBackupContext<'_>,
    password: &SecretString,
) -> Result<ClickhouseHttp, StrategyError> {
    let BackendEndpoint::UnixSocket { socket_path } = &ctx.metadata.backend else {
        return Err(StrategyError::Unsupported(
            "this ClickHouse instance has no unix socket backend; restart it once to upgrade its runtime"
                .to_string(),
        ));
    };
    let socket = clickhouse_http_socket_path(Path::new(socket_path)).ok_or_else(|| {
        StrategyError::Failed("invalid ClickHouse backend socket path".to_string())
    })?;
    ClickhouseHttp::new(
        &socket,
        &ctx.metadata.database.username,
        password,
        ctx.remaining()?,
    )
}

async fn capture_frozen(
    ctx: &OnlineBackupContext<'_>,
    staging: &StagingArea,
    registrar: &dyn OwnedResourceRegistrar,
) -> Result<CaptureResult, StrategyError> {
    let password = static_gate(ctx)?;
    refuse_overlapping_staging(ctx.paths, staging)?;
    let client = connect(ctx, &password)?;
    let version = client
        .query("SELECT version() FORMAT TSVRaw")
        .await?
        .trim()
        .to_string();
    let databases = client.rows::<DatabaseRow>(DATABASES_SQL).await?;
    let tables = client.rows::<TableRow>(TABLES_SQL).await?;
    let plan = inventory::plan(&databases, &tables)?;

    let resource = OwnedResource {
        kind: OwnedResourceKind::Snapshot,
        name: ctx.job.resource_tag(),
        survives_restart: true,
    };
    registrar.register(&resource).await?;
    let copied = match freeze_tables(ctx, &client, &plan, &resource.name).await {
        Ok(frozen) => {
            let tables = frozen.len();
            let data = ctx.paths.data.clone();
            let shadow = data.join("shadow").join(&resource.name);
            let destination = staging.root.join(DATA_ROOT);
            let limits = Limits {
                max_bytes: staging.native_budget_bytes,
                max_entries: MAX_DATA_ARCHIVE_ENTRIES,
                deadline: ctx.deadline,
            };
            blocking("copy the frozen data directory", move || {
                copy_frozen(&data, &shadow, &frozen, &destination, &limits)
            })
            .await
            .map(|stats| (tables, stats))
        }
        Err(error) => Err(error),
    };

    // The shadow is no longer needed either way; a failed removal stays
    // journaled and is retried by cleanup.
    let (data, name) = (ctx.paths.data.clone(), resource.name.clone());
    match blocking("remove the freeze shadow", move || {
        remove_shadow(&data, &name)
    })
    .await
    {
        Ok(()) => registrar.released(&resource).await?,
        Err(error) => {
            tracing::warn!(shadow = resource.name, %error, "freeze shadow removal failed; cleanup will retry");
        }
    }
    let (tables, stats) = copied?;
    Ok(capture_result(version, tables, &plan, stats))
}

/// Freezes every planned table under `name`, returning the store directories
/// that were frozen. Tables dropped since the inventory are skipped.
async fn freeze_tables(
    ctx: &OnlineBackupContext<'_>,
    client: &ClickhouseHttp,
    plan: &Plan,
    name: &str,
) -> Result<HashSet<PathBuf>, StrategyError> {
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(StrategyError::Failed(format!("invalid freeze name {name}")));
    }
    let mut frozen = HashSet::new();
    for table in &plan.frozen {
        ctx.remaining()?;
        let sql = format!(
            "ALTER TABLE {}.{} FREEZE WITH NAME '{name}'",
            quote_ident(&table.database),
            quote_ident(&table.name)
        );
        match client.query(&sql).await {
            Ok(_) => {
                frozen.insert(table.directory.clone());
            }
            Err(error) if error.code.is_some_and(|code| DROPPED_CODES.contains(&code)) => {}
            Err(error) => return Err(StrategyError::from(error).for_tool("ALTER TABLE FREEZE")),
        }
    }
    Ok(frozen)
}

fn capture_result(version: String, tables: usize, plan: &Plan, stats: CopyStats) -> CaptureResult {
    let mut recovery = BTreeMap::new();
    recovery.insert("frozen_tables".to_string(), tables.to_string());
    recovery.insert("parts".to_string(), stats.parts.to_string());
    recovery.insert("files".to_string(), stats.files.to_string());
    recovery.insert("bytes".to_string(), stats.bytes.to_string());
    let mut exclusions = vec!["detached parts".to_string()];
    if plan.memory_tables > 0 {
        exclusions.push("rows of Memory tables (lost on any restart)".to_string());
    }
    if plan.system_merge_trees > 0 {
        exclusions.push("rows of system log tables".to_string());
    }
    if stats.omitted_links > 0
        && let Some(note) = DataArchiveSourcePolicy::ClickhouseDataDirectory.omitted_links_note()
    {
        exclusions.push(note.to_string());
    }
    CaptureResult {
        data_root: PathBuf::from(DATA_ROOT),
        restore_target: PathBuf::from(RESTORE_TARGET),
        // Each table is consistent at its own freeze.
        consistency: ConsistencyLevel::PerObject,
        recovery: RecoveryCoordinates(recovery),
        engine_version: (!version.is_empty()).then_some(version),
        tool_versions: BTreeMap::new(),
        exclusions,
        native_manifest: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_matches_the_registry_contract() {
        let strategy = ClickhouseFreezeStrategy;
        assert_eq!(strategy.id(), CLICKHOUSE_FROZEN_PARTS);
        assert_eq!(strategy.restore_recipe().id, RESTORE_RECIPE_ID);
        assert_eq!(strategy.restorable_recipe_versions(), &[1]);
    }

    #[test]
    fn captures_record_parts_and_exclusions() {
        let plan = Plan {
            frozen: Vec::new(),
            memory_tables: 1,
            system_merge_trees: 0,
        };
        let stats = CopyStats {
            files: 9,
            bytes: 90,
            parts: 3,
            omitted_links: 2,
        };
        let capture = capture_result("25.8.1.1".to_string(), 2, &plan, stats);
        assert_eq!(capture.recovery.0["parts"], "3");
        assert_eq!(capture.recovery.0["frozen_tables"], "2");
        assert_eq!(capture.consistency, ConsistencyLevel::PerObject);
        assert_eq!(capture.exclusions.len(), 3);
        assert_eq!(capture.engine_version.as_deref(), Some("25.8.1.1"));
    }

    #[tokio::test]
    async fn restore_installs_the_copy_as_the_data_directory() {
        let root = tempfile::tempdir().unwrap();
        let tree = root.path().join(RESTORE_TARGET);
        std::fs::create_dir_all(tree.join("metadata")).unwrap();
        std::fs::write(
            tree.join("metadata/default.sql"),
            b"ATTACH DATABASE default",
        )
        .unwrap();
        let recipe = RestoreRecipeRef::new(RESTORE_RECIPE_ID, RESTORE_RECIPE_VERSION);
        let ctx = RestoreContext {
            recipe: &recipe,
            extracted_root: root.path(),
            restore_target: Path::new(RESTORE_TARGET),
        };
        ClickhouseFreezeStrategy
            .prepare_restore(&ctx)
            .await
            .unwrap();
        assert!(root.path().join("metadata/default.sql").is_file());
        assert!(!tree.exists());

        let empty = tempfile::tempdir().unwrap();
        std::fs::create_dir(empty.path().join(RESTORE_TARGET)).unwrap();
        let ctx = RestoreContext {
            recipe: &recipe,
            extracted_root: empty.path(),
            restore_target: Path::new(RESTORE_TARGET),
        };
        assert!(
            ClickhouseFreezeStrategy
                .prepare_restore(&ctx)
                .await
                .is_err()
        );
    }
}
