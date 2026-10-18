//! Dedicated MariaDB online physical backup.
//!
//! `mariadb-backup` from the instance's own immutable image runs in a
//! short-lived helper container. It mounts the instance socket directory and
//! the data directory read-only, copies the InnoDB files while it tails the
//! redo log, and writes straight into coordinator-reserved staging, so
//! nothing lands in the data volume. Every copied page is checksummed by the
//! tool as it is read. The server coordinates through `BACKUP STAGE`: DDL is
//! blocked while files are copied and commits pause only for the final
//! `BLOCK_COMMIT` stage, which copies the redo tail and the crash-safe Aria
//! system tables. The inventory refuses instances with non-InnoDB user
//! tables, which would otherwise be copied under that commit block.
//!
//! A second helper runs `mariadb-backup --prepare` on the staged copy (no
//! socket, no data mount), applying the redo up to the backup's end LSN so the
//! tree is a consistent, directly startable data directory. `verify` checks
//! the checkpoints the prepare recorded and the staged layout in-process.
//!
//! Restore moves the prepared tree into the data volume root; the server
//! starts on it without crash recovery.

mod inventory;
mod layout;

use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use futures::future::BoxFuture;
use secrecy::SecretString;

use crate::{
    runtime::docker::{BACKUP_HELPER_STAGING, BackupHelperSocket, BackupHelperSpec, DockerEnv},
    server::{
        backup::manifest::{ConsistencyLevel, RecoveryCoordinates, RestoreRecipeRef},
        placement::DeploymentMode,
    },
    subsystems::backups::{
        registry::MARIADB_BACKUP,
        strategy::{
            CaptureResult, OnlineBackupContext, OnlineBackupStrategy, OwnedResourceRegistrar,
            RestoreContext, StagingArea, StrategyError, VerificationCheck, blocking,
            refuse_overlapping_staging, require_relative, take_report,
        },
    },
    utils::{backend::MARIADB_SOCKET_DIRECTORY, shell::sh_quote},
};

use inventory::{Inventory, parse_report};
use layout::{Checkpoints, DATA_ROOT, RESTORE_TARGET};

const RESTORE_RECIPE_ID: &str = "mariadb.prepared_backup.directory";
const RESTORE_RECIPE_VERSION: u32 = 1;
const DATA_TARGET: &str = "/var/lib/mysql";
const SOCKET_FILE: &str = "mysqld.sock";
const TMP_ROOT: &str = "tmp";
const OPTION_FILE: &str = "/tmp/dbev-backup.cnf";
const PASSWORD_ENV: &str = "DBE_MARIADB_ROOT_PASSWORD";
const INVENTORY_TIMEOUT: Duration = Duration::from_secs(120);
const INVENTORY_HELPER_SUFFIX: &str = "inventory";
const PREPARE_HELPER_SUFFIX: &str = "prepare";
const INVENTORY_REPORT: &str = "inventory.report";
const MAX_INVENTORY_REPORT_BYTES: u64 = 64 * 1024;
/// Bounds each inventory statement on the server.
const INVENTORY_SESSION_TIMEOUT_SECONDS: u32 = 60;
/// Within the helper's 512 MiB memory limit.
const PREPARE_MEMORY: &str = "256M";
/// Both `--backup` and `--prepare` end with this line on success.
const COMPLETED_OK: &str = "completed OK!";

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct MariadbBackupStrategy;

impl OnlineBackupStrategy for MariadbBackupStrategy {
    fn id(&self) -> &'static str {
        MARIADB_BACKUP
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
            capture_tree(ctx, staging, registrar).await
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
            let checkpoints = blocking("check the prepared backup", move || {
                layout::check_prepared(&root)
            })
            .await?;
            Ok(vec![VerificationCheck {
                check: "mariadb_backup_prepare".to_string(),
                passed: true,
                detail: Some(format!(
                    "version-matched mariadb-backup copied every page with checksum validation and prepared the tree through LSN {}",
                    checkpoints.to_lsn
                )),
            }])
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
            layout::install_prepared(ctx.extracted_root).map_err(StrategyError::Failed)
        })
    }
}

/// Checks that need no server session; returns the root credential.
fn static_gate(ctx: &OnlineBackupContext<'_>) -> Result<SecretString, StrategyError> {
    if ctx.metadata.deployment_mode == DeploymentMode::Shared {
        return Err(StrategyError::Unsupported(
            "shared tenants keep their logical dump; physical online backup is dedicated-only"
                .to_string(),
        ));
    }
    let password = ctx
        .metadata
        .mariadb_root_password
        .as_deref()
        .filter(|password| !password.is_empty())
        .ok_or_else(|| {
            StrategyError::Unsupported("the MariaDB root credential is missing".to_string())
        })?;
    // The option file is written with printf; refuse anything that could
    // change its meaning rather than quoting it.
    if !password
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(StrategyError::Unsupported(
            "the MariaDB root credential contains characters the backup option file does not accept"
                .to_string(),
        ));
    }
    Ok(SecretString::from(password.to_string()))
}

fn option_file_prelude() -> String {
    format!(
        "set -eu\numask 077\nprintf '[client]\\nuser=root\\npassword=%s\\nsocket=%s\\nprotocol=socket\\n' \"${PASSWORD_ENV}\" {} >{OPTION_FILE}\n",
        sh_quote(&format!("{MARIADB_SOCKET_DIRECTORY}/{SOCKET_FILE}"))
    )
}

fn inventory_script() -> String {
    format!(
        "{prelude}exec >{report}\nprintf 'tool=%s\\n' \"$(mariadb-backup --version 2>&1 | head -n 1)\"\nmariadb --defaults-extra-file={OPTION_FILE} -N -B --init-command={init} <<'SQL'\n{sql}\nSQL\n",
        prelude = option_file_prelude(),
        report = sh_quote(&format!("{BACKUP_HELPER_STAGING}/{INVENTORY_REPORT}")),
        init = sh_quote(&format!(
            "SET SESSION max_statement_time={INVENTORY_SESSION_TIMEOUT_SECONDS}"
        )),
        sql = inventory::SQL,
    )
}

fn backup_script() -> String {
    let target = format!("{BACKUP_HELPER_STAGING}/{DATA_ROOT}");
    let tmp = format!("{BACKUP_HELPER_STAGING}/{TMP_ROOT}");
    format!(
        "{prelude}mkdir -p {target} {tmp}\nexec mariadb-backup --defaults-extra-file={OPTION_FILE} --backup --target-dir={target} --datadir={data} --tmpdir={tmp} --parallel=1\n",
        prelude = option_file_prelude(),
        target = sh_quote(&target),
        tmp = sh_quote(&tmp),
        data = sh_quote(DATA_TARGET),
    )
}

fn prepare_script() -> String {
    format!(
        "set -eu\numask 077\nexec mariadb-backup --prepare --target-dir={} --tmpdir={} --use-memory={PREPARE_MEMORY}\n",
        sh_quote(&format!("{BACKUP_HELPER_STAGING}/{DATA_ROOT}")),
        sh_quote(&format!("{BACKUP_HELPER_STAGING}/{TMP_ROOT}")),
    )
}

fn password_environment(password: SecretString) -> Vec<DockerEnv> {
    vec![DockerEnv {
        key: PASSWORD_ENV.to_string(),
        value: password,
    }]
}

fn socket_mount(ctx: &OnlineBackupContext<'_>) -> BackupHelperSocket {
    BackupHelperSocket {
        source: ctx.paths.sockets.clone(),
        target: MARIADB_SOCKET_DIRECTORY.to_string(),
    }
}

async fn load_inventory(
    ctx: &OnlineBackupContext<'_>,
    staging: &StagingArea,
    registrar: &dyn OwnedResourceRegistrar,
    image: &str,
) -> Result<Inventory, StrategyError> {
    let password = static_gate(ctx)?;
    let spec = BackupHelperSpec {
        name: format!("{}_{INVENTORY_HELPER_SUFFIX}", ctx.job.resource_tag()),
        instance_id: ctx.metadata.instance_id.clone(),
        image: image.to_string(),
        socket: Some(socket_mount(ctx)),
        data: None,
        staging_dir: staging.root.clone(),
        staging_read_only: false,
        script: inventory_script(),
        environment: password_environment(password),
        timeout: ctx.remaining()?.min(INVENTORY_TIMEOUT),
        max_staging_bytes: staging.native_budget_bytes,
    };
    ctx.run_helper(registrar, &spec)
        .await
        .map_err(|error| error.for_tool("inventory"))?;
    let report = take_report(
        staging.root.join(INVENTORY_REPORT),
        MAX_INVENTORY_REPORT_BYTES,
    )
    .await?;
    let inventory = parse_report(&report)
        .map_err(|error| StrategyError::Failed(format!("inventory report: {error}")))?;
    inventory.decide(staging.native_budget_bytes)?;
    Ok(inventory)
}

async fn capture_tree(
    ctx: &OnlineBackupContext<'_>,
    staging: &StagingArea,
    registrar: &dyn OwnedResourceRegistrar,
) -> Result<CaptureResult, StrategyError> {
    let image = ctx.runtime_image().await?;
    let inventory = load_inventory(ctx, staging, registrar, &image).await?;
    refuse_overlapping_staging(ctx.paths, staging)?;
    let data = ctx.paths.data.clone();
    blocking("inspect data directory links", move || {
        layout::refuse_external_tablespaces(&data)
    })
    .await
    .map_err(|error| match error {
        StrategyError::Failed(reason) => StrategyError::Unsupported(reason),
        other => other,
    })?;

    let password = static_gate(ctx)?;
    let backup = BackupHelperSpec {
        name: ctx.job.resource_tag(),
        instance_id: ctx.metadata.instance_id.clone(),
        image: image.clone(),
        socket: Some(socket_mount(ctx)),
        data: Some(BackupHelperSocket {
            source: ctx.paths.data.clone(),
            target: DATA_TARGET.to_string(),
        }),
        staging_dir: staging.root.clone(),
        staging_read_only: false,
        script: backup_script(),
        environment: password_environment(password),
        timeout: ctx.remaining()?,
        max_staging_bytes: staging.native_budget_bytes,
    };
    let output = ctx
        .run_helper(registrar, &backup)
        .await
        .map_err(|error| error.for_tool("mariadb-backup --backup"))?;
    require_completed("mariadb-backup --backup", &output.stderr)?;

    let prepare = BackupHelperSpec {
        name: format!("{}_{PREPARE_HELPER_SUFFIX}", ctx.job.resource_tag()),
        instance_id: ctx.metadata.instance_id.clone(),
        image,
        socket: None,
        data: None,
        staging_dir: staging.root.clone(),
        staging_read_only: false,
        script: prepare_script(),
        environment: Vec::new(),
        timeout: ctx.remaining()?,
        max_staging_bytes: staging.native_budget_bytes,
    };
    let output = ctx
        .run_helper(registrar, &prepare)
        .await
        .map_err(|error| error.for_tool("mariadb-backup --prepare"))?;
    require_completed("mariadb-backup --prepare", &output.stderr)?;

    let root = staging.root.clone();
    let checkpoints: Checkpoints = blocking("seal the prepared backup", move || {
        match std::fs::remove_dir_all(root.join(TMP_ROOT)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("remove the tool scratch directory: {error}")),
        }
        layout::check_prepared(&root.join(DATA_ROOT))
    })
    .await?;

    let data_root = PathBuf::from(DATA_ROOT);
    let restore_target = PathBuf::from(RESTORE_TARGET);
    require_relative(&data_root, "data root")?;
    require_relative(&restore_target, "restore target")?;
    let mut recovery = BTreeMap::new();
    recovery.insert("from_lsn".to_string(), checkpoints.from_lsn.to_string());
    recovery.insert("to_lsn".to_string(), checkpoints.to_lsn.to_string());
    recovery.insert("last_lsn".to_string(), checkpoints.last_lsn.to_string());
    let mut tool_versions = BTreeMap::new();
    tool_versions.insert("mariadb-backup".to_string(), inventory.tool_version.clone());
    Ok(CaptureResult {
        data_root,
        restore_target,
        consistency: ConsistencyLevel::PhysicalRecoveryPoint,
        recovery: RecoveryCoordinates(recovery),
        engine_version: Some(inventory.server_version.clone()),
        tool_versions,
        exclusions: Vec::new(),
        native_manifest: Some(PathBuf::from(format!(
            "{DATA_ROOT}/{}",
            checkpoints.file_name
        ))),
    })
}

fn require_completed(tool: &str, stderr: &str) -> Result<(), StrategyError> {
    if stderr.contains(COMPLETED_OK) {
        Ok(())
    } else {
        Err(StrategyError::Failed(format!(
            "{tool} exited 0 without reporting completion"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_matches_the_registry_contract() {
        let strategy = MariadbBackupStrategy;
        assert_eq!(strategy.id(), MARIADB_BACKUP);
        let recipe = strategy.restore_recipe();
        assert_eq!(recipe.id, "mariadb.prepared_backup.directory");
        assert_eq!(recipe.version, 1);
        assert_eq!(strategy.restorable_recipe_versions(), &[1]);
        assert_eq!(
            crate::databases::protocol::Protocol::Mariadb
                .engine()
                .online_backup(),
            crate::databases::engine::OnlineBackup::MariadbBackup
        );
    }

    #[test]
    fn scripts_keep_the_password_in_the_environment_and_write_only_into_staging() {
        let backup = backup_script();
        assert!(backup.starts_with("set -eu\numask 077\nprintf "));
        assert!(backup.contains(&format!("\"${PASSWORD_ENV}\"")));
        assert!(backup.contains(&format!(
            "--target-dir={}",
            sh_quote(&format!("{BACKUP_HELPER_STAGING}/{DATA_ROOT}"))
        )));
        assert!(backup.contains(&format!("--datadir={}", sh_quote(DATA_TARGET))));
        assert!(backup.contains(&format!(
            "exec mariadb-backup --defaults-extra-file={OPTION_FILE} --backup"
        )));
        let inventory = inventory_script();
        assert!(inventory.contains(&format!(
            "exec >{}\n",
            sh_quote(&format!("{BACKUP_HELPER_STAGING}/{INVENTORY_REPORT}"))
        )));
        assert!(inventory.contains("max_statement_time=60"));
        let prepare = prepare_script();
        assert!(prepare.contains("--prepare"));
        assert!(!prepare.contains(PASSWORD_ENV));
        for script in [&backup, &inventory, &prepare] {
            assert!(!script.contains("dbe-root-"));
            assert!(script.len() < 64 * 1024);
        }
        for suffix in [INVENTORY_HELPER_SUFFIX, PREPARE_HELPER_SUFFIX] {
            assert!(suffix.len() <= 16);
        }
    }

    #[test]
    fn tool_runs_must_report_completion() {
        assert!(require_completed("x", "[00] 2026-10-18 completed OK!\n").is_ok());
        assert!(require_completed("x", "").is_err());
    }
}
