//! Dedicated PostgreSQL 14–18 online physical backup.
//!
//! `pg_basebackup` runs in a short-lived helper container started from the
//! instance's own immutable image, so its binaries match the server. The
//! helper reaches the server through the instance socket directory (mounted
//! read-only) and writes a plain directory straight into the job's
//! disk-backed, coordinator-reserved staging. Nothing is staged on the socket
//! mount, which is commonly tmpfs charged to the database's memory cgroup.
//! The helper is journaled before it exists, has no network and its own CPU,
//! memory and pid limits, and is removed (and confirmed gone) on completion,
//! timeout, cancellation or once staging exceeds the native budget. That
//! budget equals what restore will extract.
//!
//! The temporary replication slot is the one `pg_basebackup` creates itself.
//! Retention starts when its WAL streamer creates `pg_basebackup_<pid>`,
//! after the spread checkpoint has returned the start LSN and before file
//! copy. Retention ends when that streamer has stored WAL through the stop
//! LSN and disconnects. The server drops the temporary slot on disconnect,
//! including when the helper is killed. This module does not pass
//! `--no-slot` and does not create a second slot, so the slot is not an owned
//! resource. The spread checkpoint has a short interval before the slot
//! exists; that is PostgreSQL's own design, because the checkpoint's redo
//! point is the backup start and its segment is not recycled by the
//! checkpoint that created it.
//!
//! `verify` runs `pg_verifybackup` in a second helper against the final
//! staged tree (mounted read-only), which also checks the streamed WAL
//! against `WAL-Ranges`, and then rehashes the tree against
//! `backup_manifest` in-process.
//!
//! The server inventory (versions, layout, roles, HBA, unlogged objects) needs
//! database sessions, so it is not part of the side-effect-free pre-admission
//! preflight. It runs after admission in its own journaled helper, never as an
//! exec in the serving container, whose timeout cannot terminate it. The
//! helper is removed with confirmation on timeout, cancellation or recovery,
//! and its sessions carry statement and lock timeouts, so server-side work
//! ends even after the client is killed.

mod command;
mod parse;
mod preflight;
mod restore;

pub(crate) use command::{
    LOCAL_CLIENT_HBA_LINE, REPLICATION_HBA_LINE, REPLICATION_ROLE, REPLICATION_ROLE_STATE,
    ensure_replication_role_sql, foreign_replication_role_diagnostic, replication_password,
    replication_role_comment_sql, replication_role_ownership_sql, replication_role_state_sql,
    reset_replication_password_sql,
};
pub(crate) use restore::prepare_basebackup_restore;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

use futures::future::BoxFuture;
use secrecy::{ExposeSecret, SecretString};

use crate::{
    databases::protocol::Protocol,
    runtime::docker::{BACKUP_HELPER_STAGING, BackupHelperSocket, BackupHelperSpec, DockerEnv},
    server::{
        backup::manifest::{ConsistencyLevel, RestoreRecipeRef, is_safe_relative},
        placement::DeploymentMode,
    },
    subsystems::backups::{
        registry::POSTGRES_BASE_BACKUP,
        strategy::{
            CaptureResult, OnlineBackupContext, OnlineBackupStrategy, OwnedResourceRegistrar,
            RestoreContext, StagingArea, StrategyError, VerificationCheck, blocking, exec_script,
            refuse_overlapping_staging, require_relative, take_report,
        },
    },
    utils::{backend::POSTGRES_SOCKET_DIRECTORY, shell::sh_quote},
};

use command::{
    DATA_ROOT, RESTORE_RECIPE_ID, RESTORE_RECIPE_VERSION, backup_label_for_tag, basebackup_argv,
    preflight_script, replication_role_ownership_preflight_sql, verifybackup_argv,
};
use preflight::{decide, parse_report, sample_space, space_allows};

const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(120);
const PREFLIGHT_HELPER_SUFFIX: &str = "preflight";
/// Written at the staging root and removed before the capture starts.
const PREFLIGHT_REPORT: &str = "preflight.report";
const MAX_PREFLIGHT_REPORT_BYTES: u64 = 4 * 1024 * 1024;
const PREFLIGHT_CONNECT_TIMEOUT_SECONDS: u64 = 10;
/// Bounds each inventory statement on the server, where a query keeps
/// running after its client is killed until it next writes to the socket.
const PREFLIGHT_SESSION_OPTIONS: &str = "-c statement_timeout=60s -c lock_timeout=10s";
const VERIFY_HELPER_SUFFIX: &str = "verify";

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PostgresBaseBackupStrategy;

impl OnlineBackupStrategy for PostgresBaseBackupStrategy {
    fn id(&self) -> &'static str {
        POSTGRES_BASE_BACKUP
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
        ctx: &'a OnlineBackupContext<'a>,
        staging: &'a StagingArea,
        capture: &'a CaptureResult,
        registrar: &'a dyn OwnedResourceRegistrar,
    ) -> BoxFuture<'a, Result<Vec<VerificationCheck>, StrategyError>> {
        Box::pin(async move {
            let _ = self;
            verify_capture(ctx, staging, capture, registrar).await
        })
    }

    fn prepare_restore<'a>(
        &'a self,
        ctx: &'a RestoreContext<'a>,
    ) -> BoxFuture<'a, Result<(), StrategyError>> {
        Box::pin(async move {
            let _ = self;
            ctx.require_recipe(RESTORE_RECIPE_ID, RESTORE_RECIPE_VERSION)?;
            let target = ctx
                .restore_target
                .to_str()
                .filter(|path| is_safe_relative(path))
                .ok_or_else(|| {
                    StrategyError::Failed("restore target is not a safe relative path".to_string())
                })?;
            let pgdata = ctx.extracted_root.join(target);
            prepare_basebackup_restore(&pgdata).map_err(StrategyError::Failed)
        })
    }
}

/// Checks that need no server session.
fn static_gate(
    ctx: &OnlineBackupContext<'_>,
) -> Result<(SecretString, SecretString), StrategyError> {
    if ctx.metadata.deployment_mode == DeploymentMode::Shared {
        return Err(StrategyError::Unsupported(
            "shared tenants keep their logical dump; physical online backup is dedicated-only"
                .to_string(),
        ));
    }
    replication_secrets(ctx)
}

/// Runs the inventory in a supervised helper and decides the capture plan.
async fn load_plan(
    ctx: &OnlineBackupContext<'_>,
    staging: &StagingArea,
    registrar: &dyn OwnedResourceRegistrar,
) -> Result<preflight::CapturePlan, StrategyError> {
    let (admin, replication) = static_gate(ctx)?;
    let (user, database) = bootstrap_login(ctx).await?;
    let spec = BackupHelperSpec {
        name: format!("{}_{PREFLIGHT_HELPER_SUFFIX}", ctx.job.resource_tag()),
        instance_id: ctx.metadata.instance_id.clone(),
        image: ctx.runtime_image().await?,
        socket: Some(BackupHelperSocket {
            source: ctx.paths.sockets.clone(),
            target: POSTGRES_SOCKET_DIRECTORY.to_string(),
        }),
        data: None,
        staging_dir: staging.root.clone(),
        staging_read_only: false,
        script: preflight_exec_script(&user, &database),
        environment: vec![
            DockerEnv::new("DBE_POSTGRES_ADMIN_PASSWORD", admin),
            DockerEnv::new("DBE_REPLICATION_PASSWORD", replication),
        ],
        timeout: ctx.remaining()?.min(PREFLIGHT_TIMEOUT),
        max_staging_bytes: staging.native_budget_bytes,
    };
    ctx.run_helper(registrar, &spec)
        .await
        .map_err(|error| error.for_tool("preflight"))?;
    let report = take_report(
        staging.root.join(PREFLIGHT_REPORT),
        MAX_PREFLIGHT_REPORT_BYTES,
    )
    .await?;
    let report = parse_report(&report)
        .map_err(|error| StrategyError::Failed(format!("preflight report: {error}")))?;
    decide(&report, ctx.metadata.deployment_mode, None).map_err(preflight::Gate::into_strategy)
}

/// The serving container's own bootstrap login, which the inventory uses.
/// The official image defaults `POSTGRES_DB` to `POSTGRES_USER`.
async fn bootstrap_login(ctx: &OnlineBackupContext<'_>) -> Result<(String, String), StrategyError> {
    let value = |key: &'static str| async move {
        ctx.state
            .docker
            .container_environment_value(Protocol::Postgres, ctx.metadata.runtime_id(), key)
            .await
            .map(|value| {
                value
                    .map(|value| value.expose_secret().to_string())
                    .filter(|value| !value.is_empty())
            })
            .map_err(|error| StrategyError::failed("inspect PostgreSQL bootstrap login", error))
    };
    let user = value("POSTGRES_USER").await?.ok_or_else(|| {
        StrategyError::Unsupported("the PostgreSQL container has no POSTGRES_USER".to_string())
    })?;
    let database = value("POSTGRES_DB").await?.unwrap_or_else(|| user.clone());
    Ok((user, database))
}

/// The preflight script with its non-secret settings, writing its report to
/// staging: helper stdout is redacted and truncated, the report must be
/// neither. Secrets stay in the environment. The replication role ownership
/// probe follows the inventory and is the report's final line.
fn preflight_exec_script(user: &str, database: &str) -> String {
    format!(
        "set -eu\numask 077\nexport POSTGRES_USER={} POSTGRES_DB={} PGCONNECT_TIMEOUT={PREFLIGHT_CONNECT_TIMEOUT_SECONDS} PGOPTIONS={}\nexec >{}\n{}PGPASSWORD=\"$DBE_POSTGRES_ADMIN_PASSWORD\" psql -X -h {} -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -v ON_ERROR_STOP=1 -Atq <<'SQL'\n{}\nSQL\n",
        sh_quote(user),
        sh_quote(database),
        sh_quote(PREFLIGHT_SESSION_OPTIONS),
        sh_quote(&format!("{BACKUP_HELPER_STAGING}/{PREFLIGHT_REPORT}")),
        preflight_script(),
        sh_quote(POSTGRES_SOCKET_DIRECTORY),
        replication_role_ownership_preflight_sql()
    )
}

async fn capture_tree(
    ctx: &OnlineBackupContext<'_>,
    staging: &StagingArea,
    registrar: &dyn OwnedResourceRegistrar,
) -> Result<CaptureResult, StrategyError> {
    let plan = load_plan(ctx, staging, registrar).await?;
    refuse_overlapping_staging(ctx.paths, staging)?;
    let space =
        sample_space(&staging.root, staging.native_budget_bytes).map_err(StrategyError::Failed)?;
    let estimate = plan.estimate().map_err(StrategyError::Failed)?;
    space_allows(estimate, &space).map_err(StrategyError::Failed)?;

    let tag = ctx.job.resource_tag();
    let label = backup_label_for_tag(&tag).ok_or_else(|| {
        StrategyError::Failed("backup job tag is not a capture label".to_string())
    })?;
    let (_admin, replication) = replication_secrets(ctx)?;
    let pgdata = format!("{BACKUP_HELPER_STAGING}/{DATA_ROOT}");
    let spec = BackupHelperSpec {
        name: tag,
        instance_id: ctx.metadata.instance_id.clone(),
        image: ctx.runtime_image().await?,
        socket: Some(BackupHelperSocket {
            source: ctx.paths.sockets.clone(),
            target: POSTGRES_SOCKET_DIRECTORY.to_string(),
        }),
        data: None,
        staging_dir: staging.root.clone(),
        staging_read_only: false,
        script: exec_script(&basebackup_argv(&pgdata, &label)),
        environment: vec![DockerEnv::new("PGPASSWORD", replication)],
        timeout: ctx.remaining()?,
        max_staging_bytes: staging.native_budget_bytes,
    };
    ctx.run_helper(registrar, &spec)
        .await
        .map_err(|error| error.for_tool("pg_basebackup"))?;

    let host_pgdata = staging.root.join(DATA_ROOT);
    let recovery = blocking("read backup description", move || {
        parse::read_recovery(&host_pgdata, &label)
    })
    .await?;

    let data_root = PathBuf::from(DATA_ROOT);
    let native_manifest = PathBuf::from(format!("{DATA_ROOT}/backup_manifest"));
    require_relative(&data_root, "data root")?;
    require_relative(&plan.restore_target, "restore target")?;
    require_relative(&native_manifest, "native manifest")?;
    let mut tool_versions = BTreeMap::new();
    tool_versions.insert("pg_basebackup".to_string(), plan.tool_basebackup);
    tool_versions.insert("pg_verifybackup".to_string(), plan.tool_verifybackup);
    Ok(CaptureResult {
        data_root,
        restore_target: plan.restore_target,
        consistency: ConsistencyLevel::PhysicalRecoveryPoint,
        recovery,
        engine_version: Some(plan.server_version),
        tool_versions,
        exclusions: plan.exclusions,
        native_manifest: Some(native_manifest),
    })
}

async fn verify_capture(
    ctx: &OnlineBackupContext<'_>,
    staging: &StagingArea,
    capture: &CaptureResult,
    registrar: &dyn OwnedResourceRegistrar,
) -> Result<Vec<VerificationCheck>, StrategyError> {
    if capture.data_root != Path::new(DATA_ROOT) {
        return Err(StrategyError::Failed(
            "capture data root is not pgdata".to_string(),
        ));
    }
    let pgdata = format!("{BACKUP_HELPER_STAGING}/{DATA_ROOT}");
    let spec = BackupHelperSpec {
        name: format!("{}_{VERIFY_HELPER_SUFFIX}", ctx.job.resource_tag()),
        instance_id: ctx.metadata.instance_id.clone(),
        image: ctx.runtime_image().await?,
        socket: None,
        data: None,
        staging_dir: staging.root.clone(),
        staging_read_only: true,
        script: exec_script(&verifybackup_argv(&pgdata)),
        environment: Vec::new(),
        timeout: ctx.remaining()?,
        max_staging_bytes: staging.native_budget_bytes,
    };
    ctx.run_helper(registrar, &spec)
        .await
        .map_err(|error| error.for_tool("pg_verifybackup"))?;
    let host_pgdata = staging.root.join(&capture.data_root);
    let files = blocking("rehash staged backup", move || {
        parse::verify_staged_tree(&host_pgdata)
    })
    .await?;
    Ok(vec![VerificationCheck {
        check: "pg_verifybackup".to_string(),
        passed: true,
        detail: Some(format!(
            "version-matched pg_verifybackup accepted the final staged tree including its WAL; {files} files rehashed against backup_manifest"
        )),
    }])
}

fn replication_secrets(
    ctx: &OnlineBackupContext<'_>,
) -> Result<(SecretString, SecretString), StrategyError> {
    let Some(admin) = ctx
        .metadata
        .postgres_admin_password
        .as_deref()
        .filter(|password| !password.is_empty())
    else {
        return Err(StrategyError::Unsupported(
            "PostgreSQL administrator credential is missing".to_string(),
        ));
    };
    let replication = replication_password(admin)
        .map_err(|reason| StrategyError::Unsupported(reason.to_string()))?;
    Ok((SecretString::from(admin.to_string()), replication))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LABEL: &str = "dbev-0123456789abcdef0123456789abcdef";

    #[test]
    fn identity_matches_the_registry_contract() {
        let strategy = PostgresBaseBackupStrategy;
        assert_eq!(strategy.id(), POSTGRES_BASE_BACKUP);
        assert_eq!(strategy.id(), "postgres.pg_basebackup");
        let recipe = strategy.restore_recipe();
        assert_eq!(recipe.id, "postgres.basebackup.directory");
        assert_eq!(recipe.version, 1);
        assert_eq!(strategy.restorable_recipe_versions(), &[1]);
    }

    #[test]
    fn helper_scripts_write_into_staging_and_never_carry_the_password() {
        let pgdata = format!("{BACKUP_HELPER_STAGING}/{DATA_ROOT}");
        let capture = exec_script(&basebackup_argv(&pgdata, LABEL));
        assert!(capture.starts_with("set -eu\n"));
        assert!(capture.contains(&sh_quote(&pgdata)));
        assert!(capture.contains(&sh_quote(POSTGRES_SOCKET_DIRECTORY)));
        assert!(capture.contains("exec "));
        assert!(!capture.contains("PGPASSWORD"));
        assert!(!capture.contains("rm -rf"));
        // Nothing is written below the socket mount any more.
        assert!(!capture.contains(&format!("{POSTGRES_SOCKET_DIRECTORY}/dbev_bk_")));
        let verify = exec_script(&verifybackup_argv(&pgdata));
        assert!(verify.contains(&sh_quote("pg_verifybackup")));
        assert!(verify.contains(&sh_quote(&pgdata)));
    }

    #[test]
    fn preflight_runs_bounded_in_a_helper_and_reports_into_staging() {
        let script = preflight_exec_script("dbe_admin", "app's db");
        assert!(script.starts_with("set -eu\numask 077\n"));
        assert!(script.contains(&format!("POSTGRES_USER={}", sh_quote("dbe_admin"))));
        assert!(script.contains(&format!("POSTGRES_DB={}", sh_quote("app's db"))));
        assert!(script.contains("PGCONNECT_TIMEOUT=10"));
        assert!(script.contains(&sh_quote(PREFLIGHT_SESSION_OPTIONS)));
        assert!(script.contains(&format!(
            "exec >{}\n",
            sh_quote(&format!("{BACKUP_HELPER_STAGING}/{PREFLIGHT_REPORT}"))
        )));
        assert!(script.contains(preflight_script()));
        // The ownership probe is the report's last line, after the inventory.
        let probe = script.split(preflight_script()).nth(1).unwrap();
        assert!(probe.contains(&replication_role_ownership_preflight_sql()));
        assert!(probe.ends_with("\nSQL\n"));
        assert!(script.len() < 64 * 1024);
        assert!(PREFLIGHT_HELPER_SUFFIX.len() <= 16);
    }

    #[test]
    fn helper_failures_name_the_native_tool() {
        let error =
            StrategyError::Failed("backup helper exited 1".to_string()).for_tool("pg_basebackup");
        assert!(
            matches!(error, StrategyError::Failed(reason) if reason.starts_with("pg_basebackup: "))
        );
        let unsupported =
            StrategyError::Unsupported("no credential".to_string()).for_tool("pg_basebackup");
        assert!(
            matches!(unsupported, StrategyError::Unsupported(reason) if reason == "no credential")
        );
    }
}
