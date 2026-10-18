//! Dedicated Redis and Valkey online snapshot backup.
//!
//! A naive copy of the live data and AOF directories after `BGREWRITEAOF`
//! does not establish a recoverable append-only state: file identity checks
//! miss same-inode truncation (Redis `ftruncate`s short AOF writes) and
//! configuration changes, and padding a shrinking file fabricates content.
//! This strategy therefore captures one completed, immutable RDB instead.
//!
//! The CLI from the instance's own immutable image runs in a short-lived
//! helper container that reaches the server through the instance socket
//! directory (mounted read-only) and asks for an rdb-only replication
//! transfer (`--rdb`). With `repl-diskless-sync yes` the server forks once and
//! streams the snapshot to the helper, which writes it straight into
//! coordinator-reserved staging. Nothing is written into the data volume, and
//! a failed transfer never touches `lastbgsave_status`, so it cannot trip
//! `stop-writes-on-bgsave-error`. The fork is the same copy-on-write fork an
//! AOF rewrite already performs; an inventory in its own helper refuses the
//! capture when the resident set leaves no headroom for it inside the
//! container memory limit, when diskless sync is off, or when RDB checksums
//! are disabled.
//!
//! `verify` runs the image's own `check-rdb` against the staged file (mounted
//! read-only), which validates every object and the trailing CRC64.
//!
//! The staged tree is shaped as the default multi-part AOF directory: the
//! snapshot is its base (`appendonly.aof.1.base.rdb`) and a manifest names
//! it. Restore installs that directory into the data volume, the restore path
//! rewrites `users.acl` from the current tenant credential, and the server
//! starts with its normal `--appendonly yes` command line, loading the base
//! and opening a fresh incremental file. No restore-time server and no
//! appendonly toggling are needed.

mod aof;
mod inventory;

use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use futures::future::BoxFuture;
use secrecy::SecretString;

use crate::{
    databases::protocol::Protocol,
    runtime::docker::{BACKUP_HELPER_STAGING, BackupHelperSocket, BackupHelperSpec, DockerEnv},
    server::{
        backup::manifest::{ConsistencyLevel, RecoveryCoordinates, RestoreRecipeRef},
        placement::DeploymentMode,
    },
    subsystems::backups::{
        registry::RESP_RDB_SNAPSHOT,
        strategy::{
            CaptureResult, OnlineBackupContext, OnlineBackupStrategy, OwnedResourceRegistrar,
            RestoreContext, StagingArea, StrategyError, VerificationCheck, blocking, exec_script,
            refuse_overlapping_staging, require_relative, take_report,
        },
    },
    utils::{
        backend::{CONTAINER_SOCKET_DIRECTORY, container_backend_socket_path},
        shell::sh_quote,
    },
};

use aof::{AOF_DIRECTORY, BASE_FILE, prepare_aof_restore, write_manifest};
use inventory::{Inventory, parse_report};

const RESTORE_RECIPE_ID: &str = "resp.aof_base.directory";
const RESTORE_RECIPE_VERSION: u32 = 1;
const INVENTORY_TIMEOUT: Duration = Duration::from_secs(60);
const INVENTORY_HELPER_SUFFIX: &str = "inventory";
const VERIFY_HELPER_SUFFIX: &str = "verify";
/// Written at the staging root and removed before the capture starts.
const INVENTORY_REPORT: &str = "inventory.report";
const MAX_INVENTORY_REPORT_BYTES: u64 = 1024 * 1024;
/// `check-rdb` prints this once every object and the checksum validated.
const CHECK_RDB_OK: &str = "RDB looks OK";

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct RespRdbSnapshotStrategy;

impl OnlineBackupStrategy for RespRdbSnapshotStrategy {
    fn id(&self) -> &'static str {
        RESP_RDB_SNAPSHOT
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
        ctx: &'a OnlineBackupContext<'a>,
        staging: &'a StagingArea,
        capture: &'a CaptureResult,
        registrar: &'a dyn OwnedResourceRegistrar,
    ) -> BoxFuture<'a, Result<Vec<VerificationCheck>, StrategyError>> {
        Box::pin(async move {
            let _ = self;
            verify_snapshot(ctx, staging, capture, registrar).await
        })
    }

    fn prepare_restore<'a>(
        &'a self,
        ctx: &'a RestoreContext<'a>,
    ) -> BoxFuture<'a, Result<(), StrategyError>> {
        Box::pin(async move {
            let _ = self;
            ctx.require_recipe(RESTORE_RECIPE_ID, RESTORE_RECIPE_VERSION)?;
            if ctx.restore_target != std::path::Path::new(AOF_DIRECTORY) {
                return Err(StrategyError::Failed(format!(
                    "restore target is not {AOF_DIRECTORY}"
                )));
            }
            prepare_aof_restore(&ctx.extracted_root.join(AOF_DIRECTORY))
                .map_err(StrategyError::Failed)
        })
    }
}

/// Native tools of one RESP engine, all shipped in its official image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tools {
    cli: &'static str,
    check_rdb: &'static str,
}

fn tools(protocol: Protocol) -> Result<Tools, StrategyError> {
    match protocol {
        Protocol::Redis => Ok(Tools {
            cli: "redis-cli",
            check_rdb: "redis-check-rdb",
        }),
        Protocol::Valkey => Ok(Tools {
            cli: "valkey-cli",
            check_rdb: "valkey-check-rdb",
        }),
        other => Err(StrategyError::Unsupported(format!(
            "{} is not a RESP engine",
            other.as_str()
        ))),
    }
}

/// Checks that need no server session; returns the tenant login.
fn static_gate(ctx: &OnlineBackupContext<'_>) -> Result<(String, SecretString), StrategyError> {
    if ctx.metadata.deployment_mode == DeploymentMode::Shared {
        return Err(StrategyError::Unsupported(
            "shared tenants keep their logical dump; snapshot online backup is dedicated-only"
                .to_string(),
        ));
    }
    tools(ctx.metadata.protocol)?;
    let username = ctx.metadata.database.username.clone();
    if username.is_empty() {
        return Err(StrategyError::Unsupported(
            "the instance has no tenant username".to_string(),
        ));
    }
    let password = ctx
        .metadata
        .tenant_password
        .as_deref()
        .filter(|password| !password.is_empty())
        .ok_or_else(|| {
            StrategyError::Unsupported("the tenant credential is missing".to_string())
        })?;
    Ok((username, SecretString::from(password.to_string())))
}

/// Both CLIs read the password from the environment; it never reaches argv.
fn auth_environment(password: &SecretString) -> Vec<DockerEnv> {
    ["REDISCLI_AUTH", "VALKEYCLI_AUTH"]
        .into_iter()
        .map(|key| DockerEnv {
            key: key.to_string(),
            value: password.clone(),
        })
        .collect()
}

fn socket_mount(ctx: &OnlineBackupContext<'_>) -> BackupHelperSocket {
    BackupHelperSocket {
        source: ctx.paths.sockets.clone(),
        target: CONTAINER_SOCKET_DIRECTORY.to_string(),
    }
}

/// The inventory script. CLI output goes to a report in staging: helper
/// stdout is redacted and truncated, the report must be neither.
fn inventory_script(tools: Tools, socket: &str, username: &str) -> String {
    let cli = format!(
        "{} -s {} --user {}",
        sh_quote(tools.cli),
        sh_quote(socket),
        sh_quote(username)
    );
    format!(
        "set -eu\numask 077\nexec >{report}\nprintf '%s\\n' '[cli]'\n{bin} --version\nprintf '%s\\n' '[info]'\n{cli} INFO server\n{cli} INFO persistence\n{cli} INFO memory\nprintf '%s\\n' '[config]'\n{cli} CONFIG GET {keys}\n",
        report = sh_quote(&format!("{BACKUP_HELPER_STAGING}/{INVENTORY_REPORT}")),
        bin = sh_quote(tools.cli),
        keys = inventory::CONFIG_KEYS.join(" "),
    )
}

fn capture_argv(tools: Tools, socket: &str, username: &str, output: &str) -> Vec<String> {
    [tools.cli, "-s", socket, "--user", username, "--rdb", output]
        .into_iter()
        .map(str::to_string)
        .collect()
}

async fn load_inventory(
    ctx: &OnlineBackupContext<'_>,
    staging: &StagingArea,
    registrar: &dyn OwnedResourceRegistrar,
) -> Result<Inventory, StrategyError> {
    let (username, password) = static_gate(ctx)?;
    let tools = tools(ctx.metadata.protocol)?;
    let socket = container_backend_socket_path(ctx.metadata.protocol);
    let spec = BackupHelperSpec {
        name: format!("{}_{INVENTORY_HELPER_SUFFIX}", ctx.job.resource_tag()),
        instance_id: ctx.metadata.instance_id.clone(),
        image: ctx.runtime_image().await?,
        socket: Some(socket_mount(ctx)),
        data: None,
        staging_dir: staging.root.clone(),
        staging_read_only: false,
        script: inventory_script(tools, &socket, &username),
        environment: auth_environment(&password),
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
    inventory.decide(ctx.metadata.limits.memory_mib)?;
    Ok(inventory)
}

async fn capture_snapshot(
    ctx: &OnlineBackupContext<'_>,
    staging: &StagingArea,
    registrar: &dyn OwnedResourceRegistrar,
) -> Result<CaptureResult, StrategyError> {
    let inventory = load_inventory(ctx, staging, registrar).await?;
    refuse_overlapping_staging(ctx.paths, staging)?;
    let (username, password) = static_gate(ctx)?;
    let tools = tools(ctx.metadata.protocol)?;
    let socket = container_backend_socket_path(ctx.metadata.protocol);
    let output = format!("{BACKUP_HELPER_STAGING}/{AOF_DIRECTORY}/{BASE_FILE}");
    let spec = BackupHelperSpec {
        name: ctx.job.resource_tag(),
        instance_id: ctx.metadata.instance_id.clone(),
        image: ctx.runtime_image().await?,
        socket: Some(socket_mount(ctx)),
        data: None,
        staging_dir: staging.root.clone(),
        staging_read_only: false,
        script: capture_script(&capture_argv(tools, &socket, &username, &output)),
        environment: auth_environment(&password),
        timeout: ctx.remaining()?,
        max_staging_bytes: staging.native_budget_bytes,
    };
    ctx.run_helper(registrar, &spec)
        .await
        .map_err(|error| error.for_tool(tools.cli))?;

    let directory = staging.root.join(AOF_DIRECTORY);
    let format = blocking("seal the AOF directory", move || {
        let format = aof::read_rdb_format(&directory.join(BASE_FILE))?;
        write_manifest(&directory)?;
        Ok(format)
    })
    .await?;

    let data_root = PathBuf::from(AOF_DIRECTORY);
    require_relative(&data_root, "data root")?;
    let mut recovery = BTreeMap::new();
    recovery.insert("rdb_format".to_string(), format);
    recovery.insert("aof_base".to_string(), BASE_FILE.to_string());
    let mut tool_versions = BTreeMap::new();
    tool_versions.insert(tools.cli.to_string(), inventory.cli_version.clone());
    Ok(CaptureResult {
        restore_target: data_root.clone(),
        data_root,
        // One forked copy of the whole keyspace at a single instant.
        consistency: ConsistencyLevel::TransactionalSnapshot,
        recovery: RecoveryCoordinates(recovery),
        engine_version: Some(inventory.server_version.clone()),
        tool_versions,
        exclusions: vec![
            "users.acl (restore rewrites it from the current tenant credential)".to_string(),
        ],
        native_manifest: Some(PathBuf::from(format!(
            "{AOF_DIRECTORY}/{}",
            aof::MANIFEST_FILE
        ))),
    })
}

/// Creates the AOF directory in staging, then hands over to the CLI.
fn capture_script(argv: &[String]) -> String {
    exec_script(argv).replacen(
        "exec ",
        &format!(
            "mkdir -p {}\nexec ",
            sh_quote(&format!("{BACKUP_HELPER_STAGING}/{AOF_DIRECTORY}"))
        ),
        1,
    )
}

async fn verify_snapshot(
    ctx: &OnlineBackupContext<'_>,
    staging: &StagingArea,
    capture: &CaptureResult,
    registrar: &dyn OwnedResourceRegistrar,
) -> Result<Vec<VerificationCheck>, StrategyError> {
    if capture.data_root != std::path::Path::new(AOF_DIRECTORY) {
        return Err(StrategyError::Failed(format!(
            "capture data root is not {AOF_DIRECTORY}"
        )));
    }
    let tools = tools(ctx.metadata.protocol)?;
    let file = format!("{BACKUP_HELPER_STAGING}/{AOF_DIRECTORY}/{BASE_FILE}");
    let spec = BackupHelperSpec {
        name: format!("{}_{VERIFY_HELPER_SUFFIX}", ctx.job.resource_tag()),
        instance_id: ctx.metadata.instance_id.clone(),
        image: ctx.runtime_image().await?,
        socket: None,
        data: None,
        staging_dir: staging.root.clone(),
        staging_read_only: true,
        script: exec_script(&[tools.check_rdb.to_string(), file]),
        environment: Vec::new(),
        timeout: ctx.remaining()?,
        max_staging_bytes: staging.native_budget_bytes,
    };
    let output = ctx
        .run_helper(registrar, &spec)
        .await
        .map_err(|error| error.for_tool(tools.check_rdb))?;
    check_rdb_accepted(tools, &output.stdout)?;
    let directory = staging.root.join(AOF_DIRECTORY);
    blocking("recheck the AOF directory", move || {
        aof::check_layout(&directory)
    })
    .await?;
    Ok(vec![VerificationCheck {
        check: "check_rdb".to_string(),
        passed: true,
        detail: Some(format!(
            "version-matched {} validated every object and the RDB checksum of the staged AOF base",
            tools.check_rdb
        )),
    }])
}

fn check_rdb_accepted(tools: Tools, stdout: &str) -> Result<(), StrategyError> {
    if stdout.contains(CHECK_RDB_OK) {
        Ok(())
    } else {
        Err(StrategyError::Failed(format!(
            "{} exited 0 without confirming the snapshot",
            tools.check_rdb
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_matches_the_registry_contract() {
        let strategy = RespRdbSnapshotStrategy;
        assert_eq!(strategy.id(), RESP_RDB_SNAPSHOT);
        let recipe = strategy.restore_recipe();
        assert_eq!(recipe.id, "resp.aof_base.directory");
        assert_eq!(recipe.version, 1);
        assert_eq!(strategy.restorable_recipe_versions(), &[1]);
    }

    #[test]
    fn both_engines_declare_the_snapshot_strategy() {
        use crate::databases::engine::OnlineBackup;
        for protocol in [Protocol::Redis, Protocol::Valkey] {
            assert_eq!(
                protocol.engine().online_backup(),
                OnlineBackup::RespRdbSnapshot
            );
            assert!(tools(protocol).is_ok());
        }
        assert!(matches!(
            tools(Protocol::Postgres),
            Err(StrategyError::Unsupported(_))
        ));
    }

    #[test]
    fn scripts_never_carry_the_password_and_write_only_into_staging() {
        let tools = tools(Protocol::Valkey).unwrap();
        let socket = container_backend_socket_path(Protocol::Valkey);
        let output = format!("{BACKUP_HELPER_STAGING}/{AOF_DIRECTORY}/{BASE_FILE}");
        let capture = capture_script(&capture_argv(tools, &socket, "app's user", &output));
        assert!(capture.starts_with("set -eu\numask 077\nmkdir -p "));
        assert!(capture.contains(&sh_quote("app's user")));
        assert!(capture.contains(&sh_quote("--rdb")));
        assert!(capture.contains(&sh_quote(&output)));
        assert!(capture.contains("\nexec 'valkey-cli' "));
        let inventory = inventory_script(tools, &socket, "app's user");
        assert!(inventory.contains(&format!(
            "exec >{}\n",
            sh_quote(&format!("{BACKUP_HELPER_STAGING}/{INVENTORY_REPORT}"))
        )));
        assert!(inventory.contains("CONFIG GET repl-diskless-sync"));
        for script in [&capture, &inventory] {
            assert!(!script.contains("AUTH"));
            assert!(!script.contains("--pass"));
            assert!(script.len() < 64 * 1024);
        }
        let env = auth_environment(&SecretString::from("hunter2"));
        assert!(env.iter().all(|entry| entry.key.ends_with("CLI_AUTH")));
        assert!(INVENTORY_HELPER_SUFFIX.len() <= 16 && VERIFY_HELPER_SUFFIX.len() <= 16);
    }

    #[test]
    fn check_rdb_must_confirm_the_snapshot() {
        let tools = tools(Protocol::Redis).unwrap();
        assert!(
            check_rdb_accepted(
                tools,
                "[offset 0] Checking RDB file\n\\o/ RDB looks OK! \\o/\n"
            )
            .is_ok()
        );
        assert!(check_rdb_accepted(tools, "").is_err());
    }
}
