//! MySQL pre-capture inventory, shared by the volume snapshot and the
//! consistent dump.
//!
//! InnoDB recovers a crash-consistent copy from its redo log and gives
//! `--single-transaction` dumps one snapshot. Non-transactional engines
//! (MyISAM, CSV, ...) do neither, so instances with such user tables are
//! refused rather than captured inconsistently.

use std::time::Duration;

use secrecy::SecretString;

use super::super::strategy::{
    OnlineBackupContext, OwnedResourceRegistrar, StagingArea, StrategyError, take_report,
};
use crate::{
    runtime::docker::{BACKUP_HELPER_STAGING, BackupHelperSocket, BackupHelperSpec, DockerEnv},
    utils::shell::sh_quote,
};

const SOCKET_DIRECTORY: &str = "/var/run/mysqld";
const PASSWORD_ENV: &str = "DBE_MYSQL_ROOT_PASSWORD";
const OPTION_FILE: &str = "/tmp/dbev-backup.cnf";
const REPORT: &str = "inventory.report";
const MAX_REPORT_BYTES: u64 = 16 * 1024;
const TIMEOUT: Duration = Duration::from_secs(120);
const HELPER_SUFFIX: &str = "inventory";
const SQL: &str = "SELECT CONCAT('version=', VERSION()); SELECT CONCAT('non_innodb_tables=', COUNT(*)) FROM information_schema.TABLES WHERE TABLE_TYPE = 'BASE TABLE' AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys') AND ENGINE <> 'InnoDB';";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MysqlInventory {
    pub version: String,
    non_innodb_tables: u64,
}

impl MysqlInventory {
    pub(crate) fn decide(&self) -> Result<(), StrategyError> {
        if self.non_innodb_tables > 0 {
            return Err(StrategyError::Unsupported(format!(
                "{} user table(s) use a non-InnoDB engine, which an online capture cannot hold consistently; convert them to InnoDB or use an offline backup",
                self.non_innodb_tables
            )));
        }
        Ok(())
    }
}

pub(crate) fn parse_report(report: &str) -> Result<MysqlInventory, String> {
    let value = |key: &str| {
        report
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .map(str::trim)
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .ok_or_else(|| format!("the inventory did not report {key}"))
    };
    Ok(MysqlInventory {
        version: value("version")?.to_string(),
        non_innodb_tables: value("non_innodb_tables")?
            .parse()
            .map_err(|_| "non_innodb_tables is not a number".to_string())?,
    })
}

fn script() -> String {
    format!(
        "set -eu\numask 077\nprintf '[client]\\nuser=root\\npassword=%s\\nsocket=%s\\nprotocol=socket\\n' \"${PASSWORD_ENV}\" {socket} >{OPTION_FILE}\nexec >{report}\nmysql --defaults-extra-file={OPTION_FILE} -N -B --init-command={init} -e {sql}\n",
        socket = sh_quote(&format!("{SOCKET_DIRECTORY}/mysqld.sock")),
        report = sh_quote(&format!("{BACKUP_HELPER_STAGING}/{REPORT}")),
        init = sh_quote("SET SESSION max_execution_time=60000"),
        sql = sh_quote(SQL),
    )
}

/// The root credential, refused when it could change the option file.
pub(crate) fn root_password(ctx: &OnlineBackupContext<'_>) -> Result<SecretString, StrategyError> {
    let password = ctx
        .metadata
        .mysql_root_password
        .as_deref()
        .filter(|password| !password.is_empty())
        .ok_or_else(|| {
            StrategyError::Unsupported("the MySQL root credential is missing".to_string())
        })?;
    if !password
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(StrategyError::Unsupported(
            "the MySQL root credential contains characters the backup option file does not accept"
                .to_string(),
        ));
    }
    Ok(SecretString::from(password.to_string()))
}

pub(crate) fn static_gate(ctx: &OnlineBackupContext<'_>) -> Result<(), StrategyError> {
    root_password(ctx).map(|_| ())
}

pub(crate) async fn inventory(
    ctx: &OnlineBackupContext<'_>,
    staging: &StagingArea,
    registrar: &dyn OwnedResourceRegistrar,
) -> Result<MysqlInventory, StrategyError> {
    let spec = BackupHelperSpec {
        name: format!("{}_{HELPER_SUFFIX}", ctx.job.resource_tag()),
        instance_id: ctx.metadata.instance_id.clone(),
        image: ctx.runtime_image().await?,
        socket: Some(BackupHelperSocket {
            source: ctx.paths.sockets.clone(),
            target: SOCKET_DIRECTORY.to_string(),
        }),
        data: None,
        staging_dir: staging.root.clone(),
        staging_read_only: false,
        script: script(),
        environment: vec![DockerEnv::new(PASSWORD_ENV, root_password(ctx)?)],
        timeout: ctx.remaining()?.min(TIMEOUT),
        max_staging_bytes: staging.native_budget_bytes,
    };
    ctx.run_helper(registrar, &spec)
        .await
        .map_err(|error| error.for_tool("mysql inventory"))?;
    let report = take_report(staging.root.join(REPORT), MAX_REPORT_BYTES).await?;
    let inventory = parse_report(&report)
        .map_err(|error| StrategyError::Failed(format!("mysql inventory: {error}")))?;
    inventory.decide()?;
    Ok(inventory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn innodb_only_instances_pass_and_others_are_unsupported() {
        let inventory = parse_report("version=8.4.6\nnon_innodb_tables=0\n").unwrap();
        assert_eq!(inventory.version, "8.4.6");
        inventory.decide().unwrap();
        let mixed = parse_report("version=8.4.6\nnon_innodb_tables=2\n").unwrap();
        assert!(matches!(mixed.decide(), Err(StrategyError::Unsupported(_))));
        assert!(parse_report("version=8.4.6\n").is_err());
        assert!(parse_report("version=8.4.6\nnon_innodb_tables=x\n").is_err());
    }

    #[test]
    fn the_script_keeps_the_password_in_the_environment() {
        let script = script();
        assert!(script.contains(&format!("\"${PASSWORD_ENV}\"")));
        assert!(script.contains(&sh_quote(SQL)));
        assert!(SQL.contains("ENGINE <> 'InnoDB'"));
        assert!(script.contains(&format!(
            "exec >{}",
            sh_quote(&format!("{BACKUP_HELPER_STAGING}/{REPORT}"))
        )));
        assert!(script.len() < 64 * 1024);
        assert!(HELPER_SUFFIX.len() <= 16);
    }
}
