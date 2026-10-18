//! Certified online backup strategies compiled into this build.

use std::sync::LazyLock;

use super::strategy::{OnlineBackupStrategy, StrategyError};
use crate::{
    databases::{
        engine::OnlineBackup, mariadb::online_backup::MariadbBackupStrategy,
        postgres::online_backup::PostgresBaseBackupStrategy,
        resp::online_backup::RespRdbSnapshotStrategy,
    },
    server::{metadata::InstanceMetadata, placement::DeploymentMode},
};

/// Manifest strategy id of the PostgreSQL `pg_basebackup` strategy.
pub(crate) const POSTGRES_BASE_BACKUP: &str = "postgres.pg_basebackup";
/// Manifest strategy id of the Redis and Valkey RDB snapshot strategy.
pub(crate) const RESP_RDB_SNAPSHOT: &str = "resp.rdb_snapshot";
/// Manifest strategy id of the MariaDB `mariadb-backup` strategy.
pub(crate) const MARIADB_BACKUP: &str = "mariadb.mariadb_backup";

static STRATEGIES: LazyLock<Vec<Box<dyn OnlineBackupStrategy>>> = LazyLock::new(|| {
    vec![
        Box::new(PostgresBaseBackupStrategy),
        Box::new(RespRdbSnapshotStrategy),
        Box::new(MariadbBackupStrategy),
    ]
});

/// Selects the certified strategy for a backup source, or explains why
/// strict online capture is unsupported. Never falls back.
pub(crate) fn strategy_for(
    metadata: &InstanceMetadata,
) -> Result<&'static dyn OnlineBackupStrategy, StrategyError> {
    if metadata.deployment_mode == DeploymentMode::Shared {
        return Err(StrategyError::Unsupported(
            "shared tenants are backed up as tenant logical dumps; whole-runtime online capture is a separate privileged operation".to_string(),
        ));
    }
    let id = match metadata.protocol.engine().online_backup() {
        OnlineBackup::Unavailable { reason } => {
            return Err(StrategyError::Unsupported(reason.to_string()));
        }
        OnlineBackup::PostgresBaseBackup => POSTGRES_BASE_BACKUP,
        OnlineBackup::RespRdbSnapshot => RESP_RDB_SNAPSHOT,
        OnlineBackup::MariadbBackup => MARIADB_BACKUP,
    };
    strategy_by_id(id).ok_or_else(|| {
        StrategyError::Unsupported(format!(
            "the {id} online backup strategy is not available in this build"
        ))
    })
}

/// Looks up a strategy recorded in a manifest or job journal.
pub(crate) fn strategy_by_id(id: &str) -> Option<&'static dyn OnlineBackupStrategy> {
    STRATEGIES
        .iter()
        .map(Box::as_ref)
        .find(|strategy| strategy.id() == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::databases::protocol::Protocol;

    #[test]
    fn engines_without_certified_strategies_fail_clearly() {
        for protocol in [Protocol::Mongodb, Protocol::Mysql] {
            let metadata = crate::server::test_support::metadata("inst_one", protocol);
            let Err(StrategyError::Unsupported(reason)) = strategy_for(&metadata) else {
                panic!("{} must not have an online strategy", protocol.as_str());
            };
            assert!(!reason.is_empty());
        }
    }

    #[test]
    fn shared_tenants_never_select_a_runtime_strategy() {
        let mut metadata = crate::server::test_support::metadata("inst_one", Protocol::Postgres);
        metadata.deployment_mode = DeploymentMode::Shared;
        assert!(matches!(
            strategy_for(&metadata),
            Err(StrategyError::Unsupported(_))
        ));
    }
}
