//! Certified online backup strategies compiled into this build.

use std::sync::LazyLock;

use super::strategy::{OnlineBackupStrategy, StrategyError};
use crate::{
    databases::{
        engine::{NativeOnline, OnlineBackup},
        mariadb::online_backup::MariadbBackupStrategy,
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
/// Manifest strategy id of the Btrfs/ZFS volume snapshot strategy.
pub(crate) const FILESYSTEM_SNAPSHOT: &str = "volume.snapshot";
/// Manifest strategy id of the MySQL single-transaction dump strategy.
pub(crate) const MYSQL_CONSISTENT_DUMP: &str = "mysql.consistent_dump";
/// Manifest strategy id of the Qdrant per-collection snapshot strategy.
pub(crate) const QDRANT_COLLECTION_SNAPSHOTS: &str = "qdrant.collection_snapshots";
/// Manifest strategy id of the ClickHouse per-table freeze strategy.
pub(crate) const CLICKHOUSE_FROZEN_PARTS: &str = "clickhouse.frozen_parts";

static STRATEGIES: LazyLock<Vec<Box<dyn OnlineBackupStrategy>>> = LazyLock::new(|| {
    vec![
        Box::new(PostgresBaseBackupStrategy),
        Box::new(RespRdbSnapshotStrategy),
        Box::new(MariadbBackupStrategy),
        Box::new(crate::subsystems::backups::snapshot::VolumeSnapshotStrategy),
        Box::new(crate::subsystems::backups::native::mysql_dump::MysqlDumpStrategy),
        Box::new(crate::subsystems::backups::native::qdrant::QdrantSnapshotStrategy),
        Box::new(crate::subsystems::backups::native::clickhouse::ClickhouseFreezeStrategy),
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
        OnlineBackup::VolumeSnapshot { otherwise } => {
            let snapshots = crate::server::disk::snapshot::SnapshotBackend::for_enforcement_method(
                &metadata.limits.disk_enforcement_method,
            )
            .is_some();
            match otherwise {
                // Without either, the snapshot strategy explains the requirement.
                Some(native) if !snapshots => native_strategy_id(native),
                _ => FILESYSTEM_SNAPSHOT,
            }
        }
    };
    strategy_by_id(id).ok_or_else(|| {
        StrategyError::Unsupported(format!(
            "the {id} online backup strategy is not available in this build"
        ))
    })
}

fn native_strategy_id(native: NativeOnline) -> &'static str {
    match native {
        NativeOnline::MysqlDump => MYSQL_CONSISTENT_DUMP,
        NativeOnline::QdrantSnapshots => QDRANT_COLLECTION_SNAPSHOTS,
        NativeOnline::ClickhouseFreeze => CLICKHOUSE_FROZEN_PARTS,
    }
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
    fn every_engine_has_an_online_strategy() {
        for (protocol, expected) in [
            (Protocol::Postgres, POSTGRES_BASE_BACKUP),
            (Protocol::Redis, RESP_RDB_SNAPSHOT),
            (Protocol::Valkey, RESP_RDB_SNAPSHOT),
            (Protocol::Mariadb, MARIADB_BACKUP),
            (Protocol::Mysql, MYSQL_CONSISTENT_DUMP),
            (Protocol::Mongodb, FILESYSTEM_SNAPSHOT),
            (Protocol::Clickhouse, CLICKHOUSE_FROZEN_PARTS),
            (Protocol::Qdrant, QDRANT_COLLECTION_SNAPSHOTS),
        ] {
            let metadata = crate::server::test_support::metadata("inst_one", protocol);
            let Ok(strategy) = strategy_for(&metadata) else {
                panic!("{} has no online strategy", protocol.as_str());
            };
            assert_eq!(strategy.id(), expected, "{protocol}");
        }
    }

    #[test]
    fn snapshot_capable_volumes_prefer_the_volume_snapshot() {
        let mut metadata = crate::server::test_support::metadata("inst_one", Protocol::Mysql);
        for (method, expected) in [
            ("host_btrfs_qgroup", FILESYSTEM_SNAPSHOT),
            ("host_zfs_refquota", FILESYSTEM_SNAPSHOT),
            ("host_xfs_project", MYSQL_CONSISTENT_DUMP),
            ("fuse_quota", MYSQL_CONSISTENT_DUMP),
        ] {
            metadata.limits.disk_enforcement_method = method.to_string();
            assert_eq!(strategy_for(&metadata).unwrap().id(), expected, "{method}");
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
