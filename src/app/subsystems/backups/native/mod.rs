//! Engine-native online backups that need no filesystem snapshots, for
//! instances on XFS/ext4 project quotas, FuseQuota or soft limits.

pub(crate) mod clickhouse;
pub(crate) mod mysql_dump;
pub(crate) mod mysql_inventory;
pub(crate) mod qdrant;
