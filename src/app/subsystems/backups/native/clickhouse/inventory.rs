//! Decides which ClickHouse tables a per-table freeze can capture.
//!
//! MergeTree tables on the default disk are frozen. Engines that keep no
//! local data (views, dictionaries, integrations) need only their metadata.
//! Anything else with files of its own (Log family, Set, Join, Buffer, ...)
//! and every database engine other than Atomic is refused: a live copy of
//! those files would not be a consistent point.

use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

use crate::subsystems::backups::strategy::StrategyError;

const DATA_DIRECTORY: &str = "/var/lib/clickhouse/";
const SYSTEM_DATABASES: [&str; 3] = ["system", "information_schema", "INFORMATION_SCHEMA"];
const DATABASE_ENGINES: [&str; 2] = ["Atomic", "Memory"];
/// Engines whose rows live elsewhere (another table, a remote system or
/// nowhere); their metadata is the whole backup.
const METADATA_ONLY_ENGINES: [&str; 17] = [
    "View",
    "MaterializedView",
    "Dictionary",
    "Merge",
    "Null",
    "URL",
    "S3",
    "MySQL",
    "PostgreSQL",
    "MongoDB",
    "Redis",
    "SQLite",
    "Kafka",
    "GenerateRandom",
    "Executable",
    "ExecutablePool",
    "Loop",
];

pub(super) const DATABASES_SQL: &str =
    "SELECT name, engine FROM system.databases FORMAT JSONEachRow";
pub(super) const TABLES_SQL: &str = "SELECT database, name, engine, toString(uuid) AS uuid, data_paths FROM system.tables WHERE is_temporary = 0 FORMAT JSONEachRow";

#[derive(Debug, Clone, Deserialize)]
pub(super) struct DatabaseRow {
    pub name: String,
    pub engine: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct TableRow {
    pub database: String,
    pub name: String,
    pub engine: String,
    pub uuid: String,
    pub data_paths: Vec<String>,
}

/// A MergeTree table to freeze and its data directory, `store/<xyz>/<uuid>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FrozenTable {
    pub database: String,
    pub name: String,
    pub directory: PathBuf,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Plan {
    pub frozen: Vec<FrozenTable>,
    pub memory_tables: usize,
    pub system_merge_trees: usize,
}

fn is_merge_tree(engine: &str) -> bool {
    engine.ends_with("MergeTree")
        && !engine.starts_with("Replicated")
        && !engine.starts_with("Shared")
}

pub(super) fn plan(databases: &[DatabaseRow], tables: &[TableRow]) -> Result<Plan, StrategyError> {
    for database in databases {
        if !SYSTEM_DATABASES.contains(&database.name.as_str())
            && !DATABASE_ENGINES.contains(&database.engine.as_str())
        {
            return Err(StrategyError::Unsupported(format!(
                "database {} uses the {} engine; the online ClickHouse backup covers Atomic databases, so use an offline backup",
                database.name, database.engine
            )));
        }
    }
    let mut plan = Plan::default();
    for table in tables {
        let system = SYSTEM_DATABASES.contains(&table.database.as_str());
        if is_merge_tree(&table.engine) {
            if system {
                plan.system_merge_trees += 1;
                continue;
            }
            plan.frozen.push(FrozenTable {
                database: table.database.clone(),
                name: table.name.clone(),
                directory: table_directory(table)?,
            });
        } else if system {
            continue;
        } else if table.engine == "Memory" {
            plan.memory_tables += 1;
        } else if !METADATA_ONLY_ENGINES.contains(&table.engine.as_str()) {
            return Err(StrategyError::Unsupported(format!(
                "table {}.{} uses the {} engine, whose files a per-table freeze does not cover; use an offline backup",
                table.database, table.name, table.engine
            )));
        }
    }
    Ok(plan)
}

/// The table's single data path on the default disk, relative to the data
/// directory: exactly `store/<first three uuid characters>/<uuid>`.
fn table_directory(table: &TableRow) -> Result<PathBuf, StrategyError> {
    let outside = || {
        StrategyError::Unsupported(format!(
            "table {}.{} keeps data outside the default disk's store; the online ClickHouse backup covers single-disk tables",
            table.database, table.name
        ))
    };
    let [path] = table.data_paths.as_slice() else {
        return Err(outside());
    };
    let relative = path.strip_prefix(DATA_DIRECTORY).ok_or_else(outside)?;
    let relative = Path::new(relative.trim_end_matches('/'));
    let parts = relative
        .components()
        .map(|component| match component {
            Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(outside)?;
    let uuid_ok = uuid::Uuid::try_parse(&table.uuid).is_ok_and(|uuid| !uuid.is_nil());
    match parts.as_slice() {
        ["store", prefix, uuid]
            if uuid_ok && *uuid == table.uuid && table.uuid.get(..3) == Some(*prefix) =>
        {
            Ok(relative.to_path_buf())
        }
        _ => Err(outside()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "4b8f2c1e-9a7d-4f3b-8c6e-2d1a0f9e8b7c";

    fn database(name: &str, engine: &str) -> DatabaseRow {
        DatabaseRow {
            name: name.to_string(),
            engine: engine.to_string(),
        }
    }

    fn table(database: &str, name: &str, engine: &str) -> TableRow {
        TableRow {
            database: database.to_string(),
            name: name.to_string(),
            engine: engine.to_string(),
            uuid: UUID.to_string(),
            data_paths: vec![format!("/var/lib/clickhouse/store/4b8/{UUID}/")],
        }
    }

    #[test]
    fn merge_trees_are_frozen_and_metadata_engines_ride_along() {
        let plan = plan(
            &[database("default", "Atomic"), database("system", "Atomic")],
            &[
                table("default", "events", "ReplacingMergeTree"),
                table("default", "events_view", "View"),
                table("default", "scratch", "Memory"),
                table("system", "query_log", "MergeTree"),
                table("system", "one", "SystemOne"),
            ],
        )
        .unwrap();
        assert_eq!(
            plan.frozen,
            vec![FrozenTable {
                database: "default".to_string(),
                name: "events".to_string(),
                directory: PathBuf::from(format!("store/4b8/{UUID}")),
            }]
        );
        assert_eq!((plan.memory_tables, plan.system_merge_trees), (1, 1));
    }

    #[test]
    fn engines_with_their_own_files_are_refused() {
        for engine in [
            "TinyLog",
            "Log",
            "StripeLog",
            "Set",
            "Join",
            "Buffer",
            "ReplicatedMergeTree",
        ] {
            let refused = plan(
                &[database("default", "Atomic")],
                &[table("default", "t", engine)],
            );
            assert!(
                matches!(refused, Err(StrategyError::Unsupported(_))),
                "{engine}"
            );
        }
        let ordinary = plan(&[database("legacy", "Ordinary")], &[]);
        assert!(matches!(ordinary, Err(StrategyError::Unsupported(_))));
    }

    #[test]
    fn data_must_sit_in_the_default_store() {
        let mut other_disk = table("default", "t", "MergeTree");
        other_disk.data_paths = vec![format!("/mnt/s3cache/store/4b8/{UUID}/")];
        let mut two_disks = table("default", "t", "MergeTree");
        two_disks
            .data_paths
            .push(format!("/var/lib/clickhouse/store/4b8/{UUID}/"));
        let mut escaping = table("default", "t", "MergeTree");
        escaping.data_paths = vec![format!("/var/lib/clickhouse/store/4b8/../{UUID}/")];
        let mut mismatched = table("default", "t", "MergeTree");
        mismatched.data_paths = vec![format!("/var/lib/clickhouse/store/abc/{UUID}/")];
        for row in [other_disk, two_disks, escaping, mismatched] {
            assert!(table_directory(&row).is_err(), "{:?}", row.data_paths);
        }
        assert!(table_directory(&table("default", "t", "MergeTree")).is_ok());
    }
}
