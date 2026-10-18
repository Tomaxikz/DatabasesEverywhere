//! Parses the MariaDB inventory report and decides whether to capture.

use std::collections::BTreeMap;

use crate::subsystems::backups::strategy::StrategyError;

/// One `key=value` line per statement.
pub(super) const SQL: &str = "SELECT CONCAT('version=', VERSION());
SELECT CONCAT('datadir=', @@datadir);
SELECT CONCAT('innodb_data_home_dir=', IFNULL(@@innodb_data_home_dir, ''));
SELECT CONCAT('innodb_log_group_home_dir=', IFNULL(@@innodb_log_group_home_dir, ''));
SELECT CONCAT('innodb_undo_directory=', IFNULL(@@innodb_undo_directory, ''));
SELECT CONCAT('non_innodb_tables=', COUNT(*)) FROM information_schema.TABLES WHERE TABLE_TYPE = 'BASE TABLE' AND TABLE_SCHEMA NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys') AND ENGINE <> 'InnoDB';
SELECT CONCAT('data_bytes=', IFNULL(SUM(DATA_LENGTH + INDEX_LENGTH), 0)) FROM information_schema.TABLES;";

/// `BACKUP STAGE`, which keeps commits running during the copy, and the
/// current redo format arrived by 10.6.
const MIN_VERSION: (u32, u32) = (10, 6);
const DATA_DIRECTORY: &str = "/var/lib/mysql";
const MAX_VALUE_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Inventory {
    pub server_version: String,
    pub tool_version: String,
    values: BTreeMap<String, String>,
}

pub(super) fn parse_report(report: &str) -> Result<Inventory, String> {
    let mut values = BTreeMap::new();
    for line in report.lines().filter(|line| !line.is_empty()) {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("unexpected inventory line {line:?}"))?;
        if value.len() > MAX_VALUE_LEN || value.chars().any(char::is_control) {
            return Err(format!("inventory value of {key} is unexpected"));
        }
        values.insert(key.to_string(), value.to_string());
    }
    for key in [
        "tool",
        "version",
        "datadir",
        "innodb_data_home_dir",
        "innodb_log_group_home_dir",
        "innodb_undo_directory",
        "non_innodb_tables",
        "data_bytes",
    ] {
        if !values.contains_key(key) {
            return Err(format!("the inventory did not report {key}"));
        }
    }
    let server_version = values["version"].clone();
    // "mariadb-backup based on MariaDB server 12.3.2-MariaDB Linux (x86_64)"
    let tool_version = values["tool"]
        .split_once("server ")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .map(str::to_string)
        .ok_or("mariadb-backup reported no server version")?;
    Ok(Inventory {
        server_version,
        tool_version,
        values,
    })
}

/// `12.3.2-MariaDB-ubu2404` -> `(12, 3, 2)`.
fn numeric(version: &str) -> Option<(u32, u32, u32)> {
    let mut parts = version
        .split(|character: char| !character.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .map(|part| part.parse::<u32>().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

fn in_data_directory(value: &str) -> bool {
    matches!(value, "" | "." | "./") || value.trim_end_matches('/') == DATA_DIRECTORY
}

impl Inventory {
    fn number(&self, key: &str) -> Result<u64, StrategyError> {
        self.values[key]
            .trim()
            .parse()
            .map_err(|_| StrategyError::Failed(format!("inventory {key} is not a number")))
    }

    pub(super) fn decide(&self, native_budget_bytes: u64) -> Result<(), StrategyError> {
        let unsupported = |reason: String| Err(StrategyError::Unsupported(reason));
        let server = numeric(&self.server_version).ok_or_else(|| {
            StrategyError::Failed(format!(
                "server version {} is not parseable",
                self.server_version
            ))
        })?;
        if (server.0, server.1) < MIN_VERSION {
            return unsupported(format!(
                "MariaDB {} predates the certified {}.{} backup stages",
                self.server_version, MIN_VERSION.0, MIN_VERSION.1
            ));
        }
        if numeric(&self.tool_version) != Some(server) {
            return unsupported(format!(
                "mariadb-backup {} does not match server {}",
                self.tool_version, self.server_version
            ));
        }
        if !in_data_directory(&self.values["datadir"]) {
            return unsupported("the server data directory is not the instance volume".to_string());
        }
        for key in [
            "innodb_data_home_dir",
            "innodb_log_group_home_dir",
            "innodb_undo_directory",
        ] {
            if !in_data_directory(&self.values[key]) {
                return unsupported(format!(
                    "{key} points outside the data directory, which the restore does not install"
                ));
            }
        }
        let non_innodb = self.number("non_innodb_tables")?;
        if non_innodb > 0 {
            return unsupported(format!(
                "{non_innodb} user table(s) use a non-InnoDB engine and could only be copied while commits are blocked; convert them to InnoDB or use an offline backup"
            ));
        }
        let estimate = self.number("data_bytes")?;
        if estimate > native_budget_bytes {
            return Err(StrategyError::Failed(format!(
                "tables report {estimate} bytes, more than the {native_budget_bytes}-byte capture budget"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(overrides: &[(&str, &str)]) -> String {
        let mut values = BTreeMap::from([
            (
                "tool",
                "mariadb-backup based on MariaDB server 12.3.2-MariaDB Linux (x86_64)",
            ),
            ("version", "12.3.2-MariaDB-ubu2404"),
            ("datadir", "/var/lib/mysql/"),
            ("innodb_data_home_dir", ""),
            ("innodb_log_group_home_dir", "./"),
            ("innodb_undo_directory", "./"),
            ("non_innodb_tables", "0"),
            ("data_bytes", "1048576"),
        ]);
        for (key, value) in overrides {
            values.insert(key, value);
        }
        values
            .iter()
            .map(|(key, value)| format!("{key}={value}\n"))
            .collect()
    }

    #[test]
    fn default_instances_are_captured() {
        let inventory = parse_report(&report(&[])).unwrap();
        assert_eq!(inventory.tool_version, "12.3.2-MariaDB");
        inventory.decide(1 << 30).unwrap();
        assert!(matches!(
            inventory.decide(1024),
            Err(StrategyError::Failed(_))
        ));
    }

    #[test]
    fn unrestorable_or_freezing_layouts_are_unsupported() {
        for overrides in [
            &[("non_innodb_tables", "1")][..],
            &[("innodb_undo_directory", "/undo")],
            &[("datadir", "/srv/mysql/")],
            &[("version", "10.5.27-MariaDB")],
            &[(
                "tool",
                "mariadb-backup based on MariaDB server 12.2.1-MariaDB Linux (x86_64)",
            )],
        ] {
            let inventory = parse_report(&report(overrides)).unwrap();
            assert!(
                matches!(
                    inventory.decide(1 << 30),
                    Err(StrategyError::Unsupported(_))
                ),
                "{overrides:?}"
            );
        }
    }

    #[test]
    fn incomplete_reports_are_rejected() {
        assert!(parse_report("version=12.3.2-MariaDB\n").is_err());
        assert!(parse_report("garbage\n").is_err());
    }
}
