//! Pure preflight decisions. The shell report is parsed here; nothing in this
//! module contacts a database.

use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};

use super::command::{
    DATA_MOUNT, MAX_INVENTORY_DATABASES, PREFLIGHT_HEADER, REPLICATION_HBA_LINE,
    REPLICATION_OWNERSHIP_PREFLIGHT_KEY, REPLICATION_ROLE, REPLICATION_ROLE_STATE,
    ReplicationRoleOwnership, foreign_replication_role_diagnostic,
    parse_replication_role_ownership,
};
use crate::server::placement::DeploymentMode;

pub(crate) const HEADROOM_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EXCLUSION_BYTES: usize = 400;
const MAX_EXCLUSIONS: usize = 48;

#[derive(Debug)]
pub(crate) enum Gate {
    Unsupported(String),
    Failed(String),
}

impl Gate {
    pub(crate) fn into_strategy(self) -> crate::subsystems::backups::strategy::StrategyError {
        match self {
            Self::Unsupported(reason) => {
                crate::subsystems::backups::strategy::StrategyError::Unsupported(reason)
            }
            Self::Failed(reason) => {
                crate::subsystems::backups::strategy::StrategyError::Failed(reason)
            }
        }
    }
}

/// Free space on the disk-backed staging filesystem and the reserved native
/// budget. The helper writes the only copy there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DiskSpace {
    pub staging_available: u64,
    pub budget_bytes: u64,
}

#[derive(Debug)]
pub(crate) struct CapturePlan {
    pub server_version: String,
    pub restore_target: PathBuf,
    pub tool_basebackup: String,
    pub tool_verifybackup: String,
    pub exclusions: Vec<String>,
    pub database_bytes: u64,
    pub wal_bytes: u64,
}

impl CapturePlan {
    pub(crate) fn estimate(&self) -> Result<u64, String> {
        capture_estimate(self.database_bytes, self.wal_bytes)
            .ok_or_else(|| "capture estimate overflowed".to_string())
    }
}

pub(crate) fn capture_estimate(database_bytes: u64, wal_bytes: u64) -> Option<u64> {
    let headroom = wal_bytes.max(HEADROOM_BYTES);
    database_bytes
        .checked_add(wal_bytes)?
        .checked_add(headroom)?
        .checked_add(HEADROOM_BYTES)
}

/// The budget is what restore extracts, so an estimate above it would
/// produce a backup the existing restore path refuses.
pub(crate) fn space_allows(estimate: u64, space: &DiskSpace) -> Result<(), String> {
    if space.budget_bytes < estimate {
        return Err(format!(
            "staging budget (what restore extracts) is {} bytes and the capture estimate is {estimate} bytes",
            space.budget_bytes
        ));
    }
    if space.staging_available < estimate {
        return Err(format!(
            "staging filesystem has {} bytes free and the capture estimate is {estimate} bytes",
            space.staging_available
        ));
    }
    Ok(())
}

pub(crate) fn pgdata_relative_path(pgdata: &str) -> Option<PathBuf> {
    let trimmed = pgdata.trim().trim_end_matches('/');
    let relative = Path::new(trimmed).strip_prefix(DATA_MOUNT).ok()?;
    let safe = relative.components().count() > 0
        && relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
    safe.then(|| relative.to_path_buf())
}

pub(crate) fn tool_major(line: &str) -> Option<u32> {
    let version = line
        .split("(PostgreSQL)")
        .nth(1)?
        .split_whitespace()
        .next()?;
    version.split('.').next()?.parse().ok()
}

pub(crate) fn parse_report(stdout: &str) -> Result<PreflightReport, String> {
    let mut lines = stdout.lines().map(|line| line.trim_end_matches('\r'));
    let header = lines
        .next()
        .ok_or_else(|| "preflight report is empty".to_string())?;
    if header != PREFLIGHT_HEADER {
        return Err("preflight report has the wrong header".to_string());
    }
    let mut singleton = BTreeMap::<String, String>::new();
    let mut repeated = BTreeMap::<String, Vec<String>>::new();
    let mut last_key = String::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.chars().any(char::is_control) {
            return Err("preflight report contains a control character".to_string());
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("preflight report line has no key: {line}"))?;
        if !KEY_SINGLETON.contains(&key) && !KEY_REPEATED.contains(&key) {
            return Err(format!("preflight report has unknown key {key}"));
        }
        last_key = key.to_string();
        if KEY_SINGLETON.contains(&key) {
            if singleton
                .insert(key.to_string(), value.to_string())
                .is_some()
            {
                return Err(format!("preflight report repeats {key}"));
            }
        } else {
            repeated
                .entry(key.to_string())
                .or_default()
                .push(value.to_string());
        }
    }
    // The ownership probe runs after the inventory script, so it is last.
    if last_key != REPLICATION_OWNERSHIP_PREFLIGHT_KEY {
        return Err("preflight report did not finish".to_string());
    }
    let require = |key: &str| -> Result<String, String> {
        singleton
            .get(key)
            .cloned()
            .filter(|value| !value.is_empty() || key.starts_with("tool_"))
            .ok_or_else(|| format!("preflight report is missing {key}"))
    };
    let number = |key: &str| -> Result<u64, String> {
        require(key)?
            .parse()
            .map_err(|_| format!("preflight report has a bad {key}"))
    };
    let (connectable_total, connectable_safe) = split_pair(&require("connectable")?)
        .ok_or_else(|| "preflight report has a bad connectable count".to_string())?;
    Ok(PreflightReport {
        server_version: require("server_version")?,
        server_version_num: number("server_version_num")?
            .try_into()
            .map_err(|_| "server_version_num does not fit".to_string())?,
        data_directory: require("data_directory")?,
        config_file: require("config_file")?,
        hba_file: require("hba_file")?,
        ident_file: require("ident_file")?,
        database_bytes: number("database_bytes")?,
        wal_bytes: number("wal_bytes")?,
        hba_errors: number("hba_errors")?,
        hba: repeated.remove("hba").unwrap_or_default(),
        role: require("role")?,
        role_ownership: parse_replication_role_ownership(&require(
            REPLICATION_OWNERSHIP_PREFLIGHT_KEY,
        )?)
        .ok_or_else(|| "preflight report has a bad role ownership".to_string())?,
        tablespaces: repeated.remove("tablespace").unwrap_or_default(),
        unlogged: repeated.remove("unlogged").unwrap_or_default(),
        extensions: repeated.remove("extension").unwrap_or_default(),
        auth: require("auth")?,
        too_many_databases: require("too_many_databases")?,
        connectable_total,
        connectable_safe,
        inventory_blocked: repeated
            .remove("inventory_blocked")
            .unwrap_or_default()
            .iter()
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| "preflight report has a bad inventory_blocked count".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?,
        tool_basebackup: singleton
            .get("tool_basebackup")
            .cloned()
            .ok_or_else(|| "preflight report is missing tool_basebackup".to_string())?,
        tool_verifybackup: singleton
            .get("tool_verifybackup")
            .cloned()
            .ok_or_else(|| "preflight report is missing tool_verifybackup".to_string())?,
    })
}

#[derive(Debug)]
pub(crate) struct PreflightReport {
    server_version: String,
    server_version_num: u32,
    data_directory: String,
    config_file: String,
    hba_file: String,
    ident_file: String,
    database_bytes: u64,
    wal_bytes: u64,
    hba_errors: u64,
    hba: Vec<String>,
    role: String,
    role_ownership: ReplicationRoleOwnership,
    tablespaces: Vec<String>,
    unlogged: Vec<String>,
    extensions: Vec<String>,
    auth: String,
    too_many_databases: String,
    connectable_total: u64,
    connectable_safe: u64,
    inventory_blocked: Vec<u64>,
    tool_basebackup: String,
    tool_verifybackup: String,
}

pub(crate) fn decide(
    report: &PreflightReport,
    deployment: DeploymentMode,
    space: Option<&DiskSpace>,
) -> Result<CapturePlan, Gate> {
    if deployment == DeploymentMode::Shared {
        return Err(Gate::Unsupported(
            "shared tenants keep their logical dump; physical online backup is dedicated-only"
                .to_string(),
        ));
    }
    let major = report.server_version_num / 10_000;
    if !(14..=18).contains(&major) {
        return Err(Gate::Unsupported(format!(
            "PostgreSQL {major} is outside the certified 14-18 online backup range"
        )));
    }
    match_tool("pg_basebackup", &report.tool_basebackup, major)?;
    match_tool("pg_verifybackup", &report.tool_verifybackup, major)?;
    let restore_target = pgdata_relative_path(&report.data_directory).ok_or_else(|| {
        Gate::Unsupported(format!(
            "data directory {} is not a safe path under {DATA_MOUNT}",
            report.data_directory
        ))
    })?;
    if let Some(tablespace) = report.tablespaces.first() {
        let name = tablespace.split('|').next().unwrap_or(tablespace);
        return Err(Gate::Unsupported(format!(
            "tablespace {name} is not supported; online backup requires only pg_default and pg_global"
        )));
    }
    if report.hba_errors > 0 {
        return Err(Gate::Unsupported(
            "pg_hba.conf has parse errors".to_string(),
        ));
    }
    // Checked before HBA and privileges: hardening leaves a tenant's own
    // role of this name untouched and keeps serving, and only the ownership
    // marker explains why capture is then unavailable.
    match report.role_ownership {
        ReplicationRoleOwnership::Owned | ReplicationRoleOwnership::Missing => {}
        ReplicationRoleOwnership::Foreign => {
            return Err(Gate::Unsupported(foreign_replication_role_diagnostic()));
        }
        ReplicationRoleOwnership::Candidate => {
            return Err(Gate::Unsupported(format!(
                "replication role {REPLICATION_ROLE} is not yet marked as managed; the next authentication hardening pass adopts it"
            )));
        }
    }
    let expected_hba = expected_hba_record();
    if report.hba.len() != 1 || report.hba[0] != expected_hba {
        return Err(Gate::Unsupported(
            "replication authentication is not the single local dbe_replication scram-sha-256 rule"
                .to_string(),
        ));
    }
    if report.role == "missing" {
        return Err(Gate::Unsupported(format!(
            "replication role {REPLICATION_ROLE} is missing; the next authentication hardening pass provisions it on the local socket"
        )));
    }
    if report.role != REPLICATION_ROLE_STATE {
        return Err(Gate::Unsupported(format!(
            "replication role {REPLICATION_ROLE} has privileges {}; expected {REPLICATION_ROLE_STATE}",
            report.role
        )));
    }
    if report.auth != "ok" {
        return Err(Gate::Unsupported(format!(
            "replication role {REPLICATION_ROLE} rejected the local socket credential"
        )));
    }
    inventory_gate(report)?;
    let exclusions = exclusions(report).map_err(Gate::Failed)?;
    if let Some(space) = space {
        let estimate = capture_estimate(report.database_bytes, report.wal_bytes)
            .ok_or_else(|| Gate::Failed("capture estimate overflowed".to_string()))?;
        space_allows(estimate, space).map_err(Gate::Failed)?;
    }
    let server_version = bounded_version(&report.server_version)
        .map_err(|error| Gate::Failed(format!("server version: {error}")))?;
    Ok(CapturePlan {
        server_version,
        restore_target,
        tool_basebackup: bounded_tool(&report.tool_basebackup).map_err(Gate::Failed)?,
        tool_verifybackup: bounded_tool(&report.tool_verifybackup).map_err(Gate::Failed)?,
        exclusions,
        database_bytes: report.database_bytes,
        wal_bytes: report.wal_bytes,
    })
}

pub(crate) fn sample_space(staging: &Path, budget_bytes: u64) -> Result<DiskSpace, String> {
    Ok(DiskSpace {
        staging_available: available_bytes(staging)?,
        budget_bytes,
    })
}

fn available_bytes(path: &Path) -> Result<u64, String> {
    let stats = rustix::fs::statvfs(path)
        .map_err(|error| format!("statvfs {}: {error}", path.display()))?;
    let block = if stats.f_frsize == 0 {
        stats.f_bsize
    } else {
        stats.f_frsize
    };
    stats
        .f_bavail
        .checked_mul(block)
        .ok_or_else(|| "disk available space overflowed".to_string())
}

fn inventory_gate(report: &PreflightReport) -> Result<(), Gate> {
    if report.too_many_databases == "blocked" || report.connectable_total != report.connectable_safe
    {
        return Err(Gate::Failed(
            "refusing to omit databases whose names cannot be recorded safely".to_string(),
        ));
    }
    if report.too_many_databases == "1" || report.connectable_total > MAX_INVENTORY_DATABASES {
        return Err(Gate::Failed(format!(
            "refusing to omit unlogged relations and extensions across more than {MAX_INVENTORY_DATABASES} connectable databases"
        )));
    }
    if report.too_many_databases != "0" {
        return Err(Gate::Failed(
            "preflight inventory counts disagree".to_string(),
        ));
    }
    if report.inventory_blocked.len() as u64 != report.connectable_safe {
        return Err(Gate::Failed(
            "preflight did not finish the per-database inventory".to_string(),
        ));
    }
    if report.inventory_blocked.iter().any(|count| *count > 0) {
        return Err(Gate::Failed(
            "refusing to omit unlogged relations or extensions whose names cannot be recorded"
                .to_string(),
        ));
    }
    Ok(())
}

fn exclusions(report: &PreflightReport) -> Result<Vec<String>, String> {
    let unlogged = report
        .unlogged
        .iter()
        .map(|row| named_row(row, 2, "unlogged relation"))
        .collect::<Result<Vec<_>, _>>()?;
    let extensions = report
        .extensions
        .iter()
        .map(|row| named_row(row, 3, "extension"))
        .collect::<Result<Vec<_>, _>>()?;
    let mut lines = vec![
        "unlogged and temporary relation contents are reset when the backup is recovered"
            .to_string(),
        bounded_list("unlogged relations at capture", &unlogged)?,
        "extension libraries are not stored in the backup; the restored image must provide them. Catalog definitions are included"
            .to_string(),
        bounded_list("extensions at capture", &extensions)?,
        configuration_line(report)?,
        "files outside PGDATA are not included".to_string(),
        "container command settings listen_addresses and password_encryption are not part of the backup"
            .to_string(),
        "commits not flushed by the stop LSN are outside this recovery point".to_string(),
        "replication slot state is not preserved".to_string(),
        "server statistics are not preserved".to_string(),
        "temporary tables are not preserved".to_string(),
    ];
    if lines.len() > MAX_EXCLUSIONS {
        return Err("exclusion record is too long".to_string());
    }
    for line in &lines {
        if line.len() > MAX_EXCLUSION_BYTES || line.chars().any(char::is_control) {
            return Err("exclusion record is not safe to publish".to_string());
        }
    }
    lines.sort();
    lines.dedup();
    Ok(lines)
}

fn configuration_line(report: &PreflightReport) -> Result<String, String> {
    let classify = |label: &str, path: &str| {
        if path_inside(&report.data_directory, path) {
            format!("{label} is inside PGDATA and included")
        } else {
            format!("{label} is outside PGDATA and is not included")
        }
    };
    let line = format!(
        "configuration: {}, {}, {}, postgresql.auto.conf is included when it is inside PGDATA",
        classify("config_file", &report.config_file),
        classify("hba_file", &report.hba_file),
        classify("ident_file", &report.ident_file),
    );
    if line.len() <= MAX_EXCLUSION_BYTES {
        return Ok(line);
    }
    Ok(
        "configuration files inside PGDATA are included; configuration files outside PGDATA are not included; postgresql.auto.conf is included when it is inside PGDATA"
            .to_string(),
    )
}

fn named_row(row: &str, parts: usize, kind: &str) -> Result<String, String> {
    let fields: Vec<&str> = row.split('|').collect();
    if fields.len() != parts || fields.iter().any(|field| field.is_empty()) {
        return Err(format!("preflight {kind} record is malformed"));
    }
    if fields
        .iter()
        .any(|field| field.chars().any(char::is_control))
    {
        return Err(format!("preflight {kind} record is not safe to publish"));
    }
    Ok(fields.join(" "))
}

fn bounded_list(prefix: &str, items: &[String]) -> Result<String, String> {
    if items.is_empty() {
        return Ok(format!("{prefix}: none"));
    }
    let mut shown = Vec::new();
    let mut used = prefix.len() + 32;
    for item in items {
        if item.len() > 180 || item.chars().any(char::is_control) {
            return Err(format!("{prefix} entry is not safe to publish"));
        }
        if shown.len() == 12 || used + item.len() + 2 > MAX_EXCLUSION_BYTES - 24 {
            break;
        }
        used += item.len() + 2;
        shown.push(item.as_str());
    }
    if shown.len() == items.len() {
        Ok(format!("{prefix}: {}: {}", items.len(), shown.join(", ")))
    } else {
        Ok(format!(
            "{prefix}: {} (showing {}): {}",
            items.len(),
            shown.len(),
            shown.join(", ")
        ))
    }
}

fn path_inside(root: &str, path: &str) -> bool {
    let root = root.trim_end_matches('/');
    path == root || path.starts_with(&format!("{root}/"))
}

fn match_tool(name: &str, line: &str, server_major: u32) -> Result<(), Gate> {
    if line.is_empty() {
        return Err(Gate::Unsupported(format!(
            "{name} is not available in the running image"
        )));
    }
    let Some(tool_major) = tool_major(line) else {
        return Err(Gate::Unsupported(format!(
            "{name} did not report a PostgreSQL version"
        )));
    };
    if tool_major != server_major {
        return Err(Gate::Unsupported(format!(
            "{name} major {tool_major} does not match the server major {server_major}"
        )));
    }
    Ok(())
}

fn expected_hba_record() -> String {
    let user = REPLICATION_HBA_LINE
        .split_whitespace()
        .nth(2)
        .unwrap_or(REPLICATION_ROLE);
    format!("local|replication|{user}|scram-sha-256")
}

fn bounded_version(value: &str) -> Result<String, String> {
    if bounded_text(value) {
        Ok(value.to_string())
    } else {
        Err("value exceeds the manifest text limit".to_string())
    }
}

fn bounded_tool(line: &str) -> Result<String, String> {
    if bounded_text(line) {
        return Ok(line.to_string());
    }
    let version = line
        .split("(PostgreSQL)")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or("");
    if bounded_text(version) && !version.is_empty() {
        Ok(version.to_string())
    } else {
        Err("tool version exceeds the manifest text limit".to_string())
    }
}

fn bounded_text(value: &str) -> bool {
    value.len() <= 512 && !value.chars().any(char::is_control)
}

fn split_pair(value: &str) -> Option<(u64, u64)> {
    let (left, right) = value.split_once('|')?;
    Some((left.parse().ok()?, right.parse().ok()?))
}

const KEY_SINGLETON: &[&str] = &[
    "tool_basebackup",
    "tool_verifybackup",
    "server_version",
    "server_version_num",
    "data_directory",
    "config_file",
    "hba_file",
    "ident_file",
    "database_bytes",
    "wal_bytes",
    "hba_errors",
    "role",
    "auth",
    "too_many_databases",
    "connectable",
    REPLICATION_OWNERSHIP_PREFLIGHT_KEY,
];

const KEY_REPEATED: &[&str] = &[
    "hba",
    "tablespace",
    "unlogged",
    "extension",
    "inventory_blocked",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_text() -> String {
        [
            "DBEV_PG_PREFLIGHT_V1",
            "tool_basebackup=pg_basebackup (PostgreSQL) 18.4",
            "tool_verifybackup=pg_verifybackup (PostgreSQL) 18.4",
            "server_version=18.4",
            "server_version_num=180004",
            "data_directory=/var/lib/postgresql/18/docker",
            "config_file=/var/lib/postgresql/18/docker/postgresql.conf",
            "hba_file=/var/lib/postgresql/18/docker/pg_hba.conf",
            "ident_file=/var/lib/postgresql/18/docker/pg_ident.conf",
            "database_bytes=1000",
            "wal_bytes=2000",
            "hba_errors=0",
            "hba=local|replication|dbe_replication|scram-sha-256",
            "role=1:1:0:0:0:0:0",
            "too_many_databases=0",
            "connectable=1|1",
            "inventory_blocked=0",
            "auth=ok",
            "role_ownership=owned",
        ]
        .join("\n")
    }

    fn decide_text(text: &str, space: Option<&DiskSpace>) -> Result<CapturePlan, Gate> {
        let report = parse_report(text).unwrap();
        decide(&report, DeploymentMode::Dedicated, space)
    }

    fn estimate_of_ready() -> u64 {
        capture_estimate(1000, 2000).unwrap()
    }

    #[test]
    fn pgdata_must_stay_under_the_data_mount() {
        assert_eq!(
            pgdata_relative_path("/var/lib/postgresql/18/docker"),
            Some(PathBuf::from("18/docker"))
        );
        assert_eq!(
            pgdata_relative_path("/var/lib/postgresql/data\n"),
            Some(PathBuf::from("data"))
        );
        assert_eq!(pgdata_relative_path("/var/lib/postgresql"), None);
        assert_eq!(pgdata_relative_path("/var/lib/postgresql/../etc"), None);
        assert_eq!(pgdata_relative_path("/srv/pgdata"), None);
    }

    #[test]
    fn certified_majors_pass_and_neighbors_do_not() {
        let plan = decide_text(&ready_text(), None).unwrap();
        assert_eq!(plan.restore_target, PathBuf::from("18/docker"));
        assert_eq!(plan.server_version, "18.4");
        let mut text = ready_text().replace("180004", "140020");
        text = text.replace("(PostgreSQL) 18.4", "(PostgreSQL) 14.19");
        text = text.replace("server_version=18.4", "server_version=14.19");
        assert!(decide_text(&text, None).is_ok());
        for (num, major) in [("130000", "13"), ("190000", "19")] {
            let text = ready_text().replace("180004", num);
            let Err(Gate::Unsupported(reason)) = decide_text(&text, None) else {
                panic!("major {major} must be rejected");
            };
            assert!(reason.contains(major), "{reason}");
        }
    }

    #[test]
    fn tool_availability_and_major_must_match_the_server() {
        let missing = ready_text().replace(
            "tool_basebackup=pg_basebackup (PostgreSQL) 18.4",
            "tool_basebackup=",
        );
        assert!(matches!(
            decide_text(&missing, None),
            Err(Gate::Unsupported(reason)) if reason.contains("pg_basebackup is not available")
        ));
        let drifted = ready_text().replace(
            "tool_verifybackup=pg_verifybackup (PostgreSQL) 18.4",
            "tool_verifybackup=pg_verifybackup (PostgreSQL) 17.6",
        );
        assert!(matches!(
            decide_text(&drifted, None),
            Err(Gate::Unsupported(reason)) if reason.contains("does not match")
        ));
        assert_eq!(
            tool_major("pg_basebackup (PostgreSQL) 16.1 (Debian 16.1-1)"),
            Some(16)
        );
    }

    #[test]
    fn layouts_roles_and_hba_rules_fail_closed() {
        assert!(matches!(
            decide(
                &parse_report(&ready_text()).unwrap(),
                DeploymentMode::Shared,
                None
            ),
            Err(Gate::Unsupported(reason)) if reason.contains("shared tenants")
        ));
        let outside = ready_text().replace(
            "data_directory=/var/lib/postgresql/18/docker",
            "data_directory=/srv/pgdata",
        );
        assert!(matches!(
            decide_text(&outside, None),
            Err(Gate::Unsupported(_))
        ));
        let escaped = ready_text().replace(
            "data_directory=/var/lib/postgresql/18/docker",
            "data_directory=/var/lib/postgresql/../etc",
        );
        assert!(matches!(
            decide_text(&escaped, None),
            Err(Gate::Unsupported(_))
        ));
        let user_space = ready_text().replace(
            "role=1:1:0:0:0:0:0",
            "tablespace=app|/var/lib/postgresql/18/docker/extra\nrole=1:1:0:0:0:0:0",
        );
        assert!(matches!(
            decide_text(&user_space, None),
            Err(Gate::Unsupported(reason)) if reason.contains("tablespace app")
        ));
        let outside_space = ready_text().replace(
            "role=1:1:0:0:0:0:0",
            "tablespace=cold|/mnt/cold\nrole=1:1:0:0:0:0:0",
        );
        assert!(matches!(
            decide_text(&outside_space, None),
            Err(Gate::Unsupported(_))
        ));
        let missing_role = ready_text().replace("role=1:1:0:0:0:0:0", "role=missing");
        assert!(matches!(
            decide_text(&missing_role, None),
            Err(Gate::Unsupported(reason)) if reason.contains("missing")
        ));
        let drifted = ready_text().replace("role=1:1:0:0:0:0:0", "role=1:1:1:0:0:0:1");
        assert!(matches!(
            decide_text(&drifted, None),
            Err(Gate::Unsupported(reason)) if reason.contains("privileges")
        ));
        let host_rule = ready_text().replace(
            "hba=local|replication|dbe_replication|scram-sha-256",
            "hba=host|replication|dbe_replication|scram-sha-256",
        );
        assert!(matches!(
            decide_text(&host_rule, None),
            Err(Gate::Unsupported(_))
        ));
        let no_rule =
            ready_text().replace("hba=local|replication|dbe_replication|scram-sha-256\n", "");
        assert!(matches!(
            decide_text(&no_rule, None),
            Err(Gate::Unsupported(_))
        ));
        let denied = ready_text().replace("auth=ok", "auth=failed");
        assert!(matches!(
            decide_text(&denied, None),
            Err(Gate::Unsupported(reason)) if reason.contains("rejected")
        ));
    }

    #[test]
    fn a_foreign_replication_role_disables_capture_with_its_cause() {
        // Even with the expected rule and privileges, an unmarked tenant
        // role is never used: hardening did not provision it.
        let foreign = ready_text().replace("role_ownership=owned", "role_ownership=foreign");
        assert!(matches!(
            decide_text(&foreign, None),
            Err(Gate::Unsupported(reason)) if reason == foreign_replication_role_diagnostic()
        ));
        // The diagnostic wins over the HBA rule a foreign role never received.
        let unprovisioned =
            foreign.replace("hba=local|replication|dbe_replication|scram-sha-256\n", "");
        assert!(matches!(
            decide_text(&unprovisioned, None),
            Err(Gate::Unsupported(reason)) if reason == foreign_replication_role_diagnostic()
        ));
        let candidate = ready_text().replace("role_ownership=owned", "role_ownership=candidate");
        assert!(matches!(
            decide_text(&candidate, None),
            Err(Gate::Unsupported(reason)) if reason.contains("not yet marked")
        ));
        let missing = ready_text()
            .replace("role=1:1:0:0:0:0:0", "role=missing")
            .replace("role_ownership=owned", "role_ownership=missing");
        assert!(matches!(
            decide_text(&missing, None),
            Err(Gate::Unsupported(reason)) if reason.contains("is missing")
        ));
    }

    #[test]
    fn space_requires_one_copy_within_the_restore_budget() {
        let estimate = estimate_of_ready();
        let enough = DiskSpace {
            staging_available: estimate,
            budget_bytes: estimate,
        };
        assert!(decide_text(&ready_text(), Some(&enough)).is_ok());
        let tight_budget = DiskSpace {
            budget_bytes: estimate - 1,
            ..enough
        };
        assert!(matches!(
            decide_text(&ready_text(), Some(&tight_budget)),
            Err(Gate::Failed(reason)) if reason.contains("restore extracts")
        ));
        let staging_short = DiskSpace {
            staging_available: estimate - 1,
            ..enough
        };
        assert!(matches!(
            decide_text(&ready_text(), Some(&staging_short)),
            Err(Gate::Failed(reason)) if reason.contains("staging")
        ));
    }

    #[test]
    fn exclusions_record_limits_without_control_characters() {
        let mut text = ready_text();
        text = text.replace(
            "inventory_blocked=0",
            "unlogged=app|public.session\nextension=app|postgis|3.4.0\ninventory_blocked=0",
        );
        let plan = decide_text(&text, None).unwrap();
        assert!(
            plan.exclusions
                .iter()
                .any(|line| line.contains("public.session"))
        );
        assert!(
            plan.exclusions
                .iter()
                .any(|line| line.contains("postgis 3.4.0"))
        );
        assert!(
            plan.exclusions
                .iter()
                .any(|line| line.contains("listen_addresses"))
        );
        assert!(
            plan.exclusions
                .iter()
                .any(|line| line.contains("replication slot"))
        );
        assert!(plan.exclusions.len() <= MAX_EXCLUSIONS);
        for line in &plan.exclusions {
            assert!(line.len() <= MAX_EXCLUSION_BYTES, "{line}");
            assert!(!line.chars().any(char::is_control), "{line}");
        }
        let many = (0..30)
            .map(|index| format!("unlogged=app|public.relation_{index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let crowded = ready_text().replace(
            "inventory_blocked=0",
            &format!("{many}\ninventory_blocked=0"),
        );
        let plan = decide_text(&crowded, None).unwrap();
        let unlogged = plan
            .exclusions
            .iter()
            .find(|line| line.starts_with("unlogged relations"))
            .unwrap();
        assert!(unlogged.contains("showing"), "{unlogged}");
        assert!(unlogged.contains("30"), "{unlogged}");
    }

    #[test]
    fn parser_rejects_a_corrupt_report() {
        assert!(parse_report("nope\nauth=ok").is_err());
        assert!(parse_report(&ready_text().replace("\n", "\r\n")).is_ok());
        let duplicate = ready_text().replace(
            "server_version=18.4",
            "server_version=18.4\nserver_version=18.4",
        );
        assert!(parse_report(&duplicate).is_err());
        let unknown = ready_text().replace("auth=ok", "surprise=1\nauth=ok");
        assert!(parse_report(&unknown).is_err());
        // The inventory finished but the ownership probe did not run.
        let truncated = ready_text().replace("\nrole_ownership=owned", "");
        assert!(parse_report(&truncated).is_err());
        let bad = ready_text().replace("role_ownership=owned", "role_ownership=maybe");
        assert!(parse_report(&bad).is_err());
    }
}
