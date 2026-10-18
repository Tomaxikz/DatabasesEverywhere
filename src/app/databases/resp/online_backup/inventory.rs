//! Parses the RESP inventory report and decides whether to capture.

use std::collections::BTreeMap;

use crate::subsystems::backups::strategy::StrategyError;

/// Settings the capture and the restore layout depend on.
pub(super) const CONFIG_KEYS: [&str; 4] = [
    "repl-diskless-sync",
    "rdbchecksum",
    "appendfilename",
    "appenddirname",
];
/// Multi-part AOF, which the restore layout relies on, arrived in 7.0.
const MIN_MAJOR: u32 = 7;
/// Copy-on-write during the fork can at worst duplicate the resident set.
const FORK_HEADROOM_FACTOR: u64 = 2;
const MAX_VALUE_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Inventory {
    pub server_version: String,
    pub cli_version: String,
    loading: bool,
    used_memory_rss: u64,
    config: BTreeMap<String, String>,
}

pub(super) fn parse_report(report: &str) -> Result<Inventory, String> {
    let mut section = "";
    let mut cli = Vec::new();
    let mut info = BTreeMap::new();
    let mut config = Vec::new();
    for line in report.lines().map(|line| line.trim_end_matches('\r')) {
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
            .filter(|name| matches!(*name, "cli" | "info" | "config"))
        {
            section = name;
            continue;
        }
        match section {
            "cli" if !line.is_empty() => cli.push(line),
            "info" => {
                if let Some((key, value)) = line.split_once(':')
                    && !key.starts_with('#')
                {
                    info.insert(key.to_string(), value.to_string());
                }
            }
            "config" => config.push(line),
            _ => {}
        }
    }
    let server_version = info
        .get("valkey_version")
        .or_else(|| info.get("redis_version"))
        .cloned()
        .ok_or("INFO reports no server version")?;
    let cli_version = cli
        .first()
        .and_then(|line| line.split_whitespace().nth(1))
        .map(str::to_string)
        .ok_or("the CLI reports no version")?;
    let number = |key: &str| -> Result<u64, String> {
        info.get(key)
            .ok_or_else(|| format!("INFO reports no {key}"))?
            .trim()
            .parse()
            .map_err(|_| format!("INFO {key} is not a number"))
    };
    let loading = number("loading")? != 0;
    let used_memory_rss = number("used_memory_rss")?;
    let config = parse_config(&config)?;
    for value in [&server_version, &cli_version] {
        bounded(value)?;
    }
    Ok(Inventory {
        server_version,
        cli_version,
        loading,
        used_memory_rss,
        config,
    })
}

/// `CONFIG GET` prints alternating name and value lines.
fn parse_config(lines: &[&str]) -> Result<BTreeMap<String, String>, String> {
    let lines: Vec<&str> = match lines.last() {
        Some(&"") => &lines[..lines.len() - 1],
        _ => lines,
    }
    .to_vec();
    if !lines.len().is_multiple_of(2) {
        return Err("CONFIG GET output is not name/value pairs".to_string());
    }
    let mut config = BTreeMap::new();
    for pair in lines.chunks(2) {
        bounded(pair[1])?;
        config.insert(pair[0].to_ascii_lowercase(), pair[1].to_string());
    }
    for key in CONFIG_KEYS {
        if !config.contains_key(key) {
            return Err(format!("CONFIG GET did not report {key}"));
        }
    }
    Ok(config)
}

fn bounded(value: &str) -> Result<(), String> {
    if value.len() > MAX_VALUE_LEN || value.chars().any(char::is_control) {
        Err("the inventory reported an unexpected value".to_string())
    } else {
        Ok(())
    }
}

impl Inventory {
    fn setting(&self, key: &str) -> &str {
        self.config.get(key).map_or("", String::as_str)
    }

    /// Refuses layouts the strategy cannot capture *and* restore, and a fork
    /// the container memory limit cannot absorb.
    pub(super) fn decide(&self, memory_limit_mib: u64) -> Result<(), StrategyError> {
        let major = self
            .server_version
            .split('.')
            .next()
            .and_then(|major| major.parse::<u32>().ok())
            .ok_or_else(|| {
                StrategyError::Failed(format!(
                    "server version {} is not parseable",
                    self.server_version
                ))
            })?;
        if major < MIN_MAJOR {
            return Err(StrategyError::Unsupported(format!(
                "server {} predates multi-part AOF; {MIN_MAJOR}.0 or newer is required",
                self.server_version
            )));
        }
        let unsupported = |reason: String| Err(StrategyError::Unsupported(reason));
        if self.setting("repl-diskless-sync") != "yes" {
            // A disk-based sync writes dump.rdb into the data volume and a
            // failed save would stop writes.
            return unsupported(
                "repl-diskless-sync is off; the snapshot must stream without a disk save"
                    .to_string(),
            );
        }
        if self.setting("rdbchecksum") != "yes" {
            return unsupported(
                "rdbchecksum is off, so the snapshot could not be verified".to_string(),
            );
        }
        if self.setting("appendfilename") != "appendonly.aof"
            || self.setting("appenddirname") != super::aof::AOF_DIRECTORY
        {
            return unsupported(
                "the AOF uses non-default names the restore layout does not install".to_string(),
            );
        }
        if self.loading {
            return Err(StrategyError::Failed(
                "the server is still loading its dataset".to_string(),
            ));
        }
        let limit = memory_limit_mib.saturating_mul(1024 * 1024);
        let needed = self.used_memory_rss.saturating_mul(FORK_HEADROOM_FACTOR);
        if limit == 0 || needed > limit {
            return Err(StrategyError::Failed(format!(
                "resident set {} bytes leaves no copy-on-write headroom for the snapshot fork inside the {memory_limit_mib} MiB memory limit",
                self.used_memory_rss
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(version_key: &str, version: &str, config: &[(&str, &str)]) -> String {
        let mut report = format!(
            "[cli]\nredis-cli 8.8.0\n[info]\n# Server\r\n{version_key}:{version}\r\nos:Linux\r\n# Persistence\r\nloading:0\r\n# Memory\r\nused_memory_rss:104857600\r\n[config]\n"
        );
        for (key, value) in config {
            report.push_str(&format!("{key}\n{value}\n"));
        }
        report
    }

    const DEFAULTS: [(&str, &str); 4] = [
        ("appenddirname", "appendonlydir"),
        ("appendfilename", "appendonly.aof"),
        ("rdbchecksum", "yes"),
        ("repl-diskless-sync", "yes"),
    ];

    #[test]
    fn default_servers_with_headroom_are_captured() {
        let inventory = parse_report(&report("redis_version", "8.8.0", &DEFAULTS)).unwrap();
        assert_eq!(inventory.server_version, "8.8.0");
        assert_eq!(inventory.cli_version, "8.8.0");
        inventory.decide(1024).unwrap();
        // 100 MiB resident needs 200 MiB for the fork.
        assert!(matches!(
            inventory.decide(199),
            Err(StrategyError::Failed(_))
        ));
    }

    #[test]
    fn valkey_reports_its_own_version() {
        let mut text = report("redis_version", "7.2.4", &DEFAULTS);
        text = text.replace("os:Linux", "valkey_version:9.1.1");
        assert_eq!(parse_report(&text).unwrap().server_version, "9.1.1");
    }

    #[test]
    fn unsafe_settings_and_old_servers_are_unsupported() {
        for (key, value) in [
            ("repl-diskless-sync", "no"),
            ("rdbchecksum", "no"),
            ("appenddirname", "aof"),
            ("appendfilename", "redis.aof"),
        ] {
            let config: Vec<_> = DEFAULTS
                .iter()
                .map(|&(name, default)| (name, if name == key { value } else { default }))
                .collect();
            let inventory = parse_report(&report("redis_version", "8.8.0", &config)).unwrap();
            assert!(
                matches!(inventory.decide(1024), Err(StrategyError::Unsupported(_))),
                "{key}"
            );
        }
        let old = parse_report(&report("redis_version", "6.2.14", &DEFAULTS)).unwrap();
        assert!(matches!(
            old.decide(1024),
            Err(StrategyError::Unsupported(_))
        ));
    }

    #[test]
    fn incomplete_reports_are_rejected() {
        assert!(parse_report(&report("redis_version", "8.8.0", &DEFAULTS[..3])).is_err());
        assert!(parse_report("[cli]\nredis-cli 8.8.0\n").is_err());
        let loading = report("redis_version", "8.8.0", &DEFAULTS).replace("loading:0", "loading:1");
        assert!(matches!(
            parse_report(&loading).unwrap().decide(1024),
            Err(StrategyError::Failed(_))
        ));
    }
}
