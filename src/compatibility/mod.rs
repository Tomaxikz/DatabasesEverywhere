mod boot;
mod probe;

use std::fmt;

use crate::shared::protocol::Protocol;

pub(crate) use boot::reconcile_managed_compatibility_on_boot;
pub(crate) use probe::{compatibility_attestation, probe_instance_compatibility};

/// Increment when the probe command, normalization, or compatibility policy
/// changes in a way that requires every managed container to be checked again.
pub(crate) const COMPATIBILITY_PROBE_REVISION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct EngineVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl fmt::Display for EngineVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProtocolCapabilities {
    pub postgres_direct_tls: bool,
    pub postgres_cancel_request: bool,
    pub mysql_caching_sha2_backend: bool,
    pub redis_resp3: bool,
    pub mongodb_scram_sha256: bool,
    pub qdrant_rest: bool,
    pub qdrant_grpc: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatibilityProfile {
    pub version: EngineVersion,
    pub capabilities: ProtocolCapabilities,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompatibilityPolicyError {
    #[error("database version output did not contain a semantic version")]
    Unparseable,
    #[error("{protocol} {version} is outside DBEV's tested compatibility matrix: {supported}")]
    Unsupported {
        protocol: Protocol,
        version: EngineVersion,
        supported: &'static str,
    },
}

pub fn parse_engine_version(value: &str) -> Result<EngineVersion, CompatibilityPolicyError> {
    let bytes = value.as_bytes();
    let mut start = None;
    for (index, byte) in bytes.iter().enumerate() {
        if byte.is_ascii_digit() {
            start = Some(index);
            break;
        }
    }
    let start = start.ok_or(CompatibilityPolicyError::Unparseable)?;
    let token = value[start..]
        .split(|character: char| !(character.is_ascii_digit() || character == '.'))
        .next()
        .unwrap_or_default();
    let mut components = token.split('.');
    let major = components
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(CompatibilityPolicyError::Unparseable)?;
    let minor = components
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    let patch = components
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    Ok(EngineVersion {
        major,
        minor,
        patch,
    })
}

pub fn compatibility_profile(
    protocol: Protocol,
    normalized_version: &str,
) -> Result<CompatibilityProfile, CompatibilityPolicyError> {
    let version = parse_engine_version(normalized_version)?;
    let supported = match protocol {
        Protocol::Postgres => (14..=18).contains(&version.major),
        Protocol::Mysql => {
            (version.major == 8 && (version.minor > 0 || version.patch >= 11))
                || matches!(version.major, 9 | 26)
        }
        Protocol::Mariadb => matches!(
            (version.major, version.minor),
            (10, 11) | (11, 4 | 8) | (12, 3)
        ),
        Protocol::Mongodb => matches!(version.major, 7 | 8),
        Protocol::Redis => {
            matches!((version.major, version.minor), (6, 2) | (7, 2 | 4)) || version.major == 8
        }
        Protocol::Valkey => {
            matches!((version.major, version.minor), (7, 2)) || matches!(version.major, 8 | 9)
        }
        Protocol::Clickhouse => matches!(version.major, 25 | 26),
        Protocol::Qdrant => version.major == 1 && matches!(version.minor, 17 | 18),
    };
    if !supported {
        return Err(CompatibilityPolicyError::Unsupported {
            protocol,
            version,
            supported: supported_versions(protocol),
        });
    }

    let mut capabilities = ProtocolCapabilities::default();
    match protocol {
        Protocol::Postgres => {
            capabilities.postgres_cancel_request = true;
            capabilities.postgres_direct_tls = version.major >= 17;
        }
        Protocol::Mysql | Protocol::Mariadb => {
            capabilities.mysql_caching_sha2_backend = protocol == Protocol::Mysql;
        }
        Protocol::Redis | Protocol::Valkey => {
            capabilities.redis_resp3 = version.major >= 6;
        }
        Protocol::Mongodb => capabilities.mongodb_scram_sha256 = true,
        Protocol::Qdrant => {
            capabilities.qdrant_rest = true;
            capabilities.qdrant_grpc = true;
        }
        Protocol::Clickhouse => {}
    }
    Ok(CompatibilityProfile {
        version,
        capabilities,
    })
}

pub const fn supported_versions(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Postgres => "PostgreSQL 14-18",
        Protocol::Mysql => "MySQL 8.0.11+, 9.x, or 26.x",
        Protocol::Mariadb => "MariaDB 10.11, 11.4, 11.8, or 12.3",
        Protocol::Mongodb => "MongoDB 7 or 8",
        Protocol::Redis => "Redis 6.2, 7.2, 7.4, or 8.x",
        Protocol::Valkey => "Valkey 7.2, 8.x, or 9.x",
        Protocol::Clickhouse => "ClickHouse 25.x or 26.x",
        Protocol::Qdrant => "Qdrant 1.17 or 1.18",
    }
}

pub(crate) fn database_version_script(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Postgres => "postgres --version 2>/dev/null || psql --version",
        Protocol::Mariadb => "mariadb --version 2>/dev/null || mysqld --version",
        Protocol::Mysql => "mysqld --version 2>/dev/null || mysql --version",
        Protocol::Redis => "redis-server --version",
        Protocol::Valkey => "valkey-server --version",
        Protocol::Mongodb => "mongod --version | awk '/db version/ {print $3; exit}'",
        Protocol::Clickhouse => "clickhouse-server --version 2>/dev/null || clickhouse --version",
        Protocol::Qdrant => {
            "if command -v qdrant >/dev/null 2>&1; then qdrant --version; elif [ -x /qdrant/qdrant ]; then /qdrant/qdrant --version; else cat /qdrant/VERSION 2>/dev/null; fi"
        }
    }
}

pub(crate) fn normalize_database_version(protocol: Protocol, stdout: &str) -> Option<String> {
    let line = stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())?;
    let version = match protocol {
        Protocol::Postgres => line
            .strip_prefix("postgres (PostgreSQL) ")
            .or_else(|| line.strip_prefix("psql (PostgreSQL) "))
            .unwrap_or(line),
        Protocol::Mariadb => line
            .split("Distrib ")
            .nth(1)
            .and_then(|rest| rest.split([',', ' ']).next())
            .unwrap_or(line),
        Protocol::Mysql => line
            .split("Ver ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .or_else(|| {
                line.split("Distrib ")
                    .nth(1)
                    .and_then(|rest| rest.split([',', ' ']).next())
            })
            .unwrap_or(line),
        Protocol::Redis | Protocol::Valkey => line
            .split_whitespace()
            .find_map(|part| part.strip_prefix("v="))
            .unwrap_or(line),
        Protocol::Mongodb => line.strip_prefix('v').unwrap_or(line),
        Protocol::Clickhouse => line
            .strip_prefix("ClickHouse server version ")
            .or_else(|| line.strip_prefix("ClickHouse local version "))
            .or_else(|| line.strip_prefix("ClickHouse client version "))
            .unwrap_or(line)
            .split(" (")
            .next()
            .unwrap_or(line),
        Protocol::Qdrant => line
            .strip_prefix("qdrant ")
            .or_else(|| line.strip_prefix("Qdrant "))
            .unwrap_or(line),
    }
    .trim()
    .trim_end_matches('.');

    (!version.is_empty()).then(|| version.to_string())
}

#[cfg(test)]
mod tests;
