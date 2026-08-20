use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Postgres,
    Redis,
    Valkey,
    Mariadb,
    Mysql,
    Mongodb,
    Clickhouse,
    Qdrant,
}

impl Protocol {
    pub const ALL: [Self; 8] = [
        Self::Postgres,
        Self::Redis,
        Self::Valkey,
        Self::Mariadb,
        Self::Mysql,
        Self::Mongodb,
        Self::Clickhouse,
        Self::Qdrant,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Redis => "redis",
            Self::Valkey => "valkey",
            Self::Mariadb => "mariadb",
            Self::Mysql => "mysql",
            Self::Mongodb => "mongodb",
            Self::Clickhouse => "clickhouse",
            Self::Qdrant => "qdrant",
        }
    }

    pub fn default_container_port(self) -> u16 {
        match self {
            Self::Postgres => 5432,
            Self::Redis => 6379,
            Self::Valkey => 6379,
            Self::Mariadb => 3306,
            Self::Mysql => 3306,
            Self::Mongodb => 27017,
            Self::Clickhouse => 9000,
            Self::Qdrant => 6334,
        }
    }

    pub fn container_data_target(self) -> &'static str {
        match self {
            Self::Postgres => "/var/lib/postgresql",
            Self::Redis | Self::Valkey => "/data",
            Self::Mariadb | Self::Mysql => "/var/lib/mysql",
            Self::Mongodb => "/data/db",
            Self::Clickhouse => "/var/lib/clickhouse",
            Self::Qdrant => "/dbe-qdrant",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Protocol {
    type Err = ProtocolParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "postgres" | "postgresql" => Ok(Self::Postgres),
            "redis" => Ok(Self::Redis),
            "valkey" => Ok(Self::Valkey),
            "mariadb" => Ok(Self::Mariadb),
            "mysql" => Ok(Self::Mysql),
            "mongodb" | "mongo" => Ok(Self::Mongodb),
            "clickhouse" | "ch" => Ok(Self::Clickhouse),
            "qdrant" | "qdrant-grpc" => Ok(Self::Qdrant),
            _ => Err(ProtocolParseError {
                value: value.to_string(),
            }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unsupported database protocol: {value}")]
pub struct ProtocolParseError {
    value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_protocols_remain_distinct_first_class_variants() {
        for (name, protocol, related, port) in [
            ("mysql", Protocol::Mysql, Protocol::Mariadb, 3306),
            ("valkey", Protocol::Valkey, Protocol::Redis, 6379),
        ] {
            assert_eq!(name.parse::<Protocol>().unwrap(), protocol);
            assert_ne!(protocol, related);
            assert!(Protocol::ALL.contains(&protocol));
            assert_eq!(protocol.default_container_port(), port);
        }
    }
}
