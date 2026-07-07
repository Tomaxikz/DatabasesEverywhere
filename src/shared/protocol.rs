use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Postgres,
    Redis,
    Mariadb,
    Mongodb,
    Clickhouse,
    Qdrant,
}

impl Protocol {
    pub const ALL: [Self; 6] = [
        Self::Postgres,
        Self::Redis,
        Self::Mariadb,
        Self::Mongodb,
        Self::Clickhouse,
        Self::Qdrant,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Redis => "redis",
            Self::Mariadb => "mariadb",
            Self::Mongodb => "mongodb",
            Self::Clickhouse => "clickhouse",
            Self::Qdrant => "qdrant",
        }
    }

    pub fn default_container_port(self) -> u16 {
        match self {
            Self::Postgres => 5432,
            Self::Redis => 6379,
            Self::Mariadb => 3306,
            Self::Mongodb => 27017,
            Self::Clickhouse => 9000,
            Self::Qdrant => 6334,
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
            "mariadb" | "mysql" => Ok(Self::Mariadb),
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
