use serde::{Deserialize, Serialize};

use crate::databases::protocol::Protocol;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImageConfig {
    pub postgres: String,
    pub redis: String,
    pub valkey: String,
    pub mariadb: String,
    pub mysql: String,
    pub mongodb: String,
    pub clickhouse: String,
    pub qdrant: String,
    pub allowed: ImageAllowlistConfig,
}

impl Default for ImageConfig {
    fn default() -> Self {
        Self {
            postgres: "postgres:18.4".to_string(),
            redis: "redis:8.8.0".to_string(),
            valkey: "valkey/valkey:9.1.1".to_string(),
            mariadb: "mariadb:12.3.2".to_string(),
            mysql: "mysql:8.4".to_string(),
            mongodb: "mongo:7.0.37".to_string(),
            clickhouse: "clickhouse/clickhouse-server:25.8.25.37".to_string(),
            qdrant: "qdrant/qdrant:v1.18.2".to_string(),
            allowed: ImageAllowlistConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImageAllowlistConfig {
    pub postgres: Vec<String>,
    pub redis: Vec<String>,
    pub valkey: Vec<String>,
    pub mariadb: Vec<String>,
    pub mysql: Vec<String>,
    pub mongodb: Vec<String>,
    pub clickhouse: Vec<String>,
    pub qdrant: Vec<String>,
}

impl ImageConfig {
    pub fn configured_for_protocol(&self, protocol: Protocol) -> &str {
        protocol.engine().images(self).configured
    }

    pub fn allowed_for_protocol(&self, protocol: Protocol) -> Vec<&str> {
        let configured = self.configured_for_protocol(protocol);
        let mut allowed = protocol
            .engine()
            .images(self)
            .allowed
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if !allowed.contains(&configured) {
            allowed.push(configured);
        }
        allowed
    }
}
