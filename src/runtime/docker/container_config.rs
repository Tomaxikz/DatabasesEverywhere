use std::collections::HashMap;

use bollard::models::{ContainerStatsResponse, HealthConfig, Mount, MountType, PortBinding};

use crate::shared::protocol::Protocol;

pub fn bind_mount(source: &std::path::Path, target: &str, read_only: bool) -> Mount {
    Mount {
        typ: Some(MountType::BIND),
        source: Some(source.display().to_string()),
        target: Some(target.to_string()),
        read_only: Some(read_only),
        ..Default::default()
    }
}

pub fn healthcheck(protocol: Protocol) -> HealthConfig {
    let test = match protocol {
        Protocol::Postgres => vec!["CMD-SHELL", "pg_isready -U \"$POSTGRES_USER\""],
        Protocol::Redis => vec![
            "CMD",
            "redis-cli",
            "--user",
            "dbe_health",
            "-a",
            "healthcheck",
            "--no-auth-warning",
            "ping",
        ],
        Protocol::Mariadb => vec![
            "CMD-SHELL",
            "mariadb-admin ping -h 127.0.0.1 -u \"$MARIADB_USER\" -p\"$MARIADB_PASSWORD\"",
        ],
        Protocol::Mongodb => vec![
            "CMD-SHELL",
            "mongosh --quiet -u \"$DBE_MONGO_USER\" -p \"$DBE_MONGO_PASSWORD\" --authenticationDatabase \"$DBE_MONGO_DATABASE\" \"$DBE_MONGO_DATABASE\" --eval 'db.adminCommand({ ping: 1 })'",
        ],
        Protocol::Clickhouse => vec![
            "CMD-SHELL",
            "clickhouse-client --user \"$CLICKHOUSE_USER\" --password \"$CLICKHOUSE_PASSWORD\" --database \"$CLICKHOUSE_DB\" --query 'SELECT 1'",
        ],
        Protocol::Qdrant => vec!["CMD-SHELL", "true"],
    };
    HealthConfig {
        test: Some(test.into_iter().map(ToString::to_string).collect()),
        interval: Some(30_000_000_000),
        timeout: Some(5_000_000_000),
        retries: Some(3),
        start_period: Some(120_000_000_000),
        start_interval: Some(1_000_000_000),
    }
}

pub fn exposed_ports(
    enabled: bool,
    host_port: Option<u16>,
    container_port: u16,
) -> Option<Vec<String>> {
    if enabled && host_port.is_some() {
        Some(vec![format!("{container_port}/tcp")])
    } else {
        None
    }
}

pub fn published_port_bindings(
    enabled: bool,
    host_port: Option<u16>,
    container_port: u16,
) -> Option<HashMap<String, Option<Vec<PortBinding>>>> {
    if !enabled {
        return None;
    }
    let host_port = host_port?;
    Some(HashMap::from([(
        format!("{container_port}/tcp"),
        Some(vec![PortBinding {
            host_ip: Some("127.0.0.1".to_string()),
            host_port: Some(host_port.to_string()),
        }]),
    )]))
}

pub fn cpu_to_nano(cpu_cores: f64) -> i64 {
    (cpu_cores * 1_000_000_000.0).round() as i64
}

pub fn mib_to_bytes(memory_mib: u64) -> i64 {
    (memory_mib * 1024 * 1024) as i64
}

pub fn serialize_stats(stats: &ContainerStatsResponse) -> Result<String, serde_json::Error> {
    serde_json::to_string(stats)
}
