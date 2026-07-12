use bollard::models::{ContainerStatsResponse, HealthConfig, Mount, MountType};

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
        Protocol::Postgres => vec![
            "CMD-SHELL",
            "psql -X -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -Atqc 'SELECT 1' >/dev/null",
        ],
        Protocol::Redis => vec![
            "CMD",
            "redis-cli",
            "-s",
            "/run/dbev/redis.sock",
            "--user",
            "dbe_health",
            "-a",
            "healthcheck",
            "--no-auth-warning",
            "ping",
        ],
        Protocol::Mariadb => vec![
            "CMD-SHELL",
            "mariadb-admin ping --protocol=socket --socket=/run/mysqld/mysqld.sock -u \"$MARIADB_USER\" -p\"$MARIADB_PASSWORD\"",
        ],
        Protocol::Mysql => vec![
            "CMD-SHELL",
            "test \"$(cat /proc/1/comm)\" = mysqld && MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u root -N -B -e 'SELECT 1' >/dev/null",
        ],
        Protocol::Mongodb => vec![
            "CMD-SHELL",
            "mongosh --quiet -u \"$DBE_MONGO_USER\" -p \"$DBE_MONGO_PASSWORD\" --authenticationDatabase \"$DBE_MONGO_DATABASE\" \"$DBE_MONGO_DATABASE\" --eval 'db.adminCommand({ ping: 1 })'",
        ],
        Protocol::Clickhouse => vec![
            "CMD-SHELL",
            "clickhouse-client --user \"$CLICKHOUSE_USER\" --password \"$CLICKHOUSE_PASSWORD\" --database \"$CLICKHOUSE_DB\" --query 'SELECT 1'",
        ],
        Protocol::Qdrant => vec![
            "CMD",
            "/opt/dbev/dbev-socket-bridge",
            "__socket-bridge-healthcheck",
            "127.0.0.1:6334",
        ],
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

pub fn cpu_to_nano(cpu_cores: f64) -> Option<i64> {
    if !cpu_cores.is_finite() || cpu_cores <= 0.0 {
        return None;
    }

    let nano_cpus = (cpu_cores * 1_000_000_000.0).round();
    if nano_cpus < 1.0 || nano_cpus >= i64::MAX as f64 {
        return None;
    }
    Some(nano_cpus as i64)
}

pub fn mib_to_bytes(memory_mib: u64) -> Option<i64> {
    memory_mib
        .checked_mul(1024 * 1024)
        .and_then(|bytes| i64::try_from(bytes).ok())
}

pub fn serialize_stats(stats: &ContainerStatsResponse) -> Result<String, serde_json::Error> {
    serde_json::to_string(stats)
}
