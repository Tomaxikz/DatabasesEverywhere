use bollard::models::{HealthConfig, Mount, MountType};

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

/// Explicitly disables image-provided and daemon-managed healthchecks.
///
/// DBE performs a bounded readiness query while an instance starts. Keeping a
/// Docker healthcheck after startup would run synthetic database traffic
/// forever without providing any automatic recovery.
pub fn disabled_healthcheck() -> HealthConfig {
    HealthConfig {
        test: Some(vec!["NONE".to_string()]),
        ..Default::default()
    }
}

/// A real database readiness query used only while starting an instance.
pub fn startup_readiness_script(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Postgres => {
            "psql -X -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -Atqc 'SELECT 1' >/dev/null"
        }
        Protocol::Redis => {
            "redis-cli -s /run/dbev/redis.sock --user dbe_health -a healthcheck --no-auth-warning ping >/dev/null"
        }
        Protocol::Valkey => {
            "valkey-cli -s /run/dbev/valkey.sock --user dbe_health -a healthcheck --no-auth-warning ping >/dev/null"
        }
        Protocol::Mariadb => {
            "tenant_password=\"${DBE_MARIADB_PASSWORD:-${MARIADB_PASSWORD:-}}\"; MYSQL_PWD=\"$tenant_password\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -u \"$MARIADB_USER\" \"$MARIADB_DATABASE\" -N -B -e 'SELECT 1' >/dev/null"
        }
        Protocol::Mysql => {
            "test \"$(cat /proc/1/comm)\" = mysqld && MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u root -N -B -e 'SELECT 1' >/dev/null"
        }
        Protocol::Mongodb => {
            "mongosh --quiet -u \"$DBE_MONGO_USER\" -p \"$DBE_MONGO_PASSWORD\" --authenticationDatabase \"$DBE_MONGO_DATABASE\" \"$DBE_MONGO_DATABASE\" --eval 'db.adminCommand({ ping: 1 })' >/dev/null"
        }
        Protocol::Clickhouse => {
            "clickhouse-client --user \"$CLICKHOUSE_USER\" --password \"$CLICKHOUSE_PASSWORD\" --database \"$CLICKHOUSE_DB\" --query 'SELECT 1' >/dev/null"
        }
        Protocol::Qdrant => {
            "/opt/dbev/dbev-socket-bridge __socket-bridge-healthcheck 127.0.0.1:6334"
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mariadb_readiness_requires_an_authenticated_query() {
        let script = startup_readiness_script(Protocol::Mariadb);

        assert!(script.contains("DBE_MARIADB_PASSWORD"));
        assert!(script.contains("MARIADB_PASSWORD"));
        assert!(script.contains("SELECT 1"));
        assert!(!script.contains("mariadb-admin ping"));
    }
}
