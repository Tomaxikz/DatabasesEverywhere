use bollard::models::{HealthConfig, HostConfigLogConfig, Mount, MountType};

pub(super) const LOG_POLICY_LABEL: &str = "dbev.console-policy";
pub(super) const LOG_POLICY_VERSION: &str = "1";

pub(super) fn log_config(engine: crate::config::DaemonEngine) -> HostConfigLogConfig {
    let (driver, options) = match engine {
        crate::config::DaemonEngine::Docker => (
            "local",
            vec![("max-size", "5m"), ("max-file", "1"), ("compress", "false")],
        ),
        crate::config::DaemonEngine::Podman => ("k8s-file", vec![("max-size", "5m")]),
    };
    HostConfigLogConfig {
        typ: Some(driver.into()),
        config: Some(
            options
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        ),
    }
}

pub(super) fn bind_mount(source: &std::path::Path, target: &str, read_only: bool) -> Mount {
    Mount {
        typ: Some(MountType::BIND),
        source: Some(super::host_paths::to_host(source).display().to_string()),
        target: Some(target.to_string()),
        read_only: Some(read_only),
        ..Default::default()
    }
}

/// A Docker healthcheck after startup would run synthetic traffic forever without providing recovery.
pub(super) fn disabled_healthcheck() -> HealthConfig {
    HealthConfig {
        test: Some(vec!["NONE".to_string()]),
        ..Default::default()
    }
}

pub(super) fn cpu_to_nano(cpu_cores: f64) -> Option<i64> {
    if !cpu_cores.is_finite() || cpu_cores <= 0.0 {
        return None;
    }

    let nano_cpus = (cpu_cores * 1_000_000_000.0).round();
    if nano_cpus < 1.0 || nano_cpus >= i64::MAX as f64 {
        return None;
    }
    Some(nano_cpus as i64)
}

pub(super) fn mib_to_bytes(memory_mib: u64) -> Option<i64> {
    memory_mib
        .checked_mul(1024 * 1024)
        .and_then(|bytes| i64::try_from(bytes).ok())
}

#[cfg(test)]
mod tests {
    use crate::databases::protocol::Protocol;

    #[test]
    fn readiness_scripts_use_internal_admins_and_local_endpoints() {
        let script = Protocol::Mariadb.engine().startup_readiness_script();

        assert!(script.contains("/proc/1/comm"));
        assert!(script.contains("mariadbd"));
        assert!(script.contains("DBE_MARIADB_ROOT_PASSWORD"));
        assert!(!script.contains("DBE_MARIADB_PASSWORD:-"));
        assert!(script.contains("SELECT 1"));
        assert!(!script.contains("mariadb-admin ping"));

        let script = Protocol::Mongodb.engine().startup_readiness_script();

        assert!(script.contains("DBE_MONGO_ROOT_USER"));
        assert!(script.contains("DBE_MONGO_ROOT_PASSWORD"));
        assert!(!script.contains("DBE_MONGO_PASSWORD\""));

        let script = Protocol::Clickhouse.engine().startup_readiness_script();

        assert!(script.contains("--host 127.0.0.1"));

        let script = Protocol::Postgres.engine().startup_readiness_script();

        assert!(script.contains("-h /var/run/postgresql"));
        assert!(script.contains("/proc/1/comm"));
        assert!(script.contains("PGPASSWORD=\"$POSTGRES_PASSWORD\""));
        assert!(script.contains("pg_isready"));
        assert!(!script.contains("if psql"));
    }
}
