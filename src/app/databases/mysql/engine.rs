use crate::{
    databases::engine::{
        EngineCompatibility, EngineFamily, EngineInfo, JobCostProfile, SQL_JOB_COST,
        SharedPoolProfile,
    },
    instance::auth_hardening::MYSQL_HARDENING_REVISION,
    instance::compatibility::{EngineVersion, ProtocolCapabilities, distrib_version},
    utils::{backend::MYSQL_SOCKET_DIRECTORY, protocol::Protocol},
};

pub(crate) struct Mysql;

impl EngineInfo for Mysql {
    fn protocol(&self) -> Protocol {
        Protocol::Mysql
    }

    fn family(&self) -> EngineFamily {
        EngineFamily::Mysql
    }

    fn default_container_port(&self) -> u16 {
        3306
    }

    fn container_data_target(&self) -> &'static str {
        "/var/lib/mysql"
    }

    fn container_socket_directory(&self) -> &'static str {
        MYSQL_SOCKET_DIRECTORY
    }

    fn socket_filename(&self) -> &'static str {
        "mysqld.sock"
    }

    fn rootless_podman_identity(&self) -> (&'static str, &'static str) {
        ("999:999", "keep-id:uid=999,gid=999")
    }

    fn startup_readiness_script(&self) -> &'static str {
        "test \"$(cat /proc/1/comm)\" = mysqld && MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock -u root -N -B -e 'SELECT 1' >/dev/null"
    }

    fn shared_pool(&self) -> Option<SharedPoolProfile> {
        Some(SharedPoolProfile {
            disk_overhead_mib: 512,
            max_database_name_bytes: 64,
            reserved_databases: &["performance_schema", "sys"],
        })
    }

    fn dump_extension(&self) -> &'static str {
        "mysql.sql"
    }

    fn dump_candidate_suffixes(&self) -> &'static [&'static str] {
        &[".mysql.sql", ".sql"]
    }

    fn database_env_key(&self) -> Option<&'static str> {
        Some("MYSQL_DATABASE")
    }

    fn export_expansion_factor(&self) -> u64 {
        4
    }

    fn job_cost(&self) -> JobCostProfile {
        SQL_JOB_COST
    }

    fn default_remote_port(&self, _tls: bool) -> u16 {
        3306
    }

    fn sql_backslash_strings(&self) -> bool {
        true
    }

    fn auth_hardening_revision(&self) -> Option<u32> {
        Some(MYSQL_HARDENING_REVISION)
    }

    fn gateway_counts_operations(&self) -> bool {
        true
    }
}

impl EngineCompatibility for Mysql {
    fn is_supported_version(&self, version: EngineVersion) -> bool {
        (version.major == 8 && (version.minor > 0 || version.patch >= 11))
            || matches!(version.major, 9 | 26)
    }

    fn supported_versions(&self) -> &'static str {
        "MySQL 8.0.11+, 9.x, or 26.x"
    }

    fn capabilities(&self, _version: EngineVersion) -> ProtocolCapabilities {
        ProtocolCapabilities {
            mysql_caching_sha2_backend: true,
            ..ProtocolCapabilities::default()
        }
    }

    fn version_script(&self) -> &'static str {
        "mysqld --version 2>/dev/null || mysql --version"
    }

    fn normalize_version<'a>(&self, line: &'a str) -> &'a str {
        line.split("Ver ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .or_else(|| distrib_version(line))
            .unwrap_or(line)
    }
}
