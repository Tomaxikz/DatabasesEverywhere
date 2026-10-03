use crate::{
    databases::engine::{
        EngineCompatibility, EngineFamily, EngineInfo, JobCostProfile, SQL_JOB_COST,
        SharedPoolProfile,
    },
    instance::auth_hardening::POSTGRES_HARDENING_REVISION,
    instance::compatibility::{EngineVersion, ProtocolCapabilities},
    utils::{backend::POSTGRES_SOCKET_DIRECTORY, protocol::Protocol},
};

use super::docker::CONTROL_DATABASE;

pub(crate) struct Postgres;

impl EngineInfo for Postgres {
    fn protocol(&self) -> Protocol {
        Protocol::Postgres
    }

    fn family(&self) -> EngineFamily {
        EngineFamily::Postgres
    }

    fn default_container_port(&self) -> u16 {
        5432
    }

    fn container_data_target(&self) -> &'static str {
        "/var/lib/postgresql"
    }

    fn container_socket_directory(&self) -> &'static str {
        POSTGRES_SOCKET_DIRECTORY
    }

    fn socket_filename(&self) -> &'static str {
        ".s.PGSQL.5432"
    }

    fn rootless_podman_identity(&self) -> (&'static str, &'static str) {
        ("999:999", "keep-id:uid=999,gid=999")
    }

    fn startup_readiness_script(&self) -> &'static str {
        "test \"$(cat /proc/1/comm)\" = postgres || exit 1; if PGPASSWORD=\"$POSTGRES_PASSWORD\" psql -X -h /var/run/postgresql -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -Atqc 'SELECT 1' >/dev/null 2>&1; then exit 0; fi; pg_isready -q -h /var/run/postgresql -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\""
    }

    fn shared_pool(&self) -> Option<SharedPoolProfile> {
        Some(SharedPoolProfile {
            disk_overhead_mib: 2048,
            max_database_name_bytes: 63,
            reserved_databases: &[CONTROL_DATABASE],
        })
    }

    fn dump_extension(&self) -> &'static str {
        "postgres.sql"
    }

    fn dump_candidate_suffixes(&self) -> &'static [&'static str] {
        &[".postgres.sql", ".pgsql.sql", ".sql"]
    }

    fn database_env_key(&self) -> Option<&'static str> {
        Some("POSTGRES_DB")
    }

    fn export_expansion_factor(&self) -> u64 {
        4
    }

    fn job_cost(&self) -> JobCostProfile {
        SQL_JOB_COST
    }

    fn default_remote_port(&self, _tls: bool) -> u16 {
        5432
    }

    fn is_driver_placeholder_database(&self, username: &str, database: Option<&str>) -> bool {
        database == Some(username)
    }

    fn auth_hardening_revision(&self) -> Option<u32> {
        Some(POSTGRES_HARDENING_REVISION)
    }

    fn gateway_counts_operations(&self) -> bool {
        true
    }

    fn release_line_components(&self) -> usize {
        1
    }
}

impl EngineCompatibility for Postgres {
    fn is_supported_version(&self, version: EngineVersion) -> bool {
        (14..=18).contains(&version.major)
    }

    fn supported_versions(&self) -> &'static str {
        "PostgreSQL 14-18"
    }

    fn capabilities(&self, version: EngineVersion) -> ProtocolCapabilities {
        ProtocolCapabilities {
            postgres_cancel_request: true,
            postgres_direct_tls: version.major >= 17,
            ..ProtocolCapabilities::default()
        }
    }

    fn version_script(&self) -> &'static str {
        "postgres --version 2>/dev/null || psql --version"
    }

    fn normalize_version<'a>(&self, line: &'a str) -> &'a str {
        line.strip_prefix("postgres (PostgreSQL) ")
            .or_else(|| line.strip_prefix("psql (PostgreSQL) "))
            .unwrap_or(line)
    }
}
