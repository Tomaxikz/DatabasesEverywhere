use std::path::PathBuf;

use secrecy::SecretString;

use crate::{
    runtime::docker::{DockerEnv, DockerInstanceSpec, DockerMount},
    shared::protocol::Protocol,
};

pub const INTERNAL_ADMIN_USERNAME: &str = "dbe_admin";
pub const CONTROL_DATABASE: &str = "dbe_control";

struct TenantBootstrap<'a> {
    database: &'a str,
    username: &'a str,
    password: SecretString,
}

#[allow(clippy::too_many_arguments)]
pub fn instance_spec(
    instance_id: &str,
    image: &str,
    database: &str,
    username: &str,
    password: SecretString,
    admin_password: SecretString,
    data_path: PathBuf,
    logs_path: PathBuf,
    runtime_path: PathBuf,
) -> DockerInstanceSpec {
    build_spec(
        instance_id,
        image,
        Some(TenantBootstrap {
            database,
            username,
            password,
        }),
        admin_password,
        data_path,
        logs_path,
        runtime_path,
    )
}

pub fn shared_spec(
    runtime_id: &str,
    image: &str,
    admin_password: SecretString,
    data_path: PathBuf,
    logs_path: PathBuf,
    runtime_path: PathBuf,
) -> DockerInstanceSpec {
    build_spec(
        runtime_id,
        image,
        None,
        admin_password,
        data_path,
        logs_path,
        runtime_path,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_spec(
    runtime_id: &str,
    image: &str,
    tenant: Option<TenantBootstrap<'_>>,
    admin_password: SecretString,
    data_path: PathBuf,
    logs_path: PathBuf,
    runtime_path: PathBuf,
) -> DockerInstanceSpec {
    let database = tenant
        .as_ref()
        .map(|tenant| tenant.database)
        .unwrap_or(CONTROL_DATABASE);
    let mut env = vec![
        DockerEnv {
            key: "POSTGRES_DB".to_string(),
            value: SecretString::from(database.to_string()),
        },
        DockerEnv {
            key: "POSTGRES_USER".to_string(),
            value: SecretString::from(INTERNAL_ADMIN_USERNAME.to_string()),
        },
        DockerEnv {
            key: "POSTGRES_PASSWORD".to_string(),
            value: admin_password,
        },
        DockerEnv {
            key: "POSTGRES_INITDB_ARGS".to_string(),
            value: SecretString::from(
                "--auth-local=scram-sha-256 --auth-host=scram-sha-256".to_string(),
            ),
        },
    ];
    if let Some(tenant) = tenant {
        env.extend([
            DockerEnv {
                key: "DBE_POSTGRES_USER".to_string(),
                value: SecretString::from(tenant.username.to_string()),
            },
            DockerEnv {
                key: "DBE_POSTGRES_PASSWORD".to_string(),
                value: tenant.password,
            },
        ]);
    }

    let command = vec![
        "postgres".to_string(),
        "-c".to_string(),
        "listen_addresses=".to_string(),
        "-c".to_string(),
        "password_encryption=scram-sha-256".to_string(),
    ];
    DockerInstanceSpec {
        instance_id: runtime_id.to_string(),
        protocol: Protocol::Postgres,
        image: image.to_string(),
        project_id: None,
        user: None,
        working_dir: None,
        entrypoint: None,
        cpu_cores: 1.0,
        memory_mib: 1024,
        disk_mib: 10240,
        pids_limit: None,
        data_path,
        data_target: "/var/lib/postgresql".to_string(),
        logs_path,
        logs_target: "/logs".to_string(),
        extra_mounts: vec![DockerMount {
            source: runtime_path,
            target: "/var/run/postgresql".to_string(),
            read_only: false,
        }],
        socket_bridges: Vec::new(),
        env,
        command,
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn mounts_parent_postgresql_directory_for_pre_18_and_18_images() {
        let spec = instance_spec(
            "inst_pg_1",
            "postgres:18.4",
            "pg_1",
            "app_pg_1",
            SecretString::from("secret"),
            SecretString::from("admin-secret"),
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/logs"),
            PathBuf::from("/tmp/run"),
        );

        assert_eq!(spec.data_target, "/var/lib/postgresql");
        assert_eq!(spec.extra_mounts[0].target, "/var/run/postgresql");
        assert_eq!(
            spec.command,
            [
                "postgres",
                "-c",
                "listen_addresses=",
                "-c",
                "password_encryption=scram-sha-256"
            ]
        );
        assert_eq!(env_value(&spec, "POSTGRES_USER"), INTERNAL_ADMIN_USERNAME);
        assert_eq!(env_value(&spec, "POSTGRES_DB"), "pg_1");
        assert_eq!(env_value(&spec, "DBE_POSTGRES_USER"), "app_pg_1");
        assert_eq!(env_value(&spec, "DBE_POSTGRES_PASSWORD"), "secret");
        assert_eq!(env_value(&spec, "POSTGRES_PASSWORD"), "admin-secret");
        assert!(
            spec.command
                .iter()
                .all(|arg| !arg.contains("pg_stat_statements"))
        );
        assert_ne!(env_value(&spec, "POSTGRES_PASSWORD"), "secret");
        assert_eq!(
            env_value(&spec, "POSTGRES_INITDB_ARGS"),
            "--auth-local=scram-sha-256 --auth-host=scram-sha-256"
        );
        assert!(spec.socket_bridges.is_empty());
    }

    #[test]
    fn shared_runtime_bootstraps_only_control_admin() {
        let spec = shared_spec(
            "pool_pg_1",
            "postgres:18.4",
            SecretString::from("admin-secret"),
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/logs"),
            PathBuf::from("/tmp/run"),
        );

        assert_eq!(env_value(&spec, "POSTGRES_DB"), CONTROL_DATABASE);
        assert_eq!(env_value(&spec, "POSTGRES_USER"), INTERNAL_ADMIN_USERNAME);
        assert_eq!(env_value(&spec, "POSTGRES_PASSWORD"), "admin-secret");
        assert!(
            spec.env
                .iter()
                .all(|env| !env.key.starts_with("DBE_POSTGRES_"))
        );
    }

    fn env_value<'a>(spec: &'a DockerInstanceSpec, key: &str) -> &'a str {
        spec.env
            .iter()
            .find(|environment| environment.key == key)
            .unwrap()
            .value
            .expose_secret()
    }
}
