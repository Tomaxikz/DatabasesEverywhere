use crate::databases::engine::DedicatedSpecInput;
use std::path::PathBuf;

use secrecy::SecretString;

use crate::{
    databases::protocol::Protocol,
    runtime::docker::{DockerEnv, DockerInstanceSpec, DockerMount},
};

pub const INTERNAL_ADMIN_USERNAME: &str = "dbe_admin";
pub const CONTROL_DATABASE: &str = "dbe_control";

struct TenantBootstrap<'a> {
    database: &'a str,
    username: &'a str,
    password: SecretString,
}

pub(crate) fn instance_spec(input: DedicatedSpecInput<'_>) -> DockerInstanceSpec {
    build_spec(
        input.instance_id,
        input.image,
        Some(TenantBootstrap {
            database: input.database,
            username: input.username,
            password: input.password,
        }),
        input.maintenance_password,
        input.data_path,
        input.sockets,
    )
}

pub fn shared_spec(
    runtime_id: &str,
    image: &str,
    admin_password: SecretString,
    data_path: PathBuf,
    runtime_path: PathBuf,
) -> DockerInstanceSpec {
    build_spec(
        runtime_id,
        image,
        None,
        admin_password,
        data_path,
        runtime_path,
    )
}

fn build_spec(
    runtime_id: &str,
    image: &str,
    tenant: Option<TenantBootstrap<'_>>,
    admin_password: SecretString,
    data_path: PathBuf,
    runtime_path: PathBuf,
) -> DockerInstanceSpec {
    let database = tenant
        .as_ref()
        .map(|tenant| tenant.database)
        .unwrap_or(CONTROL_DATABASE);
    let mut env = vec![
        DockerEnv::new("POSTGRES_DB", SecretString::from(database.to_string())),
        DockerEnv::new(
            "POSTGRES_USER",
            SecretString::from(INTERNAL_ADMIN_USERNAME.to_string()),
        ),
        DockerEnv::new("POSTGRES_PASSWORD", admin_password),
        DockerEnv {
            key: "POSTGRES_INITDB_ARGS".to_string(),
            value: SecretString::from(
                "--auth-local=scram-sha-256 --auth-host=scram-sha-256".to_string(),
            ),
        },
    ];
    if let Some(tenant) = tenant {
        env.extend([
            DockerEnv::new(
                "DBE_POSTGRES_USER",
                SecretString::from(tenant.username.to_string()),
            ),
            DockerEnv::new("DBE_POSTGRES_PASSWORD", tenant.password),
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
        extra_mounts: vec![DockerMount {
            source: runtime_path,
            target: "/var/run/postgresql".to_string(),
            read_only: false,
        }],
        env,
        command,
        ..DockerInstanceSpec::with_defaults(
            runtime_id,
            Protocol::Postgres,
            image,
            data_path,
            "/var/lib/postgresql",
        )
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn mounts_parent_postgresql_directory_for_pre_18_and_18_images() {
        let spec = instance_spec(DedicatedSpecInput {
            instance_id: "inst_pg_1",
            image: "postgres:18.4",
            database: "pg_1",
            username: "app_pg_1",
            password: SecretString::from("secret"),
            maintenance_password: SecretString::from("admin-secret"),
            data_path: PathBuf::from("/tmp/data"),
            sockets: PathBuf::from("/tmp/run"),
            hosted_config: None,
            socket_bridge_binary: PathBuf::new(),
        });

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
