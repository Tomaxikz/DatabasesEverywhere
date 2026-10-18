use crate::databases::engine::DedicatedSpecInput;
use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretString};

use crate::{
    databases::protocol::Protocol,
    runtime::docker::{DockerEnv, DockerInstanceSpec, DockerMount},
};

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
    root_password: SecretString,
    data_path: PathBuf,
    runtime_path: PathBuf,
) -> DockerInstanceSpec {
    build_spec(
        runtime_id,
        image,
        None,
        root_password,
        data_path,
        runtime_path,
    )
}

fn build_spec(
    runtime_id: &str,
    image: &str,
    tenant: Option<TenantBootstrap<'_>>,
    root_password: SecretString,
    data_path: PathBuf,
    runtime_path: PathBuf,
) -> DockerInstanceSpec {
    let shared = tenant.is_none();
    // The official image accepts precomputed native-password hashes. Supplying
    // the exact verifier avoids version-dependent plaintext initialization and
    // guarantees that DBE's gateway verifier matches the database account.
    // DBE-prefixed plaintext values remain in the isolated container
    // configuration for daemon maintenance commands and are never returned by
    // the API.
    let root_password_hash = docker_native_password_hash(root_password.expose_secret());
    let mut env = Vec::new();
    if let Some(tenant) = tenant {
        env.extend([
            DockerEnv::new(
                "MARIADB_DATABASE",
                SecretString::from(tenant.database.to_string()),
            ),
            DockerEnv::new(
                "MARIADB_USER",
                SecretString::from(tenant.username.to_string()),
            ),
            DockerEnv {
                key: "MARIADB_PASSWORD_HASH".to_string(),
                value: SecretString::from(docker_native_password_hash(
                    tenant.password.expose_secret(),
                )),
            },
            DockerEnv::new(
                "MARIADB_ROOT_PASSWORD_HASH",
                SecretString::from(root_password_hash),
            ),
            DockerEnv::new("DBE_MARIADB_PASSWORD", tenant.password),
            DockerEnv::new("DBE_MARIADB_ROOT_PASSWORD", root_password),
        ]);
    } else {
        env.extend([
            DockerEnv::new(
                "MARIADB_ROOT_PASSWORD_HASH",
                SecretString::from(root_password_hash),
            ),
            DockerEnv::new("DBE_MARIADB_ROOT_PASSWORD", root_password),
        ]);
    }

    let mut command = vec![
        "--skip-networking=ON".to_string(),
        "--skip-name-resolve".to_string(),
        "--skip-symbolic-links".to_string(),
        "--skip-log-bin".to_string(),
        "--innodb-file-per-table=ON".to_string(),
        "--wsrep-on=OFF".to_string(),
        "--wsrep-node-address=127.0.0.1".to_string(),
        "--wsrep-node-incoming-address=127.0.0.1".to_string(),
    ];
    if shared {
        command.push("--userstat=ON".to_string());
    }

    DockerInstanceSpec {
        extra_mounts: vec![DockerMount {
            source: runtime_path,
            target: "/run/mysqld".to_string(),
            read_only: false,
        }],
        env,
        command,
        ..DockerInstanceSpec::with_defaults(
            runtime_id,
            Protocol::Mariadb,
            image,
            data_path,
            "/var/lib/mysql",
        )
    }
}

fn docker_native_password_hash(password: &str) -> String {
    format!(
        "*{}",
        crate::gateway::protocols::mariadb::native_password_sha1_stage2_hex(password)
            .to_ascii_uppercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_mysql_data_directory_and_no_public_port() {
        let spec = instance_spec(DedicatedSpecInput {
            instance_id: "inst_mysql_1",
            image: "mariadb:11",
            database: "mysql_1",
            username: "app_mysql_1",
            password: SecretString::from("secret"),
            maintenance_password: SecretString::from("root-secret"),
            data_path: PathBuf::from("/tmp/data"),
            sockets: PathBuf::from("/tmp/run"),
            hosted_config: None,
            socket_bridge_binary: PathBuf::new(),
        });

        assert_eq!(spec.protocol, Protocol::Mariadb);
        assert_eq!(spec.data_target, "/var/lib/mysql");
        assert_eq!(spec.extra_mounts[0].target, "/run/mysqld");
        assert!(spec.command.iter().any(|arg| arg == "--skip-networking=ON"));
        assert!(spec.command.iter().any(|arg| arg == "--skip-name-resolve"));
        assert!(
            spec.command
                .iter()
                .any(|arg| arg == "--skip-symbolic-links")
        );
        assert!(spec.command.iter().any(|arg| arg == "--skip-log-bin"));
        assert!(spec.command.iter().any(|arg| arg == "--wsrep-on=OFF"));
        assert!(
            spec.command
                .iter()
                .any(|arg| arg == "--wsrep-node-address=127.0.0.1")
        );
        assert!(spec.socket_bridges.is_empty());
        let env = spec
            .env
            .iter()
            .map(|entry| (entry.key.as_str(), entry.value.expose_secret()))
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            env["MARIADB_PASSWORD_HASH"],
            docker_native_password_hash("secret")
        );
        assert_eq!(
            env["MARIADB_ROOT_PASSWORD_HASH"],
            docker_native_password_hash("root-secret")
        );
        assert_eq!(env["DBE_MARIADB_PASSWORD"], "secret");
        assert_eq!(env["DBE_MARIADB_ROOT_PASSWORD"], "root-secret");
        assert!(!env.contains_key("MARIADB_PASSWORD"));
        assert!(!env.contains_key("MARIADB_ROOT_PASSWORD"));
    }

    #[test]
    fn shared_runtime_bootstraps_only_root_auth() {
        let spec = shared_spec(
            "pool_mariadb_1",
            "mariadb:12",
            SecretString::from("root-secret"),
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/run"),
        );
        let keys = spec
            .env
            .iter()
            .map(|env| env.key.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            keys,
            ["MARIADB_ROOT_PASSWORD_HASH", "DBE_MARIADB_ROOT_PASSWORD"]
        );
        assert!(keys.iter().all(|key| !key.contains("DATABASE")));
        assert!(keys.iter().all(|key| !key.contains("USER")));
        assert!(spec.command.iter().any(|arg| arg == "--userstat=ON"));
    }
}
