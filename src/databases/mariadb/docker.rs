use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretString};

use crate::{
    runtime::docker::{DockerEnv, DockerInstanceSpec, DockerMount},
    shared::protocol::Protocol,
};

#[allow(clippy::too_many_arguments)]
pub fn instance_spec(
    instance_id: &str,
    image: &str,
    database: &str,
    username: &str,
    password: SecretString,
    root_password: SecretString,
    data_path: PathBuf,
    logs_path: PathBuf,
    runtime_path: PathBuf,
) -> DockerInstanceSpec {
    // The official image accepts precomputed native-password hashes. Supplying
    // the exact verifier avoids version-dependent plaintext initialization and
    // guarantees that DBE's gateway verifier matches the database account.
    // DBE-prefixed plaintext values remain in the isolated container
    // configuration for daemon maintenance commands and are never returned by
    // the API.
    let password_hash = docker_native_password_hash(password.expose_secret());
    let root_password_hash = docker_native_password_hash(root_password.expose_secret());
    DockerInstanceSpec {
        instance_id: instance_id.to_string(),
        protocol: Protocol::Mariadb,
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
        data_target: "/var/lib/mysql".to_string(),
        logs_path,
        logs_target: "/logs".to_string(),
        extra_mounts: vec![DockerMount {
            source: runtime_path,
            target: "/run/mysqld".to_string(),
            read_only: false,
        }],
        socket_bridges: Vec::new(),
        env: vec![
            DockerEnv {
                key: "MARIADB_DATABASE".to_string(),
                value: SecretString::from(database.to_string()),
            },
            DockerEnv {
                key: "MARIADB_USER".to_string(),
                value: SecretString::from(username.to_string()),
            },
            DockerEnv {
                key: "MARIADB_PASSWORD_HASH".to_string(),
                value: SecretString::from(password_hash),
            },
            DockerEnv {
                key: "MARIADB_ROOT_PASSWORD_HASH".to_string(),
                value: SecretString::from(root_password_hash),
            },
            DockerEnv {
                key: "DBE_MARIADB_PASSWORD".to_string(),
                value: password,
            },
            DockerEnv {
                key: "DBE_MARIADB_ROOT_PASSWORD".to_string(),
                value: root_password,
            },
        ],
        command: vec!["--skip-networking=ON".to_string()],
    }
}

fn docker_native_password_hash(password: &str) -> String {
    format!(
        "*{}",
        crate::protocols::mariadb::native_password_sha1_stage2_hex(password).to_ascii_uppercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_mysql_data_directory_and_no_public_port() {
        let spec = instance_spec(
            "inst_mysql_1",
            "mariadb:11",
            "mysql_1",
            "app_mysql_1",
            SecretString::from("secret"),
            SecretString::from("root-secret"),
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/logs"),
            PathBuf::from("/tmp/run"),
        );

        assert_eq!(spec.protocol, Protocol::Mariadb);
        assert_eq!(spec.data_target, "/var/lib/mysql");
        assert_eq!(spec.extra_mounts[0].target, "/run/mysqld");
        assert_eq!(spec.command, ["--skip-networking=ON"]);
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
}
