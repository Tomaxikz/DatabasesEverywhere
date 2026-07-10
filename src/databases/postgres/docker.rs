use std::path::PathBuf;

use secrecy::SecretString;

use crate::{
    runtime::docker::{DockerEnv, DockerInstanceSpec, DockerMount},
    shared::protocol::Protocol,
};

pub const INTERNAL_ADMIN_USERNAME: &str = "dbe_admin";

#[allow(clippy::too_many_arguments)]
pub fn instance_spec(
    instance_id: &str,
    image: &str,
    database: &str,
    username: &str,
    password: SecretString,
    data_path: PathBuf,
    logs_path: PathBuf,
    runtime_path: PathBuf,
) -> DockerInstanceSpec {
    let bootstrap_password =
        SecretString::from(format!("dbe-admin-{}", uuid::Uuid::new_v4().simple()));

    DockerInstanceSpec {
        instance_id: instance_id.to_string(),
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
        env: vec![
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
                value: bootstrap_password,
            },
            DockerEnv {
                key: "DBE_POSTGRES_USER".to_string(),
                value: SecretString::from(username.to_string()),
            },
            DockerEnv {
                key: "DBE_POSTGRES_PASSWORD".to_string(),
                value: password,
            },
        ],
        command: vec![
            "postgres".to_string(),
            "-c".to_string(),
            "listen_addresses=".to_string(),
        ],
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
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/logs"),
            PathBuf::from("/tmp/run"),
        );

        assert_eq!(spec.data_target, "/var/lib/postgresql");
        assert_eq!(spec.extra_mounts[0].target, "/var/run/postgresql");
        assert_eq!(spec.command, ["postgres", "-c", "listen_addresses="]);
        assert_eq!(env_value(&spec, "POSTGRES_USER"), INTERNAL_ADMIN_USERNAME);
        assert_eq!(env_value(&spec, "POSTGRES_DB"), "pg_1");
        assert_eq!(env_value(&spec, "DBE_POSTGRES_USER"), "app_pg_1");
        assert_eq!(env_value(&spec, "DBE_POSTGRES_PASSWORD"), "secret");
        assert_ne!(env_value(&spec, "POSTGRES_PASSWORD"), "secret");
        assert!(spec.socket_bridges.is_empty());
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
