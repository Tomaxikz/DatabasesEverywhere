use std::path::PathBuf;

use secrecy::SecretString;

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
    data_path: PathBuf,
    logs_path: PathBuf,
    runtime_path: PathBuf,
) -> DockerInstanceSpec {
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
        container_port: Protocol::Postgres.default_container_port(),
        public_backend_port: None,
        data_path,
        data_target: "/var/lib/postgresql".to_string(),
        logs_path,
        logs_target: "/logs".to_string(),
        extra_mounts: vec![DockerMount {
            source: runtime_path,
            target: "/var/run/postgresql".to_string(),
            read_only: false,
        }],
        env: vec![
            DockerEnv {
                key: "POSTGRES_DB".to_string(),
                value: SecretString::from(database.to_string()),
            },
            DockerEnv {
                key: "POSTGRES_USER".to_string(),
                value: SecretString::from(username.to_string()),
            },
            DockerEnv {
                key: "POSTGRES_PASSWORD".to_string(),
                value: password,
            },
        ],
        command: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
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
        assert_eq!(spec.container_port, 5432);
        assert_eq!(spec.public_backend_port, None);
        assert_eq!(spec.extra_mounts[0].target, "/var/run/postgresql");
    }
}
