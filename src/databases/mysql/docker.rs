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
    root_password: SecretString,
    data_path: PathBuf,
    logs_path: PathBuf,
    runtime_path: PathBuf,
) -> DockerInstanceSpec {
    DockerInstanceSpec {
        instance_id: instance_id.to_string(),
        protocol: Protocol::Mysql,
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
            target: "/var/run/mysqld".to_string(),
            read_only: false,
        }],
        socket_bridges: Vec::new(),
        env: vec![
            DockerEnv {
                key: "MYSQL_DATABASE".to_string(),
                value: SecretString::from(database.to_string()),
            },
            DockerEnv {
                key: "MYSQL_ROOT_PASSWORD".to_string(),
                value: root_password,
            },
        ],
        // The gateway terminates public TLS and authenticates clients itself. The
        // database is reachable only through its per-instance Unix socket.
        command: vec![
            "--skip-networking=ON".to_string(),
            "--mysql-native-password=ON".to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_private_mysql_data_and_socket_mounts() {
        let spec = instance_spec(
            "inst_mysql_1",
            "mysql:8.4",
            "mysql_1",
            SecretString::from("root-secret"),
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/logs"),
            PathBuf::from("/tmp/run"),
        );

        assert_eq!(spec.protocol, Protocol::Mysql);
        assert_eq!(spec.data_target, "/var/lib/mysql");
        assert_eq!(spec.extra_mounts[0].target, "/var/run/mysqld");
        assert_eq!(
            spec.command,
            ["--skip-networking=ON", "--mysql-native-password=ON"]
        );
        assert!(spec.socket_bridges.is_empty());
        assert!(spec.env.iter().all(|env| env.key != "MYSQL_PASSWORD"));
        assert!(spec.env.iter().all(|env| env.key != "MYSQL_USER"));
    }
}
