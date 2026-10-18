use std::path::PathBuf;

use secrecy::SecretString;

use crate::{
    databases::protocol::Protocol,
    runtime::docker::{DockerEnv, DockerInstanceSpec, DockerMount},
};

pub fn instance_spec(
    instance_id: &str,
    image: &str,
    database: &str,
    root_password: SecretString,
    data_path: PathBuf,
    runtime_path: PathBuf,
) -> DockerInstanceSpec {
    build_spec(
        instance_id,
        image,
        Some(database),
        root_password,
        data_path,
        runtime_path,
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
    database: Option<&str>,
    root_password: SecretString,
    data_path: PathBuf,
    runtime_path: PathBuf,
) -> DockerInstanceSpec {
    let mut env = vec![DockerEnv::new("MYSQL_ROOT_PASSWORD", root_password)];
    if let Some(database) = database {
        env.insert(
            0,
            DockerEnv::new("MYSQL_DATABASE", SecretString::from(database.to_string())),
        );
    }

    DockerInstanceSpec {
        extra_mounts: vec![DockerMount {
            source: runtime_path,
            target: "/var/run/mysqld".to_string(),
            read_only: false,
        }],
        env,
        command: vec![
            "--skip-networking=ON".to_string(),
            "--skip-name-resolve".to_string(),
            "--skip-mysqlx".to_string(),
            "--skip-log-bin".to_string(),
            "--innodb-file-per-table=ON".to_string(),
        ],
        ..DockerInstanceSpec::with_defaults(
            runtime_id,
            Protocol::Mysql,
            image,
            data_path,
            "/var/lib/mysql",
        )
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
            PathBuf::from("/tmp/run"),
        );

        assert_eq!(spec.protocol, Protocol::Mysql);
        assert_eq!(spec.data_target, "/var/lib/mysql");
        assert_eq!(spec.extra_mounts[0].target, "/var/run/mysqld");
        assert_eq!(
            spec.command,
            [
                "--skip-networking=ON",
                "--skip-name-resolve",
                "--skip-mysqlx",
                "--skip-log-bin",
                "--innodb-file-per-table=ON"
            ]
        );
        assert!(spec.socket_bridges.is_empty());
        assert!(spec.env.iter().all(|env| env.key != "MYSQL_PASSWORD"));
        assert!(spec.env.iter().all(|env| env.key != "MYSQL_USER"));
    }

    #[test]
    fn shared_runtime_bootstraps_only_root_auth() {
        let spec = shared_spec(
            "pool_mysql_1",
            "mysql:8.4",
            SecretString::from("root-secret"),
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/run"),
        );

        assert_eq!(spec.env.len(), 1);
        assert_eq!(spec.env[0].key, "MYSQL_ROOT_PASSWORD");
    }
}
