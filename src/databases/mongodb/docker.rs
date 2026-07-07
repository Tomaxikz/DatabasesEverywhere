use std::path::PathBuf;

use secrecy::SecretString;

use crate::{
    runtime::docker::{DockerEnv, DockerInstanceSpec},
    shared::protocol::Protocol,
};

pub struct MongodbAuth {
    pub username: String,
    pub password: SecretString,
    pub root_password: SecretString,
}

pub fn instance_spec(
    instance_id: &str,
    image: &str,
    database: &str,
    auth: MongodbAuth,
    data_path: PathBuf,
    logs_path: PathBuf,
) -> DockerInstanceSpec {
    DockerInstanceSpec {
        instance_id: instance_id.to_string(),
        protocol: Protocol::Mongodb,
        image: image.to_string(),
        project_id: None,
        user: None,
        working_dir: None,
        entrypoint: None,
        cpu_cores: 1.0,
        memory_mib: 1024,
        disk_mib: 10240,
        pids_limit: None,
        container_port: Protocol::Mongodb.default_container_port(),
        public_backend_port: None,
        data_path,
        data_target: "/data/db".to_string(),
        logs_path,
        logs_target: "/logs".to_string(),
        extra_mounts: Vec::new(),
        env: vec![
            DockerEnv {
                key: "DBE_MONGO_USER".to_string(),
                value: SecretString::from(auth.username),
            },
            DockerEnv {
                key: "DBE_MONGO_PASSWORD".to_string(),
                value: auth.password,
            },
            DockerEnv {
                key: "DBE_MONGO_DATABASE".to_string(),
                value: SecretString::from(database.to_string()),
            },
            DockerEnv {
                key: "DBE_MONGO_ROOT_USER".to_string(),
                value: SecretString::from("dbe_root".to_string()),
            },
            DockerEnv {
                key: "DBE_MONGO_ROOT_PASSWORD".to_string(),
                value: auth.root_password,
            },
        ],
        command: vec![
            "mongod".to_string(),
            "--auth".to_string(),
            "--bind_ip".to_string(),
            "0.0.0.0".to_string(),
            "--setParameter".to_string(),
            "diagnosticDataCollectionEnabled=false".to_string(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_mongo_data_directory_without_entrypoint_init_mount() {
        let spec = instance_spec(
            "inst_mongo_1",
            "mongo:7",
            "mongo_1",
            MongodbAuth {
                username: "app_mongo_1".to_string(),
                password: SecretString::from("tenant-secret"),
                root_password: SecretString::from("root-secret"),
            },
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/logs"),
        );

        assert_eq!(spec.protocol, Protocol::Mongodb);
        assert_eq!(spec.data_target, "/data/db");
        assert_eq!(spec.container_port, 27017);
        assert_eq!(spec.public_backend_port, None);
        assert!(spec.extra_mounts.is_empty());
        assert!(spec.env.iter().any(|env| env.key == "DBE_MONGO_USER"));
        assert!(
            spec.env
                .iter()
                .any(|env| env.key == "DBE_MONGO_ROOT_PASSWORD")
        );
        assert!(
            !spec
                .env
                .iter()
                .any(|env| env.key.starts_with("MONGO_INITDB_"))
        );
        assert_eq!(
            spec.command,
            [
                "mongod",
                "--auth",
                "--bind_ip",
                "0.0.0.0",
                "--setParameter",
                "diagnosticDataCollectionEnabled=false"
            ]
        );
    }
}
