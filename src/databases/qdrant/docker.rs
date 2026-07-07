use std::path::PathBuf;

use secrecy::SecretString;

use crate::{
    runtime::docker::{DockerEnv, DockerInstanceSpec},
    shared::protocol::Protocol,
};

pub fn instance_spec(
    instance_id: &str,
    image: &str,
    api_key: SecretString,
    data_path: PathBuf,
    logs_path: PathBuf,
) -> DockerInstanceSpec {
    DockerInstanceSpec {
        instance_id: instance_id.to_string(),
        protocol: Protocol::Qdrant,
        image: image.to_string(),
        project_id: None,
        user: None,
        working_dir: None,
        entrypoint: None,
        cpu_cores: 1.0,
        memory_mib: 1024,
        disk_mib: 10240,
        pids_limit: None,
        container_port: Protocol::Qdrant.default_container_port(),
        public_backend_port: None,
        data_path,
        data_target: "/dbe-qdrant".to_string(),
        logs_path,
        logs_target: "/logs".to_string(),
        extra_mounts: Vec::new(),
        env: vec![
            DockerEnv {
                key: "QDRANT__SERVICE__HOST".to_string(),
                value: SecretString::from("0.0.0.0"),
            },
            DockerEnv {
                key: "QDRANT__SERVICE__HTTP_PORT".to_string(),
                value: SecretString::from("6333"),
            },
            DockerEnv {
                key: "QDRANT__SERVICE__GRPC_PORT".to_string(),
                value: SecretString::from("6334"),
            },
            DockerEnv {
                key: "QDRANT__SERVICE__API_KEY".to_string(),
                value: api_key,
            },
            DockerEnv {
                key: "QDRANT__STORAGE__STORAGE_PATH".to_string(),
                value: SecretString::from("/dbe-qdrant/storage"),
            },
            DockerEnv {
                key: "QDRANT__STORAGE__SNAPSHOTS_PATH".to_string(),
                value: SecretString::from("/dbe-qdrant/snapshots"),
            },
            DockerEnv {
                key: "QDRANT_INIT_FILE_PATH".to_string(),
                value: SecretString::from("/dbe-qdrant/.qdrant-initialized"),
            },
        ],
        command: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn uses_qdrant_storage_and_grpc_port() {
        let spec = instance_spec(
            "inst_qdrant_1",
            "qdrant/qdrant:v1.18.2",
            SecretString::from("api-key"),
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/logs"),
        );

        assert_eq!(spec.protocol, Protocol::Qdrant);
        assert_eq!(spec.data_target, "/dbe-qdrant");
        assert_eq!(spec.working_dir, None);
        assert_eq!(spec.entrypoint, None);
        assert_eq!(spec.container_port, 6334);
        assert_eq!(spec.public_backend_port, None);
        assert!(
            spec.env
                .iter()
                .any(|env| env.key == "QDRANT__SERVICE__API_KEY")
        );
        assert!(
            spec.env
                .iter()
                .any(|env| env.key == "QDRANT__SERVICE__GRPC_PORT")
        );
        assert!(spec.env.iter().any(|env| {
            env.key == "QDRANT__STORAGE__SNAPSHOTS_PATH"
                && env.value.expose_secret() == "/dbe-qdrant/snapshots"
        }));
        assert!(spec.env.iter().any(|env| {
            env.key == "QDRANT_INIT_FILE_PATH"
                && env.value.expose_secret() == "/dbe-qdrant/.qdrant-initialized"
        }));
    }
}
