use std::path::PathBuf;

use secrecy::SecretString;

use crate::{
    runtime::docker::{DockerEnv, DockerInstanceSpec, DockerMount},
    shared::{backend::CONTAINER_SOCKET_DIRECTORY, protocol::Protocol},
};

pub struct MongodbAuth {
    pub username: String,
    pub password: SecretString,
    pub root_password: SecretString,
}

pub const INTERNAL_ROOT_USERNAME: &str = "dbe_root";

struct TenantBootstrap {
    database: String,
    username: String,
    password: SecretString,
}

pub fn instance_spec(
    instance_id: &str,
    image: &str,
    database: &str,
    auth: MongodbAuth,
    data_path: PathBuf,
    runtime_path: PathBuf,
) -> DockerInstanceSpec {
    build_spec(
        instance_id,
        image,
        Some(TenantBootstrap {
            database: database.to_string(),
            username: auth.username,
            password: auth.password,
        }),
        auth.root_password,
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

#[allow(clippy::too_many_arguments)]
fn build_spec(
    runtime_id: &str,
    image: &str,
    tenant: Option<TenantBootstrap>,
    root_password: SecretString,
    data_path: PathBuf,
    runtime_path: PathBuf,
) -> DockerInstanceSpec {
    let shared = tenant.is_none();
    let mut env = Vec::new();
    if let Some(tenant) = tenant {
        env.extend([
            DockerEnv {
                key: "DBE_MONGO_USER".to_string(),
                value: SecretString::from(tenant.username),
            },
            DockerEnv {
                key: "DBE_MONGO_PASSWORD".to_string(),
                value: tenant.password,
            },
            DockerEnv {
                key: "DBE_MONGO_DATABASE".to_string(),
                value: SecretString::from(tenant.database),
            },
        ]);
    }
    env.extend([
        DockerEnv {
            key: "DBE_MONGO_ROOT_USER".to_string(),
            value: SecretString::from(INTERNAL_ROOT_USERNAME.to_string()),
        },
        DockerEnv {
            key: "DBE_MONGO_ROOT_PASSWORD".to_string(),
            value: root_password,
        },
    ]);

    let mut command = vec![
        "mongod".to_string(),
        "--auth".to_string(),
        "--bind_ip".to_string(),
        "127.0.0.1".to_string(),
        "--unixSocketPrefix".to_string(),
        CONTAINER_SOCKET_DIRECTORY.to_string(),
        "--setParameter".to_string(),
        "diagnosticDataCollectionEnabled=false".to_string(),
    ];
    if shared {
        // Tenant workloads do not need server-side JavaScript. Disabling it on
        // shared engines removes an avoidable cross-tenant resource-abuse and
        // code-execution surface while mongosh maintenance scripts continue to
        // run client-side.
        command.push("--noscripting".to_string());
    }

    DockerInstanceSpec {
        instance_id: runtime_id.to_string(),
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
        data_path,
        data_target: "/data/db".to_string(),
        extra_mounts: vec![DockerMount {
            source: runtime_path,
            target: CONTAINER_SOCKET_DIRECTORY.to_string(),
            read_only: false,
        }],
        socket_bridges: Vec::new(),
        env,
        command,
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
            PathBuf::from("/tmp/run"),
        );

        assert_eq!(spec.protocol, Protocol::Mongodb);
        assert_eq!(spec.data_target, "/data/db");
        assert_eq!(spec.extra_mounts[0].target, CONTAINER_SOCKET_DIRECTORY);
        assert!(spec.socket_bridges.is_empty());
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
                "127.0.0.1",
                "--unixSocketPrefix",
                "/run/dbev",
                "--setParameter",
                "diagnosticDataCollectionEnabled=false"
            ]
        );
    }

    #[test]
    fn shared_runtime_bootstraps_only_root_auth() {
        let spec = shared_spec(
            "pool_mongo_1",
            "mongo:8",
            SecretString::from("root-secret"),
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/run"),
        );
        let keys = spec
            .env
            .iter()
            .map(|env| env.key.as_str())
            .collect::<Vec<_>>();

        assert_eq!(keys, ["DBE_MONGO_ROOT_USER", "DBE_MONGO_ROOT_PASSWORD"]);
        assert!(keys.iter().all(|key| !key.contains("DATABASE")));
        assert!(spec.command.iter().any(|arg| arg == "--noscripting"));
    }
}
