use crate::{
    instances::metadata::{
        DatabaseIdentity, DesiredInstanceState, InstanceMetadata, InstanceStatus, PublicEndpoint,
        RuntimeKind, RuntimeMetadata, SCHEMA_VERSION,
    },
    placement::DeploymentMode,
    shared::{backend::BackendEndpoint, limits::InstanceLimits, protocol::Protocol},
};

/// Complete, neutral instance metadata for tests that only care about a few fields.
///
/// Callers should override the fields involved in the behavior under test. Keeping
/// the unrelated defaults here makes schema additions a one-line test maintenance
/// change instead of forcing every fixture to repeat the full durable record.
pub(crate) fn metadata(instance_id: &str, protocol: Protocol) -> InstanceMetadata {
    let port = protocol.default_container_port();
    InstanceMetadata {
        schema_version: SCHEMA_VERSION,
        instance_id: instance_id.to_string(),
        deployment_mode: DeploymentMode::Dedicated,
        runtime_id: String::new(),
        protocol,
        status: InstanceStatus::Running,
        desired_state: DesiredInstanceState::Running,
        disk_limit_blocked: false,
        public: PublicEndpoint {
            host: "db.example.com".to_string(),
            port,
        },
        backend: BackendEndpoint::DockerTcp {
            host: "127.0.0.1".to_string(),
            port,
        },
        runtime: RuntimeMetadata {
            kind: RuntimeKind::Docker,
            container_name: format!("dbe-{}-{instance_id}", protocol.as_str()),
            network_mode: "none".to_string(),
        },
        database: DatabaseIdentity {
            name: "database".to_string(),
            username: "user".to_string(),
        },
        route_key_sha256: None,
        mariadb_native_password_sha1_stage2: None,
        mariadb_root_password: None,
        mysql_native_password_sha1_stage2: None,
        mysql_root_password: None,
        mongodb_root_password: None,
        postgres_admin_password: None,
        tenant_password: None,
        limits: InstanceLimits::default(),
        image: None,
        database_version: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    }
}

/// Shared MySQL tenant used by lifecycle, job-lock, and quota tests.
pub(crate) fn shared_metadata() -> InstanceMetadata {
    let mut metadata = metadata("tenant-a", Protocol::Mysql);
    metadata.deployment_mode = DeploymentMode::Shared;
    metadata.runtime_id = "pool-a".to_string();
    metadata.backend = BackendEndpoint::UnixSocket {
        socket_path: "/run/mysql.sock".to_string(),
    };
    metadata.runtime.container_name = "pool-a".to_string();
    metadata.database.name = "app_a".to_string();
    metadata.database.username = "tenant_a".to_string();
    metadata
}
