use sqlx::SqlitePool;

use crate::{
    instances::metadata::{
        DatabaseIdentity, DesiredInstanceState, InstanceStatus, PublicEndpoint, RuntimeKind,
        RuntimeMetadata,
    },
    shared::{backend::BackendEndpoint, protocol::Protocol},
    storage::repositories::InstanceRepository,
};

/// Persists a complete dedicated instance through the production repository.
/// Tests that only need an instance foreign key should still exercise the
/// placement invariants instead of bypassing them with partial SQL rows.
pub(crate) async fn seed_dedicated_instance(
    pool: &SqlitePool,
    instance_id: &str,
    created_at: &str,
) {
    let mut metadata = crate::instances::test_support::metadata(instance_id, Protocol::Postgres);
    metadata.runtime_id = instance_id.to_string();
    metadata.status = InstanceStatus::Stopped;
    metadata.desired_state = DesiredInstanceState::Stopped;
    metadata.public = PublicEndpoint {
        host: "127.0.0.1".to_string(),
        port: 15_432,
    };
    metadata.backend = BackendEndpoint::UnixSocket {
        socket_path: format!("/run/dbev/{instance_id}/.s.PGSQL.5432"),
    };
    metadata.runtime = RuntimeMetadata {
        kind: RuntimeKind::Docker,
        container_name: format!("container_{instance_id}"),
        network_mode: "none".to_string(),
    };
    metadata.database = DatabaseIdentity {
        name: format!("db_{instance_id}"),
        username: format!("user_{instance_id}"),
    };
    metadata.created_at = created_at.to_string();
    metadata.updated_at = created_at.to_string();

    InstanceRepository::new(pool.clone())
        .upsert(&metadata)
        .await
        .unwrap();
}
