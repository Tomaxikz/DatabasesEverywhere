use super::{
    DeploymentMode, ENGINE_RUNTIME_SCHEMA_VERSION, EngineRuntime, EngineRuntimeStatus,
    RuntimeReservation,
};
use crate::{instances::test_support::metadata, shared::protocol::Protocol};

/// Neutral shared runtime; callers override the fields relevant to their case.
pub(crate) fn runtime(runtime_id: &str, protocol: Protocol, image: &str) -> EngineRuntime {
    let instance = metadata(runtime_id, protocol);
    EngineRuntime {
        pending_image: None,
        desired_state: crate::instances::metadata::DesiredInstanceState::Running,
        owner: Some(owner(runtime_id)),
        schema_version: ENGINE_RUNTIME_SCHEMA_VERSION,
        runtime_id: runtime_id.to_string(),
        protocol,
        deployment_mode: DeploymentMode::Shared,
        status: EngineRuntimeStatus::Running,
        backend: instance.backend,
        runtime: instance.runtime,
        limits: instance.limits,
        image: image.to_string(),
        database_version: None,
        compatibility: None,

        max_tenants: 10,
        reserved: RuntimeReservation::default(),
        admin_secret: None,
        created_at: instance.created_at,
        updated_at: instance.updated_at,
    }
}

pub(crate) fn owner(server_id: &str) -> super::PoolOwner {
    super::PoolOwner {
        panel_id: "test-panel".into(),
        server_id: server_id.into(),
    }
}
