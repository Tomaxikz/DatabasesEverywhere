use super::{
    DeploymentMode, ENGINE_RUNTIME_SCHEMA_VERSION, EngineRuntime, EngineRuntimeStatus,
    RuntimeReservation,
};
use crate::{instances::test_support::metadata, shared::protocol::Protocol};

/// Neutral shared runtime; callers override the fields relevant to their case.
pub(crate) fn runtime(runtime_id: &str, protocol: Protocol, image: &str) -> EngineRuntime {
    let instance = metadata(runtime_id, protocol);
    EngineRuntime {
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
        compatibility_key: format!("{}:{image}", protocol.as_str()),
        max_tenants: 10,
        reserved: RuntimeReservation::default(),
        admin_secret: None,
        created_at: instance.created_at,
        updated_at: instance.updated_at,
    }
}
