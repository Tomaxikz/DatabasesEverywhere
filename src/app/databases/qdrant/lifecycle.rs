use crate::{
    databases::engine::{DedicatedSpecInput, EngineLifecycle, RouteIdentity},
    runtime::docker::DockerInstanceSpec,
};

use super::{docker::instance_spec, engine::Qdrant};

impl EngineLifecycle for Qdrant {
    fn route_key_fingerprint(&self, daemon_secret: &[u8], password: &str) -> Option<String> {
        Some(crate::gateway::protocols::qdrant::route_key_fingerprint(
            daemon_secret,
            password,
        ))
    }

    fn route_identity(&self) -> RouteIdentity {
        RouteIdentity::RouteKey
    }

    fn dedicated_spec(&self, input: DedicatedSpecInput<'_>) -> DockerInstanceSpec {
        instance_spec(
            input.instance_id,
            input.image,
            input.password,
            input.data_path,
            input.sockets,
            input.socket_bridge_binary,
        )
    }

    fn major_upgrade_block(&self) -> Option<&'static str> {
        Some(
            "qdrant major upgrades are blocked because Qdrant snapshot compatibility is version-specific; create a fresh Qdrant instance or use a dedicated Qdrant migration workflow",
        )
    }
}
