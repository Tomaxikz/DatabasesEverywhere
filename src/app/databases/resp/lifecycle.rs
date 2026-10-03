use crate::{
    databases::engine::{DedicatedSpecInput, EngineLifecycle, RouteIdentity},
    runtime::docker::DockerInstanceSpec,
    utils::protocol::Protocol,
};

use super::{
    engine::{Redis, Valkey},
    instance_spec,
};

impl EngineLifecycle for Redis {
    fn acl_file_stage(&self) -> Option<&'static str> {
        Some("writing Redis ACL configuration")
    }

    fn route_identity(&self) -> RouteIdentity {
        RouteIdentity::Username
    }

    fn dedicated_spec(&self, input: DedicatedSpecInput<'_>) -> DockerInstanceSpec {
        instance_spec(
            Protocol::Redis,
            input.instance_id,
            input.image,
            input.data_path,
            input.sockets,
        )
    }

    fn major_upgrade_block(&self) -> Option<&'static str> {
        Some(
            "redis major upgrades are blocked because Redis uses physical archive restore here; create a fresh Redis instance or use a dedicated Redis migration workflow",
        )
    }
}

impl EngineLifecycle for Valkey {
    fn acl_file_stage(&self) -> Option<&'static str> {
        Some("writing Valkey ACL configuration")
    }

    fn route_identity(&self) -> RouteIdentity {
        RouteIdentity::Username
    }

    fn dedicated_spec(&self, input: DedicatedSpecInput<'_>) -> DockerInstanceSpec {
        instance_spec(
            Protocol::Valkey,
            input.instance_id,
            input.image,
            input.data_path,
            input.sockets,
        )
    }

    fn major_upgrade_block(&self) -> Option<&'static str> {
        Some(
            "valkey major upgrades are blocked because Valkey uses physical archive restore here; create a fresh Valkey instance or use a dedicated Valkey migration workflow",
        )
    }
}
