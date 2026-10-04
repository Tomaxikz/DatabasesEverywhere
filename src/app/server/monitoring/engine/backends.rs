use futures::future::BoxFuture;

use super::{Capabilities, CollectError, EngineSample};
use crate::{
    databases::protocol::Protocol, runtime::docker::DockerRuntime, server::placement::EngineRuntime,
};

/// Engine-specific collection only: generation checks, failure backoff, tenant
/// attribution, and committing a successful checkpoint belong to the sampler.
pub(crate) trait EngineTelemetry: Sync {
    fn requires_preparation(&self) -> bool;

    /// `None` leaves existing capabilities unchanged when no setup is needed.
    fn prepare<'a>(
        &self,
        docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
    ) -> BoxFuture<'a, Result<Option<Capabilities>, CollectError>>;

    fn collect<'a>(
        &self,
        docker: &'a DockerRuntime,
        runtime: &'a EngineRuntime,
        capabilities: Capabilities,
        checkpoint: Option<u64>,
    ) -> BoxFuture<'a, Result<EngineSample, CollectError>>;
}

pub(super) fn for_protocol(protocol: Protocol) -> Option<&'static dyn EngineTelemetry> {
    protocol.engine().telemetry()
}

#[cfg(test)]
mod tests {
    use super::super::SampleMode;
    use super::*;

    fn runtime(protocol: Protocol) -> EngineRuntime {
        let mut runtime =
            crate::server::placement::test_support::runtime("pool_test", protocol, "test");
        // Fail before executing any command, even if a local daemon is running.
        runtime.admin_secret = None;
        runtime
    }

    fn assert_send<T: Send>(value: T) -> T {
        value
    }

    #[tokio::test]
    async fn registry_preserves_preparation_and_send_contracts() {
        let docker = DockerRuntime::offline_for_tests(&Default::default(), false);
        for protocol in [Protocol::Mysql, Protocol::Mariadb, Protocol::Clickhouse] {
            let backend = for_protocol(protocol).unwrap();
            let runtime = runtime(protocol);
            let result = assert_send(backend.prepare(&docker, &runtime)).await;
            if protocol == Protocol::Clickhouse {
                assert!(!backend.requires_preparation());
                assert_eq!(result.unwrap(), None);
            } else {
                assert!(backend.requires_preparation());
                assert!(matches!(result, Err(CollectError::Unavailable)));
            }
            let result = assert_send(backend.collect(
                &docker,
                &runtime,
                Capabilities {
                    cpu: true,
                    ..Capabilities::default()
                },
                Some(42),
            ))
            .await;
            assert!(matches!(result, Err(CollectError::Unavailable)));
        }
    }

    #[test]
    fn registry_rejects_engines_without_attributable_cpu_collectors() {
        for protocol in [
            Protocol::Postgres,
            Protocol::Mongodb,
            Protocol::Redis,
            Protocol::Valkey,
            Protocol::Qdrant,
        ] {
            assert!(for_protocol(protocol).is_none());
        }
    }

    #[tokio::test]
    async fn mysql_without_capabilities_does_not_execute_a_command() {
        let docker = DockerRuntime::offline_for_tests(&Default::default(), false);
        let runtime = runtime(Protocol::Mysql);
        let capabilities = Capabilities::default();
        let sample = for_protocol(runtime.protocol)
            .unwrap()
            .collect(&docker, &runtime, capabilities, Some(42))
            .await
            .unwrap();

        assert_eq!(sample.capabilities, capabilities);
        assert_eq!(sample.mode, SampleMode::Cumulative);
        assert!(sample.rows.is_empty());
        assert_eq!(sample.next_clickhouse_checkpoint, None);
    }
}
