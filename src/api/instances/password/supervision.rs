use std::future::Future;

use tokio::task::JoinError;

use super::{password_quarantine_summary, quarantine_instance};
use crate::{
    api::routes::AppState,
    instances::{locks::InstanceLocks, metadata::InstanceMetadata},
    shared::protocol::Protocol,
};

pub(super) async fn run_password_worker_with_panic_recovery<T, W, R, RF>(
    locks: &InstanceLocks,
    instance_id: &str,
    worker: W,
    recovery: R,
) -> T
where
    T: Send + 'static,
    W: Future<Output = T> + Send + 'static,
    R: FnOnce(JoinError) -> RF + Send,
    RF: Future<Output = T> + Send,
{
    let _operation = locks.lock(instance_id).await;
    match tokio::spawn(worker).await {
        Ok(result) => result,
        Err(error) => recovery(error).await,
    }
}

pub(super) enum PasswordWorkerPanicRecoveryPlan {
    QuarantineDurable(Box<InstanceMetadata>),
    StopWithoutPersistence {
        protocol: Option<Protocol>,
        reason: String,
    },
}

pub(super) fn classify_password_worker_panic_recovery(
    persisted: Result<Option<InstanceMetadata>, String>,
    stale_store: Option<&InstanceMetadata>,
) -> PasswordWorkerPanicRecoveryPlan {
    match persisted {
        Ok(Some(metadata)) => {
            PasswordWorkerPanicRecoveryPlan::QuarantineDurable(Box::new(metadata))
        }
        Ok(None) => PasswordWorkerPanicRecoveryPlan::StopWithoutPersistence {
            protocol: stale_store.map(|metadata| metadata.protocol),
            reason: "the durable instance metadata row is missing".to_string(),
        },
        Err(reason) => PasswordWorkerPanicRecoveryPlan::StopWithoutPersistence {
            protocol: stale_store.map(|metadata| metadata.protocol),
            reason: format!("the durable instance metadata could not be read: {reason}"),
        },
    }
}

pub(super) async fn recover_password_worker_panic(state: &AppState, instance_id: &str) -> String {
    // This durable read runs while the supervisor still owns the instance
    // operation lock. A successful credential commit may have happened just
    // before the worker panicked, while the in-memory store is still stale.
    let persisted = state
        .manager
        .get_persisted(instance_id)
        .await
        .map_err(|error| error.to_string());
    let stale_store = state.instances.get(instance_id).await;
    match classify_password_worker_panic_recovery(persisted, stale_store.as_ref()) {
        PasswordWorkerPanicRecoveryPlan::QuarantineDurable(metadata) => {
            let result = quarantine_instance(state, &metadata).await;
            password_quarantine_summary(&result)
        }
        PasswordWorkerPanicRecoveryPlan::StopWithoutPersistence { protocol, reason } => {
            let stop_summary =
                stop_without_persisting_stale_credentials(state, instance_id, protocol).await;
            format!("{reason}; {stop_summary}")
        }
    }
}

async fn stop_without_persisting_stale_credentials(
    state: &AppState,
    instance_id: &str,
    protocol: Option<Protocol>,
) -> String {
    state.instances.remove(instance_id).await;

    let protocols = protocol
        .map(|protocol| vec![protocol])
        .unwrap_or_else(|| Protocol::ALL.to_vec());
    let mut failures = Vec::new();
    for protocol in protocols {
        match state.docker.stop(protocol, instance_id).await {
            Ok(_) => {}
            Err(error) if error.is_not_found() || error.is_not_running() => {}
            Err(error) => failures.push(format!("{protocol}: {error}")),
        }
    }

    state.instance_runtime_cache.remove(instance_id).await;
    state.resource_cache.remove(instance_id).await;
    state.monitoring_cache.invalidate().await;

    if failures.is_empty() {
        "the in-memory route was removed and the managed runtime was stopped without rewriting durable credentials"
            .to_string()
    } else {
        format!(
            "the in-memory route was removed without rewriting durable credentials, but runtime shutdown was incomplete: {}",
            failures.join("; ")
        )
    }
}
