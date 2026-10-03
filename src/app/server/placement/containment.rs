//! Shared-pool containment for HTTP operations and boot reconciliation alike.
//!
//! Callers hold the runtime operation lock. This coordinator owns fencing,
//! durable quarantine, and verified stopping; transport handlers only report
//! its outcome and must not implement a separate containment sequence.

use std::{collections::HashSet, time::Duration};

use crate::{
    runtime::docker::DockerContainerStatus,
    server::metadata::{DesiredInstanceState, InstanceStatus},
    server::placement::{DeploymentMode, EngineRuntime, EngineRuntimeStatus},
    state::AppState,
    storage::quarantine::QuarantineKind,
    utils::time::now_rfc3339,
};

const STOP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Default)]
pub(crate) struct ContainmentReport {
    pub routes_fenced: bool,
    pub quarantine_persisted: bool,
    pub pool_stopped: bool,
    pub errors: Vec<String>,
}

impl ContainmentReport {
    pub(crate) fn contained(&self) -> bool {
        self.routes_fenced && self.quarantine_persisted && self.pool_stopped
    }

    pub(crate) fn summary(&self) -> String {
        if self.errors.is_empty() {
            return "completed".to_string();
        }
        self.errors.join("; ")
    }
}

/// Fails one shared runtime closed while its runtime operation lock is held.
///
/// Routes are removed before any fallible durable or container operation. A
/// durable `Quarantined` state blocks ordinary startup. Boot recovery may only
/// release it after full validation; the physical pool is force-stopped if
/// graceful shutdown is inconclusive.
pub(crate) async fn contain_locked(
    state: &AppState,
    snapshot: &EngineRuntime,
    reason: &str,
    kind: Option<QuarantineKind>,
) -> ContainmentReport {
    let tenant_ids = tenant_ids(state, &snapshot.runtime_id).await;
    for instance_id in &tenant_ids {
        crate::server::sessions::fence(
            &state.instances,
            &state.gateway_supervisor.tenant_sessions(),
            instance_id,
        )
        .await;
    }

    let mut report = ContainmentReport {
        routes_fenced: true,
        ..ContainmentReport::default()
    };
    report.quarantine_persisted =
        persist_quarantine(state, snapshot, &tenant_ids, kind, &mut report).await;
    report.pool_stopped = match stop_pool(state, snapshot).await {
        Ok(()) => true,
        Err(error) => {
            report.errors.push(error);
            false
        }
    };

    if kind.is_none() && snapshot.status == EngineRuntimeStatus::Quarantined && report.contained() {
        tracing::info!(event = "audit shared_runtime_quarantine_reconciled",
            runtime_id = %snapshot.runtime_id, protocol = %snapshot.protocol, %reason,
            "confirmed existing quarantine before recovery; routes fenced and pool stopped");
        return report;
    }
    tracing::error!(
        event = "audit shared_runtime_contained",
        runtime_id = %snapshot.runtime_id,
        protocol = %snapshot.protocol,
        %reason,
        routes_fenced = report.routes_fenced,
        quarantine_persisted = report.quarantine_persisted,
        pool_stopped = report.pool_stopped,
        errors = %report.summary(),
        contained = report.contained(),
        "fenced every shared tenant and contained its physical pool"
    );
    report
}

async fn tenant_ids(state: &AppState, runtime_id: &str) -> Vec<String> {
    let mut ids = state
        .instances
        .list()
        .await
        .into_iter()
        .filter(|metadata| {
            metadata.deployment_mode == DeploymentMode::Shared
                && metadata.runtime_id() == runtime_id
        })
        .map(|metadata| metadata.instance_id)
        .collect::<HashSet<_>>();
    match state.placements.tenants(runtime_id).await {
        Ok(persisted) => ids.extend(persisted),
        Err(error) => tracing::error!(
            event = "audit shared_runtime_containment_tenant_lookup_failed",
            runtime_id,
            %error,
            "continued containment using the loaded route store"
        ),
    }
    ids.into_iter().collect()
}

async fn persist_quarantine(
    state: &AppState,
    snapshot: &EngineRuntime,
    tenant_ids: &[String],
    kind: Option<QuarantineKind>,
    report: &mut ContainmentReport,
) -> bool {
    let persisted = persist_runtime_quarantine(state, snapshot, kind, report).await;
    persist_tenant_quarantines(state, snapshot, tenant_ids, kind, report).await;
    persisted
}

async fn persist_runtime_quarantine(
    state: &AppState,
    snapshot: &EngineRuntime,
    kind: Option<QuarantineKind>,
    report: &mut ContainmentReport,
) -> bool {
    let mut runtime = match state.placements.get(&snapshot.runtime_id).await {
        Ok(Some(runtime))
            if runtime.deployment_mode == DeploymentMode::Shared
                && runtime.protocol == snapshot.protocol
                && runtime.created_at == snapshot.created_at =>
        {
            runtime
        }
        Ok(Some(_)) => {
            report
                .errors
                .push("runtime identity changed before quarantine persistence".to_string());
            return false;
        }
        Ok(None) => {
            report
                .errors
                .push("runtime disappeared before quarantine persistence".to_string());
            return false;
        }
        Err(error) => {
            report
                .errors
                .push(format!("failed to load runtime for quarantine: {error}"));
            return false;
        }
    };
    runtime.status = EngineRuntimeStatus::Quarantined;
    runtime.updated_at = now_rfc3339();
    let saved = match kind {
        Some(kind) => state.placements.save_quarantined(&runtime, kind).await,
        None => state.placements.save(&runtime).await,
    };
    let Err(error) = saved else {
        return true;
    };
    let confirmed = quarantine_confirmed_after_failed_save(state, snapshot, &runtime, kind).await;
    if !confirmed {
        report
            .errors
            .push(format!("failed to persist runtime quarantine: {error}"));
    }
    confirmed
}

async fn quarantine_confirmed_after_failed_save(
    state: &AppState,
    snapshot: &EngineRuntime,
    runtime: &EngineRuntime,
    kind: Option<QuarantineKind>,
) -> bool {
    let recorded = match kind {
        Some(kind) => state
            .placements
            .quarantine_recorded(runtime, kind)
            .await
            .unwrap_or(false),
        None => true,
    };
    if !recorded {
        return false;
    }
    state
        .placements
        .get(&snapshot.runtime_id)
        .await
        .ok()
        .flatten()
        .is_some_and(|stored| {
            stored.status == EngineRuntimeStatus::Quarantined
                && stored.protocol == snapshot.protocol
                && stored.created_at == snapshot.created_at
        })
}

async fn persist_tenant_quarantines(
    state: &AppState,
    snapshot: &EngineRuntime,
    tenant_ids: &[String],
    kind: Option<QuarantineKind>,
    report: &mut ContainmentReport,
) {
    for instance_id in tenant_ids {
        let mut metadata = match state.manager.get_persisted(instance_id).await {
            Ok(Some(metadata))
                if metadata.deployment_mode == DeploymentMode::Shared
                    && metadata.runtime_id() == snapshot.runtime_id
                    && metadata.protocol == snapshot.protocol =>
            {
                metadata
            }
            Ok(_) => continue,
            Err(error) => {
                report.errors.push(format!(
                    "failed to load tenant {instance_id} for quarantine: {error}"
                ));
                continue;
            }
        };
        if metadata.status == InstanceStatus::Deleting {
            continue;
        }
        metadata.status = InstanceStatus::Quarantined;
        metadata.desired_state = DesiredInstanceState::Stopped;
        metadata.updated_at = now_rfc3339();
        let saved = match kind {
            Some(kind) => state.manager.quarantine(metadata, kind).await,
            None => state.manager.upsert_fenced(metadata).await,
        };
        if let Err(error) = saved {
            report.errors.push(format!(
                "failed to persist tenant {instance_id} quarantine: {error}"
            ));
        }
    }
}

pub(crate) async fn stop_pool(state: &AppState, runtime: &EngineRuntime) -> Result<(), String> {
    let graceful = tokio::time::timeout(
        STOP_TIMEOUT,
        state
            .docker
            .stop_with_timeout(runtime.protocol, &runtime.runtime_id, STOP_TIMEOUT),
    )
    .await;
    match graceful {
        Ok(Ok(_)) => match pool_is_stopped(state, runtime).await {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => tracing::warn!(
                runtime_id = %runtime.runtime_id,
                protocol = %runtime.protocol,
                %error,
                "shared-pool shutdown could not be verified; forcing shutdown"
            ),
        },
        Ok(Err(error)) if error.is_not_running() || error.is_not_found() => return Ok(()),
        Ok(Err(error)) => tracing::warn!(
            runtime_id = %runtime.runtime_id,
            protocol = %runtime.protocol,
            %error,
            "graceful shared-pool containment failed; forcing shutdown"
        ),
        Err(_) => tracing::warn!(
            runtime_id = %runtime.runtime_id,
            protocol = %runtime.protocol,
            "graceful shared-pool containment timed out; forcing shutdown"
        ),
    }

    match tokio::time::timeout(
        STOP_TIMEOUT,
        state.docker.kill(runtime.protocol, &runtime.runtime_id),
    )
    .await
    {
        Ok(Ok(_)) => match pool_is_stopped(state, runtime).await {
            Ok(true) => Ok(()),
            Ok(false) => Err("shared pool remained active after forced shutdown".to_string()),
            Err(error) => Err(format!(
                "forced shutdown completed but could not be verified: {error}"
            )),
        },
        Ok(Err(error)) if error.is_not_running() || error.is_not_found() => Ok(()),
        Ok(Err(error)) => Err(format!("failed to stop or kill shared pool: {error}")),
        Err(_) => Err("timed out stopping and killing shared pool".to_string()),
    }
}

async fn pool_is_stopped(state: &AppState, runtime: &EngineRuntime) -> Result<bool, String> {
    match state
        .docker
        .inspect_instance(runtime.protocol, &runtime.runtime_id)
        .await
    {
        Ok(inspection) => Ok(!matches!(
            inspection.status,
            DockerContainerStatus::Running | DockerContainerStatus::Starting
        )),
        Err(error) if error.is_not_found() => Ok(true),
        Err(error) => Err(format!(
            "could not verify shared pool shutdown before forced kill: {error}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::ContainmentReport;

    #[test]
    fn containment_requires_every_safety_boundary() {
        for routes_fenced in [false, true] {
            for quarantine_persisted in [false, true] {
                for pool_stopped in [false, true] {
                    let report = ContainmentReport {
                        routes_fenced,
                        quarantine_persisted,
                        pool_stopped,
                        errors: Vec::new(),
                    };
                    assert_eq!(
                        report.contained(),
                        routes_fenced && quarantine_persisted && pool_stopped,
                    );
                }
            }
        }
    }
}
