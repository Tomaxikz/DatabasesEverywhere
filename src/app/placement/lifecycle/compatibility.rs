use futures::StreamExt;

use crate::{
    api::http::router::AppState,
    compatibility::{COMPATIBILITY_PROBE_REVISION, compatibility_profile},
    constants::MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY,
    placement::{
        EngineRuntime, EngineRuntimeStatus, RuntimeCompatibility, runtime as runtime_ops,
        tenant as tenant_ops,
    },
    shared::time::now_rfc3339,
};

use super::{isolate_runtime, save_runtime, shared_runtimes};

#[derive(Debug, Clone, Default)]
pub(crate) struct SharedCompatibilitySummary {
    pub(crate) checked: usize,
    pub(crate) reused: usize,
    pub(crate) probed: usize,
    pub(crate) failed: usize,
}

pub(crate) async fn sync_shared_compatibility(state: &AppState) -> SharedCompatibilitySummary {
    let runtimes = match shared_runtimes(&state.placements).await {
        Ok(runtimes) => runtimes
            .into_iter()
            .filter(|runtime| runtime.status == EngineRuntimeStatus::Running)
            .collect::<Vec<_>>(),
        Err(error) => {
            tracing::error!(%error, "failed to load shared pools for compatibility attestation");
            return SharedCompatibilitySummary {
                failed: 1,
                ..SharedCompatibilitySummary::default()
            };
        }
    };
    let outcomes = futures::stream::iter(runtimes)
        .map(|snapshot| attest_runtime(state, snapshot))
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut summary = SharedCompatibilitySummary::default();
    for outcome in outcomes {
        summary.checked += 1;
        match outcome {
            AttestOutcome::Reused => summary.reused += 1,
            AttestOutcome::Probed => summary.probed += 1,
            AttestOutcome::Failed => summary.failed += 1,
        }
    }
    summary
}

async fn attest_runtime(state: &AppState, snapshot: EngineRuntime) -> AttestOutcome {
    let runtime_id = snapshot.runtime_id.clone();
    let _operation = state.instance_locks.lock(&runtime_id).await;
    let Ok(Some(mut runtime)) = state.placements.get(&runtime_id).await else {
        return AttestOutcome::Failed;
    };
    if runtime.status != EngineRuntimeStatus::Running {
        return AttestOutcome::Failed;
    }
    match attest_locked(state, &mut runtime).await {
        Ok(false) => AttestOutcome::Reused,
        Ok(true) => {
            runtime.updated_at = now_rfc3339();
            let failed_runtime = runtime.clone();
            if let Err(error) = save_runtime(&state.placements, &state.manager, runtime).await {
                tracing::error!(runtime_id, %error, "failed to persist shared compatibility attestation");
                isolate_runtime(
                    state,
                    failed_runtime,
                    "shared compatibility attestation could not be persisted",
                )
                .await;
                AttestOutcome::Failed
            } else {
                AttestOutcome::Probed
            }
        }
        Err(error) => {
            isolate_runtime(state, runtime, &error).await;
            AttestOutcome::Failed
        }
    }
}

pub(crate) async fn attest_runtime_locked(
    state: &AppState,
    runtime: &mut EngineRuntime,
) -> Result<(), String> {
    attest_locked(state, runtime).await.map(|_| ())
}

async fn attest_locked(state: &AppState, runtime: &mut EngineRuntime) -> Result<bool, String> {
    tenant_ops::secure_pool(&state.docker, runtime)
        .await
        .map_err(|error| format!("shared pool isolation reconciliation failed: {error}"))?;
    let identity = state
        .docker
        .verified_compatibility_identity(runtime.protocol, &runtime.runtime_id)
        .await
        .map_err(|error| format!("shared pool identity inspection failed: {error}"))?
        .ok_or_else(|| "shared pool disappeared before compatibility attestation".to_string())?;
    if attestation_matches(runtime, &identity.id, &identity.image_id) {
        return Ok(false);
    }
    let probe = runtime_ops::probe_compatibility(&state.docker, runtime).await?;
    runtime.database_version = Some(probe.version);
    runtime.compatibility = Some(probe.compatibility);
    Ok(true)
}

pub(crate) fn attestation_matches(
    runtime: &EngineRuntime,
    container_id: &str,
    image_id: &str,
) -> bool {
    let Some(version) = runtime.database_version.as_deref() else {
        return false;
    };
    if compatibility_profile(runtime.protocol, version).is_err() {
        return false;
    }
    runtime.compatibility.as_ref().is_some_and(|stored| {
        stored
            == &RuntimeCompatibility {
                container_id: container_id.to_string(),
                image_id: image_id.to_string(),
                probe_revision: COMPATIBILITY_PROBE_REVISION,
            }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttestOutcome {
    Reused,
    Probed,
    Failed,
}
