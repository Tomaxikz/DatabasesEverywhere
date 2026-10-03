use crate::storage::quarantine::QuarantineKind;
use anyhow::{Context, ensure};

use crate::{
    runtime::docker::DockerError,
    server::metadata::DesiredInstanceState,
    server::placement::containment,
    server::placement::{EngineRuntime, EngineRuntimeStatus},
    state::AppState,
    utils::time::now_rfc3339,
};

/// These are the decision points, not guesses based on text in an engine error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Metadata,
    StorageBoundary,
    SocketDirectory,
    HostedConfig,
    ResourceLimits,
    EngineStart,
    Readiness,
    PoolSecurity,
    Isolation,
    TenantSecurity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Decision {
    KeepDown,
    Quarantine,
}

#[derive(Debug, thiserror::Error)]
#[error("storage capacity could not be admitted; keep the pool down")]
pub(crate) struct CapacityUnavailable;

#[derive(Debug, thiserror::Error)]
#[error("shared pool exited unexpectedly")]
pub(crate) struct EngineExited;

#[derive(Debug, thiserror::Error)]
#[error("shared pool was OOM-killed (configured pool memory limit: {memory_mib} MiB)")]
pub(crate) struct EngineOutOfMemory {
    pub memory_mib: u64,
}

pub(crate) fn engine_exit(oom_killed: bool, memory_mib: u64) -> anyhow::Error {
    if oom_killed {
        EngineOutOfMemory { memory_mib }.into()
    } else {
        EngineExited.into()
    }
}

pub(crate) fn decide(phase: Phase, error: &anyhow::Error) -> Decision {
    // Once credentials/tenant state or durable publication are uncertain, a
    // transport error is not sufficient evidence that the operation was safe.
    if matches!(
        phase,
        Phase::Metadata | Phase::PoolSecurity | Phase::TenantSecurity
    ) {
        return Decision::Quarantine;
    }
    if let Some(error) = error.downcast_ref::<DockerError>() {
        return match error {
            DockerError::Api(_)
            | DockerError::PodmanApiRequest { .. }
            | DockerError::PodmanApiResponse { .. }
            | DockerError::ManagedContainerNotFound { .. }
            | DockerError::ContainerNotReady { .. }
            | DockerError::AutostartBlocked(_)
            | DockerError::ResourceLimit(_)
            | DockerError::CpuLimitConversion { .. }
            | DockerError::MemoryLimitConversion { .. } => Decision::KeepDown,
            // Includes foreign ownership, invalid mounts, malformed credentials,
            // missing identity, and failures to persist startup history.
            _ => Decision::Quarantine,
        };
    }
    if phase == Phase::StorageBoundary && error.is::<CapacityUnavailable>() {
        return Decision::KeepDown;
    }
    if phase == Phase::Readiness && (error.is::<EngineExited>() || error.is::<EngineOutOfMemory>())
    {
        return Decision::KeepDown;
    }
    if matches!(phase, Phase::SocketDirectory | Phase::HostedConfig)
        && errno_allows_keep_down(raw_os_error(error))
    {
        return Decision::KeepDown;
    }
    // Unknown errors, symlinks/non-directories, mismatched socket binds and
    // isolation failures are never downgraded just because their text looks benign.
    Decision::Quarantine
}

fn raw_os_error(error: &anyhow::Error) -> Option<i32> {
    if let Some(errno) = error.downcast_ref::<rustix::io::Errno>() {
        return Some(errno.raw_os_error());
    }
    error
        .downcast_ref::<std::io::Error>()
        .and_then(|io_error| io_error.raw_os_error())
}

fn errno_allows_keep_down(errno: Option<i32>) -> bool {
    matches!(
        errno,
        Some(libc::ENOENT | libc::EACCES | libc::EPERM | libc::ENOSPC | libc::EDQUOT | libc::EROFS)
    )
}

pub(crate) async fn handle(
    state: &AppState,
    runtime: &mut EngineRuntime,
    phase: Phase,
    error: &anyhow::Error,
) -> anyhow::Result<()> {
    let mut cause = quarantine_kind(phase, error);
    let decision = if runtime.pending_image.is_some() {
        cause = QuarantineKind::ImageChangeIncomplete;
        Decision::Quarantine
    } else {
        decide(phase, error)
    };
    if decision == Decision::KeepDown {
        match keep_down(state, runtime).await {
            Ok(()) => {
                super::clear_runtime_caches(state, &runtime.runtime_id).await;
                tracing::warn!(event = "audit shared_pool_failure_decision", runtime_id = %runtime.runtime_id,
                    ?phase, decision = "keep_down", %error, "pool failed; kept down until validated boot recovery or an explicit retry");
                return Ok(());
            }
            Err(stop_error) => {
                cause = if stop_error.is::<UnconfirmedStop>() {
                    QuarantineKind::ShutdownUnconfirmed
                } else {
                    QuarantineKind::MetadataUncertain
                };
                tracing::error!(event = "audit shared_pool_failure_escalated", runtime_id = %runtime.runtime_id,
                    ?phase, %error, %stop_error, "could not persist or confirm a safe stopped state; quarantining pool");
            }
        }
    }
    let report = containment::contain_locked(
        state,
        runtime,
        "pool failure requires integrity recovery",
        Some(cause),
    )
    .await;
    runtime.status = EngineRuntimeStatus::Quarantined;
    super::clear_runtime_caches(state, &runtime.runtime_id).await;
    tracing::error!(event = "audit shared_pool_failure_decision", runtime_id = %runtime.runtime_id,
        ?phase, decision = "quarantine", %error, containment = %report.summary());
    ensure!(
        report.contained(),
        "could not contain failed pool {}: {}",
        runtime.runtime_id,
        report.summary()
    );
    Ok(())
}

async fn keep_down(state: &AppState, runtime: &mut EngineRuntime) -> anyhow::Result<()> {
    ensure!(
        super::fence_runtime(state, &runtime.runtime_id).await,
        "could not fence every tenant"
    );
    containment::stop_pool(state, runtime)
        .await
        .map_err(anyhow::Error::msg)
        .context(UnconfirmedStop)?;
    persist_failed(state, runtime).await?;
    Ok(())
}

async fn persist_failed(state: &AppState, runtime: &mut EngineRuntime) -> anyhow::Result<()> {
    let current = state
        .placements
        .get(&runtime.runtime_id)
        .await?
        .context("failed pool disappeared")?;
    ensure!(
        current.created_at == runtime.created_at
            && current.owner == runtime.owner
            && current.protocol == runtime.protocol
            && current.pending_image.is_none()
            && !matches!(
                current.status,
                EngineRuntimeStatus::Quarantined | EngineRuntimeStatus::Deleting
            ),
        "pool identity or lifecycle state changed during failure handling"
    );
    runtime.status = EngineRuntimeStatus::Failed;
    // Preserve each tenant's own desired state. Block ordinary restart loops;
    // an explicit start or the next boot recovery pass must validate any retry.
    runtime.desired_state = DesiredInstanceState::Stopped;
    runtime.updated_at = now_rfc3339();
    super::save_runtime(&state.placements, &state.manager, runtime.clone()).await?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[error("physical pool shutdown could not be verified")]
struct UnconfirmedStop;

fn quarantine_kind(phase: Phase, error: &anyhow::Error) -> QuarantineKind {
    if let Some(error) = error.downcast_ref::<DockerError>() {
        match error {
            DockerError::UntrustedContainerNameCollision { .. } => {
                return QuarantineKind::OwnershipMismatch;
            }
            DockerError::DiskBindSourceMismatch { .. } | DockerError::InvalidMountSource { .. } => {
                return QuarantineKind::StorageBoundary;
            }
            DockerError::InvalidLegacyCredentialEnvironment { .. } => {
                return QuarantineKind::CredentialIntegrity;
            }
            _ => {}
        }
    }
    match phase {
        Phase::Metadata => QuarantineKind::MetadataUncertain,
        Phase::StorageBoundary => QuarantineKind::StorageBoundary,
        Phase::SocketDirectory | Phase::HostedConfig => QuarantineKind::RuntimePathUnsafe,
        Phase::PoolSecurity | Phase::TenantSecurity => QuarantineKind::SecurityAttestation,
        Phase::Isolation => QuarantineKind::IsolationMismatch,
        _ => QuarantineKind::Unknown,
    }
}

#[cfg(test)]
mod tests;
