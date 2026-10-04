use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    time::Duration,
};

use crate::{
    databases::protocol::Protocol,
    routes::http::{response::ApiError, router::AppState},
    server::paths::InstancePaths,
};

use super::super::super::ImportMode;
use super::{
    CLEANUP_TIMEOUT,
    bridge::QdrantBridge,
    http::QdrantHttp,
    selection::{QdrantAlias, alias_actions},
};

pub(super) async fn within_deadline<T>(
    deadline: tokio::time::Instant,
    phase: &str,
    operation: impl std::future::Future<Output = Result<T, ApiError>>,
) -> Result<T, ApiError> {
    tokio::time::timeout_at(deadline, operation)
        .await
        .map_err(|_| operation_timeout_error(phase))?
}

pub(super) async fn abandon_source_phase(
    source_client: &QdrantHttp,
    source_snapshots: &[(String, String)],
    staging: &Path,
) {
    cleanup_source_snapshots(source_client, source_snapshots).await;
    cleanup_staging(staging).await;
}

pub(super) fn describe_quarantine(quarantine: Result<(), ApiError>) -> String {
    match quarantine {
        Ok(()) => "target was stopped and quarantined".to_string(),
        Err(error) => format!(
            "gateway routes were removed and the target was quarantined in memory, but complete shutdown/persistence reported: {error}"
        ),
    }
}

pub(super) fn qdrant_rollback_needs_stop(mutation_started: bool) -> bool {
    mutation_started
}

pub(super) async fn quiesce_rollback_target(
    state: &AppState,
    instance_id: &str,
    paths: &InstancePaths,
    target_key: &secrecy::SecretString,
    request_timeout: Duration,
    deadline: tokio::time::Instant,
    bridge: &mut Option<QdrantBridge>,
) -> Result<QdrantHttp, ApiError> {
    // A timed-out `wait=true` request can continue mutating Qdrant after its client future is
    // dropped. A confirmed container stop is the generation fence: only after the old server
    // process is gone is it safe to restore snapshots into a newly-started process.
    match tokio::time::timeout_at(deadline, state.docker.stop(Protocol::Qdrant, instance_id)).await
    {
        Ok(Ok(_)) => {}
        Ok(Err(error)) if error.is_not_running() => {}
        Ok(Err(error)) => {
            return Err(ApiError::Runtime(format!(
                "failed to stop qdrant before rollback: {error}"
            )));
        }
        Err(_) => {
            return Err(operation_timeout_error("target quiescence before rollback"));
        }
    }

    // Stopping the container killed the old bridge. Disarm its in-container cleanup so it
    // cannot race the replacement bridge after the target starts again.
    if let Some(old_bridge) = bridge.take() {
        old_bridge.disarm();
    }

    tokio::time::timeout_at(deadline, state.docker.start(Protocol::Qdrant, instance_id))
        .await
        .map_err(|_| operation_timeout_error("target restart before rollback"))?
        .map_err(|error| {
            ApiError::Runtime(format!("failed to start qdrant before rollback: {error}"))
        })?;

    let ready_timeout = deadline.saturating_duration_since(tokio::time::Instant::now());
    if ready_timeout.is_zero() {
        return Err(operation_timeout_error("target readiness before rollback"));
    }
    tokio::time::timeout_at(
        deadline,
        state
            .docker
            .wait_until_ready(Protocol::Qdrant, instance_id, ready_timeout),
    )
    .await
    .map_err(|_| operation_timeout_error("target readiness before rollback"))?
    .map_err(|error| ApiError::Runtime(format!("qdrant was not ready for rollback: {error}")))?;

    let replacement_bridge =
        tokio::time::timeout_at(deadline, QdrantBridge::start(state, instance_id, paths))
            .await
            .map_err(|_| operation_timeout_error("rollback bridge startup"))??;
    let rollback_client = QdrantHttp::target(paths, target_key, request_timeout)?;
    *bridge = Some(replacement_bridge);
    Ok(rollback_client)
}

pub(super) async fn stop_bridge(bridge: &mut Option<QdrantBridge>) {
    if let Some(bridge) = bridge.take() {
        bridge.stop().await;
    }
}

pub(super) async fn rollback_target(
    target: &QdrantHttp,
    source_names: &HashSet<String>,
    mode: ImportMode,
    rollback: &[(String, PathBuf)],
    target_aliases: &[QdrantAlias],
) -> Result<(), ApiError> {
    let current = target.collections().await?;
    for collection in current {
        if mode == ImportMode::Wipe || source_names.contains(&collection) {
            target.delete_collection(&collection).await?;
        }
    }
    for (collection, path) in rollback {
        target.upload_snapshot(collection, path).await?;
    }
    let current_aliases = target.aliases().await?;
    let actions = alias_actions(&current_aliases, target_aliases);
    if !actions.is_empty() {
        target.update_aliases(actions).await?;
    }
    Ok(())
}

pub(super) async fn delete_snapshots_within_cleanup_timeout(
    client: &QdrantHttp,
    snapshots: &[(String, String)],
) -> Result<usize, tokio::time::error::Elapsed> {
    let cleanup = async {
        let mut failures = 0_usize;
        for (collection, snapshot) in snapshots {
            if client.delete_snapshot(collection, snapshot).await.is_err() {
                failures += 1;
            }
        }
        failures
    };
    tokio::time::timeout(CLEANUP_TIMEOUT, cleanup).await
}

pub(super) async fn cleanup_source_snapshots(source: &QdrantHttp, snapshots: &[(String, String)]) {
    match delete_snapshots_within_cleanup_timeout(source, snapshots).await {
        Ok(0) => {}
        Ok(failures) => {
            tracing::warn!(
                failures,
                total = snapshots.len(),
                "failed to delete one or more temporary remote qdrant source snapshots"
            );
        }
        Err(_) => {
            tracing::warn!(
                total = snapshots.len(),
                "timed out deleting temporary remote qdrant source snapshots"
            );
        }
    }
}

pub(super) async fn cleanup_target_snapshots(target: &QdrantHttp, snapshots: &[(String, String)]) {
    match delete_snapshots_within_cleanup_timeout(target, snapshots).await {
        Ok(0) => {}
        Ok(failures) => {
            tracing::warn!(
                failures,
                total = snapshots.len(),
                "failed to delete one or more temporary managed qdrant rollback snapshots"
            );
        }
        Err(_) => {
            tracing::warn!(
                total = snapshots.len(),
                "timed out deleting temporary managed qdrant rollback snapshots"
            );
        }
    }
}

pub(super) fn operation_timeout_error(phase: &str) -> ApiError {
    ApiError::ServiceUnavailable(format!(
        "qdrant remote import exceeded the configured operation timeout during {phase}"
    ))
}

pub(super) async fn cleanup_staging(staging: &Path) {
    if tokio::fs::remove_dir_all(staging).await.is_err() {
        tracing::warn!("failed to remove qdrant remote import staging directory");
    }
}
