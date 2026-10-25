use std::{collections::HashSet, time::Duration};

use crate::{
    routes::http::{response::ApiError, router::AppState},
    subsystems::import_export::{ImportExportSelection, SelectionMode},
};

use super::super::{ImportMode, REMOTE_IMPORT_LIMITER, RemoteImportSource, staging_directory};

const MAX_JSON_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_QDRANT_COLLECTIONS: usize = 512;
const MAX_QDRANT_ALIASES: usize = 4096;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
const BRIDGE_READY_TIMEOUT: Duration = Duration::from_secs(10);
const BRIDGE_READY_POLL_INTERVAL: Duration = Duration::from_millis(50);
const HOST_BRIDGE_SOCKET_NAME: &str = "qdrant-http-import.sock";
const TARGET_BRIDGE_SOCKET: &str = "/run/dbev/qdrant-http-import.sock";
const TARGET_BRIDGE_PID: &str = "/tmp/dbev-qdrant-http-import.pid";
const TARGET_BRIDGE_LOG: &str = "/tmp/dbev-qdrant-http-import.log";
const TARGET_BRIDGE_MARKER: &str = "dbev-qdrant-http-import-bridge";

pub(crate) async fn import_qdrant(
    state: &AppState,
    instance_id: &str,
    source: &RemoteImportSource,
    selection: &ImportExportSelection,
    mode: ImportMode,
) -> Result<(), ApiError> {
    let _permit = REMOTE_IMPORT_LIMITER
        .acquire(state.config.security.remote_import.max_concurrent_jobs)
        .await;
    let policy = &state.config.security.remote_import;
    let timeout = Duration::from_secs(policy.operation_timeout_seconds);
    // Preserve the final quarter of the configured operation window for rollback. Database
    // requests also have per-request timeouts, but those alone would allow hundreds of
    // collection operations to multiply the configured limit.
    let operation_started = tokio::time::Instant::now();
    let operation_deadline = operation_started + timeout;
    let rollback_budget = timeout / 4;
    let work_deadline = operation_deadline - rollback_budget;
    let source_client = QdrantHttp::source(source, policy)?;
    let staging = staging_directory(state).await?;
    let mut source_snapshots = Vec::new();
    let mut staged_bytes = 0_u64;

    let acquire_result = within_deadline(work_deadline, "source snapshot acquisition", async {
        let source_version = source_client.version().await?;
        source_client.check_standalone().await?;
        let source_collections =
            selected_collections(source_client.collections().await?, selection)?;
        if source_collections.is_empty() && selection.mode == SelectionMode::Selective {
            return Err(ApiError::BadRequest(
                "remote qdrant selection contains no collections".to_string(),
            ));
        }
        let source_names = source_collections.iter().cloned().collect::<HashSet<_>>();
        let source_aliases = selected_aliases(source_client.aliases().await?, &source_names);
        for (index, collection) in source_collections.iter().enumerate() {
            let snapshot = source_client.create_snapshot(collection).await?;
            source_snapshots.push((collection.clone(), snapshot.clone()));
            let path = staging.join(format!("source-{index}.snapshot"));
            let downloaded = source_client
                .download_snapshot(
                    collection,
                    &snapshot,
                    &path,
                    policy.max_staged_bytes.saturating_sub(staged_bytes),
                )
                .await?;
            staged_bytes = staged_bytes.checked_add(downloaded).ok_or_else(|| {
                ApiError::BadRequest("qdrant snapshot staging size overflowed".to_string())
            })?;
            // Once the private local copy is synced, the source-side snapshot is no longer
            // needed. Deleting it here keeps the crash-residue window to one collection.
            source_client.delete_snapshot(collection, &snapshot).await?;
            source_snapshots.pop();
        }
        Ok((source_version, source_collections, source_aliases))
    })
    .await;
    let (source_version, source_collections, source_aliases) = match acquire_result {
        Ok(acquired) => acquired,
        Err(error) => {
            abandon_source_phase(&source_client, &source_snapshots, &staging).await;
            return Err(error);
        }
    };
    apply_staged_source(
        state,
        instance_id,
        StagedSource {
            staging,
            version: source_version,
            collections: source_collections,
            aliases: source_aliases,
            staged_bytes,
            operation: "remote import",
        },
        mode,
        ApplyBudget {
            request_timeout: timeout,
            work_deadline,
            operation_deadline,
            max_staged_bytes: policy.max_staged_bytes,
        },
    )
    .await
}

mod bridge_scripts;

mod apply;
pub(crate) mod backup;
mod bridge;
mod cleanup;
mod compat;
mod http;
mod recovery;
mod selection;

use apply::{ApplyBudget, StagedSource, apply_staged_source};
use bridge::QdrantBridge;
pub(crate) use bridge::cleanup_stale_bridge;
use cleanup::{
    abandon_source_phase, cleanup_staging, cleanup_target_snapshots, describe_quarantine,
    qdrant_rollback_needs_stop, quiesce_rollback_target, rollback_target, stop_bridge,
    within_deadline,
};
use compat::check_snapshot_compatibility;
use http::{QdrantHttp, target_api_key};
use recovery::write_recovery_manifest;
use selection::{
    alias_actions, check_qdrant_names, desired_import_aliases, selected_aliases,
    selected_collections,
};

#[cfg(test)]
mod tests;
