use std::{
    collections::{BTreeMap, HashSet},
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
    time::Duration,
};

use reqwest::{
    Client, Method, StatusCode,
    header::{CONTENT_TYPE, HeaderValue},
    multipart::{Form, Part},
    redirect::Policy,
};

use secrecy::ExposeSecret;

use serde::Serialize;

use serde_json::{Value, json};

use tokio::io::AsyncWriteExt;

use crate::{
    databases::protocol::Protocol,
    routes::http::{response::ApiError, router::AppState},
    server::paths::InstancePaths,
    subsystems::import_export::{ImportExportSelection, SelectionMode},
    utils::{backend::SOCKET_BRIDGE_CONTAINER_PATH, shell::sh_quote},
};

use super::super::{
    ImportMode, REMOTE_IMPORT_LIMITER, RemoteImportSource, commit_recovery_manifest,
    staging_directory, sync_recovery_file,
};

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
    let recovery_manifest = staging.join("recovery-manifest.json");
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
        Ok((
            source_version,
            source_collections,
            source_names,
            source_aliases,
        ))
    })
    .await;
    let (source_version, source_collections, source_names, source_aliases) = match acquire_result {
        Ok(acquired) => acquired,
        Err(error) => {
            abandon_source_phase(&source_client, &source_snapshots, &staging).await;
            return Err(error);
        }
    };

    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let bridge = match within_deadline(
        work_deadline,
        "target bridge startup",
        QdrantBridge::start(state, instance_id, &paths),
    )
    .await
    {
        Ok(bridge) => bridge,
        Err(error) => {
            abandon_source_phase(&source_client, &source_snapshots, &staging).await;
            return Err(error);
        }
    };
    let mut bridge = Some(bridge);
    let target_connection = async {
        let target_key = within_deadline(
            work_deadline,
            "target credential lookup",
            target_api_key(state, instance_id),
        )
        .await?;
        let target_client = QdrantHttp::target(&paths, &target_key, timeout)?;
        Ok::<_, ApiError>((target_key, target_client))
    }
    .await;
    let (target_key, target_client) = match target_connection {
        Ok(connection) => connection,
        Err(error) => {
            stop_bridge(&mut bridge).await;
            abandon_source_phase(&source_client, &source_snapshots, &staging).await;
            return Err(error);
        }
    };

    let mut target_snapshots = Vec::new();
    let mut retain_staging = false;
    let preparation = within_deadline(work_deadline, "target recovery preparation", async {
        let target_version = target_client.version().await?;
        target_client.check_standalone().await?;
        check_snapshot_compatibility(&source_version, &target_version)?;
        let existing = target_client.collections().await?;
        let target_aliases = target_client.aliases().await?;
        check_qdrant_names(&source_names, &source_aliases, &existing, &target_aliases)?;
        let affected = if mode == ImportMode::Wipe {
            existing.clone()
        } else {
            existing
                .iter()
                .filter(|name| source_names.contains(*name))
                .cloned()
                .collect()
        };
        let affected_names = affected.iter().cloned().collect::<HashSet<_>>();

        let mut rollback = Vec::new();
        for (index, collection) in affected.iter().enumerate() {
            let snapshot = target_client.create_snapshot(collection).await?;
            target_snapshots.push((collection.clone(), snapshot.clone()));
            let path = staging.join(format!("rollback-{index}.snapshot"));
            let downloaded = target_client
                .download_snapshot(
                    collection,
                    &snapshot,
                    &path,
                    policy.max_staged_bytes.saturating_sub(staged_bytes),
                )
                .await?;
            staged_bytes = staged_bytes.checked_add(downloaded).ok_or_else(|| {
                ApiError::BadRequest("qdrant rollback staging size overflowed".to_string())
            })?;
            // The fsynced local rollback copy is authoritative from this point on.
            target_client.delete_snapshot(collection, &snapshot).await?;
            target_snapshots.pop();
            rollback.push((collection.clone(), path));
        }
        write_recovery_manifest(
            &recovery_manifest,
            instance_id,
            mode,
            &source_collections,
            &rollback,
            &target_aliases,
        )
        .await?;
        Ok((target_aliases, affected, affected_names, rollback))
    })
    .await;

    let mut mutation_started = false;
    let result = match preparation {
        Err(error) => Err(error),
        Ok((target_aliases, affected, affected_names, rollback)) => {
            let mutation = within_deadline(work_deadline, "target mutation", async {
                for collection in &affected {
                    // A request can mutate Qdrant and then fail while its response is in flight.
                    // Treat every attempted delete as a mutation requiring rollback.
                    mutation_started = true;
                    target_client.delete_collection(collection).await?;
                }
                for (index, collection) in source_collections.iter().enumerate() {
                    mutation_started = true;
                    target_client
                        .upload_snapshot(
                            collection,
                            &staging.join(format!("source-{index}.snapshot")),
                        )
                        .await?;
                }
                let desired_aliases =
                    desired_import_aliases(&target_aliases, &source_aliases, &affected_names);
                let current_aliases = target_client.aliases().await?;
                let actions = alias_actions(&current_aliases, &desired_aliases);
                if !actions.is_empty() {
                    // Alias updates are atomic in Qdrant, but a successful request can still lose
                    // its response. Mark the target mutated before sending it so rollback runs.
                    mutation_started = true;
                    target_client.update_aliases(actions).await?;
                }
                Ok(())
            })
            .await;
            match mutation {
                Ok(()) => Ok(()),
                Err(primary) => {
                    let rollback_succeeded = if qdrant_rollback_needs_stop(mutation_started) {
                        match quiesce_rollback_target(
                            state,
                            instance_id,
                            &paths,
                            &target_key,
                            timeout,
                            operation_deadline,
                            &mut bridge,
                        )
                        .await
                        {
                            Ok(rollback_client) => tokio::time::timeout_at(
                                operation_deadline,
                                rollback_target(
                                    &rollback_client,
                                    &source_names,
                                    mode,
                                    &rollback,
                                    &target_aliases,
                                ),
                            )
                            .await
                            .is_ok_and(|result| result.is_ok()),
                            Err(error) => {
                                tracing::error!(
                                    instance_id,
                                    %error,
                                    "could not quiesce qdrant before remote import rollback"
                                );
                                false
                            }
                        }
                    } else {
                        true
                    };
                    if rollback_succeeded {
                        Err(primary)
                    } else {
                        retain_staging = true;
                        let quarantine =
                            crate::subsystems::import_export::quarantine_uncertain_import(
                                state,
                                instance_id,
                            )
                            .await;
                        if quarantine.is_ok()
                            && let Some(stopped_bridge) = bridge.take()
                        {
                            stopped_bridge.disarm();
                        }
                        let quarantine = describe_quarantine(quarantine);
                        Err(ApiError::Runtime(format!(
                            "qdrant remote import failed ({primary}) and automatic rollback failed or timed out; {quarantine}; recovery snapshots were retained at {}",
                            staging.display()
                        )))
                    }
                }
            }
        }
    };

    cleanup_target_snapshots(&target_client, &target_snapshots).await;
    stop_bridge(&mut bridge).await;
    cleanup_source_snapshots(&source_client, &source_snapshots).await;
    if retain_staging {
        return result;
    }
    if let Err(commit_error) = commit_recovery_manifest(&recovery_manifest).await {
        let quarantine = describe_quarantine(
            crate::subsystems::import_export::quarantine_uncertain_import(state, instance_id).await,
        );
        return match result {
            Ok(()) => Err(ApiError::Runtime(format!(
                "qdrant import was applied, but its recovery commit marker could not be removed: {commit_error}; {quarantine}; recovery staging was retained at {}",
                staging.display()
            ))),
            Err(primary) => Err(ApiError::Runtime(format!(
                "qdrant import failed: {primary}; rollback completed, but recovery metadata could not be committed: {commit_error}; {quarantine}; recovery staging was retained at {}",
                staging.display()
            ))),
        };
    }
    cleanup_staging(&staging).await;
    result
}

mod bridge_scripts;

use bridge_scripts::{qdrant_bridge_start_script, qdrant_bridge_stop_script};

mod selection;
use selection::*;
mod recovery;
use recovery::*;
mod cleanup;
use cleanup::*;
mod http;
use http::*;
mod bridge;
pub(crate) use bridge::*;
mod compat;
use compat::*;

#[cfg(test)]
mod tests;
