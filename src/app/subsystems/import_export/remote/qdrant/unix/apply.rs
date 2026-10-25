//! Applies staged collection snapshots to the managed Qdrant target.
//!
//! The target's affected collections are first downloaded as rollback
//! snapshots and recorded in a recovery manifest. A failed mutation restores
//! them; a failed rollback quarantines the instance and keeps the staging.

use std::{collections::HashSet, path::PathBuf, time::Duration};

use crate::{
    routes::http::{response::ApiError, router::AppState},
    server::paths::InstancePaths,
};

use super::{
    super::super::{ImportMode, commit_recovery_manifest},
    QdrantBridge, QdrantHttp, alias_actions, check_qdrant_names, check_snapshot_compatibility,
    cleanup_staging, cleanup_target_snapshots, describe_quarantine, desired_import_aliases,
    qdrant_rollback_needs_stop, quiesce_rollback_target, rollback_target,
    selection::QdrantAlias,
    stop_bridge, target_api_key, within_deadline, write_recovery_manifest,
};

/// Collection snapshots staged as `source-{index}.snapshot` inside `staging`,
/// in the order of `collections`.
pub(super) struct StagedSource {
    pub(super) staging: PathBuf,
    pub(super) version: String,
    pub(super) collections: Vec<String>,
    pub(super) aliases: Vec<QdrantAlias>,
    pub(super) staged_bytes: u64,
    /// Names the operation in error messages ("remote import").
    pub(super) operation: &'static str,
}

pub(super) struct ApplyBudget {
    pub(super) request_timeout: Duration,
    /// Mutations stop here; the rest of the window is left for rollback.
    pub(super) work_deadline: tokio::time::Instant,
    pub(super) operation_deadline: tokio::time::Instant,
    /// Cap on staged source and rollback snapshots together.
    pub(super) max_staged_bytes: u64,
}

/// Replaces (wipe) or overwrites (merge) the target's collections with the
/// staged snapshots. The staging directory is consumed: removed on every
/// outcome except a failed rollback, where it holds the recovery snapshots.
pub(super) async fn apply_staged_source(
    state: &AppState,
    instance_id: &str,
    source: StagedSource,
    mode: ImportMode,
    budget: ApplyBudget,
) -> Result<(), ApiError> {
    let StagedSource {
        staging,
        version: source_version,
        collections: source_collections,
        aliases: source_aliases,
        mut staged_bytes,
        operation,
    } = source;
    let source_names = source_collections.iter().cloned().collect::<HashSet<_>>();
    let recovery_manifest = staging.join("recovery-manifest.json");
    let paths =
        InstancePaths::new(&state.config.paths, instance_id).map_err(ApiError::bad_request)?;
    let bridge = match within_deadline(
        budget.work_deadline,
        "target bridge startup",
        QdrantBridge::start(state, instance_id, &paths),
    )
    .await
    {
        Ok(bridge) => bridge,
        Err(error) => {
            cleanup_staging(&staging).await;
            return Err(error);
        }
    };
    let mut bridge = Some(bridge);
    let target_connection = async {
        let target_key = within_deadline(
            budget.work_deadline,
            "target credential lookup",
            target_api_key(state, instance_id),
        )
        .await?;
        let target_client = QdrantHttp::target(&paths, &target_key, budget.request_timeout)?;
        Ok::<_, ApiError>((target_key, target_client))
    }
    .await;
    let (target_key, target_client) = match target_connection {
        Ok(connection) => connection,
        Err(error) => {
            stop_bridge(&mut bridge).await;
            cleanup_staging(&staging).await;
            return Err(error);
        }
    };

    let mut target_snapshots = Vec::new();
    let mut retain_staging = false;
    let preparation = within_deadline(budget.work_deadline, "target recovery preparation", async {
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
                    budget.max_staged_bytes.saturating_sub(staged_bytes),
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
            let mutation = within_deadline(budget.work_deadline, "target mutation", async {
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
                            budget.request_timeout,
                            budget.operation_deadline,
                            &mut bridge,
                        )
                        .await
                        {
                            Ok(rollback_client) => tokio::time::timeout_at(
                                budget.operation_deadline,
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
                                    "could not quiesce qdrant before {operation} rollback"
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
                            "qdrant {operation} failed ({primary}) and automatic rollback failed or timed out; {quarantine}; recovery snapshots were retained at {}",
                            staging.display()
                        )))
                    }
                }
            }
        }
    };

    cleanup_target_snapshots(&target_client, &target_snapshots).await;
    stop_bridge(&mut bridge).await;
    if retain_staging {
        return result;
    }
    if let Err(commit_error) = commit_recovery_manifest(&recovery_manifest).await {
        let quarantine = describe_quarantine(
            crate::subsystems::import_export::quarantine_uncertain_import(state, instance_id).await,
        );
        return match result {
            Ok(()) => Err(ApiError::Runtime(format!(
                "qdrant {operation} was applied, but its recovery commit marker could not be removed: {commit_error}; {quarantine}; recovery staging was retained at {}",
                staging.display()
            ))),
            Err(primary) => Err(ApiError::Runtime(format!(
                "qdrant {operation} failed: {primary}; rollback completed, but recovery metadata could not be committed: {commit_error}; {quarantine}; recovery staging was retained at {}",
                staging.display()
            ))),
        };
    }
    cleanup_staging(&staging).await;
    result
}
