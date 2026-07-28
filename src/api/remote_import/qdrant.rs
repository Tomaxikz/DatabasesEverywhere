#[cfg(unix)]
mod unix {
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
        api::{
            api_response::ApiError,
            import_export::{ImportExportSelection, SelectionMode},
            routes::AppState,
        },
        instances::paths::InstancePaths,
        shared::{backend::SOCKET_BRIDGE_CONTAINER_PATH, protocol::Protocol, shell::sh_quote},
    };

    use super::super::{
        ImportMode, REMOTE_IMPORT_LIMITER, RemoteImportSource, commit_recovery_manifest,
        remote_staging_directory, sync_recovery_file,
    };

    const MAX_JSON_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
    const MAX_QDRANT_COLLECTIONS: usize = 512;
    const MAX_QDRANT_ALIASES: usize = 4096;
    const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
    const TARGET_BRIDGE_SOCKET: &str = "/run/dbev/qdrant-http-import.sock";
    const TARGET_BRIDGE_PID: &str = "/tmp/dbev-qdrant-http-import.pid";
    const TARGET_BRIDGE_LOG: &str = "/tmp/dbev-qdrant-http-import.log";
    const TARGET_BRIDGE_MARKER: &str = "dbev-qdrant-http-import-bridge";

    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    struct QdrantAlias {
        alias_name: String,
        collection_name: String,
    }

    #[derive(Serialize)]
    struct QdrantRecoverySnapshot<'a> {
        collection: &'a str,
        file: String,
    }

    #[derive(Serialize)]
    struct QdrantRecoveryManifest<'a> {
        schema_version: u32,
        recovery_kind: &'static str,
        instance_id: &'a str,
        protocol: &'static str,
        import_mode: ImportMode,
        source_snapshots: Vec<QdrantRecoverySnapshot<'a>>,
        rollback_snapshots: Vec<QdrantRecoverySnapshot<'a>>,
        target_aliases: &'a [QdrantAlias],
        created_at: String,
    }

    pub async fn import_qdrant(
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
        let staging = remote_staging_directory(state).await?;
        let recovery_manifest = staging.join("recovery-manifest.json");
        let mut source_snapshots = Vec::new();
        let mut staged_bytes = 0_u64;

        let acquire_result = tokio::time::timeout_at(work_deadline, async {
            let source_version = source_client.version().await?;
            source_client.ensure_standalone_topology().await?;
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
            Ok::<_, ApiError>((
                source_version,
                source_collections,
                source_names,
                source_aliases,
            ))
        })
        .await;
        let (source_version, source_collections, source_names, source_aliases) =
            match acquire_result {
                Ok(Ok(acquired)) => acquired,
                Ok(Err(error)) => {
                    cleanup_source_snapshots(&source_client, &source_snapshots).await;
                    cleanup_staging(&staging).await;
                    return Err(error);
                }
                Err(_) => {
                    cleanup_source_snapshots(&source_client, &source_snapshots).await;
                    cleanup_staging(&staging).await;
                    return Err(operation_timeout_error("source snapshot acquisition"));
                }
            };

        let paths = InstancePaths::new(&state.config.paths, instance_id)
            .map_err(|error| ApiError::BadRequest(error.to_string()))?;
        let bridge = match tokio::time::timeout_at(
            work_deadline,
            QdrantBridge::start(state, instance_id, &paths),
        )
        .await
        {
            Ok(Ok(bridge)) => bridge,
            Ok(Err(error)) => {
                cleanup_source_snapshots(&source_client, &source_snapshots).await;
                cleanup_staging(&staging).await;
                return Err(error);
            }
            Err(_) => {
                cleanup_source_snapshots(&source_client, &source_snapshots).await;
                cleanup_staging(&staging).await;
                return Err(operation_timeout_error("target bridge startup"));
            }
        };
        let mut bridge = Some(bridge);
        let target_key = match tokio::time::timeout_at(
            work_deadline,
            target_api_key(state, instance_id),
        )
        .await
        {
            Ok(Ok(key)) => key,
            Ok(Err(error)) => {
                stop_bridge(&mut bridge).await;
                cleanup_source_snapshots(&source_client, &source_snapshots).await;
                cleanup_staging(&staging).await;
                return Err(error);
            }
            Err(_) => {
                stop_bridge(&mut bridge).await;
                cleanup_source_snapshots(&source_client, &source_snapshots).await;
                cleanup_staging(&staging).await;
                return Err(operation_timeout_error("target credential lookup"));
            }
        };
        let target_client = match QdrantHttp::target(&paths, &target_key, timeout) {
            Ok(client) => client,
            Err(error) => {
                stop_bridge(&mut bridge).await;
                cleanup_source_snapshots(&source_client, &source_snapshots).await;
                cleanup_staging(&staging).await;
                return Err(error);
            }
        };

        let mut target_snapshots = Vec::new();
        let mut retain_staging = false;
        let preparation = tokio::time::timeout_at(work_deadline, async {
            let target_version = target_client.version().await?;
            target_client.ensure_standalone_topology().await?;
            ensure_snapshot_compatible(&source_version, &target_version)?;
            let existing = target_client.collections().await?;
            let target_aliases = target_client.aliases().await?;
            ensure_no_qdrant_name_collisions(
                &source_names,
                &source_aliases,
                &existing,
                &target_aliases,
            )?;
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
            write_qdrant_recovery_manifest(
                &recovery_manifest,
                instance_id,
                mode,
                &source_collections,
                &rollback,
                &target_aliases,
            )
            .await?;
            Ok::<_, ApiError>((target_aliases, affected, affected_names, rollback))
        })
        .await;

        let mut mutation_started = false;
        let result = match preparation {
            Ok(Ok((target_aliases, affected, affected_names, rollback))) => {
                let mutation = tokio::time::timeout_at(work_deadline, async {
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
                    Ok::<(), ApiError>(())
                })
                .await;
                let mutation = match mutation {
                    Ok(result) => result,
                    Err(_) => Err(operation_timeout_error("target mutation")),
                };
                if let Err(primary) = mutation {
                    let rollback_succeeded =
                        if qdrant_rollback_requires_quiescence(mutation_started) {
                            match quiesce_target_for_rollback(
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
                    if !rollback_succeeded {
                        retain_staging = true;
                        let quarantine =
                            crate::api::import_export::quarantine_after_uncertain_import(
                                state,
                                instance_id,
                            )
                            .await;
                        if quarantine.is_ok()
                            && let Some(stopped_bridge) = bridge.take()
                        {
                            stopped_bridge.disarm();
                        }
                        let quarantine = match quarantine {
                            Ok(()) => "target was stopped and quarantined".to_string(),
                            Err(error) => format!(
                                "gateway routes were removed and the target was quarantined in memory, but complete shutdown/persistence reported: {error}"
                            ),
                        };
                        Err(ApiError::Runtime(format!(
                            "qdrant remote import failed ({primary}) and automatic rollback failed or timed out; {quarantine}; recovery snapshots were retained at {}",
                            staging.display()
                        )))
                    } else {
                        Err(primary)
                    }
                } else {
                    Ok(())
                }
            }
            Ok(Err(error)) => Err(error),
            Err(_) => Err(operation_timeout_error("target recovery preparation")),
        };

        cleanup_target_snapshots(&target_client, &target_snapshots).await;
        stop_bridge(&mut bridge).await;
        cleanup_source_snapshots(&source_client, &source_snapshots).await;
        if !retain_staging {
            if let Err(commit_error) = commit_recovery_manifest(&recovery_manifest).await {
                let quarantine = crate::api::import_export::quarantine_after_uncertain_import(
                    state,
                    instance_id,
                )
                .await;
                let quarantine = match quarantine {
                    Ok(()) => "target was stopped and quarantined".to_string(),
                    Err(error) => format!(
                        "gateway routes were removed and the target was quarantined in memory, but complete shutdown/persistence reported: {error}"
                    ),
                };
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
        }
        result
    }

    fn qdrant_rollback_requires_quiescence(mutation_started: bool) -> bool {
        mutation_started
    }

    async fn quiesce_target_for_rollback(
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
        match tokio::time::timeout_at(deadline, state.docker.stop(Protocol::Qdrant, instance_id))
            .await
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
        .map_err(|error| {
            ApiError::Runtime(format!("qdrant was not ready for rollback: {error}"))
        })?;

        let replacement_bridge =
            tokio::time::timeout_at(deadline, QdrantBridge::start(state, instance_id, paths))
                .await
                .map_err(|_| operation_timeout_error("rollback bridge startup"))??;
        let rollback_client = QdrantHttp::target(paths, target_key, request_timeout)?;
        *bridge = Some(replacement_bridge);
        Ok(rollback_client)
    }

    async fn stop_bridge(bridge: &mut Option<QdrantBridge>) {
        if let Some(bridge) = bridge.take() {
            bridge.stop().await;
        }
    }

    async fn rollback_target(
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

    async fn cleanup_source_snapshots(source: &QdrantHttp, snapshots: &[(String, String)]) {
        let cleanup = async {
            let mut failures = 0_usize;
            for (collection, snapshot) in snapshots {
                if source.delete_snapshot(collection, snapshot).await.is_err() {
                    failures += 1;
                }
            }
            failures
        };
        match tokio::time::timeout(CLEANUP_TIMEOUT, cleanup).await {
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

    async fn cleanup_target_snapshots(target: &QdrantHttp, snapshots: &[(String, String)]) {
        let cleanup = async {
            let mut failures = 0_usize;
            for (collection, snapshot) in snapshots {
                if target.delete_snapshot(collection, snapshot).await.is_err() {
                    failures += 1;
                }
            }
            failures
        };
        match tokio::time::timeout(CLEANUP_TIMEOUT, cleanup).await {
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

    fn operation_timeout_error(phase: &str) -> ApiError {
        ApiError::ServiceUnavailable(format!(
            "qdrant remote import exceeded the configured operation timeout during {phase}"
        ))
    }

    async fn cleanup_staging(staging: &Path) {
        if tokio::fs::remove_dir_all(staging).await.is_err() {
            tracing::warn!("failed to remove qdrant remote import staging directory");
        }
    }

    async fn write_qdrant_recovery_manifest(
        path: &Path,
        instance_id: &str,
        mode: ImportMode,
        source_collections: &[String],
        rollback: &[(String, PathBuf)],
        target_aliases: &[QdrantAlias],
    ) -> Result<(), ApiError> {
        let staging = path.parent().ok_or_else(|| {
            ApiError::Runtime("qdrant recovery manifest has no staging directory".to_string())
        })?;
        for index in 0..source_collections.len() {
            sync_recovery_file(&staging.join(format!("source-{index}.snapshot"))).await?;
        }
        for (_, rollback_path) in rollback {
            sync_recovery_file(rollback_path).await?;
        }
        let manifest = QdrantRecoveryManifest {
            schema_version: 1,
            recovery_kind: "qdrant_remote_import",
            instance_id,
            protocol: "qdrant",
            import_mode: mode,
            source_snapshots: source_collections
                .iter()
                .enumerate()
                .map(|(index, collection)| QdrantRecoverySnapshot {
                    collection,
                    file: format!("source-{index}.snapshot"),
                })
                .collect(),
            rollback_snapshots: rollback
                .iter()
                .enumerate()
                .map(|(index, (collection, _))| QdrantRecoverySnapshot {
                    collection,
                    file: format!("rollback-{index}.snapshot"),
                })
                .collect(),
            target_aliases,
            created_at: crate::jobs::import_export::now_rfc3339(),
        };
        let contents = serde_json::to_vec_pretty(&manifest).map_err(|error| {
            ApiError::Runtime(format!(
                "failed to encode qdrant recovery manifest: {error}"
            ))
        })?;
        let path = path.to_path_buf();
        tokio::task::spawn_blocking(move || {
            crate::shared::files::atomic_write_private(&path, &contents)
        })
        .await
        .map_err(|error| {
            ApiError::Runtime(format!("failed to write qdrant recovery manifest: {error}"))
        })?
        .map_err(|error| {
            ApiError::Runtime(format!("failed to write qdrant recovery manifest: {error}"))
        })
    }

    fn selected_collections(
        collections: Vec<String>,
        selection: &ImportExportSelection,
    ) -> Result<Vec<String>, ApiError> {
        let available = collections.into_iter().collect::<HashSet<_>>();
        let excluded = selection.exclude.iter().collect::<HashSet<_>>();
        let selected = if selection.mode == SelectionMode::Full {
            available
                .into_iter()
                .filter(|name| !excluded.contains(name))
                .collect::<Vec<_>>()
        } else {
            let missing = selection
                .include
                .iter()
                .filter(|name| !available.contains(*name))
                .cloned()
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                return Err(ApiError::BadRequest(
                    "remote qdrant source is missing one or more selected collections".to_string(),
                ));
            }
            selection
                .include
                .iter()
                .filter(|name| !excluded.contains(*name))
                .cloned()
                .collect::<Vec<_>>()
        };
        let mut selected = selected;
        selected.sort();
        Ok(selected)
    }

    fn ensure_no_qdrant_name_collisions(
        source_collections: &HashSet<String>,
        source_aliases: &[QdrantAlias],
        target_collections: &[String],
        target_aliases: &[QdrantAlias],
    ) -> Result<(), ApiError> {
        let target_alias_names = target_aliases
            .iter()
            .map(|alias| alias.alias_name.as_str())
            .collect::<HashSet<_>>();
        if let Some(collision) = source_collections
            .iter()
            .find(|collection| target_alias_names.contains(collection.as_str()))
        {
            return Err(ApiError::BadRequest(format!(
                "remote qdrant collection {collision} conflicts with an existing target alias; rename or remove the target alias before importing"
            )));
        }

        let target_collection_names = target_collections
            .iter()
            .map(String::as_str)
            .collect::<HashSet<_>>();
        if let Some(collision) = source_aliases
            .iter()
            .find(|alias| target_collection_names.contains(alias.alias_name.as_str()))
        {
            return Err(ApiError::BadRequest(format!(
                "remote qdrant alias {} conflicts with an existing target collection; rename or remove the target collection before importing",
                collision.alias_name
            )));
        }
        Ok(())
    }

    fn selected_aliases(
        aliases: Vec<QdrantAlias>,
        selected_collections: &HashSet<String>,
    ) -> Vec<QdrantAlias> {
        aliases
            .into_iter()
            .filter(|alias| selected_collections.contains(&alias.collection_name))
            .collect()
    }

    fn desired_import_aliases(
        target_aliases: &[QdrantAlias],
        source_aliases: &[QdrantAlias],
        affected_collections: &HashSet<String>,
    ) -> Vec<QdrantAlias> {
        let mut desired = BTreeMap::new();
        for alias in target_aliases {
            if !affected_collections.contains(&alias.collection_name) {
                desired.insert(alias.alias_name.clone(), alias.collection_name.clone());
            }
        }
        // Source mappings intentionally win an alias-name conflict. This keeps every alias
        // selected from the source attached to the collection that was just imported.
        for alias in source_aliases {
            desired.insert(alias.alias_name.clone(), alias.collection_name.clone());
        }
        desired
            .into_iter()
            .map(|(alias_name, collection_name)| QdrantAlias {
                alias_name,
                collection_name,
            })
            .collect()
    }

    fn alias_actions(current: &[QdrantAlias], desired: &[QdrantAlias]) -> Vec<Value> {
        let current = current
            .iter()
            .map(|alias| (&alias.alias_name, &alias.collection_name))
            .collect::<BTreeMap<_, _>>();
        let desired = desired
            .iter()
            .map(|alias| (&alias.alias_name, &alias.collection_name))
            .collect::<BTreeMap<_, _>>();
        let mut actions = Vec::new();
        for (alias_name, collection_name) in &current {
            if desired.get(alias_name) != Some(collection_name) {
                actions.push(json!({
                    "delete_alias": {
                        "alias_name": alias_name,
                    }
                }));
            }
        }
        for (alias_name, collection_name) in &desired {
            if current.get(alias_name) != Some(collection_name) {
                actions.push(json!({
                    "create_alias": {
                        "alias_name": alias_name,
                        "collection_name": collection_name,
                    }
                }));
            }
        }
        actions
    }

    struct QdrantHttp {
        client: Client,
        base_url: String,
        api_key: Option<HeaderValue>,
        source: bool,
    }

    impl QdrantHttp {
        fn source(
            source: &RemoteImportSource,
            policy: &crate::config::RemoteImportSecurityConfig,
        ) -> Result<Self, ApiError> {
            let mut builder = Client::builder()
                .no_proxy()
                .redirect(Policy::none())
                .connect_timeout(Duration::from_secs(policy.connect_timeout_seconds))
                .timeout(Duration::from_secs(policy.operation_timeout_seconds))
                .https_only(source.endpoint.tls);
            builder = builder
                .resolve_to_addrs(&source.endpoint.host, source.endpoint.addresses.as_slice());
            let client = builder.build().map_err(|_| {
                ApiError::Runtime("failed to build qdrant source client".to_string())
            })?;
            let host = if source.endpoint.host.contains(':') {
                format!("[{}]", source.endpoint.host)
            } else {
                source.endpoint.host.clone()
            };
            let scheme = if source.endpoint.tls { "https" } else { "http" };
            Ok(Self {
                client,
                base_url: format!("{scheme}://{host}:{}", source.endpoint.port),
                api_key: secret_header(source.api_key.as_ref())?,
                source: true,
            })
        }

        fn target(
            paths: &InstancePaths,
            api_key: &secrecy::SecretString,
            timeout: Duration,
        ) -> Result<Self, ApiError> {
            let client = Client::builder()
                .no_proxy()
                .redirect(Policy::none())
                .timeout(timeout)
                .unix_socket(paths.sockets.join("qdrant-http-import.sock"))
                .build()
                .map_err(|_| {
                    ApiError::Runtime("failed to build managed qdrant client".to_string())
                })?;
            let mut header = HeaderValue::from_str(api_key.expose_secret()).map_err(|_| {
                ApiError::Runtime("managed qdrant API key is not a valid HTTP header".to_string())
            })?;
            header.set_sensitive(true);
            Ok(Self {
                client,
                base_url: "http://qdrant.internal".to_string(),
                api_key: Some(header),
                source: false,
            })
        }

        async fn version(&self) -> Result<String, ApiError> {
            let json = self.json(Method::GET, "/", None).await?;
            json.get("version")
                .and_then(Value::as_str)
                .or_else(|| json.pointer("/result/version").and_then(Value::as_str))
                .map(ToString::to_string)
                .ok_or_else(|| self.bad_response("qdrant did not report its version"))
        }

        async fn ensure_standalone_topology(&self) -> Result<(), ApiError> {
            let json = self.json(Method::GET, "/cluster", None).await?;
            match qdrant_topology_is_standalone(&json) {
                Some(true) => Ok(()),
                Some(false) if self.source => Err(ApiError::BadRequest(
                    "remote qdrant distributed mode is unsupported because a snapshot from one endpoint can omit shards held by other nodes; use a standalone source or Qdrant's distributed migration tooling"
                        .to_string(),
                )),
                Some(false) => Err(ApiError::Runtime(
                    "managed qdrant target unexpectedly has distributed mode enabled; remote snapshot import requires a standalone target"
                        .to_string(),
                )),
                None => Err(self.bad_response(
                    "qdrant returned an invalid cluster topology response",
                )),
            }
        }

        async fn collections(&self) -> Result<Vec<String>, ApiError> {
            let json = self.json(Method::GET, "/collections", None).await?;
            let collections = json
                .pointer("/result/collections")
                .and_then(Value::as_array)
                .ok_or_else(|| self.bad_response("qdrant returned an invalid collection list"))?;
            if collections.len() > MAX_QDRANT_COLLECTIONS {
                return Err(
                    self.bad_response("qdrant collection count exceeds the supported import limit")
                );
            }
            let mut names = Vec::with_capacity(collections.len());
            for collection in collections {
                let name = collection
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        self.bad_response("qdrant collection response is missing a name")
                    })?;
                if !valid_qdrant_name(name) {
                    return Err(self.bad_response("qdrant returned an invalid collection name"));
                }
                names.push(name.to_string());
            }
            Ok(names)
        }

        async fn aliases(&self) -> Result<Vec<QdrantAlias>, ApiError> {
            let json = self.json(Method::GET, "/aliases", None).await?;
            let aliases = json
                .pointer("/result/aliases")
                .and_then(Value::as_array)
                .ok_or_else(|| self.bad_response("qdrant returned an invalid alias list"))?;
            if aliases.len() > MAX_QDRANT_ALIASES {
                return Err(
                    self.bad_response("qdrant alias count exceeds the supported import limit")
                );
            }
            let mut mappings = BTreeMap::new();
            for alias in aliases {
                let alias_name =
                    alias
                        .get("alias_name")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            self.bad_response("qdrant alias response is missing an alias name")
                        })?;
                let collection_name = alias
                    .get("collection_name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        self.bad_response("qdrant alias response is missing a collection name")
                    })?;
                if !valid_qdrant_name(alias_name) || !valid_qdrant_name(collection_name) {
                    return Err(self.bad_response("qdrant returned an invalid alias mapping"));
                }
                if mappings
                    .insert(alias_name.to_string(), collection_name.to_string())
                    .is_some()
                {
                    return Err(self.bad_response("qdrant returned duplicate alias names"));
                }
            }
            Ok(mappings
                .into_iter()
                .map(|(alias_name, collection_name)| QdrantAlias {
                    alias_name,
                    collection_name,
                })
                .collect())
        }

        async fn update_aliases(&self, actions: Vec<Value>) -> Result<(), ApiError> {
            if actions.is_empty() {
                return Ok(());
            }
            self.json(
                Method::POST,
                "/collections/aliases?timeout=120",
                Some(json!({ "actions": actions })),
            )
            .await
            .map(|_| ())
        }

        async fn create_snapshot(&self, collection: &str) -> Result<String, ApiError> {
            let path = format!(
                "/collections/{}/snapshots?wait=true",
                encode_path_segment(collection)
            );
            let json = self.json(Method::POST, &path, None).await?;
            json.pointer("/result/name")
                .and_then(Value::as_str)
                .map(ToString::to_string)
                .ok_or_else(|| self.bad_response("qdrant did not return a snapshot name"))
        }

        async fn delete_snapshot(&self, collection: &str, snapshot: &str) -> Result<(), ApiError> {
            let path = format!(
                "/collections/{}/snapshots/{}?wait=true",
                encode_path_segment(collection),
                encode_path_segment(snapshot)
            );
            self.json(Method::DELETE, &path, None).await.map(|_| ())
        }

        async fn delete_collection(&self, collection: &str) -> Result<(), ApiError> {
            let path = format!(
                "/collections/{}?timeout=120",
                encode_path_segment(collection)
            );
            self.json(Method::DELETE, &path, None).await.map(|_| ())
        }

        async fn download_snapshot(
            &self,
            collection: &str,
            snapshot: &str,
            path: &Path,
            max_bytes: u64,
        ) -> Result<u64, ApiError> {
            let endpoint = format!(
                "/collections/{}/snapshots/{}",
                encode_path_segment(collection),
                encode_path_segment(snapshot)
            );
            let mut request = self.client.get(self.url(&endpoint));
            if let Some(key) = self.api_key.as_ref() {
                request = request.header("api-key", key.clone());
            }
            let mut response = request
                .send()
                .await
                .map_err(|error| self.request_error("download snapshot", error))?;
            if !response.status().is_success() {
                return Err(self.status_error("download snapshot", response.status()));
            }
            if response
                .content_length()
                .is_some_and(|length| length > max_bytes)
            {
                return Err(ApiError::BadRequest(format!(
                    "qdrant snapshot exceeds the remaining {max_bytes}-byte staging limit"
                )));
            }
            let mut options = tokio::fs::OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            let mut output = options.open(path).await.map_err(|error| {
                ApiError::Runtime(format!(
                    "failed to create qdrant snapshot staging file: {error}"
                ))
            })?;
            let mut total = 0_u64;
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|error| self.request_error("read snapshot", error))?
            {
                total = total.checked_add(chunk.len() as u64).ok_or_else(|| {
                    ApiError::BadRequest("qdrant snapshot size overflowed".to_string())
                })?;
                if total > max_bytes {
                    let _ = tokio::fs::remove_file(path).await;
                    return Err(ApiError::BadRequest(format!(
                        "qdrant snapshot exceeds the remaining {max_bytes}-byte staging limit"
                    )));
                }
                output.write_all(&chunk).await.map_err(|error| {
                    ApiError::Runtime(format!("failed to stage qdrant snapshot: {error}"))
                })?;
            }
            output.sync_all().await.map_err(|error| {
                ApiError::Runtime(format!("failed to sync qdrant snapshot: {error}"))
            })?;
            if total == 0 {
                drop(output);
                let _ = tokio::fs::remove_file(path).await;
                return Err(self.bad_response("qdrant returned an empty snapshot"));
            }
            Ok(total)
        }

        async fn upload_snapshot(&self, collection: &str, path: &Path) -> Result<(), ApiError> {
            let part = Part::file(path).await.map_err(|error| {
                ApiError::Runtime(format!("failed to open staged qdrant snapshot: {error}"))
            })?;
            let form = Form::new().part("snapshot", part);
            let endpoint = format!(
                "/collections/{}/snapshots/upload?priority=snapshot&wait=true",
                encode_path_segment(collection)
            );
            let mut request = self.client.post(self.url(&endpoint)).multipart(form);
            if let Some(key) = self.api_key.as_ref() {
                request = request.header("api-key", key.clone());
            }
            let response = request
                .send()
                .await
                .map_err(|error| self.request_error("upload snapshot", error))?;
            if !response.status().is_success() {
                return Err(self.status_error("upload snapshot", response.status()));
            }
            Ok(())
        }

        async fn json(
            &self,
            method: Method,
            path: &str,
            body: Option<Value>,
        ) -> Result<Value, ApiError> {
            let mut request = self.client.request(method, self.url(path));
            if let Some(key) = self.api_key.as_ref() {
                request = request.header("api-key", key.clone());
            }
            if let Some(body) = body {
                request = request.header(CONTENT_TYPE, "application/json").json(&body);
            }
            let mut response = request
                .send()
                .await
                .map_err(|error| self.request_error("API request", error))?;
            if !response.status().is_success() {
                return Err(self.status_error("API request", response.status()));
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|error| self.request_error("read API response", error))?
            {
                if bytes.len().saturating_add(chunk.len()) > MAX_JSON_RESPONSE_BYTES {
                    return Err(self.bad_response("qdrant API response was too large"));
                }
                bytes.extend_from_slice(&chunk);
            }
            serde_json::from_slice(&bytes)
                .map_err(|_| self.bad_response("qdrant returned invalid JSON"))
        }

        fn url(&self, path: &str) -> String {
            format!("{}{}", self.base_url, path)
        }

        fn request_error(&self, operation: &str, error: reqwest::Error) -> ApiError {
            if self.source {
                ApiError::BadRequest(format!(
                    "remote qdrant {operation} failed: {}",
                    safe_reqwest_error(&error)
                ))
            } else {
                ApiError::Runtime(format!(
                    "managed qdrant {operation} failed: {}",
                    safe_reqwest_error(&error)
                ))
            }
        }

        fn status_error(&self, operation: &str, status: StatusCode) -> ApiError {
            if self.source {
                ApiError::BadRequest(format!(
                    "remote qdrant {operation} returned HTTP {}",
                    status.as_u16()
                ))
            } else {
                ApiError::Runtime(format!(
                    "managed qdrant {operation} returned HTTP {}",
                    status.as_u16()
                ))
            }
        }

        fn bad_response(&self, message: &str) -> ApiError {
            if self.source {
                ApiError::BadRequest(format!("remote {message}"))
            } else {
                ApiError::Runtime(format!("managed {message}"))
            }
        }
    }

    struct QdrantBridge {
        cleanup: Option<QdrantBridgeCleanup>,
    }

    struct QdrantBridgeCleanup {
        state: AppState,
        instance_id: String,
    }

    pub(crate) async fn cleanup_stale_qdrant_bridge(
        state: &AppState,
        instance_id: &str,
    ) -> Result<(), ApiError> {
        tokio::time::timeout(
            CLEANUP_TIMEOUT,
            state
                .docker
                .exec_shell(Protocol::Qdrant, instance_id, &qdrant_bridge_stop_script()),
        )
        .await
        .map_err(|_| {
            ApiError::Runtime(
                "timed out cleaning up a stale managed qdrant HTTP bridge".to_string(),
            )
        })?
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to clean up a stale managed qdrant HTTP bridge: {error}"
            ))
        })?;
        Ok(())
    }

    impl QdrantBridge {
        async fn start(
            state: &AppState,
            instance_id: &str,
            paths: &InstancePaths,
        ) -> Result<Self, ApiError> {
            // Arm cleanup before the start command is sent. Docker exec can be cancelled after the
            // command has started but before its response arrives, so arming afterward can leak a
            // live bridge and its socket/state artifacts.
            let bridge = Self {
                cleanup: Some(QdrantBridgeCleanup {
                    state: state.clone(),
                    instance_id: instance_id.to_string(),
                }),
            };
            let start = qdrant_bridge_start_script();
            if let Err(error) = state
                .docker
                .exec_shell(Protocol::Qdrant, instance_id, &start)
                .await
            {
                let error = ApiError::Runtime(format!(
                    "failed to start managed qdrant HTTP bridge: {error}"
                ));
                bridge.stop().await;
                return Err(error);
            }
            let host_socket = paths.sockets.join("qdrant-http-import.sock");
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                if tokio::fs::symlink_metadata(&host_socket)
                    .await
                    .is_ok_and(|metadata| metadata.file_type().is_socket())
                {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    bridge.stop().await;
                    return Err(ApiError::Runtime(
                        "managed qdrant HTTP bridge did not become ready".to_string(),
                    ));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok(bridge)
        }

        fn disarm(mut self) {
            self.cleanup.take();
        }

        async fn stop(mut self) {
            let Some(cleanup) = self.cleanup.take() else {
                return;
            };
            let instance_id = cleanup.instance_id.clone();

            // Spawn before awaiting so cancellation of the caller cannot cancel cleanup. Taking
            // the payload first disarms Drop and guarantees that cleanup is scheduled once.
            if let Err(error) = tokio::spawn(cleanup.run()).await {
                tracing::warn!(
                    instance_id = %instance_id,
                    %error,
                    "temporary qdrant HTTP bridge cleanup task failed"
                );
            }
        }
    }

    impl Drop for QdrantBridge {
        fn drop(&mut self) {
            let Some(cleanup) = self.cleanup.take() else {
                return;
            };
            let instance_id = cleanup.instance_id.clone();
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    let _cleanup_task = handle.spawn(cleanup.run());
                }
                Err(error) => {
                    tracing::warn!(
                        instance_id = %instance_id,
                        %error,
                        "could not schedule temporary qdrant HTTP bridge cleanup"
                    );
                }
            }
        }
    }

    impl QdrantBridgeCleanup {
        async fn run(self) {
            if let Err(error) = cleanup_stale_qdrant_bridge(&self.state, &self.instance_id).await {
                tracing::warn!(
                    instance_id = self.instance_id,
                    %error,
                    "failed to stop temporary qdrant HTTP bridge"
                );
            }
        }
    }

    fn qdrant_bridge_start_script() -> String {
        format!(
            r#"{cleanup}
set -eu
{binary} __socket-bridge-supervisor \
  --socket {socket} --tcp 127.0.0.1:6333 \
  -- sh -c 'exec sleep 86400' {marker} >/dev/null 2>&1 &
qdrant_bridge_pid=$!
qdrant_bridge_start=$(qdrant_bridge_process_start_time "$qdrant_bridge_pid")
rm -f -- {pid_temp}
(
  umask 077
  set -C
  printf 'v1 %s %s\n' "$qdrant_bridge_pid" "$qdrant_bridge_start" > {pid_temp}
)
mv -f -- {pid_temp} {pid}
"#,
            cleanup = qdrant_bridge_stop_script(),
            pid = sh_quote(TARGET_BRIDGE_PID),
            pid_temp = sh_quote(&format!("{TARGET_BRIDGE_PID}.new")),
            socket = sh_quote(TARGET_BRIDGE_SOCKET),
            binary = sh_quote(SOCKET_BRIDGE_CONTAINER_PATH),
            marker = sh_quote(TARGET_BRIDGE_MARKER),
        )
    }

    fn qdrant_bridge_process_helpers_script() -> String {
        format!(
            r#"qdrant_bridge_process_start_time() {{
  qdrant_bridge_stat=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
  qdrant_bridge_stat=${{qdrant_bridge_stat#*) }}
  set -- $qdrant_bridge_stat
  [ "$#" -ge 20 ] || return 1
  qdrant_bridge_start=${{20}}
  case "$qdrant_bridge_start" in
    ''|*[!0-9]*) return 1 ;;
  esac
  printf '%s\n' "$qdrant_bridge_start"
}}

qdrant_bridge_process_is_owned() {{
  qdrant_bridge_candidate=$1
  qdrant_bridge_expected_start=$2
  case "$qdrant_bridge_candidate" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$qdrant_bridge_candidate" -gt 1 ] 2>/dev/null || return 1
  qdrant_bridge_actual_start=$(qdrant_bridge_process_start_time "$qdrant_bridge_candidate") ||
    return 1
  [ "$qdrant_bridge_actual_start" = "$qdrant_bridge_expected_start" ] || return 1
  qdrant_bridge_actual_cmdline=$(
    tr '\000' '\n' < "/proc/$qdrant_bridge_candidate/cmdline" 2>/dev/null
  ) || return 1
  qdrant_bridge_expected_cmdline=$(printf '%s\n' \
    {binary} __socket-bridge-supervisor \
    --socket {socket} --tcp 127.0.0.1:6333 \
    -- sh -c 'exec sleep 86400' {marker})
  qdrant_bridge_legacy_cmdline=$(printf '%s\n' \
    {binary} __socket-bridge-supervisor \
    --socket {socket} --tcp 127.0.0.1:6333 \
    -- sh -c 'exec sleep 86400')
  if [ "$qdrant_bridge_actual_cmdline" != "$qdrant_bridge_expected_cmdline" ] &&
     [ "$qdrant_bridge_actual_cmdline" != "$qdrant_bridge_legacy_cmdline" ]; then
    return 1
  fi
  qdrant_bridge_actual_start=$(qdrant_bridge_process_start_time "$qdrant_bridge_candidate") ||
    return 1
  [ "$qdrant_bridge_actual_start" = "$qdrant_bridge_expected_start" ]
}}

qdrant_bridge_stop_owned_process() {{
  qdrant_bridge_stop_pid=$1
  qdrant_bridge_stop_start=$2
  qdrant_bridge_process_is_owned "$qdrant_bridge_stop_pid" "$qdrant_bridge_stop_start" ||
    return 0
  kill -TERM "$qdrant_bridge_stop_pid" 2>/dev/null || true
  qdrant_bridge_wait=0
  while qdrant_bridge_process_is_owned \
      "$qdrant_bridge_stop_pid" "$qdrant_bridge_stop_start" &&
      [ "$qdrant_bridge_wait" -lt 100 ]; do
    sleep 0.05
    qdrant_bridge_wait=$((qdrant_bridge_wait + 1))
  done
  if qdrant_bridge_process_is_owned \
      "$qdrant_bridge_stop_pid" "$qdrant_bridge_stop_start"; then
    kill -KILL "$qdrant_bridge_stop_pid" 2>/dev/null || true
    qdrant_bridge_wait=0
    while qdrant_bridge_process_is_owned \
        "$qdrant_bridge_stop_pid" "$qdrant_bridge_stop_start" &&
        [ "$qdrant_bridge_wait" -lt 50 ]; do
      sleep 0.05
      qdrant_bridge_wait=$((qdrant_bridge_wait + 1))
    done
  fi
  ! qdrant_bridge_process_is_owned \
    "$qdrant_bridge_stop_pid" "$qdrant_bridge_stop_start"
}}
"#,
            binary = sh_quote(SOCKET_BRIDGE_CONTAINER_PATH),
            socket = sh_quote(TARGET_BRIDGE_SOCKET),
            marker = sh_quote(TARGET_BRIDGE_MARKER),
        )
    }

    fn qdrant_bridge_stop_script() -> String {
        format!(
            r#"set -u
{helpers}
qdrant_bridge_cleanup_failed=0
for qdrant_bridge_proc in /proc/[0-9]*; do
  [ -d "$qdrant_bridge_proc" ] || continue
  qdrant_bridge_scan_pid=${{qdrant_bridge_proc#/proc/}}
  qdrant_bridge_scan_start=$(
    qdrant_bridge_process_start_time "$qdrant_bridge_scan_pid"
  ) || continue
  if qdrant_bridge_process_is_owned \
      "$qdrant_bridge_scan_pid" "$qdrant_bridge_scan_start"; then
    qdrant_bridge_stop_owned_process \
      "$qdrant_bridge_scan_pid" "$qdrant_bridge_scan_start" ||
      qdrant_bridge_cleanup_failed=1
  fi
done
[ "$qdrant_bridge_cleanup_failed" -eq 0 ] || exit 1
rm -f -- {socket} {pid} {pid_temp} {log}
"#,
            helpers = qdrant_bridge_process_helpers_script(),
            pid = sh_quote(TARGET_BRIDGE_PID),
            pid_temp = sh_quote(&format!("{TARGET_BRIDGE_PID}.new")),
            socket = sh_quote(TARGET_BRIDGE_SOCKET),
            log = sh_quote(TARGET_BRIDGE_LOG),
        )
    }

    async fn target_api_key(
        state: &AppState,
        instance_id: &str,
    ) -> Result<secrecy::SecretString, ApiError> {
        let output = state
            .docker
            .exec(
                Protocol::Qdrant,
                instance_id,
                vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    "printf '%s' \"$QDRANT__SERVICE__API_KEY\"".to_string(),
                ],
            )
            .await
            .map_err(|error| {
                ApiError::Runtime(format!(
                    "failed to access managed qdrant credentials: {error}"
                ))
            })?;
        let key = output.stdout;
        if key.is_empty() || key.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
            return Err(ApiError::Runtime(
                "managed qdrant API key is unavailable".to_string(),
            ));
        }
        Ok(secrecy::SecretString::from(key))
    }

    fn secret_header(
        secret: Option<&secrecy::SecretString>,
    ) -> Result<Option<HeaderValue>, ApiError> {
        let Some(secret) = secret else {
            return Ok(None);
        };
        let mut value = HeaderValue::from_str(secret.expose_secret()).map_err(|_| {
            ApiError::BadRequest(
                "source.api_key contains characters that are invalid in an HTTP header".to_string(),
            )
        })?;
        value.set_sensitive(true);
        Ok(Some(value))
    }

    fn ensure_snapshot_compatible(source: &str, target: &str) -> Result<(), ApiError> {
        let source_parts = version_triplet(source).ok_or_else(|| {
            ApiError::BadRequest("remote qdrant reported an invalid version".to_string())
        })?;
        let target_parts = version_triplet(target).ok_or_else(|| {
            ApiError::Runtime("managed qdrant reported an invalid version".to_string())
        })?;
        let same_minor = source_parts.0 == target_parts.0 && source_parts.1 == target_parts.1;
        let compatible_patch = target_parts.2 >= source_parts.2;
        if !same_minor || !compatible_patch {
            return Err(ApiError::BadRequest(
                "remote qdrant snapshots are not compatible with the managed target; use the same major and minor version without a target patch downgrade"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn qdrant_topology_is_standalone(response: &Value) -> Option<bool> {
        let result = response.get("result")?.as_object()?;
        let status = result.get("status")?.as_str()?;
        let peer_count = match result.get("peers") {
            None | Some(Value::Null) => 0,
            Some(Value::Object(peers)) => peers.len(),
            Some(_) => return None,
        };
        match status {
            "disabled" => Some(peer_count <= 1),
            "enabled" => Some(false),
            _ => None,
        }
    }

    fn version_triplet(version: &str) -> Option<(u32, u32, u32)> {
        let core = version
            .trim_start_matches('v')
            .split(|character| matches!(character, '-' | '+'))
            .next()?;
        let mut parts = core.split('.');
        let version = (
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
            parts.next()?.parse().ok()?,
        );
        if parts.next().is_some() {
            return None;
        }
        Some(version)
    }

    fn valid_qdrant_name(name: &str) -> bool {
        !name.is_empty() && name.len() <= 255 && !name.contains('\0')
    }

    fn encode_path_segment(value: &str) -> String {
        let mut encoded = String::new();
        for byte in value.bytes() {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                encoded.push(char::from(byte));
            } else {
                use std::fmt::Write as _;
                let _ = write!(encoded, "%{byte:02X}");
            }
        }
        encoded
    }

    fn safe_reqwest_error(error: &reqwest::Error) -> &'static str {
        if error.is_timeout() {
            "request timed out"
        } else if error.is_connect() {
            "connection failed"
        } else if error.is_decode() {
            "response decoding failed"
        } else {
            "request failed"
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn path_segments_are_encoded() {
            assert_eq!(encode_path_segment("name/a b"), "name%2Fa%20b");
        }

        #[test]
        fn qdrant_snapshot_versions_follow_the_supported_upgrade_window() {
            assert!(ensure_snapshot_compatible("1.12.0", "1.13.1").is_err());
            assert!(ensure_snapshot_compatible("1.13.0", "1.13.1").is_ok());
            assert!(ensure_snapshot_compatible("1.13.0", "1.12.9").is_err());
            assert!(ensure_snapshot_compatible("1.16.0", "1.18.0").is_err());
            assert!(ensure_snapshot_compatible("1.13.2", "1.13.1").is_err());
            assert!(ensure_snapshot_compatible("2.0.0", "1.99.0").is_err());
        }

        #[test]
        fn qdrant_topology_rejects_distributed_or_multi_peer_sources() {
            assert_eq!(
                qdrant_topology_is_standalone(&json!({
                    "result": { "status": "disabled" }
                })),
                Some(true)
            );
            assert_eq!(
                qdrant_topology_is_standalone(&json!({
                    "result": {
                        "status": "enabled",
                        "peers": { "1": { "uri": "http://node-1" } }
                    }
                })),
                Some(false)
            );
            assert_eq!(
                qdrant_topology_is_standalone(&json!({
                    "result": {
                        "status": "disabled",
                        "peers": {
                            "1": { "uri": "http://node-1" },
                            "2": { "uri": "http://node-2" }
                        }
                    }
                })),
                Some(false)
            );
        }

        #[test]
        fn qdrant_version_errors_do_not_echo_remote_text() {
            let invalid = "secret-source-version";
            let error = ensure_snapshot_compatible(invalid, "1.13.1").unwrap_err();
            assert!(!error.to_string().contains(invalid));

            let incompatible = "9.0-secret-source-version";
            let error = ensure_snapshot_compatible(incompatible, "1.13.1").unwrap_err();
            assert!(!error.to_string().contains(incompatible));
        }

        #[test]
        fn qdrant_bridge_guard_owns_static_cleanup_state() {
            fn assert_send_static<T: Send + 'static>() {}

            assert_send_static::<QdrantBridge>();
            assert!(std::mem::needs_drop::<QdrantBridge>());
        }

        #[test]
        fn every_attempted_qdrant_mutation_requires_a_process_fence_before_rollback() {
            // A lost upload response can outlive the HTTP future inside Qdrant. Never optimize
            // this to an immediate rollback based only on the client-side error kind.
            assert!(qdrant_rollback_requires_quiescence(true));
            assert!(!qdrant_rollback_requires_quiescence(false));
        }

        #[test]
        fn qdrant_bridge_cleanup_terminates_process_and_removes_every_artifact() {
            let script = qdrant_bridge_stop_script();

            assert!(script.contains("kill -TERM"));
            assert!(script.contains("kill -KILL"));
            assert!(script.contains("/proc/[0-9]*"));
            assert!(script.contains("qdrant_bridge_process_is_owned"));
            assert!(script.contains("qdrant_bridge_expected_start"));
            assert!(script.contains(SOCKET_BRIDGE_CONTAINER_PATH));
            assert!(script.contains(TARGET_BRIDGE_MARKER));
            assert!(script.contains(&sh_quote(TARGET_BRIDGE_SOCKET)));
            assert!(script.contains(&sh_quote(TARGET_BRIDGE_PID)));
            assert!(script.contains(&sh_quote(TARGET_BRIDGE_LOG)));
            assert!(script.contains("rm -f --"));
        }

        #[test]
        fn qdrant_bridge_cleanup_never_trusts_the_pid_file_as_a_signal_target() {
            let script = qdrant_bridge_stop_script();

            assert!(!script.contains(&format!("cat {}", sh_quote(TARGET_BRIDGE_PID))));
            assert!(!script.contains(&format!("< {}", sh_quote(TARGET_BRIDGE_PID))));
            assert!(script.contains("/proc/$qdrant_bridge_candidate/cmdline"));
            assert!(script.contains("--socket"));
            assert!(script.contains("127.0.0.1:6333"));
        }

        #[test]
        fn qdrant_bridge_start_records_its_generation_atomically() {
            let script = qdrant_bridge_start_script();

            assert!(script.contains("qdrant_bridge_process_start_time"));
            assert!(script.contains("printf 'v1 %s %s\\n'"));
            assert!(script.contains("umask 077"));
            assert!(script.contains("set -C"));
            assert!(script.contains(&sh_quote(&format!("{TARGET_BRIDGE_PID}.new"))));
            assert!(script.contains("mv -f --"));
            assert!(script.contains(TARGET_BRIDGE_MARKER));
            assert!(!script.contains(&format!("> {}", sh_quote(TARGET_BRIDGE_LOG))));
        }

        #[test]
        fn an_empty_full_source_is_valid() {
            assert_eq!(
                selected_collections(Vec::new(), &ImportExportSelection::default()).unwrap(),
                Vec::<String>::new()
            );
        }

        #[test]
        fn qdrant_alias_selection_follows_collection_selection() {
            let selected = HashSet::from(["included".to_string()]);
            let aliases = vec![
                qdrant_alias("keep", "included"),
                qdrant_alias("omit", "excluded"),
            ];

            assert_eq!(
                selected_aliases(aliases, &selected),
                vec![qdrant_alias("keep", "included")]
            );
        }

        #[test]
        fn incoming_collection_cannot_resolve_through_a_target_alias() {
            let error = ensure_no_qdrant_name_collisions(
                &HashSet::from(["orders".to_string()]),
                &[],
                &["unrelated".to_string()],
                &[qdrant_alias("orders", "unrelated")],
            )
            .unwrap_err();

            assert!(error.to_string().contains("target alias"));
        }

        #[test]
        fn incoming_alias_cannot_shadow_a_target_collection() {
            let error = ensure_no_qdrant_name_collisions(
                &HashSet::from(["imported".to_string()]),
                &[qdrant_alias("orders", "imported")],
                &["orders".to_string()],
                &[],
            )
            .unwrap_err();

            assert!(error.to_string().contains("target collection"));
        }

        #[test]
        fn source_aliases_replace_conflicts_and_target_aliases_for_replaced_collections() {
            let target = vec![
                qdrant_alias("keep", "untouched"),
                qdrant_alias("conflict", "untouched"),
                qdrant_alias("old", "replaced"),
            ];
            let source = vec![
                qdrant_alias("conflict", "imported"),
                qdrant_alias("source", "imported"),
            ];
            let affected = HashSet::from(["replaced".to_string()]);

            assert_eq!(
                desired_import_aliases(&target, &source, &affected),
                vec![
                    qdrant_alias("conflict", "imported"),
                    qdrant_alias("keep", "untouched"),
                    qdrant_alias("source", "imported"),
                ]
            );
        }

        #[test]
        fn qdrant_alias_actions_exactly_reconcile_in_one_atomic_request() {
            let current = vec![
                qdrant_alias("extra", "old"),
                qdrant_alias("keep", "stable"),
                qdrant_alias("wrong", "old"),
            ];
            let desired = vec![
                qdrant_alias("keep", "stable"),
                qdrant_alias("new", "new_collection"),
                qdrant_alias("wrong", "replacement"),
            ];

            assert_eq!(
                alias_actions(&current, &desired),
                vec![
                    json!({ "delete_alias": { "alias_name": "extra" } }),
                    json!({ "delete_alias": { "alias_name": "wrong" } }),
                    json!({
                        "create_alias": {
                            "alias_name": "new",
                            "collection_name": "new_collection"
                        }
                    }),
                    json!({
                        "create_alias": {
                            "alias_name": "wrong",
                            "collection_name": "replacement"
                        }
                    }),
                ]
            );
        }

        fn qdrant_alias(alias_name: &str, collection_name: &str) -> QdrantAlias {
            QdrantAlias {
                alias_name: alias_name.to_string(),
                collection_name: collection_name.to_string(),
            }
        }
    }
}

#[cfg(unix)]
pub(crate) use unix::cleanup_stale_qdrant_bridge;
#[cfg(unix)]
pub use unix::import_qdrant;

#[cfg(not(unix))]
pub(crate) async fn cleanup_stale_qdrant_bridge(
    _state: &crate::api::routes::AppState,
    _instance_id: &str,
) -> Result<(), crate::api::api_response::ApiError> {
    Ok(())
}

#[cfg(not(unix))]
pub async fn import_qdrant(
    _state: &crate::api::routes::AppState,
    _instance_id: &str,
    _source: &super::RemoteImportSource,
    _selection: &crate::api::import_export::ImportExportSelection,
    _mode: super::ImportMode,
) -> Result<(), crate::api::api_response::ApiError> {
    Err(crate::api::api_response::ApiError::NotImplemented(
        "qdrant remote import requires a Unix host".to_string(),
    ))
}
