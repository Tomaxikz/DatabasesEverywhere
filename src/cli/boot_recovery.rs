use super::*;

pub(super) async fn complete_managed_runtime_boot(state: AppState) {
    let Some(_mutation) = state.daemon_shutdown.try_admit_background_mutation() else {
        return;
    };
    if let Err(error) = start_known_instances_on_boot(
        &state.config,
        &state.manager,
        &state.docker,
        &state.instance_locks,
    )
    .await
    {
        tracing::error!(
            %error,
            "managed instance background startup failed; API remains available and database gateways remain closed"
        );
        state
            .gateway_supervisor
            .fail_and_stop("managed instance startup failed");
        return;
    }
    if !state.import_export_jobs.is_accepting() {
        return;
    }

    let compatibility = crate::compatibility::reconcile_managed_compatibility_on_boot(&state).await;
    if compatibility.failed == 0 {
        tracing::info!(
            checked = compatibility.checked,
            attestations_reused = compatibility.attestations_reused,
            probed = compatibility.probed,
            images_upgraded = compatibility.images_upgraded,
            unchanged_images = compatibility
                .checked
                .saturating_sub(compatibility.images_upgraded),
            failed = 0,
            "configured image reconciliation and database compatibility attestation completed successfully"
        );
    } else {
        tracing::warn!(
            checked = compatibility.checked,
            attestations_reused = compatibility.attestations_reused,
            probed = compatibility.probed,
            images_upgraded = compatibility.images_upgraded,
            failed = compatibility.failed,
            "configured image reconciliation completed with isolated instance failures"
        );
    }
    if !state.import_export_jobs.is_accepting() {
        return;
    }

    let (qdrant_bridges_checked, qdrant_bridge_cleanup_errors) =
        cleanup_stale_qdrant_import_bridges_on_boot(&state).await;
    if qdrant_bridge_cleanup_errors > 0 {
        tracing::warn!(
            qdrant_bridges_checked,
            qdrant_bridge_cleanup_errors,
            "stale qdrant remote-import bridge cleanup completed with errors"
        );
    } else {
        tracing::info!(
            qdrant_bridges_checked,
            "stale qdrant remote-import bridge cleanup complete"
        );
    }
    if !state.import_export_jobs.is_accepting() {
        return;
    }

    let postgres_role_hardening = crate::databases::postgres::hardening::harden_on_boot(
        &state.manager,
        &state.docker,
        &state.instance_locks,
    )
    .await;
    for failure in &postgres_role_hardening.failures {
        tracing::debug!(
            instance_id = %failure.instance_id,
            reason = %failure.reason,
            "PostgreSQL boot-hardening failure included in the per-instance summary"
        );
    }
    if postgres_role_hardening.failures.is_empty() {
        tracing::info!(
            checked = postgres_role_hardening.checked,
            hardened = postgres_role_hardening.hardened,
            administrator_credentials_migrated =
                postgres_role_hardening.administrator_credentials_migrated,
            attestations_reused = postgres_role_hardening.attestations_reused,
            deferred = postgres_role_hardening.deferred,
            failed = 0,
            "PostgreSQL role and local authentication hardening completed successfully"
        );
    } else {
        tracing::warn!(
            checked = postgres_role_hardening.checked,
            hardened = postgres_role_hardening.hardened,
            administrator_credentials_migrated =
                postgres_role_hardening.administrator_credentials_migrated,
            attestations_reused = postgres_role_hardening.attestations_reused,
            deferred = postgres_role_hardening.deferred,
            failed = postgres_role_hardening.failures.len(),
            "PostgreSQL authentication hardening completed with isolated instance failures"
        );
    }
    if !state.import_export_jobs.is_accepting() {
        return;
    }

    let mysql_auth_hardening =
        crate::api::instance_create::harden_mysql_accounts_on_boot(&state).await;
    for failure in &mysql_auth_hardening.failures {
        tracing::debug!(
            instance_id = %failure.instance_id,
            reason = %failure.reason,
            "MySQL boot-hardening failure included in the per-instance summary"
        );
    }
    if mysql_auth_hardening.failures.is_empty() {
        tracing::info!(
            checked = mysql_auth_hardening.checked,
            root_credentials_migrated = mysql_auth_hardening.root_credentials_migrated,
            verifiers_repaired = mysql_auth_hardening.verifiers_repaired,
            attestations_reused = mysql_auth_hardening.attestations_reused,
            failed = 0,
            "MySQL caching_sha2_password migration completed successfully"
        );
    } else {
        tracing::warn!(
            checked = mysql_auth_hardening.checked,
            root_credentials_migrated = mysql_auth_hardening.root_credentials_migrated,
            verifiers_repaired = mysql_auth_hardening.verifiers_repaired,
            attestations_reused = mysql_auth_hardening.attestations_reused,
            failed = mysql_auth_hardening.failures.len(),
            "MySQL authentication migration completed with isolated instance failures"
        );
    }
    if !state.import_export_jobs.is_accepting() {
        return;
    }

    if let Err(error) = start_gateway_listeners(
        &state.config,
        state.instances.clone(),
        state.resource_cache.clone(),
        state.gateway_supervisor.clone(),
    )
    .await
    {
        tracing::error!(
            %error,
            "database gateway startup failed; API remains available"
        );
        return;
    }
    log_gateway_listener_summary(&state.config);
    crate::api::backups::start_scheduler(state);
}

pub(super) async fn cleanup_stale_qdrant_import_bridges_on_boot(
    state: &AppState,
) -> (usize, usize) {
    let instance_ids = state
        .instances
        .list()
        .await
        .into_iter()
        .filter(|metadata| metadata.protocol == Protocol::Qdrant)
        .map(|metadata| metadata.instance_id)
        .collect::<Vec<_>>();
    let outcomes = futures::stream::iter(instance_ids)
        .map(|instance_id| async move {
            let _operation = state.instance_locks.lock(&instance_id).await;
            let Some(metadata) = state.instances.get(&instance_id).await else {
                return Ok::<_, (String, ApiError)>(false);
            };
            if metadata.protocol != Protocol::Qdrant || metadata.status != InstanceStatus::Running {
                return Ok(false);
            }
            crate::api::remote_import::cleanup_stale_qdrant_bridge(state, &instance_id)
                .await
                .map(|()| true)
                .map_err(|error| (instance_id, error))
        })
        .buffer_unordered(MANAGED_INSTANCE_LIFECYCLE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;

    let mut checked = 0_usize;
    let mut errors = 0_usize;
    for outcome in outcomes {
        match outcome {
            Ok(true) => checked += 1,
            Ok(false) => {}
            Err((instance_id, error)) => {
                errors += 1;
                tracing::warn!(
                    %instance_id,
                    %error,
                    "failed to clean stale qdrant remote-import bridge"
                );
            }
        }
    }
    (checked, errors)
}

pub(super) async fn quarantine_interrupted_job_instances(
    manager: &InstanceManager,
    instance_ids: &[String],
) -> anyhow::Result<usize> {
    let store = manager.store();
    let mut quarantined = 0;
    for instance_id in instance_ids {
        let Some(mut metadata) = store.get(instance_id).await else {
            tracing::warn!(
                %instance_id,
                "interrupted running import job references missing instance metadata"
            );
            continue;
        };
        metadata.status = InstanceStatus::Quarantined;
        metadata.desired_state = crate::instances::metadata::DesiredInstanceState::Stopped;
        metadata.updated_at = crate::jobs::import_export::now_rfc3339();
        manager
            .upsert(metadata.clone())
            .await
            .with_context(|| format!("failed to quarantine interrupted instance {instance_id}"))?;
        quarantined += 1;
        tracing::warn!(
            event = "audit interrupted_job_instance_quarantined",
            %instance_id,
            protocol = %metadata.protocol,
            "quarantined instance before container reconciliation and gateway startup"
        );
    }
    Ok(quarantined)
}

pub(super) async fn quarantine_retained_physical_restore_workspaces(
    manager: &InstanceManager,
    volumes_root: &Path,
) -> anyhow::Result<usize> {
    const MAX_SCANNED_ENTRIES: usize = 4096;

    let mut entries = match tokio::fs::read_dir(volumes_root).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to scan physical restore workspaces below {}",
                    volumes_root.display()
                )
            });
        }
    };
    let mut scanned = 0_usize;
    let mut quarantined = 0_usize;
    let mut seen_instances = std::collections::HashSet::new();
    while let Some(entry) = entries.next_entry().await.with_context(|| {
        format!(
            "failed while scanning physical restore workspaces below {}",
            volumes_root.display()
        )
    })? {
        scanned += 1;
        if scanned > MAX_SCANNED_ENTRIES {
            anyhow::bail!(
                "volumes root {} exceeds the {}-entry physical restore recovery scan safety limit",
                volumes_root.display(),
                MAX_SCANNED_ENTRIES
            );
        }
        let Some(instance_id) = physical_restore_workspace_instance_id(&entry.file_name()) else {
            continue;
        };
        let file_type = entry.file_type().await.with_context(|| {
            format!(
                "failed to inspect physical restore workspace {}",
                entry.path().display()
            )
        })?;
        if file_type.is_symlink() || !file_type.is_dir() {
            tracing::warn!(
                event = "audit unsafe_physical_restore_workspace_ignored",
                path = %entry.path().display(),
                %instance_id,
                "ignored a generated physical restore workspace name that is not a real directory"
            );
            continue;
        }
        if !seen_instances.insert(instance_id.clone()) {
            continue;
        }
        tracing::error!(
            event = "audit retained_physical_restore_workspace",
            path = %entry.path().display(),
            %instance_id,
            "an interrupted physical restore left rollback state beside the instance volume; quarantining its target"
        );
        let Some(mut instance) = manager.store().get(&instance_id).await else {
            tracing::warn!(
                path = %entry.path().display(),
                %instance_id,
                "physical restore workspace references missing instance metadata"
            );
            continue;
        };
        let already_safe = instance.status == InstanceStatus::Quarantined
            && instance.desired_state == crate::instances::metadata::DesiredInstanceState::Stopped;
        if already_safe {
            continue;
        }
        instance.status = InstanceStatus::Quarantined;
        instance.desired_state = crate::instances::metadata::DesiredInstanceState::Stopped;
        instance.updated_at = crate::jobs::import_export::now_rfc3339();
        manager.upsert(instance).await.with_context(|| {
            format!("failed to persist physical restore recovery quarantine for {instance_id}")
        })?;
        quarantined += 1;
    }
    Ok(quarantined)
}

pub(super) fn physical_restore_workspace_instance_id(name: &std::ffi::OsStr) -> Option<String> {
    const PREFIX: &str = ".dbe-restore-";
    const UUID_LENGTH: usize = 36;

    let name = name.to_str()?;
    let value = name.strip_prefix(PREFIX)?;
    if value.len() <= UUID_LENGTH
        || value.as_bytes().get(value.len() - UUID_LENGTH - 1) != Some(&b'-')
    {
        return None;
    }
    let split = value.len() - UUID_LENGTH - 1;
    let instance_id = &value[..split];
    let uuid = &value[split + 1..];
    let parsed = uuid::Uuid::parse_str(uuid).ok()?;
    if parsed.hyphenated().to_string() != uuid {
        return None;
    }
    crate::shared::ids::validate_instance_id(instance_id).ok()?;
    Some(instance_id.to_string())
}

#[derive(Debug, Deserialize)]
pub(super) struct RetainedImportRecoveryIdentity {
    schema_version: u32,
    recovery_kind: String,
    instance_id: String,
    protocol: String,
}

pub(super) async fn quarantine_retained_import_recovery_manifests(
    manager: &InstanceManager,
    tmp_root: &Path,
) -> anyhow::Result<usize> {
    const MAX_MANIFESTS: usize = 1024;
    const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
    const MAX_SCANNED_ENTRIES_PER_ROOT: usize = 4096;

    let root = tmp_root.join("import-export");
    let mut manifests = Vec::new();
    collect_logical_recovery_manifests(
        &root,
        &mut manifests,
        MAX_MANIFESTS,
        MAX_SCANNED_ENTRIES_PER_ROOT,
    )
    .await?;
    let remote_root = tmp_root.join("remote-import");
    collect_remote_recovery_manifests(
        &remote_root,
        &mut manifests,
        MAX_MANIFESTS,
        MAX_SCANNED_ENTRIES_PER_ROOT,
    )
    .await?;

    let mut quarantined = 0_usize;
    let mut seen_instances = std::collections::HashSet::new();
    for path in manifests {
        let manifest_path = path.clone();
        let contents = tokio::task::spawn_blocking(move || {
            crate::shared::files::read_private_regular_file_bounded(
                &manifest_path,
                MAX_MANIFEST_BYTES,
            )
        })
        .await
        .with_context(|| format!("failed to join recovery manifest read {}", path.display()))?
        .with_context(|| format!("failed to read recovery manifest {}", path.display()))?;
        let identity: RetainedImportRecoveryIdentity = serde_json::from_slice(&contents)
            .with_context(|| format!("invalid recovery manifest {}", path.display()))?;
        if identity.schema_version != 1
            || !matches!(
                identity.recovery_kind.as_str(),
                "logical_remote_import"
                    | "redis_remote_import"
                    | "valkey_remote_import"
                    | "qdrant_remote_import"
            )
        {
            anyhow::bail!(
                "unsupported recovery manifest schema or kind in {}",
                path.display()
            );
        }
        crate::shared::ids::validate_instance_id(&identity.instance_id)
            .with_context(|| format!("unsafe instance id in {}", path.display()))?;
        let manifest_protocol = identity
            .protocol
            .parse::<Protocol>()
            .with_context(|| format!("invalid protocol in {}", path.display()))?;
        if !recovery_kind_matches_protocol(&identity.recovery_kind, manifest_protocol) {
            anyhow::bail!(
                "recovery kind and protocol do not match in {}",
                path.display()
            );
        }
        tracing::error!(
            event = "audit retained_import_recovery_manifest",
            path = %path.display(),
            instance_id = %identity.instance_id,
            protocol = %manifest_protocol,
            recovery_kind = %identity.recovery_kind,
            "an interrupted import has durable rollback metadata; quarantining its target"
        );
        if !seen_instances.insert(identity.instance_id.clone()) {
            continue;
        }
        let Some(mut instance) = manager.store().get(&identity.instance_id).await else {
            tracing::warn!(
                instance_id = %identity.instance_id,
                path = %path.display(),
                "recovery manifest references missing instance metadata"
            );
            continue;
        };
        if instance.protocol != manifest_protocol {
            anyhow::bail!(
                "recovery manifest {} protocol {} does not match stored instance {} protocol {}",
                path.display(),
                manifest_protocol,
                identity.instance_id,
                instance.protocol
            );
        }
        if instance.status != InstanceStatus::Quarantined {
            instance.status = InstanceStatus::Quarantined;
            instance.desired_state = crate::instances::metadata::DesiredInstanceState::Stopped;
            instance.updated_at = crate::jobs::import_export::now_rfc3339();
            manager.upsert(instance).await.with_context(|| {
                format!(
                    "failed to persist recovery quarantine for {}",
                    identity.instance_id
                )
            })?;
            quarantined += 1;
        }
    }
    Ok(quarantined)
}

pub(super) async fn collect_logical_recovery_manifests(
    root: &Path,
    manifests: &mut Vec<PathBuf>,
    max_manifests: usize,
    max_scanned_entries: usize,
) -> anyhow::Result<()> {
    let mut entries = match tokio::fs::read_dir(root).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to scan recovery root {}", root.display()));
        }
    };
    let mut scanned = 0_usize;
    while let Some(entry) = entries
        .next_entry()
        .await
        .with_context(|| format!("failed while scanning recovery root {}", root.display()))?
    {
        scanned += 1;
        if scanned > max_scanned_entries {
            anyhow::bail!(
                "recovery root {} exceeds the {}-entry scan safety limit",
                root.display(),
                max_scanned_entries
            );
        }
        let name = entry.file_name();
        if is_generated_logical_recovery_manifest_name(&name) {
            push_recovery_manifest(manifests, entry.path(), max_manifests)?;
        }
    }
    Ok(())
}

pub(super) async fn collect_remote_recovery_manifests(
    root: &Path,
    manifests: &mut Vec<PathBuf>,
    max_manifests: usize,
    max_scanned_entries: usize,
) -> anyhow::Result<()> {
    let mut entries = match tokio::fs::read_dir(root).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to scan recovery root {}", root.display()));
        }
    };
    let mut scanned = 0_usize;
    while let Some(entry) = entries
        .next_entry()
        .await
        .with_context(|| format!("failed while scanning recovery root {}", root.display()))?
    {
        scanned += 1;
        if scanned > max_scanned_entries {
            anyhow::bail!(
                "recovery root {} exceeds the {}-entry scan safety limit",
                root.display(),
                max_scanned_entries
            );
        }
        if !is_canonical_uuid_file_name(&entry.file_name()) {
            continue;
        }
        let directory = entry.path();
        let metadata = tokio::fs::symlink_metadata(&directory)
            .await
            .with_context(|| {
                format!(
                    "failed to inspect remote-import recovery entry {}",
                    directory.display()
                )
            })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        let manifest = directory.join("recovery-manifest.json");
        match tokio::fs::symlink_metadata(&manifest).await {
            Ok(_) => push_recovery_manifest(manifests, manifest, max_manifests)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to inspect recovery manifest {}", manifest.display())
                });
            }
        }
    }
    Ok(())
}

pub(super) fn push_recovery_manifest(
    manifests: &mut Vec<PathBuf>,
    path: PathBuf,
    max_manifests: usize,
) -> anyhow::Result<()> {
    if manifests.len() >= max_manifests {
        anyhow::bail!(
            "retained import recovery manifest count exceeds the {}-file safety limit",
            max_manifests
        );
    }
    manifests.push(path);
    Ok(())
}

pub(super) fn is_generated_logical_recovery_manifest_name(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(uuid) = name
        .strip_prefix(".dbe-import-recovery-")
        .and_then(|name| name.strip_suffix(".json"))
    else {
        return false;
    };
    is_canonical_uuid(uuid)
}

pub(super) fn is_canonical_uuid_file_name(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(is_canonical_uuid)
}

pub(super) fn is_canonical_uuid(value: &str) -> bool {
    value.len() == 36
        && uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.hyphenated().to_string() == value)
}

pub(super) fn recovery_kind_matches_protocol(kind: &str, protocol: Protocol) -> bool {
    match kind {
        "logical_remote_import" => !matches!(
            protocol,
            Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
        ),
        "redis_remote_import" => protocol == Protocol::Redis,
        "valkey_remote_import" => protocol == Protocol::Valkey,
        "qdrant_remote_import" => protocol == Protocol::Qdrant,
        _ => false,
    }
}
