//! Crash recovery for online backup jobs and unsettled publications.
//!
//! Only resources journaled by a job are touched, and generation-bound
//! resources (sessions, temporary slots, in-container helpers) are cleaned
//! only while the runtime still runs the generation that created them; after
//! a restart they no longer exist. Helper containers are removed by the
//! coordinator itself and must be confirmed gone. Staging is removed only
//! once no owned resource remains. Unknown strategies, stopped runtimes,
//! failed cleanups and uploaded objects that could not be removed leave the
//! job `cleanup_pending` for a later attempt, and a new online backup of that
//! instance refuses to start until it is resolved.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use super::{
    online::{journal_error, remove_staging, runtime_generation},
    publication::{self, Resolution},
    registry::strategy_by_id,
    strategy::{
        BackupJobIdentity, CleanupContext, OnlineBackupStrategy, OwnedResource, OwnedResourceKind,
    },
};
use crate::{
    routes::http::{response::ApiError, router::AppState},
    server::{
        backup::is_capture_dir_name, jobs::import_export::now_rfc3339, metadata::InstanceMetadata,
    },
    storage::backup_jobs::{BackupJobRecord, BackupJobState, BackupResourceRecord},
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BackupRecoverySummary {
    pub recovered: usize,
    pub published: usize,
    pub cleanup_pending: usize,
}

/// Classifies every interrupted or cleanup-pending job at daemon startup.
pub(crate) async fn recover_interrupted_backups(
    state: &AppState,
) -> Result<BackupRecoverySummary, ApiError> {
    let jobs = state
        .backup_jobs
        .needing_recovery(None)
        .await
        .map_err(journal_error)?;
    let mut summary = BackupRecoverySummary::default();
    for job in jobs {
        let _operation = state.instance_locks.lock(&job.instance_id).await;
        match recover_job(state, &job).await {
            Ok(BackupJobState::Published) => summary.published += 1,
            Ok(BackupJobState::CleanupPending) => summary.cleanup_pending += 1,
            Ok(_) => summary.recovered += 1,
            Err(error) => {
                summary.cleanup_pending += 1;
                tracing::error!(job_id = job.job_id, %error, "online backup job recovery failed");
            }
        }
    }
    // Offline and shared backups, and publications whose job already ended.
    for resolution in publication::recover(state, None, false).await? {
        match resolution {
            Resolution::Published => summary.published += 1,
            Resolution::Removed => summary.recovered += 1,
            Resolution::Pending(_) => summary.cleanup_pending += 1,
        }
    }
    sweep_capture_staging(state).await?;
    Ok(summary)
}

/// Startup keeps capture staging for recovery. Once jobs are recovered only
/// `cleanup_pending` jobs, whose helpers may still exist, keep theirs; any
/// other capture directory belongs to no live job and is removed.
async fn sweep_capture_staging(state: &AppState) -> Result<(), ApiError> {
    let staging_root = PathBuf::from(state.config.paths.backups_root()).join(".staging");
    let keep: HashSet<PathBuf> = state
        .backup_jobs
        .needing_recovery(None)
        .await
        .map_err(journal_error)?
        .into_iter()
        .map(|job| PathBuf::from(job.staging_path))
        .collect();
    let mut instances = match tokio::fs::read_dir(&staging_root).await {
        Ok(instances) => instances,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(ApiError::Runtime(format!("read backup staging: {error}")));
        }
    };
    while let Ok(Some(instance)) = instances.next_entry().await {
        let Some(instance_id) = instance.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(mut entries) = tokio::fs::read_dir(instance.path()).await else {
            continue;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if is_capture_dir_name(&entry.file_name())
                && is_job_staging(&staging_root, &instance_id, &path)
                && !keep.contains(&path)
            {
                remove_staging(&path).await;
            }
        }
    }
    Ok(())
}

/// Retries cleanup for one instance before a new online backup. The caller
/// holds the instance lock. Fails while any earlier job still owns
/// resources or uploaded objects.
pub(super) async fn recover_instance_jobs(
    state: &AppState,
    instance_id: &str,
) -> Result<(), ApiError> {
    let jobs = state
        .backup_jobs
        .needing_recovery(Some(instance_id))
        .await
        .map_err(journal_error)?;
    for job in jobs {
        if recover_job(state, &job).await? == BackupJobState::CleanupPending {
            return Err(ApiError::Conflict(format!(
                "online backup job {} still owns resources or uploaded objects that could not be cleaned up; resolve it before starting another online backup",
                job.job_id
            )));
        }
    }
    Ok(())
}

/// Best-effort retry of this instance's unsettled publications before any
/// backup. The caller holds the instance lock. Never blocks the backup.
pub(super) async fn recover_instance_publications(state: &AppState, instance_id: &str) {
    match publication::recover(state, Some(instance_id), true).await {
        Ok(resolutions) => {
            for resolution in resolutions {
                if let Resolution::Pending(reason) = resolution {
                    tracing::warn!(instance_id, %reason,
                        "an earlier backup's uploaded objects still await removal");
                }
            }
        }
        Err(error) => {
            tracing::warn!(instance_id, %error, "could not read unsettled backup publications")
        }
    }
}

async fn recover_job(state: &AppState, job: &BackupJobRecord) -> Result<BackupJobState, ApiError> {
    let now = now_rfc3339();
    let resolution = match state
        .backup_jobs
        .publication(&job.backup_id)
        .await
        .map_err(journal_error)?
    {
        Some(record) => Some(publication::resolve(state, &record).await),
        None => None,
    };
    // Publication happens after the lock is released; a crash between the
    // storage commit and the journal update leaves a valid published backup.
    let published = match &resolution {
        Some(resolution) => *resolution == Resolution::Published,
        None => job.state == BackupJobState::Validated && is_published(state, job).await,
    };
    if published {
        state
            .backup_jobs
            .transition(&job.job_id, BackupJobState::Published, None, &now)
            .await
            .map_err(journal_error)?;
        return Ok(BackupJobState::Published);
    }
    let publication_pending = match resolution {
        Some(Resolution::Pending(reason)) => Some(reason),
        _ => None,
    };
    let identity = BackupJobIdentity {
        job_id: job.job_id.parse().map_err(|_| {
            ApiError::Runtime(format!("backup job {} has an invalid id", job.job_id))
        })?,
        instance_id: job.instance_id.clone(),
        runtime_generation: job.runtime_generation.clone(),
    };
    let metadata = state.instances.get(&job.instance_id).await;
    let generation_matches = match metadata.as_ref() {
        Some(metadata) => runtime_generation(state, metadata)
            .await
            .is_ok_and(|current| current == job.runtime_generation),
        None => false,
    };
    let remaining = match strategy_by_id(&job.strategy) {
        Some(strategy) => {
            cleanup_job_resources(
                state,
                metadata.as_ref(),
                strategy,
                &identity,
                generation_matches,
            )
            .await?
        }
        None => release_generation_bound(state, &identity, generation_matches).await?,
    };
    // A helper that may still exist could still be writing to staging.
    if remaining.is_empty() {
        remove_journaled_staging(state, job).await;
    }
    let interrupted = BackupJobState::IN_FLIGHT.contains(&job.state);
    let error = match &publication_pending {
        Some(reason) => Some(format!(
            "uploaded objects of backup {} await removal: {reason}",
            job.backup_id
        )),
        None => {
            interrupted.then(|| "daemon restarted before the online backup completed".to_string())
        }
    };
    let to = if remaining.is_empty() && publication_pending.is_none() {
        BackupJobState::Failed
    } else {
        BackupJobState::CleanupPending
    };
    state
        .backup_jobs
        .transition(&job.job_id, to, error.as_deref(), &now)
        .await
        .map_err(journal_error)?;
    tracing::warn!(
        event = "audit online_backup_recovered",
        job_id = job.job_id,
        instance_id = job.instance_id,
        previous_state = job.state.as_str(),
        state = to.as_str(),
        remaining_resources = remaining.len(),
    );
    Ok(to)
}

/// Cleans every unreleased resource of a job that is provably still owned.
/// Returns the resources that remain.
pub(super) async fn cleanup_job_resources(
    state: &AppState,
    metadata: Option<&InstanceMetadata>,
    strategy: &dyn OnlineBackupStrategy,
    identity: &BackupJobIdentity,
    generation_matches: bool,
) -> Result<Vec<BackupResourceRecord>, ApiError> {
    let job_id = identity.job_id.to_string();
    let mut remaining = Vec::new();
    for record in state
        .backup_jobs
        .unreleased_resources(&job_id)
        .await
        .map_err(journal_error)?
    {
        let Some(resource) = owned_resource(identity, &record) else {
            // Never act on a name this job cannot prove it minted.
            remaining.push(record);
            continue;
        };
        let cleaned = if resource.kind == OwnedResourceKind::HelperContainer {
            remove_helper(state, &job_id, &resource.name).await
        } else {
            match (metadata, resource.survives_restart, generation_matches) {
                // The creating process is gone; generation-bound state went with it.
                (_, false, false) => true,
                (Some(metadata), _, _) => {
                    let ctx = CleanupContext {
                        state,
                        metadata,
                        job: identity,
                        generation_matches,
                    };
                    match strategy.cleanup_owned(&ctx, &resource).await {
                        Ok(()) => true,
                        Err(error) => {
                            tracing::warn!(job_id, resource = resource.name, %error,
                            "owned backup resource cleanup failed");
                            false
                        }
                    }
                }
                // A surviving resource of a deleted instance needs its runtime.
                (None, true, _) => false,
                (None, false, true) => true,
            }
        };
        if cleaned {
            state
                .backup_jobs
                .release_resource(&job_id, &record.kind, &record.name)
                .await
                .map_err(journal_error)?;
        } else {
            remaining.push(record);
        }
    }
    Ok(remaining)
}

/// Without the strategy in this build only generation-bound resources of a
/// replaced runtime can be released.
async fn release_generation_bound(
    state: &AppState,
    identity: &BackupJobIdentity,
    generation_matches: bool,
) -> Result<Vec<BackupResourceRecord>, ApiError> {
    let job_id = identity.job_id.to_string();
    let mut remaining = Vec::new();
    for record in state
        .backup_jobs
        .unreleased_resources(&job_id)
        .await
        .map_err(journal_error)?
    {
        let helper = owned_resource(identity, &record)
            .filter(|resource| resource.kind == OwnedResourceKind::HelperContainer);
        let cleaned = match helper {
            Some(resource) => remove_helper(state, &job_id, &resource.name).await,
            None => !record.survives_restart && !generation_matches,
        };
        if cleaned {
            state
                .backup_jobs
                .release_resource(&job_id, &record.kind, &record.name)
                .await
                .map_err(journal_error)?;
        } else {
            remaining.push(record);
        }
    }
    Ok(remaining)
}

/// Helper containers outlive the runtime and need no strategy: force-remove
/// and confirm absence.
async fn remove_helper(state: &AppState, job_id: &str, name: &str) -> bool {
    match state.docker.remove_backup_helper(name).await {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(job_id, helper = name, %error, "backup helper removal is unconfirmed");
            false
        }
    }
}

fn owned_resource(
    identity: &BackupJobIdentity,
    record: &BackupResourceRecord,
) -> Option<OwnedResource> {
    let kind = OwnedResourceKind::parse(&record.kind)?;
    identity.owns_name(&record.name).then(|| OwnedResource {
        kind,
        name: record.name.clone(),
        survives_restart: record.survives_restart,
    })
}

async fn is_published(state: &AppState, job: &BackupJobRecord) -> bool {
    match super::storage::backup_storage(state) {
        Ok(storage) => storage.find(&job.instance_id, &job.backup_id).await.is_ok(),
        Err(_) => false,
    }
}

/// Removes the journaled capture staging, but only inside backup staging.
async fn remove_journaled_staging(state: &AppState, job: &BackupJobRecord) {
    let staging_root = PathBuf::from(state.config.paths.backups_root()).join(".staging");
    let path = Path::new(&job.staging_path);
    if is_job_staging(&staging_root, &job.instance_id, path) {
        remove_staging(path).await;
    } else {
        tracing::warn!(job_id = job.job_id, path = %path.display(),
            "refusing to remove backup staging outside the staging root");
    }
}

fn is_job_staging(staging_root: &Path, instance_id: &str, path: &Path) -> bool {
    path.parent() == Some(staging_root.join(instance_id).as_path())
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with('.') && name.ends_with(".capture"))
}

#[cfg(test)]
mod tests {
    use super::super::{
        online::JournalRegistrar,
        strategy::{
            CaptureResult, OnlineBackupContext, OwnedResourceRegistrar, StagingArea, StrategyError,
            VerificationCheck,
        },
    };
    use super::*;
    use crate::server::backup::manifest::RestoreRecipeRef;
    use futures::future::BoxFuture;

    fn identity() -> BackupJobIdentity {
        BackupJobIdentity {
            job_id: uuid::Uuid::new_v4(),
            instance_id: "inst_one".to_string(),
            runtime_generation: "abc@1".to_string(),
        }
    }

    #[test]
    fn only_tagged_known_resources_are_actionable() {
        let job = identity();
        let tagged = BackupResourceRecord {
            kind: "replication_slot".to_string(),
            name: format!("{}_slot", job.resource_tag()),
            survives_restart: false,
        };
        assert!(owned_resource(&job, &tagged).is_some());
        let foreign = BackupResourceRecord {
            name: "dbev_bk_someone_else".to_string(),
            ..tagged.clone()
        };
        assert!(owned_resource(&job, &foreign).is_none());
        let unknown_kind = BackupResourceRecord {
            kind: "tablespace".to_string(),
            ..tagged
        };
        assert!(owned_resource(&job, &unknown_kind).is_none());
    }

    #[test]
    fn staging_removal_is_confined_to_capture_directories() {
        let root = Path::new("/backups/.staging");
        assert!(is_job_staging(
            root,
            "inst_one",
            Path::new("/backups/.staging/inst_one/.abc.capture")
        ));
        for path in [
            "/backups/.staging/inst_two/.abc.capture",
            "/backups/.staging/inst_one/.abc.bundle",
            "/backups/inst_one/.abc.capture",
            "/",
        ] {
            assert!(!is_job_staging(root, "inst_one", Path::new(path)));
        }
    }

    struct FakeStrategy {
        fail_cleanup: bool,
        cleaned: std::sync::Mutex<Vec<String>>,
    }

    impl OnlineBackupStrategy for FakeStrategy {
        fn id(&self) -> &'static str {
            "test.fake"
        }

        fn restore_recipe(&self) -> RestoreRecipeRef {
            RestoreRecipeRef::new("test.fake", 1)
        }

        fn restorable_recipe_versions(&self) -> &'static [u32] {
            &[1]
        }

        fn preflight<'a>(
            &'a self,
            _ctx: &'a OnlineBackupContext<'a>,
        ) -> BoxFuture<'a, Result<(), StrategyError>> {
            Box::pin(async { Ok(()) })
        }

        fn capture<'a>(
            &'a self,
            _ctx: &'a OnlineBackupContext<'a>,
            _staging: &'a StagingArea,
            _registrar: &'a dyn OwnedResourceRegistrar,
        ) -> BoxFuture<'a, Result<CaptureResult, StrategyError>> {
            Box::pin(async { Err(StrategyError::Failed("not used".to_string())) })
        }

        fn verify<'a>(
            &'a self,
            _ctx: &'a OnlineBackupContext<'a>,
            _staging: &'a StagingArea,
            _capture: &'a CaptureResult,
            _registrar: &'a dyn OwnedResourceRegistrar,
        ) -> BoxFuture<'a, Result<Vec<VerificationCheck>, StrategyError>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn cleanup_owned<'a>(
            &'a self,
            ctx: &'a CleanupContext<'a>,
            resource: &'a OwnedResource,
        ) -> BoxFuture<'a, Result<(), StrategyError>> {
            Box::pin(async move {
                assert!(ctx.job.owns_name(&resource.name));
                if self.fail_cleanup {
                    return Err(StrategyError::Failed("runtime unavailable".to_string()));
                }
                self.cleaned.lock().unwrap().push(resource.name.clone());
                Ok(())
            })
        }
    }

    async fn journal_state() -> (tempfile::TempDir, AppState) {
        use crate::{
            auth::api_token::ApiToken,
            server::{manager::InstanceManager, state::InstanceStore},
            storage::repositories::InstanceRepository,
        };
        let dir = tempfile::tempdir().unwrap();
        let pool = crate::storage::sqlite::connect(dir.path()).await.unwrap();
        let store = InstanceStore::default();
        let manager = InstanceManager::new(store.clone(), InstanceRepository::new(pool.clone()));
        let mut config = crate::config::Config::default();
        config.paths.backups = dir.path().join("backups").display().to_string();
        let state = crate::subsystems::test_support::state(
            config,
            Default::default(),
            ApiToken::new("test-token"),
            store,
            manager,
            pool,
        );
        (dir, state)
    }

    async fn admit_capturing(state: &AppState, job: &BackupJobIdentity) {
        let now = now_rfc3339();
        state
            .backup_jobs
            .admit(&BackupJobRecord {
                job_id: job.job_id.to_string(),
                instance_id: job.instance_id.clone(),
                backup_id: "one.physical.tar.gz".to_string(),
                strategy: "test.fake".to_string(),
                runtime_generation: job.runtime_generation.clone(),
                source_identity: "{}".to_string(),
                staging_path: "/backups/.staging/inst_one/.x.capture".to_string(),
                state: BackupJobState::Admitted,
                error: None,
                created_at: now.clone(),
                updated_at: now.clone(),
            })
            .await
            .unwrap();
        state
            .backup_jobs
            .transition(
                &job.job_id.to_string(),
                BackupJobState::Capturing,
                None,
                &now,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn registrar_journals_only_job_tagged_resources() {
        let (_dir, state) = journal_state().await;
        let job = identity();
        admit_capturing(&state, &job).await;
        let registrar = JournalRegistrar {
            repository: &state.backup_jobs,
            job: &job,
        };
        let owned = OwnedResource {
            kind: OwnedResourceKind::ReplicationSlot,
            name: format!("{}_slot", job.resource_tag()),
            survives_restart: false,
        };
        registrar.register(&owned).await.unwrap();
        let foreign = OwnedResource {
            name: "pg_basebackup_123".to_string(),
            ..owned.clone()
        };
        assert!(registrar.register(&foreign).await.is_err());
        let job_id = job.job_id.to_string();
        let journaled = state
            .backup_jobs
            .unreleased_resources(&job_id)
            .await
            .unwrap();
        assert_eq!(journaled.len(), 1);
        registrar.released(&owned).await.unwrap();
        assert!(
            state
                .backup_jobs
                .unreleased_resources(&job_id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn cleanup_releases_gone_resources_and_cleans_only_provable_survivors() {
        let (_dir, state) = journal_state().await;
        let job = identity();
        admit_capturing(&state, &job).await;
        let job_id = job.job_id.to_string();
        let now = now_rfc3339();
        let session = BackupResourceRecord {
            kind: "server_session".to_string(),
            name: format!("{}_session", job.resource_tag()),
            survives_restart: false,
        };
        let slot = BackupResourceRecord {
            kind: "replication_slot".to_string(),
            name: format!("{}_slot", job.resource_tag()),
            survives_restart: true,
        };
        // A journal row this job cannot prove it minted is never acted on.
        let foreign = BackupResourceRecord {
            kind: "helper_process".to_string(),
            name: "someone_elses_process".to_string(),
            survives_restart: true,
        };
        for record in [&session, &slot, &foreign] {
            state
                .backup_jobs
                .register_resource(&job_id, record, &now)
                .await
                .unwrap();
        }
        let metadata = crate::server::test_support::metadata(
            "inst_one",
            crate::databases::protocol::Protocol::Postgres,
        );

        let failing = FakeStrategy {
            fail_cleanup: true,
            cleaned: Default::default(),
        };
        let remaining = cleanup_job_resources(&state, Some(&metadata), &failing, &job, false)
            .await
            .unwrap();
        // The replaced runtime took the session with it; the slot survives.
        assert_eq!(remaining, vec![foreign.clone(), slot.clone()]);

        let strategy = FakeStrategy {
            fail_cleanup: false,
            cleaned: Default::default(),
        };
        let remaining = cleanup_job_resources(&state, Some(&metadata), &strategy, &job, false)
            .await
            .unwrap();
        assert_eq!(remaining, vec![foreign]);
        assert_eq!(*strategy.cleaned.lock().unwrap(), vec![slot.name]);
    }

    #[tokio::test]
    async fn an_unconfirmed_helper_keeps_the_job_pending_and_journaled() {
        let (_dir, state) = journal_state().await;
        let job = identity();
        admit_capturing(&state, &job).await;
        let job_id = job.job_id.to_string();
        let helper = BackupResourceRecord {
            kind: "helper_container".to_string(),
            name: job.resource_tag(),
            survives_restart: true,
        };
        state
            .backup_jobs
            .register_resource(&job_id, &helper, &now_rfc3339())
            .await
            .unwrap();
        // The offline test runtime cannot confirm removal, so nothing is
        // released and the job blocks further online backups.
        let record = state.backup_jobs.get(&job_id).await.unwrap().unwrap();
        assert_eq!(
            recover_job(&state, &record).await.unwrap(),
            BackupJobState::CleanupPending
        );
        assert_eq!(
            state
                .backup_jobs
                .unreleased_resources(&job_id)
                .await
                .unwrap(),
            vec![helper]
        );
        assert!(
            recover_instance_jobs(&state, "inst_one")
                .await
                .is_err_and(|error| matches!(error, ApiError::Conflict(_)))
        );
    }

    #[tokio::test]
    async fn unsettled_publications_are_removed_or_kept_pending() {
        let (_dir, state) = journal_state().await;
        let storage = crate::subsystems::backups::storage::backup_storage(&state).unwrap();
        // A deleted instance's interrupted upload is removed by backup id.
        publication::begin(&state, &storage, "inst_gone", "a.physical.tar.gz", None)
            .await
            .unwrap();
        // A publication journaled against another storage target is never
        // cleaned against the current one.
        state
            .backup_jobs
            .begin_publication(&crate::storage::backup_jobs::BackupPublicationRecord {
                backup_id: "b.physical.tar.gz".to_string(),
                instance_id: "inst_gone".to_string(),
                storage_kind: "s3".to_string(),
                storage_identity: "s3:https://example.invalid/|bucket|".to_string(),
                job_id: None,
                state: crate::storage::backup_jobs::PublicationState::Publishing,
                error: None,
                created_at: now_rfc3339(),
                updated_at: now_rfc3339(),
            })
            .await
            .unwrap();
        let resolutions = publication::recover(&state, None, false).await.unwrap();
        assert_eq!(resolutions.len(), 2);
        assert_eq!(resolutions[0], Resolution::Removed);
        assert!(
            matches!(&resolutions[1], Resolution::Pending(reason) if reason.contains("storage changed"))
        );
        let left = state
            .backup_jobs
            .unsettled_publications(None)
            .await
            .unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].backup_id, "b.physical.tar.gz");
        assert!(
            left[0]
                .error
                .as_deref()
                .unwrap()
                .contains("storage changed")
        );
    }
}
