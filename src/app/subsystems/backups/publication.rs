//! Durable publication of finished backups.
//!
//! A publication is journaled (storage target and backup id) before anything
//! is uploaded. After the upload the instance management lock is reacquired,
//! so the final existence check is serialized with instance deletion, which
//! purges backups under the same lock. A failed upload, or an instance that
//! was deleted during the upload, turns the row into `unpublish` and every
//! object of the backup id is removed idempotently, whether or not its
//! metadata exists. Rows stay until the outcome is settled, so storage
//! errors and daemon restarts are retried by recovery; an online job whose
//! objects could not be removed stays `cleanup_pending`.
//!
//! Providers journal remote resources that the backup id cannot find again
//! (Kopia source paths, S3 multipart upload ids) through [`Journal`] while
//! they upload; removal includes them and must be confirmed by the provider.

use futures::future::BoxFuture;

use super::{
    checks::store_error,
    online::{finish_publication, journal_error},
    storage::backup_storage,
};
use crate::{
    routes::http::{response::ApiError, router::AppState},
    server::{
        backup::{
            BackupStorage, BackupStoreError,
            drivers::{PublicationJournal, PublicationResource},
        },
        jobs::import_export::now_rfc3339,
    },
    storage::backup_jobs::{BackupPublicationRecord, PublicationResourceRecord, PublicationState},
};

/// Records the resources of one journaled publication.
pub(super) struct Journal<'a> {
    state: &'a AppState,
    backup_id: &'a str,
}

pub(super) fn journal<'a>(state: &'a AppState, backup_id: &'a str) -> Journal<'a> {
    Journal { state, backup_id }
}

impl PublicationJournal for Journal<'_> {
    fn record<'a>(
        &'a self,
        resource: &'a PublicationResource,
    ) -> BoxFuture<'a, Result<(), BackupStoreError>> {
        Box::pin(async move {
            let (kind, locator, detail) = resource.journal_parts();
            self.state
                .backup_jobs
                .record_publication_resource(
                    self.backup_id,
                    &PublicationResourceRecord {
                        kind: kind.to_string(),
                        locator: locator.to_string(),
                        detail: detail.to_string(),
                    },
                    &now_rfc3339(),
                )
                .await
                .map_err(|error| {
                    BackupStoreError::Runtime(format!(
                        "could not journal a backup publication resource: {error}"
                    ))
                })
        })
    }
}

/// How recovery settled one unsettled publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Resolution {
    /// The backup is visible and its instance still exists.
    Published,
    /// Every object of the backup id is gone.
    Removed,
    /// Still unsettled; retried later.
    Pending(String),
}

/// Journals the publication before any object is uploaded.
pub(super) async fn begin(
    state: &AppState,
    storage: &BackupStorage,
    instance_id: &str,
    backup_id: &str,
    job_id: Option<&str>,
) -> Result<(), ApiError> {
    let now = now_rfc3339();
    state
        .backup_jobs
        .begin_publication(&BackupPublicationRecord {
            backup_id: backup_id.to_string(),
            instance_id: instance_id.to_string(),
            storage_kind: storage.kind().as_str().to_string(),
            storage_identity: storage.identity(),
            job_id: job_id.map(str::to_string),
            state: PublicationState::Publishing,
            error: None,
            created_at: now.clone(),
            updated_at: now,
        })
        .await
        .map_err(journal_error)
}

/// Settles a finished upload. Returns the backup's outcome for the caller.
pub(super) async fn finish(
    state: &AppState,
    storage: &BackupStorage,
    instance_id: &str,
    backup_id: &str,
    online_job: Option<&str>,
    committed: Result<(), ApiError>,
) -> Result<(), ApiError> {
    let failure = match committed {
        Err(error) => error,
        Ok(()) => {
            // Serialized with deletion: either deletion runs later and purges
            // this backup, or it already ran and the backup is removed here.
            let _operation = state.instance_locks.lock(instance_id).await;
            if state.instances.get(instance_id).await.is_some() {
                if let Some(job_id) = online_job {
                    finish_publication(state, job_id, Ok(()), false).await;
                }
                // A leftover row is settled by recovery: the backup is found.
                if let Err(error) = state.backup_jobs.settle_publication(backup_id).await {
                    tracing::warn!(backup_id, %error, "published backup could not be settled in the journal");
                }
                return Ok(());
            }
            let removal = unpublish(
                state,
                storage,
                instance_id,
                backup_id,
                "the instance was deleted while the backup uploaded",
            )
            .await;
            if let Err(reason) = &removal {
                tracing::warn!(instance_id, backup_id, %reason,
                    "backup of a deleted instance could not be removed yet; recovery retries it");
            }
            if let Some(job_id) = online_job {
                finish_publication(state, job_id, Err(&ApiError::NotFound), removal.is_err()).await;
            }
            return Err(ApiError::NotFound);
        }
    };
    let removal = unpublish(state, storage, instance_id, backup_id, &failure.to_string()).await;
    let removal_pending = removal.is_err();
    let failure = match removal {
        Ok(()) => failure,
        Err(reason) => ApiError::Runtime(format!(
            "{failure}; partially uploaded objects await removal by recovery: {reason}"
        )),
    };
    if let Some(job_id) = online_job {
        finish_publication(state, job_id, Err(&failure), removal_pending).await;
    }
    Err(failure)
}

/// Settles one journaled publication. The caller holds the instance lock.
pub(super) async fn resolve(state: &AppState, record: &BackupPublicationRecord) -> Resolution {
    let storage = match backup_storage(state) {
        Ok(storage) => storage,
        Err(error) => return pending(state, record, &error.to_string()).await,
    };
    if storage.kind().as_str() != record.storage_kind
        || storage.identity() != record.storage_identity
    {
        return pending(
            state,
            record,
            "backup storage changed since this publication began; restore that storage configuration so its objects can be removed",
        )
        .await;
    }
    let instance_exists = state.instances.get(&record.instance_id).await.is_some();
    if record.state == PublicationState::Publishing && instance_exists {
        match storage.find(&record.instance_id, &record.backup_id).await {
            Ok(_) => {
                return match state
                    .backup_jobs
                    .settle_publication(&record.backup_id)
                    .await
                {
                    Ok(()) => Resolution::Published,
                    Err(error) => Resolution::Pending(error.to_string()),
                };
            }
            // Never became visible: remove whatever was partially written.
            Err(BackupStoreError::NotFound) => {}
            // Never remove objects that cannot be interpreted.
            Err(error) => return pending(state, record, &error.to_string()).await,
        }
    }
    let reason = if instance_exists {
        "the publication did not complete"
    } else {
        "the instance no longer exists"
    };
    match unpublish(
        state,
        &storage,
        &record.instance_id,
        &record.backup_id,
        reason,
    )
    .await
    {
        Ok(()) => Resolution::Removed,
        Err(reason) => Resolution::Pending(reason),
    }
}

/// Settles journaled publications of one instance (or all), each under its
/// instance lock unless the caller already holds it.
pub(super) async fn recover(
    state: &AppState,
    instance_id: Option<&str>,
    locked: bool,
) -> Result<Vec<Resolution>, ApiError> {
    let records = state
        .backup_jobs
        .unsettled_publications(instance_id)
        .await
        .map_err(journal_error)?;
    let mut resolutions = Vec::with_capacity(records.len());
    for record in records {
        let _operation = if locked {
            None
        } else {
            Some(state.instance_locks.lock(&record.instance_id).await)
        };
        let resolution = resolve(state, &record).await;
        tracing::warn!(
            event = "audit backup_publication_recovered",
            instance_id = record.instance_id,
            backup_id = record.backup_id,
            previous_state = record.state.as_str(),
            resolution = ?resolution,
        );
        resolutions.push(resolution);
    }
    Ok(resolutions)
}

async fn unpublish(
    state: &AppState,
    storage: &BackupStorage,
    instance_id: &str,
    backup_id: &str,
    reason: &str,
) -> Result<(), String> {
    let now = now_rfc3339();
    state
        .backup_jobs
        .mark_unpublish(backup_id, Some(reason), &now)
        .await
        .map_err(|error| error.to_string())?;
    let purged = match journaled_resources(state, backup_id).await {
        Ok(resources) => storage
            .purge_unpublished(instance_id, backup_id, &resources)
            .await
            .map_err(|error| store_error(error).to_string()),
        Err(error) => Err(error),
    };
    if let Err(error) = purged {
        if let Err(journal) = state
            .backup_jobs
            .note_publication_error(backup_id, &error, &now)
            .await
        {
            tracing::warn!(backup_id, %journal, "could not record a backup cleanup failure");
        }
        return Err(error);
    }
    state
        .backup_jobs
        .settle_publication(backup_id)
        .await
        .map_err(|error| error.to_string())
}

/// An unreadable resource keeps the publication pending: settling it would
/// forget a remote resource that may still exist.
async fn journaled_resources(
    state: &AppState,
    backup_id: &str,
) -> Result<Vec<PublicationResource>, String> {
    state
        .backup_jobs
        .publication_resources(backup_id)
        .await
        .map_err(|error| error.to_string())?
        .iter()
        .map(|record| {
            PublicationResource::from_journal(&record.kind, &record.locator, &record.detail)
                .map_err(|error| error.to_string())
        })
        .collect()
}

async fn pending(state: &AppState, record: &BackupPublicationRecord, reason: &str) -> Resolution {
    if let Err(error) = state
        .backup_jobs
        .note_publication_error(&record.backup_id, reason, &now_rfc3339())
        .await
    {
        tracing::warn!(backup_id = record.backup_id, %error, "could not record a backup cleanup failure");
    }
    Resolution::Pending(reason.to_string())
}
