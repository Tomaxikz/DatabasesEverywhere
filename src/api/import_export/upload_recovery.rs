use std::{
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    time::Duration,
};

use sha2::{Digest, Sha256};

use crate::{
    api::{api_response::ApiError, routes::AppState},
    instances::metadata::InstanceStatus,
    jobs::import_export::{ImportExportAction, ImportExportJob, ImportExportStatus},
    shared::time::now_rfc3339,
    storage::import_uploads::{
        ImportUpload, ImportUploadState, ImportUploadStorageError, InterruptedImportDisposition,
    },
};

use super::uploads::{remove_upload_file, upload_file_path};

const RECOVERY_BATCH_SIZE: u32 = 1_000;
const SWEEP_BATCH_SIZE: u32 = 256;
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const NONTERMINAL_RETRY_MINIMUM_AGE_SECONDS: u32 = 120;
const INTERRUPTED_JOB_ERROR: &str = "daemon restarted before import/export job completed";
const PROCESSING_RECOVERY_REASON: &str =
    "dump inspection was interrupted by a daemon restart; inspect the upload again if needed";
const FAILED_JOB_RECOVERY_REASON: &str =
    "the failed import ended before its temporary upload claim was released";
const UNCERTAIN_IMPORT_REASON: &str = "the import outcome is uncertain after a daemon restart; this upload is blocked to prevent a duplicate mutation";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ImportUploadRecoverySummary {
    pub examined: u64,
    pub restored_ready: u64,
    pub blocked: u64,
    pub deleted: u64,
    pub failures: u64,
}

impl ImportUploadRecoverySummary {
    fn record(&mut self, outcome: RecoveryOutcome) {
        self.examined = self.examined.saturating_add(1);
        match outcome {
            RecoveryOutcome::RestoredReady => {
                self.restored_ready = self.restored_ready.saturating_add(1);
            }
            RecoveryOutcome::Blocked => self.blocked = self.blocked.saturating_add(1),
            RecoveryOutcome::Deleted => self.deleted = self.deleted.saturating_add(1),
            RecoveryOutcome::Skipped => {}
        }
    }

    fn merge(&mut self, other: Self) {
        self.examined = self.examined.saturating_add(other.examined);
        self.restored_ready = self.restored_ready.saturating_add(other.restored_ready);
        self.blocked = self.blocked.saturating_add(other.blocked);
        self.deleted = self.deleted.saturating_add(other.deleted);
        self.failures = self.failures.saturating_add(other.failures);
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ImportUploadRecoveryError {
    #[error("temporary import upload storage reconciliation failed: {0}")]
    Storage(#[from] ImportUploadStorageError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryOutcome {
    RestoredReady,
    Blocked,
    Deleted,
    Skipped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterruptedImportAction {
    Consume,
    RestoreReady,
    Block,
}

pub(crate) async fn reconcile_import_uploads_once(
    state: &AppState,
) -> Result<ImportUploadRecoverySummary, ImportUploadRecoveryError> {
    let mut summary = ImportUploadRecoverySummary::default();
    let mut after_upload_id = None;
    loop {
        let uploads = state
            .import_uploads
            .repository()
            .list_recoverable_after(after_upload_id.as_deref(), RECOVERY_BATCH_SIZE)
            .await?;
        let Some(next_cursor) = uploads.last().map(|upload| upload.upload_id.clone()) else {
            break;
        };
        for upload in uploads {
            match recover_one(state, upload).await {
                Ok(outcome) => summary.record(outcome),
                Err(()) => summary.failures = summary.failures.saturating_add(1),
            }
        }
        after_upload_id = Some(next_cursor);
    }
    summary.merge(sweep_expired_batch(state).await?);
    Ok(summary)
}

pub(crate) async fn run_import_upload_sweeper(state: AppState) {
    let mut shutdown = state.daemon_shutdown.subscribe();
    if *shutdown.borrow() {
        return;
    }
    let mut interval = tokio::time::interval(SWEEP_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            _ = interval.tick() => {
                let mut summary = match sweep_expired_batch(&state).await {
                    Ok(summary) => summary,
                    Err(_) => {
                        tracing::error!("temporary import upload expiry sweep could not query durable state");
                        continue;
                    }
                };
                match retry_terminal_cleanup_batch(&state).await {
                    Ok(retries) => summary.merge(retries),
                    Err(_) => {
                        summary.failures = summary.failures.saturating_add(1);
                        tracing::error!("temporary import upload cleanup retry could not query durable state");
                    }
                }
                match retry_nonterminal_recovery_batch(&state).await {
                    Ok(retries) => summary.merge(retries),
                    Err(_) => {
                        summary.failures = summary.failures.saturating_add(1);
                        tracing::error!("temporary import upload recovery retry could not query durable state");
                    }
                }
                if summary.examined > 0 || summary.failures > 0 {
                    tracing::info!(
                        examined = summary.examined,
                        deleted = summary.deleted,
                        failures = summary.failures,
                        "temporary import upload sweep completed"
                    );
                }
            }
        }
    }
}

async fn recover_one(state: &AppState, snapshot: ImportUpload) -> Result<RecoveryOutcome, ()> {
    let _operation = state.instance_locks.lock(&snapshot.instance_id).await;
    let current = match state
        .import_uploads
        .repository()
        .get(&snapshot.instance_id, &snapshot.upload_id)
        .await
    {
        Ok(Some(upload)) => upload,
        Ok(None) => return Ok(RecoveryOutcome::Skipped),
        Err(_) => return recovery_failed(&snapshot, "load"),
    };

    match current.state {
        ImportUploadState::Uploading => recover_uploading(state, &current).await,
        ImportUploadState::Uploaded => recover_uploaded(state, &current).await,
        ImportUploadState::Processing => recover_processing(state, &current).await,
        ImportUploadState::Importing => recover_importing(state, &current).await,
        ImportUploadState::Consumed | ImportUploadState::Deleting => {
            cleanup_terminal_upload(state, &current).await
        }
        ImportUploadState::Ready | ImportUploadState::Failed => Ok(RecoveryOutcome::Skipped),
    }
}

async fn recover_uploading(state: &AppState, upload: &ImportUpload) -> Result<RecoveryOutcome, ()> {
    if remove_known_upload_files(state, upload).await.is_err() {
        return recovery_failed(upload, "remove_incomplete");
    }
    match state
        .import_uploads
        .repository()
        .abort_uploading(&upload.instance_id, &upload.upload_id)
        .await
    {
        Ok(true) => Ok(RecoveryOutcome::Deleted),
        Ok(false) => Ok(RecoveryOutcome::Skipped),
        Err(_) => recovery_failed(upload, "finalize_incomplete"),
    }
}

async fn recover_uploaded(state: &AppState, upload: &ImportUpload) -> Result<RecoveryOutcome, ()> {
    let path = match upload_file_path(state, upload) {
        Ok(path) => path,
        Err(_) => return recovery_failed(upload, "resolve_completed"),
    };
    let expected_size = upload.size_bytes;
    let expected_digest = match upload.sha256.clone() {
        Some(digest) => digest,
        None => return claim_and_delete(state, upload).await,
    };
    let valid = tokio::task::spawn_blocking(move || {
        verify_completed_upload(&path, expected_size, &expected_digest)
    })
    .await
    .ok()
    .and_then(Result::ok)
    .unwrap_or(false);
    if !valid {
        return claim_and_delete(state, upload).await;
    }
    match state
        .import_uploads
        .repository()
        .mark_ready(
            &upload.instance_id,
            &upload.upload_id,
            upload.catalog_json.as_deref(),
            &now_rfc3339(),
        )
        .await
    {
        Ok(true) => Ok(RecoveryOutcome::RestoredReady),
        Ok(false) => Ok(RecoveryOutcome::Skipped),
        Err(_) => recovery_failed(upload, "restore_completed"),
    }
}

async fn recover_processing(
    state: &AppState,
    upload: &ImportUpload,
) -> Result<RecoveryOutcome, ()> {
    match state
        .import_uploads
        .repository()
        .restore_ready_after_processing(
            &upload.instance_id,
            &upload.upload_id,
            upload.archive_format,
            upload.catalog_json.as_deref(),
            Some(PROCESSING_RECOVERY_REASON),
            &now_rfc3339(),
        )
        .await
    {
        Ok(true) => Ok(RecoveryOutcome::RestoredReady),
        Ok(false) => Ok(RecoveryOutcome::Skipped),
        Err(_) => recovery_failed(upload, "restore_inspection"),
    }
}

async fn recover_importing(state: &AppState, upload: &ImportUpload) -> Result<RecoveryOutcome, ()> {
    let Some(job_id) = upload.claimed_job_id.as_deref() else {
        return recovery_failed(upload, "missing_claim");
    };
    let job = match state.import_export_jobs.get(job_id).await {
        Ok(job) => job,
        Err(_) => return recovery_failed(upload, "load_job"),
    };
    let target_quarantined = state
        .instances
        .get(&upload.instance_id)
        .await
        .is_none_or(|metadata| metadata.status == InstanceStatus::Quarantined);
    match interrupted_import_action(upload, job.as_ref(), target_quarantined) {
        InterruptedImportAction::Consume => {
            match state
                .import_uploads
                .repository()
                .mark_consumed(
                    &upload.instance_id,
                    &upload.upload_id,
                    job_id,
                    &now_rfc3339(),
                )
                .await
            {
                Ok(true) => {
                    let mut consumed = upload.clone();
                    consumed.state = ImportUploadState::Consumed;
                    cleanup_terminal_upload(state, &consumed).await
                }
                Ok(false) => Ok(RecoveryOutcome::Skipped),
                Err(_) => recovery_failed(upload, "record_consumed"),
            }
        }
        InterruptedImportAction::RestoreReady => {
            reconcile_interrupted_claim(
                state,
                upload,
                job_id,
                InterruptedImportDisposition::Ready,
                FAILED_JOB_RECOVERY_REASON,
                RecoveryOutcome::RestoredReady,
            )
            .await
        }
        InterruptedImportAction::Block => {
            reconcile_interrupted_claim(
                state,
                upload,
                job_id,
                InterruptedImportDisposition::Failed,
                UNCERTAIN_IMPORT_REASON,
                RecoveryOutcome::Blocked,
            )
            .await
        }
    }
}

async fn reconcile_interrupted_claim(
    state: &AppState,
    upload: &ImportUpload,
    job_id: &str,
    disposition: InterruptedImportDisposition,
    reason: &str,
    outcome: RecoveryOutcome,
) -> Result<RecoveryOutcome, ()> {
    match state
        .import_uploads
        .repository()
        .reconcile_interrupted_importing(
            &upload.instance_id,
            &upload.upload_id,
            job_id,
            disposition,
            reason,
            &now_rfc3339(),
        )
        .await
    {
        Ok(true) => Ok(outcome),
        Ok(false) => Ok(RecoveryOutcome::Skipped),
        Err(_) => recovery_failed(upload, "reconcile_claim"),
    }
}

fn interrupted_import_action(
    upload: &ImportUpload,
    job: Option<&ImportExportJob>,
    target_quarantined: bool,
) -> InterruptedImportAction {
    let Some(job) = job.filter(|job| {
        job.job_id == upload.claimed_job_id.as_deref().unwrap_or_default()
            && job.instance_id == upload.instance_id
            && job.action == ImportExportAction::Import
    }) else {
        return InterruptedImportAction::Block;
    };
    match job.status {
        ImportExportStatus::Succeeded => InterruptedImportAction::Consume,
        ImportExportStatus::Failed
            if !target_quarantined && job.error.as_deref() != Some(INTERRUPTED_JOB_ERROR) =>
        {
            InterruptedImportAction::RestoreReady
        }
        ImportExportStatus::Queued | ImportExportStatus::Running | ImportExportStatus::Failed => {
            InterruptedImportAction::Block
        }
    }
}

async fn sweep_expired_batch(
    state: &AppState,
) -> Result<ImportUploadRecoverySummary, ImportUploadRecoveryError> {
    let uploads = state
        .import_uploads
        .repository()
        .list_expired(&now_rfc3339(), SWEEP_BATCH_SIZE)
        .await?;
    let mut summary = ImportUploadRecoverySummary::default();
    for snapshot in uploads {
        let _operation = state.instance_locks.lock(&snapshot.instance_id).await;
        let current = match state
            .import_uploads
            .repository()
            .get(&snapshot.instance_id, &snapshot.upload_id)
            .await
        {
            Ok(Some(upload)) => upload,
            Ok(None) => {
                summary.record(RecoveryOutcome::Skipped);
                continue;
            }
            Err(_) => {
                summary.failures = summary.failures.saturating_add(1);
                continue;
            }
        };
        if !matches!(
            current.state,
            ImportUploadState::Uploaded | ImportUploadState::Ready | ImportUploadState::Failed
        ) {
            summary.record(RecoveryOutcome::Skipped);
            continue;
        }
        match claim_and_delete(state, &current).await {
            Ok(outcome) => summary.record(outcome),
            Err(()) => summary.failures = summary.failures.saturating_add(1),
        }
    }
    Ok(summary)
}

async fn retry_terminal_cleanup_batch(
    state: &AppState,
) -> Result<ImportUploadRecoverySummary, ImportUploadRecoveryError> {
    let mut summary = ImportUploadRecoverySummary::default();
    let mut after_upload_id = None;
    loop {
        let uploads = state
            .import_uploads
            .repository()
            .list_terminal_cleanup_after(after_upload_id.as_deref(), SWEEP_BATCH_SIZE)
            .await?;
        let Some(next_cursor) = uploads.last().map(|upload| upload.upload_id.clone()) else {
            break;
        };
        for snapshot in uploads {
            let _operation = state.instance_locks.lock(&snapshot.instance_id).await;
            let current = match state
                .import_uploads
                .repository()
                .get(&snapshot.instance_id, &snapshot.upload_id)
                .await
            {
                Ok(Some(upload)) => upload,
                Ok(None) => {
                    summary.record(RecoveryOutcome::Skipped);
                    continue;
                }
                Err(_) => {
                    summary.failures = summary.failures.saturating_add(1);
                    continue;
                }
            };
            if !matches!(
                current.state,
                ImportUploadState::Consumed | ImportUploadState::Deleting
            ) {
                summary.record(RecoveryOutcome::Skipped);
                continue;
            }
            match cleanup_terminal_upload(state, &current).await {
                Ok(outcome) => summary.record(outcome),
                Err(()) => summary.failures = summary.failures.saturating_add(1),
            }
        }
        after_upload_id = Some(next_cursor);
    }
    Ok(summary)
}

async fn retry_nonterminal_recovery_batch(
    state: &AppState,
) -> Result<ImportUploadRecoverySummary, ImportUploadRecoveryError> {
    let mut summary = ImportUploadRecoverySummary::default();
    let mut after_upload_id = None;
    let recovery_now = now_rfc3339();
    loop {
        let uploads = state
            .import_uploads
            .repository()
            .list_nonterminal_recovery_after(
                after_upload_id.as_deref(),
                &recovery_now,
                NONTERMINAL_RETRY_MINIMUM_AGE_SECONDS,
                SWEEP_BATCH_SIZE,
            )
            .await?;
        let Some(next_cursor) = uploads.last().map(|upload| upload.upload_id.clone()) else {
            break;
        };
        for upload in uploads {
            if upload.state == ImportUploadState::Importing {
                let target_quarantined = state
                    .instances
                    .get(&upload.instance_id)
                    .await
                    .is_some_and(|metadata| metadata.status == InstanceStatus::Quarantined);
                if !target_quarantined {
                    match importing_job_is_active(state, &upload).await {
                        Ok(true) => continue,
                        Ok(false) => {}
                        Err(()) => {
                            summary.failures = summary.failures.saturating_add(1);
                            continue;
                        }
                    }
                }
            }
            match recover_one(state, upload).await {
                Ok(outcome) => summary.record(outcome),
                Err(()) => summary.failures = summary.failures.saturating_add(1),
            }
        }
        after_upload_id = Some(next_cursor);
    }
    Ok(summary)
}

async fn importing_job_is_active(state: &AppState, upload: &ImportUpload) -> Result<bool, ()> {
    let Some(job_id) = upload.claimed_job_id.as_deref() else {
        return Ok(false);
    };
    match state.import_export_jobs.get(job_id).await {
        Ok(job) => Ok(is_active_import_job(upload, job.as_ref())),
        Err(_) => recovery_failed(upload, "probe_active_job"),
    }
}

fn is_active_import_job(upload: &ImportUpload, job: Option<&ImportExportJob>) -> bool {
    job.is_some_and(|job| {
        upload.claimed_job_id.as_deref() == Some(job.job_id.as_str())
            && job.instance_id == upload.instance_id
            && job.action == ImportExportAction::Import
            && matches!(
                job.status,
                ImportExportStatus::Queued | ImportExportStatus::Running
            )
    })
}

async fn claim_and_delete(state: &AppState, upload: &ImportUpload) -> Result<RecoveryOutcome, ()> {
    match state
        .import_uploads
        .repository()
        .claim_for_deletion(&upload.instance_id, &upload.upload_id, &now_rfc3339())
        .await
    {
        Ok(true) => {
            let mut deleting = upload.clone();
            deleting.state = ImportUploadState::Deleting;
            deleting.claimed_job_id = None;
            delete_deleting_upload(state, &deleting).await
        }
        Ok(false) => Ok(RecoveryOutcome::Skipped),
        Err(_) => recovery_failed(upload, "claim_cleanup"),
    }
}

async fn cleanup_terminal_upload(
    state: &AppState,
    upload: &ImportUpload,
) -> Result<RecoveryOutcome, ()> {
    if upload.state == ImportUploadState::Consumed {
        return claim_and_delete(state, upload).await;
    }
    if upload.state != ImportUploadState::Deleting {
        return Ok(RecoveryOutcome::Skipped);
    }
    delete_deleting_upload(state, upload).await
}

async fn delete_deleting_upload(
    state: &AppState,
    upload: &ImportUpload,
) -> Result<RecoveryOutcome, ()> {
    if remove_known_upload_files(state, upload).await.is_err() {
        return recovery_failed(upload, "remove_terminal");
    }
    match state
        .import_uploads
        .repository()
        .finalize_delete(&upload.instance_id, &upload.upload_id)
        .await
    {
        Ok(true) => Ok(RecoveryOutcome::Deleted),
        Ok(false) => match state
            .import_uploads
            .repository()
            .get(&upload.instance_id, &upload.upload_id)
            .await
        {
            Ok(None) => Ok(RecoveryOutcome::Deleted),
            Ok(Some(_)) | Err(_) => recovery_failed(upload, "finalize_cleanup"),
        },
        Err(_) => recovery_failed(upload, "finalize_cleanup"),
    }
}

async fn remove_known_upload_files(
    state: &AppState,
    upload: &ImportUpload,
) -> Result<(), ApiError> {
    remove_upload_file(state, upload).await?;
    let partial_path = managed_partial_path(state, upload)?;
    tokio::task::spawn_blocking(move || {
        crate::shared::files::remove_private_file_durable(&partial_path)
    })
    .await
    .map_err(|_| ApiError::Runtime("failed to join temporary upload cleanup".to_string()))?
    .or_else(|error| {
        (error.kind() == io::ErrorKind::NotFound)
            .then_some(())
            .ok_or(error)
    })
    .map_err(|_| ApiError::Runtime("failed to remove temporary upload data".to_string()))
}

fn managed_partial_path(state: &AppState, upload: &ImportUpload) -> Result<PathBuf, ApiError> {
    let final_path = upload_file_path(state, upload)?;
    let partial_name = format!(".{}.partial", upload.stored_filename);
    if !crate::shared::files::is_safe_flat_file_name(&partial_name) {
        return Err(ApiError::Runtime(
            "stored temporary upload filename is invalid".to_string(),
        ));
    }
    let parent = final_path
        .parent()
        .ok_or_else(|| ApiError::Runtime("temporary upload path has no parent".to_string()))?;
    Ok(parent.join(partial_name))
}

fn verify_completed_upload(
    path: &Path,
    expected_size: u64,
    expected_digest: &str,
) -> Result<bool, io::Error> {
    let mut file = open_regular_no_follow(path)?;
    if file.metadata()?.len() != expected_size {
        return Ok(false);
    }
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("temporary upload size overflow"))?;
        if total > expected_size {
            return Ok(false);
        }
        digest.update(&buffer[..read]);
    }
    Ok(total == expected_size && format!("{:x}", digest.finalize()) == expected_digest)
}

#[cfg(unix)]
fn open_regular_no_follow(path: &Path) -> Result<File, io::Error> {
    use rustix::fs::{FileType, Mode, OFlags};

    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "upload path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "upload path has no name"))?;
    let directory = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let descriptor = rustix::fs::openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let stat = rustix::fs::fstat(&descriptor).map_err(io::Error::from)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_nlink != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "temporary upload is not a singly-linked regular file",
        ));
    }
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_regular_no_follow(path: &Path) -> Result<File, io::Error> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "temporary upload is not a regular file",
        ));
    }
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "temporary upload is not a regular file",
        ));
    }
    Ok(file)
}

fn recovery_failed<T>(upload: &ImportUpload, phase: &'static str) -> Result<T, ()> {
    tracing::error!(
        instance_id = upload.instance_id,
        upload_id = upload.upload_id,
        phase,
        "temporary import upload recovery step failed"
    );
    Err(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::protocol::Protocol;

    fn upload() -> ImportUpload {
        ImportUpload {
            upload_id: "upl_0123456789abcdef0123456789abcdef".to_string(),
            instance_id: "instance-1".to_string(),
            original_filename: "dump.sql".to_string(),
            stored_filename: "upl_0123456789abcdef0123456789abcdef--dump.sql".to_string(),
            protocol: Protocol::Postgres,
            archive_format: None,
            state: ImportUploadState::Importing,
            size_bytes: 4,
            sha256: Some("a".repeat(64)),
            catalog_json: None,
            last_error: None,
            claimed_job_id: Some("job-1".to_string()),
            created_at: "2026-08-10T00:00:00Z".to_string(),
            updated_at: "2026-08-10T00:00:00Z".to_string(),
            expires_at: "2026-08-11T00:00:00Z".to_string(),
        }
    }

    fn job(status: ImportExportStatus, error: Option<&str>) -> ImportExportJob {
        ImportExportJob {
            job_id: "job-1".to_string(),
            instance_id: "instance-1".to_string(),
            action: ImportExportAction::Import,
            status,
            artifact_path: None,
            replay_options: None,
            error: error.map(str::to_string),
            created_at: "2026-08-10T00:00:00Z".to_string(),
            updated_at: "2026-08-10T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn succeeded_exact_job_is_consumed_without_replay() {
        let upload = upload();
        let job = job(ImportExportStatus::Succeeded, None);
        assert_eq!(
            interrupted_import_action(&upload, Some(&job), false),
            InterruptedImportAction::Consume
        );
    }

    #[test]
    fn known_failed_job_releases_upload_but_restart_failure_blocks_it() {
        let upload = upload();
        let ordinary_failure = job(ImportExportStatus::Failed, Some("dump was rejected"));
        assert_eq!(
            interrupted_import_action(&upload, Some(&ordinary_failure), false),
            InterruptedImportAction::RestoreReady
        );

        let interrupted = job(ImportExportStatus::Failed, Some(INTERRUPTED_JOB_ERROR));
        assert_eq!(
            interrupted_import_action(&upload, Some(&interrupted), false),
            InterruptedImportAction::Block
        );
    }

    #[test]
    fn missing_mismatched_or_active_job_fails_closed() {
        let upload = upload();
        assert_eq!(
            interrupted_import_action(&upload, None, false),
            InterruptedImportAction::Block
        );
        let mut mismatched = job(ImportExportStatus::Succeeded, None);
        mismatched.instance_id = "other-instance".to_string();
        assert_eq!(
            interrupted_import_action(&upload, Some(&mismatched), false),
            InterruptedImportAction::Block
        );
        let running = job(ImportExportStatus::Running, None);
        assert_eq!(
            interrupted_import_action(&upload, Some(&running), false),
            InterruptedImportAction::Block
        );
        let failed = job(ImportExportStatus::Failed, Some("dump was rejected"));
        assert_eq!(
            interrupted_import_action(&upload, Some(&failed), true),
            InterruptedImportAction::Block
        );

        assert!(is_active_import_job(
            &upload,
            Some(&job(ImportExportStatus::Queued, None))
        ));
        assert!(is_active_import_job(
            &upload,
            Some(&job(ImportExportStatus::Running, None))
        ));
        assert!(!is_active_import_job(&upload, Some(&failed)));
        assert!(!is_active_import_job(&upload, Some(&mismatched)));
    }

    #[test]
    fn completed_upload_verification_checks_size_and_digest() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("upload");
        std::fs::write(&path, b"dump").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"dump"));
        assert!(verify_completed_upload(&path, 4, &digest).unwrap());
        assert!(!verify_completed_upload(&path, 3, &digest).unwrap());
        assert!(!verify_completed_upload(&path, 4, &"0".repeat(64)).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn completed_upload_verification_rejects_links() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        let symlink_path = directory.path().join("symlink");
        let hardlink_path = directory.path().join("hardlink");
        std::fs::write(&source, b"dump").unwrap();
        symlink(&source, &symlink_path).unwrap();
        std::fs::hard_link(&source, &hardlink_path).unwrap();
        let digest = format!("{:x}", Sha256::digest(b"dump"));

        assert!(verify_completed_upload(&symlink_path, 4, &digest).is_err());
        assert!(verify_completed_upload(&hardlink_path, 4, &digest).is_err());
    }
}
