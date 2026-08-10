use super::*;

pub(super) fn spawn_export_job_supervisor(
    state: AppState,
    job_id: String,
    instance_id: String,
    artifact_path: PathBuf,
    options: ExportOptions,
    admission: ImportExportJobPermit,
) {
    tokio::spawn(async move {
        let _admission = admission;
        let _operation = state.instance_locks.lock(&instance_id).await;
        let Some(metadata) = state.instances.get(&instance_id).await else {
            let _ = update_job_result(&state, &job_id, Err(ApiError::NotFound), None).await;
            return;
        };
        let restore_running = matches!(
            metadata.protocol,
            Protocol::Redis | Protocol::Valkey | Protocol::Qdrant
        ) && metadata.status == InstanceStatus::Running;
        let execution_cost = estimate_export_execution_cost(&state, &metadata, &options).await;
        let execution = match state
            .import_export_jobs
            .acquire_execution(execution_cost)
            .await
        {
            Ok(execution) => execution,
            Err(SchedulerAcquireError::Closed) => {
                let _ = begin_import_export_job(&state, &job_id).await;
                return;
            }
            Err(SchedulerAcquireError::InsufficientCapacity) => {
                let _ =
                    update_job_result(&state, &job_id, Err(fixed_scheduler_capacity_error()), None)
                        .await;
                return;
            }
        };
        let reservations =
            match acquire_export_output_capacity(&state, &metadata, &artifact_path, &options).await
            {
                Ok(reservations) => reservations,
                Err(error) => {
                    let _ = update_job_result(&state, &job_id, Err(error), None).await;
                    return;
                }
            };
        match begin_import_export_job(&state, &job_id).await {
            JobBeginOutcome::Running => {}
            JobBeginOutcome::Closed => return,
            JobBeginOutcome::Uncertain => {
                tracing::error!(%job_id, %instance_id, "export job start could not be closed durably during shutdown");
                return;
            }
        }
        let failure_state = state.clone();
        let failure_job_id = job_id.clone();
        let failure_instance_id = instance_id.clone();
        let failure_artifact_path = artifact_path.clone();
        let worker = tokio::spawn(run_export_job_locked(
            state,
            job_id,
            metadata,
            artifact_path,
            options,
        ));
        if let Err(error) = worker.await {
            handle_export_worker_failure(
                &failure_state,
                &failure_job_id,
                &failure_instance_id,
                failure_artifact_path,
                restore_running,
                error,
            )
            .await;
        }
        drop(reservations);
        drop(execution);
    });
}

pub(super) fn spawn_import_job_supervisor(
    state: AppState,
    job_id: String,
    instance_id: String,
    options: ImportOptions,
    admission: ImportExportJobPermit,
    remote_admission: Option<RemoteJobAdmissionPermit>,
) {
    let upload_id = match &options.source {
        ImportSourceOptions::Upload { upload_id, .. } => Some(upload_id.clone()),
        _ => None,
    };
    tokio::spawn(async move {
        let _admission = admission;
        let _remote_admission = remote_admission;
        let phase = Arc::new(AtomicU8::new(IMPORT_WORKER_QUEUED));
        if let Some(upload_id) = upload_id.as_deref() {
            let claim_state = state.clone();
            let claim_instance_id = instance_id.clone();
            let claim_upload_id = upload_id.to_string();
            let claim_job_id = job_id.clone();
            let claim = tokio::spawn(async move {
                claim_upload_for_job(
                    &claim_state,
                    &claim_instance_id,
                    &claim_upload_id,
                    &claim_job_id,
                )
                .await
            });
            match claim.await {
                Ok(true) => {}
                Ok(false) => return,
                Err(error) => {
                    handle_import_worker_failure(
                        &state,
                        &job_id,
                        &instance_id,
                        Some(upload_id),
                        IMPORT_WORKER_QUEUED,
                        error,
                    )
                    .await;
                    return;
                }
            }
        }
        let _operation = state.instance_locks.lock(&instance_id).await;
        let Some(metadata) = state.instances.get(&instance_id).await else {
            finish_import_before_execution(
                &state,
                &job_id,
                &instance_id,
                upload_id.as_deref(),
                ApiError::NotFound,
            )
            .await;
            return;
        };
        let execution_cost = estimate_import_execution_cost(&state, &metadata, &options).await;
        let execution = match state
            .import_export_jobs
            .acquire_execution(execution_cost)
            .await
        {
            Ok(execution) => execution,
            Err(SchedulerAcquireError::Closed) => {
                finish_import_begin_outcome(
                    &state,
                    &job_id,
                    &instance_id,
                    upload_id.as_deref(),
                    begin_import_export_job(&state, &job_id).await,
                )
                .await;
                return;
            }
            Err(SchedulerAcquireError::InsufficientCapacity) => {
                finish_import_before_execution(
                    &state,
                    &job_id,
                    &instance_id,
                    upload_id.as_deref(),
                    fixed_scheduler_capacity_error(),
                )
                .await;
                return;
            }
        };
        let staging = match acquire_upload_staging(&state, &instance_id, &options).await {
            Ok(staging) => staging,
            Err(error) => {
                finish_import_before_execution(
                    &state,
                    &job_id,
                    &instance_id,
                    upload_id.as_deref(),
                    error,
                )
                .await;
                return;
            }
        };
        let begin = begin_import_export_job(&state, &job_id).await;
        if begin != JobBeginOutcome::Running {
            finish_import_begin_outcome(&state, &job_id, &instance_id, upload_id.as_deref(), begin)
                .await;
            return;
        }
        phase.store(IMPORT_WORKER_RUNNING, Ordering::Release);
        let worker_phase = Arc::clone(&phase);
        let failure_state = state.clone();
        let failure_job_id = job_id.clone();
        let failure_instance_id = instance_id.clone();
        let worker = tokio::spawn(async move {
            run_import_job_locked(state, job_id, instance_id, options).await;
            worker_phase.store(IMPORT_WORKER_FINISHED, Ordering::Release);
        });
        if let Err(error) = worker.await {
            handle_import_worker_failure(
                &failure_state,
                &failure_job_id,
                &failure_instance_id,
                upload_id.as_deref(),
                phase.load(Ordering::Acquire),
                error,
            )
            .await;
        }
        drop(staging);
        drop(execution);
    });
}

async fn finish_import_before_execution(
    state: &AppState,
    job_id: &str,
    instance_id: &str,
    upload_id: Option<&str>,
    error: ApiError,
) {
    let failure = PublicDiagnostic::from_api_error("import preparation", &error).message;
    let persisted = update_job_result(state, job_id, Err(error), None).await;
    if let Some(upload_id) = upload_id {
        if persisted {
            super::uploads::finish_upload_import_job(
                state,
                instance_id,
                upload_id,
                job_id,
                false,
                Some(&failure),
            )
            .await;
        } else {
            block_uncertain_upload(
                state,
                instance_id,
                upload_id,
                job_id,
                "import preparation failed but its terminal job status could not be recorded; the upload is blocked",
            )
            .await;
        }
    }
}

async fn finish_import_begin_outcome(
    state: &AppState,
    job_id: &str,
    instance_id: &str,
    upload_id: Option<&str>,
    outcome: JobBeginOutcome,
) {
    let Some(upload_id) = upload_id else {
        return;
    };
    match outcome {
        JobBeginOutcome::Running => {}
        JobBeginOutcome::Closed => {
            super::uploads::finish_upload_import_job(
                state,
                instance_id,
                upload_id,
                job_id,
                false,
                Some("daemon shutdown began before the import started"),
            )
            .await;
        }
        JobBeginOutcome::Uncertain => {
            block_uncertain_upload(
                state,
                instance_id,
                upload_id,
                job_id,
                "daemon shutdown interrupted durable import startup; the upload is blocked for recovery",
            )
            .await;
        }
    }
}

async fn handle_export_worker_failure(
    state: &AppState,
    job_id: &str,
    instance_id: &str,
    artifact_path: PathBuf,
    restore_running: bool,
    error: tokio::task::JoinError,
) {
    tracing::error!(
        %job_id,
        %instance_id,
        worker_cancelled = error.is_cancelled(),
        worker_panicked = error.is_panic(),
        "import/export export worker stopped unexpectedly"
    );
    let diagnostic = PublicDiagnostic::public(
        "worker_failure",
        "the export worker stopped unexpectedly; retry the export",
    );
    let terminal_persisted = persist_terminal_job_status(
        state,
        job_id,
        ImportExportStatus::Failed,
        Some(artifact_path.display().to_string()),
        Some(diagnostic.to_storage_string()),
    )
    .await;
    if !terminal_persisted {
        tracing::error!(%job_id, %instance_id, "export worker failed and its terminal job status could not be persisted");
    }
    let cleanup = tokio::task::spawn_blocking(move || {
        crate::shared::files::remove_private_file_durable(&artifact_path)
    })
    .await;
    match cleanup {
        Ok(Ok(())) => {}
        Ok(Err(cleanup_error)) if cleanup_error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(Err(cleanup_error)) => {
            tracing::error!(%job_id, %cleanup_error, "failed to remove a partial export artifact after worker failure");
        }
        Err(cleanup_error) => {
            tracing::error!(%job_id, %cleanup_error, "partial export artifact cleanup task failed");
        }
    }
    if restore_running
        && let Err(restart_error) =
            lifecycle_instance_locked(state, instance_id, LifecycleAction::Start).await
    {
        tracing::error!(%job_id, %instance_id, %restart_error, "failed to restore a target after physical export worker failure");
        if let Err(quarantine_error) = quarantine_after_uncertain_import(state, instance_id).await {
            tracing::error!(%job_id, %instance_id, %quarantine_error, "failed to quarantine a target after physical export recovery failed");
        }
    }
}

async fn handle_import_worker_failure(
    state: &AppState,
    job_id: &str,
    instance_id: &str,
    upload_id: Option<&str>,
    phase: u8,
    error: tokio::task::JoinError,
) {
    tracing::error!(
        %job_id,
        %instance_id,
        phase,
        worker_cancelled = error.is_cancelled(),
        worker_panicked = error.is_panic(),
        "import/export import worker stopped unexpectedly"
    );
    let may_have_mutated = phase >= IMPORT_WORKER_RUNNING;
    let diagnostic = if may_have_mutated {
        PublicDiagnostic::public(
            "worker_failure_uncertain_import",
            "the import worker stopped after the import began; the target was quarantined",
        )
    } else {
        PublicDiagnostic::public(
            "worker_failure",
            "the import worker stopped before the import began; retry the import",
        )
    };
    let terminal_persisted = persist_terminal_job_status(
        state,
        job_id,
        ImportExportStatus::Failed,
        None,
        Some(diagnostic.to_storage_string()),
    )
    .await;

    if !may_have_mutated {
        if let Some(upload_id) = upload_id {
            if terminal_persisted {
                super::uploads::finish_upload_import_job(
                    state,
                    instance_id,
                    upload_id,
                    job_id,
                    false,
                    Some("the import worker stopped before the import began"),
                )
                .await;
            } else {
                block_uncertain_upload(
                    state,
                    instance_id,
                    upload_id,
                    job_id,
                    "the import worker stopped before the import began but its terminal job status could not be recorded; the upload is blocked",
                )
                .await;
            }
        }
        return;
    }

    if let Some(upload_id) = upload_id {
        block_uncertain_upload(
            state,
            instance_id,
            upload_id,
            job_id,
            "the import worker stopped after database mutation may have begun; the upload is blocked and the target was quarantined",
        )
        .await;
    }
    if let Err(quarantine_error) = quarantine_after_uncertain_import(state, instance_id).await {
        tracing::error!(%job_id, %instance_id, %quarantine_error, "failed to fully quarantine a target after import worker failure");
    }
}

pub(super) async fn block_uncertain_upload(
    state: &AppState,
    instance_id: &str,
    upload_id: &str,
    job_id: &str,
    reason: &str,
) {
    match state
        .import_uploads
        .repository()
        .reconcile_interrupted_importing(
            instance_id,
            upload_id,
            job_id,
            crate::storage::import_uploads::InterruptedImportDisposition::Failed,
            reason,
            &crate::jobs::import_export::now_rfc3339(),
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::error!(%job_id, %instance_id, %upload_id, "uncertain import did not match the claimed upload state")
        }
        Err(upload_error) => {
            tracing::error!(%job_id, %instance_id, %upload_id, %upload_error, "failed to block an upload after an uncertain import")
        }
    }
}

async fn claim_upload_for_job(
    state: &AppState,
    instance_id: &str,
    upload_id: &str,
    job_id: &str,
) -> bool {
    let claimed = match state
        .import_uploads
        .repository()
        .claim_ready_for_job(
            instance_id,
            upload_id,
            job_id,
            &crate::jobs::import_export::now_rfc3339(),
        )
        .await
    {
        Ok(claimed) => claimed,
        Err(error) => {
            close_unclaimed_upload_job(
                state,
                job_id,
                "upload_storage",
                "the temporary import upload claim could not be persisted",
            )
            .await;
            if let Err(release_error) = state
                .import_uploads
                .repository()
                .release_claim_after_failed_job(
                    instance_id,
                    upload_id,
                    job_id,
                    "upload claim acknowledgement was uncertain; submit the import again",
                    &crate::jobs::import_export::now_rfc3339(),
                )
                .await
            {
                tracing::error!(%job_id, %release_error, "failed to reconcile an uncertain upload claim");
            }
            tracing::error!(%job_id, %error, "failed to claim the import upload for its durable job");
            return false;
        }
    };
    if !claimed {
        close_unclaimed_upload_job(
            state,
            job_id,
            "upload_conflict",
            "the temporary import upload is no longer ready",
        )
        .await;
    }
    claimed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{instances::locks::InstanceLocks, jobs::import_export::ImportExportJobs};
    use tokio::sync::Notify;

    #[tokio::test]
    async fn panic_recovery_keeps_the_instance_fenced_and_admission_active() {
        let locks = InstanceLocks::default();
        let follower_locks = locks.clone();
        let jobs = ImportExportJobs::default();
        let admission = jobs.try_admit("panic-fence").unwrap();
        let recovery_started = Arc::new(Notify::new());
        let release_recovery = Arc::new(Notify::new());
        let supervisor = {
            let recovery_started = Arc::clone(&recovery_started);
            let release_recovery = Arc::clone(&release_recovery);
            tokio::spawn(async move {
                let _admission = admission;
                let _operation = locks.lock("panic-fence").await;
                let worker = tokio::spawn(async { panic!("injected worker panic") });
                assert!(worker.await.unwrap_err().is_panic());
                recovery_started.notify_one();
                release_recovery.notified().await;
            })
        };

        recovery_started.notified().await;
        assert_eq!(jobs.active_count(), 1);
        assert!(!jobs.wait_for_drain(Duration::from_millis(10)).await);
        let follower = tokio::spawn(async move { follower_locks.lock("panic-fence").await });
        tokio::task::yield_now().await;
        assert!(!follower.is_finished());

        release_recovery.notify_one();
        supervisor.await.unwrap();
        follower.await.unwrap();
        assert!(jobs.wait_for_drain(Duration::from_secs(1)).await);
    }
}
