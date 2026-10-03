use super::*;

pub(super) async fn stream_import_export(
    mut socket: WebSocket,
    state: AppState,
    instance_id: String,
    instance_generation: String,
    query: ImportExportQuery,
    claims: Arc<Claims>,
    _connection: WebSocketConnectionPermit,
) {
    if !instance_generation_is_current(&state, &instance_id, &instance_generation).await {
        close_replaced_socket(&mut socket).await;
        return;
    }
    let mut events = state.import_export_jobs.subscribe();
    let mut shutdown = state.daemon_shutdown.subscribe();
    let expiration_deadline = jwt_expiration_deadline(claims.exp);
    let snapshot = complete_before(
        expiration_deadline,
        import_export_snapshot(&state, &instance_id, &query, &claims),
    );
    let snapshot = tokio::select! {
        _ = wait_for_daemon_shutdown(&mut shutdown) => {
            close_shutdown_socket(&mut socket).await;
            return;
        }
        snapshot = snapshot => snapshot,
    };
    let Ok(snapshot) = snapshot else {
        close_expired_socket(&mut socket).await;
        return;
    };
    if !instance_generation_is_current(&state, &instance_id, &instance_generation).await {
        close_replaced_socket(&mut socket).await;
        return;
    }
    if send_json_before(&mut socket, &snapshot, expiration_deadline)
        .await
        .is_err()
    {
        return;
    }

    let heartbeat_period = HEARTBEAT_INTERVAL;
    let mut heartbeat = interval_at(Instant::now() + heartbeat_period, heartbeat_period);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let expiration = sleep_until(expiration_deadline);
    tokio::pin!(expiration);
    let mut awaiting_pong = false;
    loop {
        tokio::select! {
            _ = wait_for_daemon_shutdown(&mut shutdown) => {
                close_shutdown_socket(&mut socket).await;
                break;
            }
            _ = &mut expiration => {
                close_expired_socket(&mut socket).await;
                break;
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Pong(_))) => awaiting_pong = false,
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(_)) => {}
                }
            }
            _ = heartbeat.tick() => {
                if !instance_generation_is_current(&state, &instance_id, &instance_generation).await {
                    close_replaced_socket(&mut socket).await;
                    break;
                }
                if awaiting_pong {
                    close_unresponsive_socket(&mut socket).await;
                    break;
                }
                if send_message_before(
                    &mut socket,
                    Message::Ping(b"dbe-heartbeat".as_slice().into()),
                    expiration_deadline,
                )
                .await
                .is_err()
                {
                    break;
                }
                awaiting_pong = true;
            }
            event = events.recv() => {
                match event {
                    Ok(job) => {
                        if !instance_generation_is_current(&state, &instance_id, &instance_generation).await {
                            close_replaced_socket(&mut socket).await;
                            break;
                        }
                        if !job_matches_access(&job, &instance_id, &query, &claims) {
                            continue;
                        }
                        if send_job_event(&mut socket, &state, job, &claims, expiration_deadline)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        if !instance_generation_is_current(&state, &instance_id, &instance_generation).await {
                            close_replaced_socket(&mut socket).await;
                            break;
                        }
                        let resynced = resync_after_lag(
                            &mut socket,
                            &state,
                            &instance_id,
                            &query,
                            &claims,
                            skipped,
                            expiration_deadline,
                        )
                        .await;
                        if resynced.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

pub(super) async fn send_job_event(
    socket: &mut WebSocket,
    state: &AppState,
    job: ImportExportJob,
    claims: &Claims,
    deadline: Instant,
) -> Result<(), ()> {
    let Ok(job) = complete_before(deadline, public_job_update(state, job, claims)).await else {
        close_expired_socket(socket).await;
        return Err(());
    };
    let event = ImportExportJobEvent {
        r#type: "import_export_job",
        job,
    };
    send_json_before(socket, &event, deadline).await
}

pub(super) async fn resync_after_lag(
    socket: &mut WebSocket,
    state: &AppState,
    instance_id: &str,
    query: &ImportExportQuery,
    claims: &Claims,
    skipped: u64,
    deadline: Instant,
) -> Result<(), ()> {
    let event = ImportExportLaggedEvent {
        r#type: "import_export_lagged",
        skipped,
    };
    send_json_before(socket, &event, deadline).await?;
    let Ok(snapshot) = complete_before(
        deadline,
        import_export_snapshot(state, instance_id, query, claims),
    )
    .await
    else {
        close_expired_socket(socket).await;
        return Err(());
    };
    send_json_before(socket, &snapshot, deadline).await
}

pub(super) async fn import_export_snapshot(
    state: &AppState,
    instance_id: &str,
    query: &ImportExportQuery,
    claims: &Claims,
) -> ImportExportSnapshot {
    let jobs = snapshot_jobs(state, instance_id, query).await;
    let mut response = Vec::with_capacity(jobs.len());
    for job in jobs {
        if job_matches_access(&job, instance_id, query, claims) {
            response.push(public_job_update(state, job, claims).await);
        }
    }
    ImportExportSnapshot {
        r#type: "import_export_snapshot",
        jobs: response,
    }
}

pub(super) async fn snapshot_jobs(
    state: &AppState,
    instance_id: &str,
    query: &ImportExportQuery,
) -> Vec<ImportExportJob> {
    if let Some(job_id) = query.job_id.as_deref() {
        return match state.import_export_jobs.get(job_id).await {
            Ok(Some(job)) => vec![job],
            Ok(None) => Vec::new(),
            Err(error) => {
                tracing::warn!(%error, %job_id, "failed to build import/export websocket snapshot");
                Vec::new()
            }
        };
    }

    list_snapshot_jobs(state, Some(instance_id)).await
}

pub(super) async fn list_snapshot_jobs(
    state: &AppState,
    instance_id: Option<&str>,
) -> Vec<ImportExportJob> {
    match state.import_export_jobs.list(instance_id, None, 100).await {
        Ok(jobs) => jobs,
        Err(error) => {
            tracing::warn!(%error, ?instance_id, "failed to build import/export websocket snapshot");
            Vec::new()
        }
    }
}

pub(super) fn job_matches_access(
    job: &ImportExportJob,
    instance_id: &str,
    query: &ImportExportQuery,
    claims: &Claims,
) -> bool {
    claims.allows_instance(&job.instance_id)
        && job.instance_id == instance_id
        && query
            .job_id
            .as_deref()
            .is_none_or(|job_id| job.job_id == job_id)
}

// Repeat the instance check at the ticket boundary so a future caller cannot
// turn an unauthorized job into a signed artifact credential.
pub(super) async fn public_job_update(
    state: &AppState,
    job: ImportExportJob,
    claims: &Claims,
) -> ImportExportJobUpdate {
    let download = download_ticket_for_job(state, &job, claims).await;
    ImportExportJobUpdate {
        job: public_job_response(job).await,
        download,
    }
}

pub(super) async fn download_ticket_for_job(
    state: &AppState,
    job: &ImportExportJob,
    claims: &Claims,
) -> Option<DownloadUrlResponse> {
    if !claims.allows_instance(&job.instance_id)
        || job.action != ImportExportAction::Export
        || job.status != ImportExportStatus::Succeeded
    {
        return None;
    }
    let artifact_name = job
        .artifact_path
        .as_deref()
        .and_then(|path| std::path::Path::new(path).file_name())
        .and_then(|name| name.to_str())?;
    match artifact_download_url(state, artifact_name, &job.instance_id, Some(120), true).await {
        Ok(ticket) => Some(ticket),
        Err(error) => {
            tracing::warn!(
                %error,
                job_id = %job.job_id,
                instance_id = %job.instance_id,
                artifact = %artifact_name,
                "failed to issue import/export websocket download ticket"
            );
            None
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct ImportExportSnapshot {
    r#type: &'static str,
    pub(super) jobs: Vec<ImportExportJobUpdate>,
}

#[derive(Debug, Serialize)]
pub(super) struct ImportExportJobEvent {
    r#type: &'static str,
    pub(super) job: ImportExportJobUpdate,
}

#[derive(Debug, Serialize)]
pub(super) struct ImportExportJobUpdate {
    #[serde(flatten)]
    pub(super) job: ImportExportJobResponse,
    pub(super) download: Option<DownloadUrlResponse>,
}

#[derive(Debug, Serialize)]
pub(super) struct ImportExportLaggedEvent {
    r#type: &'static str,
    pub(super) skipped: u64,
}
