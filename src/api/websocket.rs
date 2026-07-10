use std::{
    future::Future,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{
        Path, Query, State,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade, close_code},
    },
    http::{HeaderMap, Uri},
    response::Response,
};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio::time::{
    Duration, Instant, MissedTickBehavior, interval, interval_at, sleep_until, timeout_at,
};

use crate::{
    api::{
        artifacts::{DownloadUrlResponse, create_artifact_download_url},
        handlers::{ApiError, authorize_websocket_jwt},
        import_export::{ImportExportJobResponse, public_job_response},
        progress::InstallProgress,
        resources::{ResourceReport, resource_report_with_docker_stats},
        routes::AppState,
        security::{WebSocketAdmissionError, WebSocketConnectionPermit},
    },
    auth::{jwt::Claims, scopes},
    instances::metadata::InstanceMetadata,
    jobs::import_export::{ImportExportAction, ImportExportJob, ImportExportStatus},
    shared::redaction,
};

#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    pub tail: Option<usize>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct ImportExportQuery {
    pub job_id: Option<String>,
}

pub async fn monitoring(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    websocket: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let claims = authorize_websocket_jwt(&state, &headers, &uri, scopes::MONITOR_READ, None)?;
    let connection = admit_websocket(&state, &claims).await?;
    Ok(websocket
        .protocols(["dbe.jwt", "bearer"])
        .on_upgrade(move |socket| stream_monitoring(socket, state, claims, connection)))
}

async fn stream_monitoring(
    mut socket: WebSocket,
    state: AppState,
    claims: Claims,
    _connection: WebSocketConnectionPermit,
) {
    let _monitor = state.resource_cache.register_monitor();
    let mut ticker = interval(Duration::from_secs(1));
    let expiration_deadline = jwt_expiration_deadline(claims.exp);
    let expiration = sleep_until(expiration_deadline);
    tokio::pin!(expiration);
    loop {
        tokio::select! {
            _ = &mut expiration => {
                close_expired_socket(&mut socket).await;
                break;
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(_)) => {}
                }
            }
            _ = ticker.tick() => {
                let Ok(message) = complete_before(
                    expiration_deadline,
                    monitoring_snapshot(&state, &claims),
                )
                .await
                else {
                    close_expired_socket(&mut socket).await;
                    break;
                };
                if send_json_before(&mut socket, &message, expiration_deadline).await.is_err() {
                    break;
                }
            }
        }
    }
}

const MONITORING_FANOUT_LIMIT: usize = 16;

async fn monitoring_snapshot(state: &AppState, claims: &Claims) -> MonitoringSnapshot {
    use futures::StreamExt;

    let authorized_instances = state
        .instances
        .list()
        .await
        .into_iter()
        .filter(|metadata| claims.allows_instance(&metadata.instance_id));
    let instances = futures::stream::iter(authorized_instances)
        .map(|metadata| {
            let state = state.clone();
            async move { monitoring_instance(&state, metadata).await }
        })
        .buffer_unordered(MONITORING_FANOUT_LIMIT)
        .collect()
        .await;

    MonitoringSnapshot {
        r#type: "stats",
        instances,
        install_progress: state
            .install_progress
            .list()
            .into_iter()
            .filter(|progress| claims.allows_instance(&progress.instance_id))
            .collect(),
    }
}

async fn monitoring_instance(state: &AppState, metadata: InstanceMetadata) -> MonitoringInstance {
    match resource_report_with_docker_stats(state, metadata.clone()).await {
        Ok((resources, docker_stats)) => MonitoringInstance {
            instance_id: metadata.instance_id,
            protocol: metadata.protocol.to_string(),
            status: metadata.status.as_str().to_string(),
            runtime: metadata.runtime.kind.as_str(),
            cpu_cores: metadata.limits.cpu_cores,
            cpu_limit_cores: metadata.limits.cpu_cores,
            cpu_usage_percent: resources.cpu.usage_percent,
            memory_mib: metadata.limits.memory_mib,
            memory_usage_bytes: resources.memory.usage_bytes,
            memory_limit_bytes: resources.memory.limit_bytes,
            disk_mib: metadata.limits.disk_mib,
            disk_limit_bytes: resources.disk.limit_bytes,
            disk_used_bytes: Some(resources.disk.used_bytes),
            disk_enforced: metadata.limits.disk_enforced,
            network_rx_bytes: resources.network.rx_bytes,
            network_tx_bytes: resources.network.tx_bytes,
            resources: Some(resources),
            docker_stats,
            resource_error: None,
        },
        Err(error) => MonitoringInstance {
            instance_id: metadata.instance_id,
            protocol: metadata.protocol.to_string(),
            status: metadata.status.as_str().to_string(),
            runtime: metadata.runtime.kind.as_str(),
            cpu_cores: metadata.limits.cpu_cores,
            cpu_limit_cores: metadata.limits.cpu_cores,
            cpu_usage_percent: None,
            memory_mib: metadata.limits.memory_mib,
            memory_usage_bytes: None,
            memory_limit_bytes: None,
            disk_mib: metadata.limits.disk_mib,
            disk_limit_bytes: metadata.limits.disk_mib.saturating_mul(1024 * 1024),
            disk_used_bytes: None,
            disk_enforced: metadata.limits.disk_enforced,
            network_rx_bytes: None,
            network_tx_bytes: None,
            resources: None,
            docker_stats: None,
            resource_error: Some(error.to_string()),
        },
    }
}

#[derive(Debug, Serialize)]
struct MonitoringSnapshot {
    r#type: &'static str,
    instances: Vec<MonitoringInstance>,
    install_progress: Vec<InstallProgress>,
}

#[derive(Debug, Serialize)]
struct MonitoringInstance {
    instance_id: String,
    protocol: String,
    status: String,
    runtime: &'static str,
    cpu_cores: f64,
    cpu_limit_cores: f64,
    cpu_usage_percent: Option<f64>,
    memory_mib: u64,
    memory_usage_bytes: Option<u64>,
    memory_limit_bytes: Option<u64>,
    disk_mib: u64,
    disk_limit_bytes: u64,
    disk_used_bytes: Option<u64>,
    disk_enforced: bool,
    network_rx_bytes: Option<u64>,
    network_tx_bytes: Option<u64>,
    resources: Option<ResourceReport>,
    docker_stats: Option<String>,
    resource_error: Option<String>,
}

pub async fn logs(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    Query(query): Query<LogsQuery>,
    headers: HeaderMap,
    uri: Uri,
    websocket: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let claims = authorize_websocket_jwt(
        &state,
        &headers,
        &uri,
        scopes::LOGS_READ,
        Some(&instance_id),
    )?;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let connection = admit_websocket(&state, &claims).await?;
    Ok(websocket
        .protocols(["dbe.jwt", "bearer"])
        .on_upgrade(move |socket| {
            stream_logs(socket, state, metadata, query.tail, claims.exp, connection)
        }))
}

pub async fn import_export(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    Query(query): Query<ImportExportQuery>,
    headers: HeaderMap,
    uri: Uri,
    websocket: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let download_headers = headers.clone();
    let claims = authorize_websocket_jwt(
        &state,
        &headers,
        &uri,
        scopes::IMPORT_EXPORT_READ,
        Some(&instance_id),
    )?;
    state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let connection = admit_websocket(&state, &claims).await?;
    Ok(websocket
        .protocols(["dbe.jwt", "bearer"])
        .on_upgrade(move |socket| {
            stream_import_export(
                socket,
                state,
                instance_id,
                query,
                download_headers,
                claims,
                connection,
            )
        }))
}

async fn admit_websocket(
    state: &AppState,
    claims: &Claims,
) -> Result<WebSocketConnectionPermit, ApiError> {
    match state
        .api_rate_limiter
        .admit_websocket(&claims.jti, claims.exp)
        .await
    {
        Ok(connection) => Ok(connection),
        Err(WebSocketAdmissionError::Replay | WebSocketAdmissionError::Expired) => {
            tracing::warn!(subject = %claims.sub, "audit websocket_token_rejected");
            Err(ApiError::Unauthorized)
        }
        Err(
            WebSocketAdmissionError::TokenCapacity | WebSocketAdmissionError::ConnectionCapacity,
        ) => {
            tracing::warn!(subject = %claims.sub, "audit websocket_capacity_reached");
            Err(ApiError::RateLimited)
        }
    }
}

async fn stream_logs(
    mut socket: WebSocket,
    state: AppState,
    metadata: InstanceMetadata,
    tail: Option<usize>,
    jwt_exp: i64,
    _connection: WebSocketConnectionPermit,
) {
    let expiration_deadline = jwt_expiration_deadline(jwt_exp);
    let mut logs = match state
        .docker
        .follow_logs(metadata.protocol, &metadata.instance_id, tail)
    {
        Ok(logs) => logs,
        Err(error) => {
            let message = LogSnapshot {
                r#type: "logs",
                instance_id: metadata.instance_id,
                sequence: 1,
                stdout: None,
                stderr: None,
                error: Some(error.to_string()),
            };
            let _ = send_json_before(&mut socket, &message, expiration_deadline).await;
            return;
        }
    };
    let mut heartbeat = interval(Duration::from_secs(30));
    let mut sequence = 0_u64;
    let mut stdout_buffer = String::new();
    let mut stderr_buffer = String::new();
    let expiration = sleep_until(expiration_deadline);
    tokio::pin!(expiration);
    loop {
        let message = tokio::select! {
            _ = &mut expiration => {
                close_expired_socket(&mut socket).await;
                break;
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(_)) => continue,
                }
            }
            output = logs.recv() => {
                sequence += 1;
                match output {
                    Some(Ok(output)) => {
                        append_log_buffer(&mut stdout_buffer, &output.stdout);
                        append_log_buffer(&mut stderr_buffer, &output.stderr);
                        LogSnapshot {
                            r#type: "logs",
                            instance_id: metadata.instance_id.clone(),
                            sequence,
                            stdout: non_empty_redacted(&stdout_buffer),
                            stderr: non_empty_redacted(&stderr_buffer),
                            error: None,
                        }
                    }
                    Some(Err(error)) => LogSnapshot {
                        r#type: "logs",
                        instance_id: metadata.instance_id.clone(),
                        sequence,
                        stdout: None,
                        stderr: None,
                        error: Some(error.to_string()),
                    },
                    None => LogSnapshot {
                        r#type: "logs",
                        instance_id: metadata.instance_id.clone(),
                        sequence,
                        stdout: None,
                        stderr: None,
                        error: Some("container log stream ended".to_string()),
                    },
                }
            }
            _ = heartbeat.tick() => {
                sequence += 1;
                LogSnapshot {
                    r#type: "logs",
                    instance_id: metadata.instance_id.clone(),
                    sequence,
                    stdout: non_empty_redacted(&stdout_buffer),
                    stderr: non_empty_redacted(&stderr_buffer),
                    error: None,
                }
            }
        };

        if send_json_before(&mut socket, &message, expiration_deadline)
            .await
            .is_err()
        {
            break;
        }
    }
}

const LOG_STREAM_BUFFER_LIMIT: usize = 128 * 1024;

fn append_log_buffer(buffer: &mut String, chunk: &str) {
    if chunk.is_empty() {
        return;
    }
    buffer.push_str(chunk);
    if buffer.len() <= LOG_STREAM_BUFFER_LIMIT {
        return;
    }
    let mut start = buffer.len().saturating_sub(LOG_STREAM_BUFFER_LIMIT);
    while start < buffer.len() && !buffer.is_char_boundary(start) {
        start += 1;
    }
    buffer.replace_range(..start, "");
}

fn non_empty_redacted(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| redaction::redact_connection_url(value))
}

async fn stream_import_export(
    mut socket: WebSocket,
    state: AppState,
    instance_id: String,
    query: ImportExportQuery,
    download_headers: HeaderMap,
    claims: Claims,
    _connection: WebSocketConnectionPermit,
) {
    let mut events = state.import_export_jobs.subscribe();
    let expiration_deadline = jwt_expiration_deadline(claims.exp);
    let Ok(snapshot) = complete_before(
        expiration_deadline,
        import_export_snapshot(&state, &download_headers, &instance_id, &query, &claims),
    )
    .await
    else {
        close_expired_socket(&mut socket).await;
        return;
    };
    if send_json_before(&mut socket, &snapshot, expiration_deadline)
        .await
        .is_err()
    {
        return;
    }

    let heartbeat_period = Duration::from_secs(30);
    let mut heartbeat = interval_at(Instant::now() + heartbeat_period, heartbeat_period);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let expiration = sleep_until(expiration_deadline);
    tokio::pin!(expiration);
    let mut awaiting_pong = false;
    loop {
        tokio::select! {
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
                        if !job_matches_access(&job, &instance_id, &query, &claims) {
                            continue;
                        }
                        let Ok(job) = complete_before(
                            expiration_deadline,
                            public_job_update(&state, &download_headers, job, &claims),
                        )
                        .await
                        else {
                            close_expired_socket(&mut socket).await;
                            break;
                        };
                        let event = ImportExportJobEvent {
                            r#type: "import_export_job",
                            job,
                        };
                        if send_json_before(&mut socket, &event, expiration_deadline)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        let event = ImportExportLaggedEvent {
                            r#type: "import_export_lagged",
                            skipped,
                        };
                        if send_json_before(&mut socket, &event, expiration_deadline)
                            .await
                            .is_err()
                        {
                            break;
                        }
                        let Ok(snapshot) = complete_before(
                            expiration_deadline,
                            import_export_snapshot(
                                &state,
                                &download_headers,
                                &instance_id,
                                &query,
                                &claims,
                            ),
                        )
                        .await
                        else {
                            close_expired_socket(&mut socket).await;
                            break;
                        };
                        if send_json_before(&mut socket, &snapshot, expiration_deadline)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

async fn import_export_snapshot(
    state: &AppState,
    download_headers: &HeaderMap,
    instance_id: &str,
    query: &ImportExportQuery,
    claims: &Claims,
) -> ImportExportSnapshot {
    let jobs = snapshot_jobs(state, instance_id, query).await;
    let mut response = Vec::with_capacity(jobs.len());
    for job in jobs {
        if job_matches_access(&job, instance_id, query, claims) {
            response.push(public_job_update(state, download_headers, job, claims).await);
        }
    }
    ImportExportSnapshot {
        r#type: "import_export_snapshot",
        jobs: response,
    }
}

async fn snapshot_jobs(
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

async fn list_snapshot_jobs(state: &AppState, instance_id: Option<&str>) -> Vec<ImportExportJob> {
    match state.import_export_jobs.list(instance_id, None, 100).await {
        Ok(jobs) => jobs,
        Err(error) => {
            tracing::warn!(%error, ?instance_id, "failed to build import/export websocket snapshot");
            Vec::new()
        }
    }
}

fn job_matches_access(
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
async fn public_job_update(
    state: &AppState,
    download_headers: &HeaderMap,
    job: ImportExportJob,
    claims: &Claims,
) -> ImportExportJobUpdate {
    let download = download_ticket_for_job(state, download_headers, &job, claims).await;
    ImportExportJobUpdate {
        job: public_job_response(job).await,
        download,
    }
}

async fn download_ticket_for_job(
    state: &AppState,
    download_headers: &HeaderMap,
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
    match create_artifact_download_url(
        state,
        download_headers,
        artifact_name,
        &job.instance_id,
        Some(120),
        true,
    )
    .await
    {
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

fn jwt_expiration_deadline(exp: i64) -> Instant {
    let now_since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let expires_since_epoch = Duration::from_secs(u64::try_from(exp).unwrap_or_default());
    Instant::now() + expires_since_epoch.saturating_sub(now_since_epoch)
}

async fn close_expired_socket(socket: &mut WebSocket) {
    close_socket(socket, "JWT expired").await;
}

async fn close_unresponsive_socket(socket: &mut WebSocket) {
    close_socket(socket, "heartbeat timeout").await;
}

async fn close_socket(socket: &mut WebSocket, reason: &'static str) {
    let close_deadline = Instant::now() + Duration::from_secs(1);
    let _ = send_message_before(
        socket,
        Message::Close(Some(CloseFrame {
            code: close_code::POLICY,
            reason: reason.into(),
        })),
        close_deadline,
    )
    .await;
}

async fn send_json_before<T: Serialize>(
    socket: &mut WebSocket,
    value: &T,
    deadline: Instant,
) -> Result<(), ()> {
    let payload = serde_json::to_string(value).map_err(|error| {
        tracing::warn!(%error, "failed to serialize websocket payload");
    })?;
    send_message_before(socket, Message::Text(payload.into()), deadline).await
}

async fn send_message_before(
    socket: &mut WebSocket,
    message: Message,
    deadline: Instant,
) -> Result<(), ()> {
    let now = Instant::now();
    if now >= deadline {
        return Err(());
    }
    let send_deadline = deadline.min(now + Duration::from_secs(5));
    timeout_at(send_deadline, socket.send(message))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}

async fn complete_before<F>(deadline: Instant, future: F) -> Result<F::Output, ()>
where
    F: Future,
{
    let now = Instant::now();
    if now >= deadline {
        return Err(());
    }
    let operation_deadline = deadline.min(now + Duration::from_secs(15));
    timeout_at(operation_deadline, future).await.map_err(|_| ())
}

#[derive(Debug, Serialize)]
struct ImportExportSnapshot {
    r#type: &'static str,
    jobs: Vec<ImportExportJobUpdate>,
}

#[derive(Debug, Serialize)]
struct ImportExportJobEvent {
    r#type: &'static str,
    job: ImportExportJobUpdate,
}

#[derive(Debug, Serialize)]
struct ImportExportJobUpdate {
    #[serde(flatten)]
    job: ImportExportJobResponse,
    download: Option<DownloadUrlResponse>,
}

#[derive(Debug, Serialize)]
struct ImportExportLaggedEvent {
    r#type: &'static str,
    skipped: u64,
}

#[derive(Debug, Serialize)]
struct LogSnapshot {
    r#type: &'static str,
    instance_id: String,
    sequence: u64,
    stdout: Option<String>,
    stderr: Option<String>,
    error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_claims_filter_foreign_jobs_when_query_is_omitted() {
        let claims = claims_for_instances(vec!["inst_allowed"]);
        let foreign_job = sample_job("job-foreign", "inst_foreign");

        assert!(!job_matches_access(
            &foreign_job,
            "inst_allowed",
            &ImportExportQuery::default(),
            &claims,
        ));
    }

    #[test]
    fn scoped_claims_filter_foreign_job_id_lookup() {
        let claims = claims_for_instances(vec!["inst_allowed"]);
        let foreign_job = sample_job("job-foreign", "inst_foreign");
        let query = ImportExportQuery {
            job_id: Some(foreign_job.job_id.clone()),
        };

        assert!(!job_matches_access(
            &foreign_job,
            "inst_allowed",
            &query,
            &claims
        ));
    }

    #[test]
    fn scoped_claims_allow_own_job_events() {
        let claims = claims_for_instances(vec!["inst_allowed"]);
        let own_job = sample_job("job-own", "inst_allowed");

        assert!(job_matches_access(
            &own_job,
            "inst_allowed",
            &ImportExportQuery::default(),
            &claims,
        ));
    }

    #[test]
    fn explicit_node_wide_claim_allows_foreign_jobs() {
        let mut claims = claims_for_instances(Vec::new());
        claims.all_instances = true;
        let job = sample_job("job-any", "inst_any");

        assert!(job_matches_access(
            &job,
            "inst_any",
            &ImportExportQuery::default(),
            &claims,
        ));
    }

    #[test]
    fn empty_instance_claims_do_not_grant_access() {
        let claims = claims_for_instances(Vec::new());
        let job = sample_job("job-any", "inst_any");

        assert!(!job_matches_access(
            &job,
            "inst_any",
            &ImportExportQuery::default(),
            &claims,
        ));
    }

    fn claims_for_instances(instances: Vec<&str>) -> Claims {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        Claims {
            iss: crate::constants::jwt::ISSUER.to_string(),
            aud: crate::constants::jwt::AUDIENCE.to_string(),
            sub: "test-user".to_string(),
            all_instances: false,
            instances: instances.into_iter().map(str::to_string).collect(),
            scopes: vec![scopes::IMPORT_EXPORT_READ.to_string()],
            iat: now,
            nbf: now,
            exp: now + 60,
            jti: "test-jti".to_string(),
        }
    }

    fn sample_job(job_id: &str, instance_id: &str) -> ImportExportJob {
        ImportExportJob {
            job_id: job_id.to_string(),
            instance_id: instance_id.to_string(),
            action: ImportExportAction::Export,
            status: ImportExportStatus::Succeeded,
            artifact_path: Some(format!("/tmp/{instance_id}.sql")),
            error: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }
}
