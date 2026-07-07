use axum::{
    extract::{
        Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, Uri},
    response::Response,
};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio::time::{Duration, interval};

use crate::{
    api::{
        artifacts::{IssueDownloadTokenResponse, issue_artifact_download_ticket},
        handlers::{ApiError, authorize_websocket_jwt},
        import_export::{ImportExportJobResponse, public_job_response},
        progress::InstallProgress,
        resources::{ResourceReport, resource_report_with_docker_stats},
        routes::AppState,
    },
    auth::scopes,
    instances::metadata::InstanceMetadata,
    jobs::import_export::{ImportExportAction, ImportExportJob, ImportExportStatus},
    shared::redaction,
};

#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    pub instance_id: String,
    pub tail: Option<usize>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct ImportExportQuery {
    pub instance_id: Option<String>,
    pub job_id: Option<String>,
}

pub async fn monitoring(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    websocket: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    authorize_websocket_jwt(&state, &headers, &uri, scopes::MONITOR_READ, None)?;
    Ok(websocket
        .protocols(["dbe.jwt", "bearer"])
        .on_upgrade(move |socket| stream_monitoring(socket, state)))
}

async fn stream_monitoring(mut socket: WebSocket, state: AppState) {
    let _monitor = state.resource_cache.register_monitor();
    let mut ticker = interval(Duration::from_secs(1));
    loop {
        ticker.tick().await;
        let message = monitoring_snapshot(&state).await;
        let Ok(payload) = serde_json::to_string(&message) else {
            tracing::warn!("failed to serialize monitoring snapshot");
            break;
        };
        if socket.send(Message::Text(payload.into())).await.is_err() {
            break;
        }
    }
}

const MONITORING_FANOUT_LIMIT: usize = 16;

async fn monitoring_snapshot(state: &AppState) -> MonitoringSnapshot {
    use futures::StreamExt;

    let instances = futures::stream::iter(state.instances.list().await)
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
        install_progress: state.install_progress.list(),
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
    Query(query): Query<LogsQuery>,
    headers: HeaderMap,
    uri: Uri,
    websocket: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    authorize_websocket_jwt(
        &state,
        &headers,
        &uri,
        scopes::LOGS_READ,
        Some(&query.instance_id),
    )?;
    let metadata = state
        .instances
        .get(&query.instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    Ok(websocket
        .protocols(["dbe.jwt", "bearer"])
        .on_upgrade(move |socket| stream_logs(socket, state, metadata, query.tail)))
}

pub async fn import_export(
    State(state): State<AppState>,
    Query(query): Query<ImportExportQuery>,
    headers: HeaderMap,
    uri: Uri,
    websocket: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let download_headers = headers.clone();
    authorize_websocket_jwt(
        &state,
        &headers,
        &uri,
        scopes::IMPORT_EXPORT_READ,
        query.instance_id.as_deref(),
    )?;
    Ok(websocket
        .protocols(["dbe.jwt", "bearer"])
        .on_upgrade(move |socket| stream_import_export(socket, state, query, download_headers)))
}

async fn stream_logs(
    mut socket: WebSocket,
    state: AppState,
    metadata: InstanceMetadata,
    tail: Option<usize>,
) {
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
            let _ = send_json(&mut socket, &message).await;
            return;
        }
    };
    let mut heartbeat = interval(Duration::from_secs(30));
    let mut sequence = 0_u64;
    let mut stdout_buffer = String::new();
    let mut stderr_buffer = String::new();
    loop {
        let message = tokio::select! {
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

        let Ok(payload) = serde_json::to_string(&message) else {
            tracing::warn!(instance_id = %metadata.instance_id, "failed to serialize log snapshot");
            break;
        };
        if socket.send(Message::Text(payload.into())).await.is_err() {
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
    query: ImportExportQuery,
    download_headers: HeaderMap,
) {
    let snapshot = import_export_snapshot(&state, &download_headers, &query).await;
    if send_json(&mut socket, &snapshot).await.is_err() {
        return;
    }

    let mut events = state.import_export_jobs.subscribe();
    loop {
        match events.recv().await {
            Ok(job) => {
                if !job_matches_query(&job, &query) {
                    continue;
                }
                let event = ImportExportJobEvent {
                    r#type: "import_export_job",
                    job: public_job_update(&state, &download_headers, job).await,
                };
                if send_json(&mut socket, &event).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                let event = ImportExportLaggedEvent {
                    r#type: "import_export_lagged",
                    skipped,
                };
                if send_json(&mut socket, &event).await.is_err() {
                    break;
                }
                let snapshot = import_export_snapshot(&state, &download_headers, &query).await;
                if send_json(&mut socket, &snapshot).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

async fn import_export_snapshot(
    state: &AppState,
    download_headers: &HeaderMap,
    query: &ImportExportQuery,
) -> ImportExportSnapshot {
    let jobs = if let Some(job_id) = query.job_id.as_deref() {
        state
            .import_export_jobs
            .get(job_id)
            .await
            .into_iter()
            .collect()
    } else {
        state
            .import_export_jobs
            .list(query.instance_id.as_deref(), None, 100)
            .await
    };
    let mut response = Vec::with_capacity(jobs.len());
    for job in jobs {
        if job_matches_query(&job, query) {
            response.push(public_job_update(state, download_headers, job).await);
        }
    }
    ImportExportSnapshot {
        r#type: "import_export_snapshot",
        jobs: response,
    }
}

fn job_matches_query(job: &ImportExportJob, query: &ImportExportQuery) -> bool {
    query
        .instance_id
        .as_deref()
        .is_none_or(|instance_id| job.instance_id == instance_id)
        && query
            .job_id
            .as_deref()
            .is_none_or(|job_id| job.job_id == job_id)
}

async fn public_job_update(
    state: &AppState,
    download_headers: &HeaderMap,
    job: ImportExportJob,
) -> ImportExportJobUpdate {
    let download = download_ticket_for_job(state, download_headers, &job).await;
    ImportExportJobUpdate {
        job: public_job_response(job).await,
        download,
    }
}

async fn download_ticket_for_job(
    state: &AppState,
    download_headers: &HeaderMap,
    job: &ImportExportJob,
) -> Option<IssueDownloadTokenResponse> {
    if job.action != ImportExportAction::Export || job.status != ImportExportStatus::Succeeded {
        return None;
    }
    let artifact_name = job
        .artifact_path
        .as_deref()
        .and_then(|path| std::path::Path::new(path).file_name())
        .and_then(|name| name.to_str())?;
    match issue_artifact_download_ticket(
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

async fn send_json<T: Serialize>(socket: &mut WebSocket, value: &T) -> Result<(), ()> {
    let payload = serde_json::to_string(value).map_err(|error| {
        tracing::warn!(%error, "failed to serialize websocket payload");
    })?;
    socket
        .send(Message::Text(payload.into()))
        .await
        .map_err(|_| ())
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
    download: Option<IssueDownloadTokenResponse>,
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
