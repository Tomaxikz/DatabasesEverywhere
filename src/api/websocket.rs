use std::collections::HashMap;

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
use tokio::time::{Duration, Instant, interval};

use crate::{
    api::{
        artifacts::{IssueDownloadTokenResponse, issue_artifact_download_ticket},
        handlers::{ApiError, authorize_websocket_jwt},
        import_export::{ImportExportJobResponse, public_job_response},
        progress::InstallProgress,
        resources::{
            CpuStatsSample, ResourceReport, cpu_percent, cpu_percent_between, current_cpu_sample,
            instance_disk_used, memory_usage_bytes, mib_to_bytes, network_rx_bytes,
            network_tx_bytes,
        },
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
    let mut ticker = interval(Duration::from_secs(1));
    let mut cache = MonitoringCache::default();
    loop {
        ticker.tick().await;
        let message = monitoring_snapshot(&state, &mut cache).await;
        let Ok(payload) = serde_json::to_string(&message) else {
            tracing::warn!("failed to serialize monitoring snapshot");
            break;
        };
        if socket.send(Message::Text(payload.into())).await.is_err() {
            break;
        }
    }
}

const DISK_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Default)]
struct MonitoringCache {
    cpu_samples: HashMap<String, CpuStatsSample>,
    disk_samples: HashMap<String, CachedDiskUsage>,
}

#[derive(Debug, Clone, Copy)]
struct CachedDiskUsage {
    used_bytes: u64,
    sampled_at: Instant,
}

async fn monitoring_snapshot(state: &AppState, cache: &mut MonitoringCache) -> MonitoringSnapshot {
    let mut instances = Vec::new();
    for metadata in state.instances.list().await {
        let instance_id = metadata.instance_id.clone();
        let stats = state
            .docker
            .stats(metadata.protocol, &metadata.instance_id)
            .await
            .ok()
            .map(|output| output.stdout);
        let stats_value = stats
            .as_ref()
            .and_then(|stats| serde_json::from_str::<serde_json::Value>(stats).ok());
        let memory_usage = stats_value.as_ref().and_then(memory_usage_bytes);
        let network_rx = stats_value.as_ref().and_then(network_rx_bytes);
        let network_tx = stats_value.as_ref().and_then(network_tx_bytes);
        let cpu_usage = stats_value
            .as_ref()
            .and_then(|stats| live_cpu_percent(&instance_id, stats, cache));
        let disk_sample = cached_disk_usage(state, &instance_id, cache).await;
        let disk_used = disk_sample.as_ref().ok().map(|sample| sample.used_bytes);
        let resource_error = disk_sample.err();
        let memory_limit = mib_to_bytes(metadata.limits.memory_mib);
        let disk_limit = mib_to_bytes(metadata.limits.disk_mib);

        let resources = ResourceReport {
            instance_id: metadata.instance_id.clone(),
            protocol: metadata.protocol.to_string(),
            status: metadata.status.as_str().to_string(),
            cpu: crate::api::resources::CpuReport {
                configured_cores: metadata.limits.cpu_cores,
                usage_percent: cpu_usage,
            },
            memory: crate::api::resources::MemoryReport {
                configured_mib: metadata.limits.memory_mib,
                usage_bytes: memory_usage,
                limit_bytes: Some(memory_limit),
            },
            disk: crate::api::resources::DiskReport {
                configured_mib: metadata.limits.disk_mib,
                limit_bytes: disk_limit,
                used_bytes: disk_used.unwrap_or(0),
                enforced: metadata.limits.disk_enforced,
                enforcement_method: metadata.limits.disk_enforcement_method.clone(),
            },
            network: crate::api::resources::NetworkReport {
                rx_bytes: network_rx,
                tx_bytes: network_tx,
            },
        };

        instances.push(MonitoringInstance {
            instance_id: metadata.instance_id,
            protocol: metadata.protocol.to_string(),
            status: metadata.status.as_str().to_string(),
            runtime: metadata.runtime.kind.as_str(),
            cpu_cores: metadata.limits.cpu_cores,
            cpu_limit_cores: metadata.limits.cpu_cores,
            cpu_usage_percent: cpu_usage,
            memory_mib: metadata.limits.memory_mib,
            memory_usage_bytes: memory_usage,
            memory_limit_bytes: Some(memory_limit),
            disk_mib: metadata.limits.disk_mib,
            disk_limit_bytes: disk_limit,
            disk_used_bytes: disk_used,
            disk_enforced: metadata.limits.disk_enforced,
            network_rx_bytes: network_rx,
            network_tx_bytes: network_tx,
            resources: Some(resources),
            docker_stats: stats,
            resource_error,
        });
    }

    MonitoringSnapshot {
        r#type: "stats",
        instances,
        install_progress: state.install_progress.list(),
    }
}

fn live_cpu_percent(
    instance_id: &str,
    stats: &serde_json::Value,
    cache: &mut MonitoringCache,
) -> Option<f64> {
    let from_docker_precpu = cpu_percent(stats);
    let current = current_cpu_sample(stats);
    let from_previous_snapshot = current.and_then(|current| {
        cache
            .cpu_samples
            .get(instance_id)
            .copied()
            .and_then(|previous| cpu_percent_between(previous, current))
    });
    if let Some(current) = current {
        cache.cpu_samples.insert(instance_id.to_string(), current);
    }
    from_previous_snapshot.or(from_docker_precpu)
}

async fn cached_disk_usage(
    state: &AppState,
    instance_id: &str,
    cache: &mut MonitoringCache,
) -> Result<CachedDiskUsage, String> {
    if let Some(sample) = cache.disk_samples.get(instance_id).copied()
        && sample.sampled_at.elapsed() < DISK_REFRESH_INTERVAL
    {
        return Ok(sample);
    }

    match instance_disk_used(state, instance_id).await {
        Ok(used_bytes) => {
            let sample = CachedDiskUsage {
                used_bytes,
                sampled_at: Instant::now(),
            };
            cache.disk_samples.insert(instance_id.to_string(), sample);
            Ok(sample)
        }
        Err(error) => {
            tracing::warn!(
                %instance_id,
                %error,
                "failed to collect monitoring disk usage"
            );
            cache
                .disk_samples
                .get(instance_id)
                .copied()
                .ok_or_else(|| error.to_string())
        }
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
        .on_upgrade(move |socket| stream_logs(socket, state, metadata)))
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

async fn stream_logs(mut socket: WebSocket, state: AppState, metadata: InstanceMetadata) {
    let mut ticker = interval(Duration::from_secs(3));
    let mut sequence = 0_u64;
    loop {
        ticker.tick().await;
        sequence += 1;
        let message = match state
            .docker
            .logs(metadata.protocol, &metadata.instance_id, None)
            .await
        {
            Ok(output) => LogSnapshot {
                r#type: "logs",
                instance_id: metadata.instance_id.clone(),
                sequence,
                stdout: Some(redaction::redact_connection_url(&output.stdout)),
                stderr: Some(redaction::redact_connection_url(&output.stderr)),
                error: None,
            },
            Err(error) => LogSnapshot {
                r#type: "logs",
                instance_id: metadata.instance_id.clone(),
                sequence,
                stdout: None,
                stderr: None,
                error: Some(error.to_string()),
            },
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
