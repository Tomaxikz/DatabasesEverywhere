use std::path::{Path as FsPath, PathBuf};

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, Uri},
};
use serde::Serialize;
use serde_json::Value;

use crate::{
    api::{
        handlers::{ApiError, ApiResult, authorize_scope},
        routes::AppState,
    },
    auth::scopes,
    instances::{metadata::InstanceMetadata, paths::InstancePaths},
};

#[derive(Debug, Serialize)]
pub struct ResourceReport {
    pub instance_id: String,
    pub protocol: String,
    pub status: String,
    pub cpu: CpuReport,
    pub memory: MemoryReport,
    pub disk: DiskReport,
    pub network: NetworkReport,
}

#[derive(Debug, Serialize)]
pub struct CpuReport {
    pub configured_cores: f64,
    pub usage_percent: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct MemoryReport {
    pub configured_mib: u64,
    pub usage_bytes: Option<u64>,
    pub limit_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct DiskReport {
    pub configured_mib: u64,
    pub limit_bytes: u64,
    pub used_bytes: u64,
    pub enforced: bool,
    pub enforcement_method: String,
}

#[derive(Debug, Serialize)]
pub struct NetworkReport {
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
}

pub async fn list_resources(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<Vec<ResourceReport>> {
    authorize_scope(&state, &headers, &uri, scopes::RESOURCES_READ)?;
    let mut reports = Vec::new();
    for metadata in state.instances.list().await {
        reports.push(resource_report(&state, metadata).await?);
    }
    Ok(Json(reports))
}

pub async fn instance_resources(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<ResourceReport> {
    authorize_scope(&state, &headers, &uri, scopes::RESOURCES_READ)?;
    let metadata = state
        .instances
        .get(&instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    Ok(Json(resource_report(&state, metadata).await?))
}

pub(crate) async fn resource_report(
    state: &AppState,
    metadata: InstanceMetadata,
) -> Result<ResourceReport, ApiError> {
    resource_report_with_docker_stats(state, metadata)
        .await
        .map(|(report, _)| report)
}

pub(crate) async fn resource_report_with_docker_stats(
    state: &AppState,
    metadata: InstanceMetadata,
) -> Result<(ResourceReport, Option<String>), ApiError> {
    let stats = state
        .docker
        .stats(metadata.protocol, &metadata.instance_id)
        .await
        .ok()
        .map(|output| output.stdout);
    let stats_value = stats
        .as_ref()
        .and_then(|stats| serde_json::from_str::<Value>(stats).ok());
    let paths = InstancePaths::new(&state.config.paths, &metadata.instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let disk_used = directory_size(paths.data)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to measure disk usage: {error}")))?;

    let report = ResourceReport {
        instance_id: metadata.instance_id,
        protocol: metadata.protocol.to_string(),
        status: metadata.status.as_str().to_string(),
        cpu: CpuReport {
            configured_cores: metadata.limits.cpu_cores,
            usage_percent: stats_value.as_ref().and_then(cpu_percent),
        },
        memory: MemoryReport {
            configured_mib: metadata.limits.memory_mib,
            usage_bytes: stats_value.as_ref().and_then(memory_usage_bytes),
            limit_bytes: Some(mib_to_bytes(metadata.limits.memory_mib)),
        },
        disk: DiskReport {
            configured_mib: metadata.limits.disk_mib,
            limit_bytes: mib_to_bytes(metadata.limits.disk_mib),
            used_bytes: disk_used,
            enforced: metadata.limits.disk_enforced,
            enforcement_method: metadata.limits.disk_enforcement_method,
        },
        network: NetworkReport {
            rx_bytes: stats_value.as_ref().and_then(network_rx_bytes),
            tx_bytes: stats_value.as_ref().and_then(network_tx_bytes),
        },
    };

    Ok((report, stats))
}

pub(crate) async fn instance_disk_used(
    state: &AppState,
    instance_id: &str,
) -> Result<u64, ApiError> {
    let paths = InstancePaths::new(&state.config.paths, instance_id)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    directory_size(paths.data)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to measure disk usage: {error}")))
}

async fn directory_size(path: PathBuf) -> Result<u64, std::io::Error> {
    tokio::task::spawn_blocking(move || directory_size_blocking(&path))
        .await
        .map_err(std::io::Error::other)?
}

fn directory_size_blocking(path: &FsPath) -> Result<u64, std::io::Error> {
    let mut total = 0;
    let Ok(entries) = std::fs::read_dir(path) else {
        return Ok(0);
    };
    for entry in entries {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            total += directory_size_blocking(&entry.path())?;
        } else if metadata.is_file() {
            total += metadata.len();
        }
    }
    Ok(total)
}

pub(crate) fn cpu_percent(stats: &Value) -> Option<f64> {
    let current = cpu_sample_from_path(stats, "cpu_stats")?;
    let previous = cpu_sample_from_path(stats, "precpu_stats")?;
    cpu_percent_between(previous, current)
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CpuStatsSample {
    total_usage: u64,
    system_cpu_usage: u64,
    online_cpus: u64,
}

pub(crate) fn current_cpu_sample(stats: &Value) -> Option<CpuStatsSample> {
    cpu_sample_from_path(stats, "cpu_stats")
}

pub(crate) fn cpu_percent_between(
    previous: CpuStatsSample,
    current: CpuStatsSample,
) -> Option<f64> {
    let cpu_delta = current.total_usage.saturating_sub(previous.total_usage);
    let system_delta = current
        .system_cpu_usage
        .saturating_sub(previous.system_cpu_usage);
    if system_delta == 0 {
        return None;
    }
    Some((cpu_delta as f64 / system_delta as f64) * current.online_cpus as f64 * 100.0)
}

fn cpu_sample_from_path(stats: &Value, root: &str) -> Option<CpuStatsSample> {
    Some(CpuStatsSample {
        total_usage: value_u64(stats, &[root, "cpu_usage", "total_usage"])?,
        system_cpu_usage: value_u64(stats, &[root, "system_cpu_usage"])?,
        online_cpus: value_u64(stats, &[root, "online_cpus"]).unwrap_or(1),
    })
}

pub(crate) fn memory_usage_bytes(stats: &Value) -> Option<u64> {
    value_u64(stats, &["memory_stats", "usage"])
}

pub(crate) fn network_rx_bytes(stats: &Value) -> Option<u64> {
    network_sum(stats, "rx_bytes")
}

pub(crate) fn network_tx_bytes(stats: &Value) -> Option<u64> {
    network_sum(stats, "tx_bytes")
}

pub(crate) fn mib_to_bytes(mib: u64) -> u64 {
    mib.saturating_mul(1024 * 1024)
}

pub(crate) fn network_sum(stats: &Value, key: &str) -> Option<u64> {
    let networks = stats.get("networks")?.as_object()?;
    Some(
        networks
            .values()
            .filter_map(|network| network.get(key).and_then(Value::as_u64))
            .sum(),
    )
}

pub(crate) fn value_u64(value: &Value, path: &[&str]) -> Option<u64> {
    let mut value = value;
    for key in path {
        value = value.get(*key)?;
    }
    value.as_u64()
}
