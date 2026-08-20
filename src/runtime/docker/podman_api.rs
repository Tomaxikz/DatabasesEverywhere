use std::time::Duration;

use reqwest::{Client, Response, Url, redirect::Policy};
use serde::Serialize;

use super::{DockerError, container_config::mib_to_bytes};
use crate::shared::{limits::validate_runtime_limits, redaction};

const API_VERSION: &str = "v4.0.0";
const API_TIMEOUT: Duration = Duration::from_secs(120);
const CPU_PERIOD_MICROSECONDS: u64 = 100_000;
const MAX_ERROR_BODY_BYTES: usize = 4_096;
const UPDATE_LIMITS_OPERATION: &str = "container resource update";

#[derive(Debug, Serialize)]
struct LinuxResources {
    cpu: LinuxCpu,
    memory: LinuxMemory,
}

#[derive(Debug, Serialize)]
struct LinuxCpu {
    period: u64,
    quota: i64,
}

#[derive(Debug, Serialize)]
struct LinuxMemory {
    limit: i64,
    swap: i64,
}

pub(super) async fn update_limits(
    socket_path: &str,
    container_name: &str,
    cpu_cores: f64,
    memory_mib: u64,
) -> Result<(), DockerError> {
    let resources = update_limits_body(cpu_cores, memory_mib)?;
    let url = update_limits_url(container_name)?;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let client = Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .timeout(API_TIMEOUT)
        .unix_socket(socket_path)
        .build()
        .map_err(|error| request_error("client setup", error))?;
    let response = client
        .post(url)
        .json(&resources)
        .send()
        .await
        .map_err(|error| request_error(UPDATE_LIMITS_OPERATION, error))?;

    if response.status().is_success() {
        return Ok(());
    }
    Err(response_error(UPDATE_LIMITS_OPERATION, response).await)
}

fn update_limits_body(cpu_cores: f64, memory_mib: u64) -> Result<LinuxResources, DockerError> {
    validate_runtime_limits(cpu_cores, memory_mib)?;
    let quota = cpu_quota(cpu_cores).ok_or(DockerError::CpuLimitConversion { cpu_cores })?;
    let memory_bytes =
        mib_to_bytes(memory_mib).ok_or(DockerError::MemoryLimitConversion { memory_mib })?;

    Ok(LinuxResources {
        cpu: LinuxCpu {
            period: CPU_PERIOD_MICROSECONDS,
            quota,
        },
        memory: LinuxMemory {
            limit: memory_bytes,
            swap: memory_bytes,
        },
    })
}

fn cpu_quota(cpu_cores: f64) -> Option<i64> {
    if !cpu_cores.is_finite() || cpu_cores <= 0.0 {
        return None;
    }
    let quota = (cpu_cores * CPU_PERIOD_MICROSECONDS as f64).round();
    if quota < 1.0 || quota >= i64::MAX as f64 {
        return None;
    }
    Some(quota as i64)
}

fn update_limits_url(container_name: &str) -> Result<Url, DockerError> {
    let mut url =
        Url::parse("http://podman.internal").map_err(|error| DockerError::PodmanApiRequest {
            operation: "request URL setup",
            reason: error.to_string(),
        })?;
    url.path_segments_mut()
        .map_err(|_| DockerError::PodmanApiRequest {
            operation: "request URL setup",
            reason: "Podman API base URL cannot contain path segments".to_string(),
        })?
        .extend([
            API_VERSION,
            "libpod",
            "containers",
            container_name,
            "update",
        ]);
    Ok(url)
}

fn request_error(operation: &'static str, error: reqwest::Error) -> DockerError {
    DockerError::PodmanApiRequest {
        operation,
        reason: error.without_url().to_string(),
    }
}

async fn response_error(operation: &'static str, mut response: Response) -> DockerError {
    let status = response.status();
    let mut body = Vec::new();
    while body.len() < MAX_ERROR_BODY_BYTES {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) | Err(_) => break,
        };
        let remaining = MAX_ERROR_BODY_BYTES - body.len();
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }
    let message = String::from_utf8_lossy(&body);
    let message = redaction::redact_connection_url(message.trim());
    let message = if message.is_empty() {
        status
            .canonical_reason()
            .unwrap_or("Podman returned an empty error response")
            .to_string()
    } else {
        message
    };

    DockerError::PodmanApiResponse {
        operation,
        status: status.as_u16(),
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_update_uses_versioned_route_and_oci_cgroup_units() {
        let body = update_limits_body(0.5, 96).unwrap();
        let json = serde_json::to_value(body).unwrap();

        assert_eq!(json["cpu"]["period"], 100_000);
        assert_eq!(json["cpu"]["quota"], 50_000);
        assert_eq!(json["memory"]["limit"], 96 * 1024 * 1024);
        assert_eq!(json["memory"]["swap"], json["memory"]["limit"]);
        let url = update_limits_url("dbev_redis_instance-one").unwrap();

        assert_eq!(
            url.as_str(),
            "http://podman.internal/v4.0.0/libpod/containers/dbev_redis_instance-one/update"
        );
    }
}
