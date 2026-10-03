mod accumulator;
mod jobs;
mod load;
#[cfg(test)]
mod tests;
mod websocket;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, anyhow};
use reqwest::{
    Client, Method,
    header::{HOST, HeaderValue},
};
use serde_json::Value;

use super::metrics::{
    HttpPhaseReport, JobBenchmarkReport, RequestSample, WebSocketBenchmarkReport,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const JOB_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MAX_ERROR_BODY_BYTES: usize = 512;
pub(super) const MAX_RETAINED_REQUEST_SAMPLES: usize = 100_000;
const MAX_RECORDED_LATENCY_MICROS: u64 = 60_000_000;
const API_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const MAX_PACED_BATCH_REQUESTS: usize = 100_000;
const LATENCY_SIGNIFICANT_DIGITS: u8 = 3;
const BYTES_PER_MIB: f64 = 1024.0 * 1024.0;
const WEBSOCKET_TARGET: &str = "/ws/monitoring";

#[derive(Debug, Clone)]
pub(super) struct LoadTarget {
    pub path: String,
}

impl LoadTarget {
    pub(super) fn heartbeat() -> Self {
        Self {
            path: "/api/heartbeat".to_string(),
        }
    }

    pub(super) fn instance_status(instance_id: &str) -> Self {
        Self {
            path: format!("/api/instances/{instance_id}/status"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct FixedWindowPacing {
    pub window_started: Instant,
    pub requests_per_window: usize,
}

#[derive(Clone)]
pub(super) struct BenchClient {
    base_url: Arc<str>,
    host_header: Option<HeaderValue>,
    token: Arc<str>,
    client: Client,
    websocket_client: Client,
}

pub(super) struct MeasuredResponse {
    pub sample: RequestSample,
    pub body: Vec<u8>,
}

impl MeasuredResponse {
    pub(super) fn json(&self) -> anyhow::Result<Value> {
        serde_json::from_slice(&self.body).context("response was not valid JSON")
    }
}

pub(super) struct PhaseRun {
    pub report: HttpPhaseReport,
    pub samples: Vec<RequestSample>,
}

pub(super) struct WebSocketRun {
    pub report: WebSocketBenchmarkReport,
    pub samples: Vec<RequestSample>,
}

pub(super) struct ImportExportRun {
    pub jobs: Vec<JobBenchmarkReport>,
    pub samples: Vec<RequestSample>,
    pub warnings: Vec<String>,
}

impl BenchClient {
    pub(super) fn new(
        base_url: &str,
        host_header: Option<&str>,
        token: &str,
        concurrency: usize,
        insecure_tls: bool,
    ) -> anyhow::Result<Self> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        validate_base_url(base_url)?;
        let host_header = host_header
            .map(HeaderValue::from_str)
            .transpose()
            .context("invalid benchmark Host header")?;
        let build = |http1_only: bool| -> anyhow::Result<Client> {
            let mut builder = Client::builder()
                .tls_certs_only(crate::utils::tls::mozilla_root_certificates())
                .pool_max_idle_per_host(concurrency.max(1))
                .timeout(REQUEST_TIMEOUT)
                .danger_accept_invalid_certs(insecure_tls);
            if http1_only {
                builder = builder.http1_only();
            }
            builder.build().context("failed to build benchmark client")
        };
        Ok(Self {
            base_url: Arc::from(base_url.trim_end_matches('/')),
            host_header,
            token: Arc::from(token),
            client: build(false)?,
            websocket_client: build(true)?,
        })
    }

    pub(super) async fn warm_up(&self, count: usize) -> anyhow::Result<()> {
        for index in 0..count {
            let response = self
                .request(Method::GET, "/api/heartbeat", None, "warmup", index)
                .await;
            if !response.sample.success {
                return Err(anyhow!(
                    "benchmark warmup failed: {}",
                    response
                        .sample
                        .error
                        .unwrap_or_else(|| "unknown request failure".to_string())
                ));
            }
        }
        Ok(())
    }

    pub(super) async fn required_json(&self, path: &str, phase: &str) -> anyhow::Result<Value> {
        let response = self.request(Method::GET, path, None, phase, 0).await;
        if !response.sample.success {
            return Err(anyhow!(
                "{phase} failed: {}",
                response
                    .sample
                    .error
                    .unwrap_or_else(|| "unknown request failure".to_string())
            ));
        }
        response.json()
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        phase: &str,
        index: usize,
    ) -> MeasuredResponse {
        let started = Instant::now();
        let mut request = self
            .client
            .request(method, self.endpoint(path))
            .bearer_auth(self.token.as_ref());
        if let Some(host) = &self.host_header {
            request = request.header(HOST, host.clone());
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let finish_sample =
            |status_code: Option<u16>, success: bool, error: Option<String>| RequestSample {
                phase: phase.to_string(),
                target: path.to_string(),
                index,
                duration_micros: duration_micros(started.elapsed()),
                status_code,
                success,
                error,
            };
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                return MeasuredResponse {
                    sample: finish_sample(None, false, Some(error.to_string())),
                    body: Vec::new(),
                };
            }
        };
        let status = response.status();
        match response.bytes().await {
            Ok(body) => {
                let success = status.is_success();
                let error = (!success).then(|| format_http_error(status.as_u16(), body.as_ref()));
                MeasuredResponse {
                    sample: finish_sample(Some(status.as_u16()), success, error),
                    body: body.to_vec(),
                }
            }
            Err(error) => MeasuredResponse {
                sample: finish_sample(
                    Some(status.as_u16()),
                    false,
                    Some(format!("failed to read response body: {error}")),
                ),
                body: Vec::new(),
            },
        }
    }

    fn endpoint(&self, path: &str) -> String {
        debug_assert!(path.starts_with('/'));
        format!("{}{path}", self.base_url)
    }
}

fn validate_base_url(value: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(value).context("invalid benchmark API URL")?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(anyhow!("benchmark API URL must use http or https"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(anyhow!("benchmark API URL must not contain credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(anyhow!(
            "benchmark API URL must not contain a query or fragment"
        ));
    }
    if url.path() != "/" && !url.path().is_empty() {
        return Err(anyhow!("benchmark API URL must not contain a path"));
    }
    Ok(())
}

fn format_http_error(status: u16, body: &[u8]) -> String {
    let length = body.len().min(MAX_ERROR_BODY_BYTES);
    let message = String::from_utf8_lossy(&body[..length])
        .replace(['\r', '\n'], " ")
        .trim()
        .to_string();
    if message.is_empty() {
        format!("HTTP {status}")
    } else if body.len() > length {
        format!("HTTP {status}: {message}...")
    } else {
        format!("HTTP {status}: {message}")
    }
}

fn duration_micros(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}
