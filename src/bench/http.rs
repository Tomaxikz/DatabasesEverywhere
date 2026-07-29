use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::{StreamExt, stream};
use hdrhistogram::Histogram;
use reqwest::{
    Client, Method, StatusCode,
    header::{AUTHORIZATION, CONNECTION, HOST, HeaderValue, UPGRADE},
};
use serde_json::{Value, json};
use sha1::{Digest, Sha1};

use super::metrics::{
    HttpPhaseReport, JobBenchmarkReport, RequestSample, WebSocketBenchmarkReport,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const JOB_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MAX_ERROR_BODY_BYTES: usize = 512;
pub const MAX_RETAINED_REQUEST_SAMPLES: usize = 100_000;
const MAX_RECORDED_LATENCY_MICROS: u64 = 60_000_000;
const API_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const MAX_PACED_BATCH_REQUESTS: usize = 100_000;

#[derive(Debug, Clone)]
pub struct LoadTarget {
    pub path: String,
}

impl LoadTarget {
    pub fn heartbeat() -> Self {
        Self {
            path: "/api/heartbeat".to_string(),
        }
    }

    pub fn instance_status(instance_id: &str) -> Self {
        Self {
            path: format!("/api/instances/{instance_id}/status"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FixedWindowPacing {
    pub window_started: Instant,
    pub requests_per_window: usize,
}

#[derive(Clone)]
pub struct BenchClient {
    base_url: Arc<str>,
    host_header: Option<HeaderValue>,
    token: Arc<str>,
    client: Client,
    websocket_client: Client,
}

pub struct MeasuredResponse {
    pub sample: RequestSample,
    pub body: Vec<u8>,
}

impl MeasuredResponse {
    pub fn json(&self) -> anyhow::Result<Value> {
        serde_json::from_slice(&self.body).context("response was not valid JSON")
    }
}

pub struct PhaseRun {
    pub report: HttpPhaseReport,
    pub samples: Vec<RequestSample>,
}

pub struct WebSocketRun {
    pub report: WebSocketBenchmarkReport,
    pub samples: Vec<RequestSample>,
}

pub struct ImportExportRun {
    pub jobs: Vec<JobBenchmarkReport>,
    pub samples: Vec<RequestSample>,
    pub warnings: Vec<String>,
}

struct PhaseAccumulator {
    attempted_requests: usize,
    successful_requests: usize,
    rate_limited_requests: usize,
    transport_errors: usize,
    status_codes: std::collections::BTreeMap<String, usize>,
    target_requests: std::collections::BTreeMap<String, usize>,
    all_latencies: Histogram<u64>,
    successful_latencies: Histogram<u64>,
    retained_samples: Vec<RequestSample>,
    reservoir_rng: XorShift64,
}

impl PhaseAccumulator {
    fn new(seed: u64) -> Self {
        Self {
            attempted_requests: 0,
            successful_requests: 0,
            rate_limited_requests: 0,
            transport_errors: 0,
            status_codes: std::collections::BTreeMap::new(),
            target_requests: std::collections::BTreeMap::new(),
            all_latencies: Histogram::new_with_max(MAX_RECORDED_LATENCY_MICROS, 3)
                .expect("valid benchmark latency histogram"),
            successful_latencies: Histogram::new_with_max(MAX_RECORDED_LATENCY_MICROS, 3)
                .expect("valid benchmark latency histogram"),
            retained_samples: Vec::with_capacity(MAX_RETAINED_REQUEST_SAMPLES.min(1_024)),
            reservoir_rng: XorShift64::new(seed),
        }
    }

    fn record(&mut self, sample: RequestSample) {
        self.attempted_requests += 1;
        if sample.success {
            self.successful_requests += 1;
        }
        if sample.status_code == Some(StatusCode::TOO_MANY_REQUESTS.as_u16()) {
            self.rate_limited_requests += 1;
        }
        if let Some(status) = sample.status_code {
            *self.status_codes.entry(status.to_string()).or_default() += 1;
        } else {
            self.transport_errors += 1;
        }
        *self
            .target_requests
            .entry(sample.target.clone())
            .or_default() += 1;

        let latency = sample.duration_micros.clamp(1, MAX_RECORDED_LATENCY_MICROS);
        let _ = self.all_latencies.record(latency);
        if sample.success {
            let _ = self.successful_latencies.record(latency);
        }

        if self.retained_samples.len() < MAX_RETAINED_REQUEST_SAMPLES {
            self.retained_samples.push(sample);
            return;
        }
        let replacement = self
            .reservoir_rng
            .index_below(self.attempted_requests as u64) as usize;
        if replacement < MAX_RETAINED_REQUEST_SAMPLES {
            self.retained_samples[replacement] = sample;
        }
    }

    fn finish(
        mut self,
        name: &str,
        wall_duration: Duration,
        active_load_duration: Duration,
    ) -> PhaseRun {
        self.retained_samples
            .sort_unstable_by_key(|sample| sample.index);
        let report = HttpPhaseReport::from_histograms(
            name,
            wall_duration,
            active_load_duration,
            self.attempted_requests,
            self.successful_requests,
            self.rate_limited_requests,
            self.transport_errors,
            self.status_codes,
            self.target_requests,
            self.retained_samples.len(),
            &self.all_latencies,
            &self.successful_latencies,
        );
        PhaseRun {
            report,
            samples: self.retained_samples,
        }
    }
}

struct XorShift64(u64);

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn index_below(&mut self, upper_exclusive: u64) -> u64 {
        if upper_exclusive <= 1 {
            return 0;
        }
        let rejection_threshold = upper_exclusive.wrapping_neg() % upper_exclusive;
        loop {
            let value = self.next();
            if value >= rejection_threshold {
                return value % upper_exclusive;
            }
        }
    }
}

impl BenchClient {
    pub fn new(
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

    pub async fn warm_up(&self, count: usize) -> anyhow::Result<()> {
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

    pub async fn required_json(&self, path: &str, phase: &str) -> anyhow::Result<Value> {
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

    pub async fn benchmark_sequential(&self, count: usize) -> PhaseRun {
        let started = Instant::now();
        let mut samples = Vec::with_capacity(count);
        for index in 0..count {
            samples.push(
                self.request(
                    Method::GET,
                    "/api/heartbeat",
                    None,
                    "http_sequential",
                    index,
                )
                .await
                .sample,
            );
        }
        PhaseRun {
            report: HttpPhaseReport::from_samples("http_sequential", started.elapsed(), &samples),
            samples,
        }
    }

    pub async fn benchmark_concurrent(
        &self,
        count: usize,
        concurrency: usize,
        targets: Vec<LoadTarget>,
        reservoir_seed: u64,
    ) -> PhaseRun {
        let started = Instant::now();
        let targets = Arc::new(normalize_load_targets(targets));
        let mut accumulator = PhaseAccumulator::new(reservoir_seed);
        let active = self
            .run_concurrent_batch(
                0,
                count,
                concurrency,
                &targets,
                "http_concurrent",
                &mut accumulator,
            )
            .await;
        accumulator.finish("http_concurrent", started.elapsed(), active)
    }

    pub async fn benchmark_concurrent_for_duration(
        &self,
        duration: Duration,
        concurrency: usize,
        targets: Vec<LoadTarget>,
        reservoir_seed: u64,
        pacing: Option<FixedWindowPacing>,
    ) -> PhaseRun {
        let started = Instant::now();
        let deadline = started + duration;
        let targets = Arc::new(normalize_load_targets(targets));
        let mut accumulator = PhaseAccumulator::new(reservoir_seed);
        let mut active_load_duration = Duration::ZERO;

        if let Some(pacing) = pacing {
            let mut window_started = pacing.window_started;
            let window_budget = pacing.requests_per_window.max(1);
            let mut sent_in_window = 0_usize;
            let mut next_index = 0_usize;
            loop {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                while now.duration_since(window_started) >= API_RATE_LIMIT_WINDOW {
                    window_started += API_RATE_LIMIT_WINDOW;
                    sent_in_window = 0;
                }
                if sent_in_window >= window_budget {
                    let wake_at = (window_started + API_RATE_LIMIT_WINDOW).min(deadline);
                    tokio::time::sleep_until(tokio::time::Instant::from_std(wake_at)).await;
                    continue;
                }
                let batch_count = (window_budget - sent_in_window).min(MAX_PACED_BATCH_REQUESTS);
                active_load_duration += self
                    .run_concurrent_batch(
                        next_index,
                        batch_count,
                        concurrency,
                        &targets,
                        "http_concurrent_timed",
                        &mut accumulator,
                    )
                    .await;
                next_index = next_index.saturating_add(batch_count);
                sent_in_window = sent_in_window.saturating_add(batch_count);
            }
        } else {
            let indices = stream::unfold(0_usize, move |index| async move {
                (Instant::now() < deadline).then_some((index, index.saturating_add(1)))
            });
            let requests = indices
                .map(|index| {
                    let client = self.clone();
                    let target = choose_load_target(&targets, index).clone();
                    async move {
                        client
                            .request(
                                Method::GET,
                                &target.path,
                                None,
                                "http_concurrent_timed",
                                index,
                            )
                            .await
                            .sample
                    }
                })
                .buffer_unordered(concurrency.max(1));
            tokio::pin!(requests);
            while let Some(sample) = requests.next().await {
                accumulator.record(sample);
            }
            active_load_duration = started.elapsed();
        }
        accumulator.finish(
            "http_concurrent_timed",
            started.elapsed(),
            active_load_duration,
        )
    }

    async fn run_concurrent_batch(
        &self,
        start_index: usize,
        count: usize,
        concurrency: usize,
        targets: &Arc<Vec<LoadTarget>>,
        phase: &'static str,
        accumulator: &mut PhaseAccumulator,
    ) -> Duration {
        let started = Instant::now();
        let requests = stream::iter(start_index..start_index.saturating_add(count))
            .map(|index| {
                let client = self.clone();
                let target = choose_load_target(targets, index).clone();
                async move {
                    client
                        .request(Method::GET, &target.path, None, phase, index)
                        .await
                        .sample
                }
            })
            .buffer_unordered(concurrency.max(1));
        tokio::pin!(requests);
        while let Some(sample) = requests.next().await {
            accumulator.record(sample);
        }
        started.elapsed()
    }

    pub async fn benchmark_websockets(
        &self,
        count: usize,
        concurrency: usize,
        benchmark_id: &str,
    ) -> WebSocketRun {
        let token_started = Instant::now();
        let mut token_samples = Vec::with_capacity(count);
        let mut tokens = Vec::with_capacity(count);
        for index in 0..count {
            let body = json!({
                "subject": format!("dbev-benchmark-{benchmark_id}-{index}"),
                "scopes": ["monitor:read"],
                "instances": [],
                "all_instances": true,
                "ttl_seconds": 60
            });
            let mut response = self
                .request(
                    Method::POST,
                    "/api/ws-token",
                    Some(body),
                    "websocket_token",
                    index,
                )
                .await;
            if response.sample.success {
                match response
                    .json()
                    .ok()
                    .and_then(|value| value["token"].as_str().map(str::to_string))
                {
                    Some(token) => tokens.push((index, token)),
                    None => {
                        response.sample.success = false;
                        response.sample.error =
                            Some("WebSocket token response did not contain token".to_string());
                    }
                }
            }
            token_samples.push(response.sample);
        }
        let token_report = HttpPhaseReport::from_samples(
            "websocket_token",
            token_started.elapsed(),
            &token_samples,
        );

        let handshake_started = Instant::now();
        let handshake_samples = stream::iter(tokens)
            .map(|(index, token)| {
                let client = self.clone();
                async move { client.websocket_handshake(&token, index).await }
            })
            .buffer_unordered(concurrency.max(1))
            .collect::<Vec<_>>()
            .await;
        let handshake_report = HttpPhaseReport::from_samples(
            "websocket_handshake",
            handshake_started.elapsed(),
            &handshake_samples,
        );

        let mut samples = token_samples;
        samples.extend(handshake_samples);
        WebSocketRun {
            report: WebSocketBenchmarkReport {
                token_mint: token_report,
                handshake: handshake_report,
            },
            samples,
        }
    }

    pub async fn benchmark_import_export(
        &self,
        instance_id: &str,
        timeout: Duration,
        keep_artifact: bool,
    ) -> ImportExportRun {
        let mut samples = Vec::new();
        let mut warnings = Vec::new();
        let export = self
            .run_job(instance_id, "export", json!({}), timeout, &mut samples)
            .await;
        let artifact_id = export.artifact_id.clone();
        let export_succeeded = export.status == "succeeded";
        let mut jobs = vec![export];

        if export_succeeded {
            if let Some(artifact_id) = artifact_id.as_deref() {
                let import = self
                    .run_job(
                        instance_id,
                        "import",
                        json!({
                            "source": {
                                "type": "artifact",
                                "artifact_id": artifact_id
                            }
                        }),
                        timeout,
                        &mut samples,
                    )
                    .await;
                let import_succeeded = import.status == "succeeded";
                jobs.push(import);
                if import_succeeded && !keep_artifact {
                    let path = format!("/api/instances/{instance_id}/artifacts/{artifact_id}");
                    let cleanup = self
                        .request(Method::DELETE, &path, None, "benchmark_artifact_cleanup", 0)
                        .await;
                    if !cleanup.sample.success {
                        warnings.push(format!(
                            "benchmark artifact cleanup failed: {}",
                            cleanup
                                .sample
                                .error
                                .clone()
                                .unwrap_or_else(|| "unknown request failure".to_string())
                        ));
                    }
                    samples.push(cleanup.sample);
                } else if !import_succeeded {
                    warnings.push(format!(
                        "retained benchmark artifact {artifact_id} because its import failed"
                    ));
                }
            } else {
                jobs.push(failed_job_report(
                    "import",
                    "skipped",
                    Duration::ZERO,
                    None,
                    Some(
                        "successful export did not return an artifact_id; import was skipped"
                            .to_string(),
                    ),
                ));
            }
        } else {
            jobs.push(failed_job_report(
                "import",
                "skipped",
                Duration::ZERO,
                None,
                Some("import was skipped because benchmark export failed".to_string()),
            ));
        }

        ImportExportRun {
            jobs,
            samples,
            warnings,
        }
    }

    async fn run_job(
        &self,
        instance_id: &str,
        action: &str,
        body: Value,
        timeout: Duration,
        samples: &mut Vec<RequestSample>,
    ) -> JobBenchmarkReport {
        let started = Instant::now();
        let path = format!("/api/instances/{instance_id}/{action}");
        let queue_phase = format!("{action}_queue");
        let queue = self
            .request(Method::POST, &path, Some(body), &queue_phase, 0)
            .await;
        let queue_latency_ms = queue.sample.duration_micros as f64 / 1_000.0;
        let queue_success = queue.sample.success;
        let queue_error = queue.sample.error.clone();
        let queue_json = queue.json().ok();
        samples.push(queue.sample);
        if !queue_success {
            return failed_job_report(
                action,
                "queue_failed",
                started.elapsed(),
                Some(queue_latency_ms),
                queue_error,
            );
        }
        let Some(job_id) = queue_json
            .as_ref()
            .and_then(|value| value["job_id"].as_str())
            .map(str::to_string)
        else {
            return failed_job_report(
                action,
                "queue_failed",
                started.elapsed(),
                Some(queue_latency_ms),
                Some("queue response did not contain job_id".to_string()),
            );
        };
        let server_created_at = queue_json
            .as_ref()
            .and_then(|value| value["created_at"].as_str())
            .map(str::to_string);

        let status_path = format!("/api/instances/{instance_id}/import-export/jobs/{job_id}");
        let mut poll_index = 0_usize;
        let mut running_observed_after_ms = None;
        loop {
            if started.elapsed() >= timeout {
                return JobBenchmarkReport {
                    action: action.to_string(),
                    job_id: Some(job_id),
                    status: "timed_out".to_string(),
                    artifact_id: None,
                    artifact_size_bytes: None,
                    queue_latency_ms: Some(queue_latency_ms),
                    running_observed_after_ms,
                    total_duration_ms: started.elapsed().as_secs_f64() * 1_000.0,
                    server_duration_ms: None,
                    throughput_mib_per_second: None,
                    error: Some(format!(
                        "job did not complete within {} seconds",
                        timeout.as_secs()
                    )),
                };
            }
            tokio::time::sleep(JOB_POLL_INTERVAL).await;
            let poll_phase = format!("{action}_poll");
            let poll = self
                .request(Method::GET, &status_path, None, &poll_phase, poll_index)
                .await;
            poll_index += 1;
            let poll_success = poll.sample.success;
            let poll_status = poll.sample.status_code;
            let poll_error = poll.sample.error.clone();
            let value = poll.json().ok();
            samples.push(poll.sample);

            if !poll_success {
                if poll_status == Some(StatusCode::TOO_MANY_REQUESTS.as_u16()) {
                    continue;
                }
                return failed_job_report(
                    action,
                    "poll_failed",
                    started.elapsed(),
                    Some(queue_latency_ms),
                    poll_error,
                );
            }
            let Some(value) = value else {
                return failed_job_report(
                    action,
                    "poll_failed",
                    started.elapsed(),
                    Some(queue_latency_ms),
                    Some("job response was not valid JSON".to_string()),
                );
            };
            let status = value["status"].as_str().unwrap_or("unknown");
            if status == "running" && running_observed_after_ms.is_none() {
                running_observed_after_ms = Some(started.elapsed().as_secs_f64() * 1_000.0);
            }
            if !matches!(status, "succeeded" | "failed") {
                continue;
            }
            let total = started.elapsed();
            let size = value["artifact_size_bytes"].as_u64();
            let server_duration_ms = server_created_at.as_deref().and_then(|created_at| {
                value["updated_at"]
                    .as_str()
                    .and_then(|updated_at| rfc3339_duration_ms(created_at, updated_at))
            });
            let throughput_mib_per_second = size.and_then(|bytes| {
                let seconds = server_duration_ms
                    .map(|duration_ms| duration_ms / 1_000.0)
                    .filter(|seconds| *seconds > 0.0)
                    .unwrap_or(total.as_secs_f64());
                (seconds > 0.0).then_some(bytes as f64 / (1024.0 * 1024.0) / seconds)
            });
            return JobBenchmarkReport {
                action: action.to_string(),
                job_id: Some(job_id),
                status: status.to_string(),
                artifact_id: value["artifact_id"].as_str().map(str::to_string),
                artifact_size_bytes: size,
                queue_latency_ms: Some(queue_latency_ms),
                running_observed_after_ms,
                total_duration_ms: total.as_secs_f64() * 1_000.0,
                server_duration_ms,
                throughput_mib_per_second,
                error: public_job_error(&value),
            };
        }
    }

    async fn websocket_handshake(&self, token: &str, index: usize) -> RequestSample {
        let started = Instant::now();
        let key = STANDARD.encode(uuid::Uuid::new_v4().as_bytes());
        let expected_accept = websocket_accept(&key);
        let mut request = self
            .websocket_client
            .get(self.endpoint("/ws/monitoring"))
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header(CONNECTION, "Upgrade")
            .header(UPGRADE, "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", key)
            .header("sec-websocket-protocol", "dbe.jwt");
        if let Some(host) = &self.host_header {
            request = request.header(HOST, host.clone());
        }
        match request.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let selected_protocol = response
                    .headers()
                    .get("sec-websocket-protocol")
                    .and_then(|value| value.to_str().ok());
                let accept_matches = response
                    .headers()
                    .get("sec-websocket-accept")
                    .and_then(|value| value.to_str().ok())
                    == Some(expected_accept.as_str());
                let upgrade_matches =
                    header_contains_token(response.headers().get(UPGRADE), "websocket");
                let connection_upgraded =
                    header_contains_token(response.headers().get(CONNECTION), "upgrade");
                let success = status == StatusCode::SWITCHING_PROTOCOLS.as_u16()
                    && selected_protocol == Some("dbe.jwt")
                    && accept_matches
                    && upgrade_matches
                    && connection_upgraded;
                let error = (!success).then(|| {
                    format!(
                        "WebSocket upgrade returned HTTP {status} (protocol={selected_protocol:?}, valid_accept={accept_matches}, upgrade={upgrade_matches}, connection_upgrade={connection_upgraded})"
                    )
                });
                drop(response);
                RequestSample {
                    phase: "websocket_handshake".to_string(),
                    target: "/ws/monitoring".to_string(),
                    index,
                    duration_micros: duration_micros(started.elapsed()),
                    status_code: Some(status),
                    success,
                    error,
                }
            }
            Err(error) => RequestSample {
                phase: "websocket_handshake".to_string(),
                target: "/ws/monitoring".to_string(),
                index,
                duration_micros: duration_micros(started.elapsed()),
                status_code: None,
                success: false,
                error: Some(error.to_string()),
            },
        }
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
        match request.send().await {
            Ok(response) => {
                let status = response.status();
                match response.bytes().await {
                    Ok(body) => {
                        let success = status.is_success();
                        let error =
                            (!success).then(|| format_http_error(status.as_u16(), body.as_ref()));
                        MeasuredResponse {
                            sample: RequestSample {
                                phase: phase.to_string(),
                                target: path.to_string(),
                                index,
                                duration_micros: duration_micros(started.elapsed()),
                                status_code: Some(status.as_u16()),
                                success,
                                error,
                            },
                            body: body.to_vec(),
                        }
                    }
                    Err(error) => MeasuredResponse {
                        sample: RequestSample {
                            phase: phase.to_string(),
                            target: path.to_string(),
                            index,
                            duration_micros: duration_micros(started.elapsed()),
                            status_code: Some(status.as_u16()),
                            success: false,
                            error: Some(format!("failed to read response body: {error}")),
                        },
                        body: Vec::new(),
                    },
                }
            }
            Err(error) => MeasuredResponse {
                sample: RequestSample {
                    phase: phase.to_string(),
                    target: path.to_string(),
                    index,
                    duration_micros: duration_micros(started.elapsed()),
                    status_code: None,
                    success: false,
                    error: Some(error.to_string()),
                },
                body: Vec::new(),
            },
        }
    }

    fn endpoint(&self, path: &str) -> String {
        debug_assert!(path.starts_with('/'));
        format!("{}{path}", self.base_url)
    }
}

fn normalize_load_targets(mut targets: Vec<LoadTarget>) -> Vec<LoadTarget> {
    if targets.is_empty() {
        targets.push(LoadTarget::heartbeat());
    } else if targets[0].path != "/api/heartbeat" {
        targets.insert(0, LoadTarget::heartbeat());
    }
    targets
}

fn choose_load_target(targets: &[LoadTarget], index: usize) -> &LoadTarget {
    if targets.len() <= 1 || index.is_multiple_of(2) {
        &targets[0]
    } else {
        &targets[1 + (index / 2) % (targets.len() - 1)]
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

fn failed_job_report(
    action: &str,
    status: &str,
    elapsed: Duration,
    queue_latency_ms: Option<f64>,
    error: Option<String>,
) -> JobBenchmarkReport {
    JobBenchmarkReport {
        action: action.to_string(),
        job_id: None,
        status: status.to_string(),
        artifact_id: None,
        artifact_size_bytes: None,
        queue_latency_ms,
        running_observed_after_ms: None,
        total_duration_ms: elapsed.as_secs_f64() * 1_000.0,
        server_duration_ms: None,
        throughput_mib_per_second: None,
        error,
    }
}

fn public_job_error(value: &Value) -> Option<String> {
    let error = value.get("error")?;
    if error.is_null() {
        None
    } else if let Some(message) = error.as_str() {
        Some(message.to_string())
    } else {
        Some(error.to_string())
    }
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

fn websocket_accept(key: &str) -> String {
    const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(WEBSOCKET_GUID.as_bytes());
    STANDARD.encode(digest.finalize())
}

fn header_contains_token(value: Option<&HeaderValue>, expected: &str) -> bool {
    value
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
}

fn rfc3339_duration_ms(start: &str, end: &str) -> Option<f64> {
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};

    let start = OffsetDateTime::parse(start, &Rfc3339).ok()?;
    let end = OffsetDateTime::parse(end, &Rfc3339).ok()?;
    let duration = end - start;
    (!duration.is_negative()).then_some(duration.as_seconds_f64() * 1_000.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn rejects_api_urls_that_could_leak_credentials() {
        assert!(validate_base_url("https://user:secret@example.com").is_err());
        assert!(validate_base_url("ftp://example.com").is_err());
        assert!(validate_base_url("https://example.com/api").is_err());
        assert!(validate_base_url("https://example.com").is_ok());
    }

    #[test]
    fn truncates_and_flattens_http_errors() {
        let error = format_http_error(500, b"line one\nline two");

        assert_eq!(error, "HTTP 500: line one line two");
    }

    #[test]
    fn derives_server_job_duration_from_persisted_timestamps() {
        assert_eq!(
            rfc3339_duration_ms("2026-01-01T00:00:00Z", "2026-01-01T00:00:01.250Z"),
            Some(1_250.0)
        );
    }

    #[test]
    fn derives_rfc_websocket_accept_value() {
        assert_eq!(
            websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[tokio::test]
    async fn measures_a_real_http_upgrade_without_waiting_for_socket_close() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 8 * 1024];
            let read = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..read]).into_owned();
            let lowercase_request = request.to_ascii_lowercase();
            assert!(lowercase_request.contains("upgrade: websocket"));
            assert!(lowercase_request.contains("authorization: bearer websocket-jwt"));
            let key = request
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("sec-websocket-key")
                        .then_some(value.trim())
                })
                .unwrap();
            let accept = websocket_accept(key);
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Connection: Upgrade\r\n\
                 Upgrade: websocket\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\
                 Sec-WebSocket-Protocol: dbe.jwt\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let client =
            BenchClient::new(&format!("http://{address}"), None, "node-token", 1, false).unwrap();

        let sample = tokio::time::timeout(
            Duration::from_secs(1),
            client.websocket_handshake("websocket-jwt", 0),
        )
        .await
        .unwrap();

        assert!(sample.success, "{:?}", sample.error);
        server.abort();
    }

    #[tokio::test]
    async fn runs_a_duration_based_mixed_load() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().fallback(|| async { axum::Json(json!({"status": "running"})) }),
            )
            .await
            .unwrap();
        });
        let client =
            BenchClient::new(&format!("http://{address}"), None, "node-token", 4, false).unwrap();

        let run = client
            .benchmark_concurrent_for_duration(
                Duration::from_millis(50),
                4,
                vec![LoadTarget::instance_status("selected-db")],
                42,
                None,
            )
            .await;

        assert!(run.report.wall_duration_ms >= 40.0);
        assert!(run.report.attempted_requests >= 2);
        assert!(run.report.target_requests.contains_key("/api/heartbeat"));
        assert!(
            run.report
                .target_requests
                .contains_key("/api/instances/selected-db/status")
        );
        assert_eq!(
            run.report.attempted_requests,
            run.report.successful_requests
        );
        server.abort();
    }

    #[test]
    fn concurrent_aggregate_bounds_raw_samples_without_losing_totals() {
        let attempted = MAX_RETAINED_REQUEST_SAMPLES + 17;
        let mut accumulator = PhaseAccumulator::new(7);
        for index in 0..attempted {
            accumulator.record(RequestSample {
                phase: "http_concurrent_timed".to_string(),
                target: "/api/heartbeat".to_string(),
                index,
                duration_micros: 1_000,
                status_code: Some(200),
                success: true,
                error: None,
            });
        }

        let run = accumulator.finish(
            "http_concurrent_timed",
            Duration::from_secs(1),
            Duration::from_secs(1),
        );

        assert_eq!(run.report.attempted_requests, attempted);
        assert_eq!(run.report.successful_requests, attempted);
        assert_eq!(run.samples.len(), MAX_RETAINED_REQUEST_SAMPLES);
        assert_eq!(run.report.dropped_request_samples, 17);
        assert_eq!(run.report.all_latency_ms.unwrap().samples, attempted);
    }

    #[tokio::test]
    async fn fixed_window_pacing_bounds_a_timed_burst() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().fallback(|| async { axum::Json(json!({"status": "running"})) }),
            )
            .await
            .unwrap();
        });
        let client =
            BenchClient::new(&format!("http://{address}"), None, "node-token", 4, false).unwrap();

        let run = client
            .benchmark_concurrent_for_duration(
                Duration::from_millis(50),
                4,
                vec![LoadTarget::heartbeat()],
                42,
                Some(FixedWindowPacing {
                    window_started: Instant::now(),
                    requests_per_window: 8,
                }),
            )
            .await;

        assert_eq!(run.report.attempted_requests, 8);
        assert!(run.report.active_load_duration_ms < run.report.wall_duration_ms);
        assert!(
            run.report.active_successful_requests_per_second
                > run.report.successful_requests_per_second
        );
        server.abort();
    }
}
