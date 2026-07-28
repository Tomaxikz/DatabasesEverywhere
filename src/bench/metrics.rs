use std::{collections::BTreeMap, time::Duration};

use hdrhistogram::Histogram;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkOptionsReport {
    pub warmup_requests: usize,
    pub latency_samples: usize,
    pub concurrent_requests: Option<usize>,
    pub concurrent_duration_minutes: Option<u64>,
    pub concurrent_load_mode: String,
    pub timed_requests_per_minute: Option<usize>,
    pub concurrency: usize,
    pub websocket_connections: usize,
    pub max_instances: usize,
    pub retained_request_sample_limit: usize,
    pub timeout_seconds: u64,
    pub sample_interval_ms: u64,
    pub import_export_enabled: bool,
    pub keep_artifact: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetInstanceReport {
    pub instance_id: String,
    pub protocol: String,
    pub initial_status: String,
    pub final_status: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnvironmentReport {
    pub benchmark_client_version: String,
    pub operating_system: String,
    pub architecture: String,
    pub logical_cpu_count: usize,
    pub api_url: String,
    pub host_header: Option<String>,
    pub configured_api_rate_limit_per_minute: u32,
    pub api_rate_limit_scope: Option<String>,
    pub server_version: Option<String>,
    pub api_version: Option<String>,
    pub node_uuid: Option<String>,
    pub daemon_engine: Option<String>,
    pub target_instance: Option<TargetInstanceReport>,
    pub selected_instances: Vec<TargetInstanceReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestSample {
    pub phase: String,
    pub target: String,
    pub index: usize,
    pub duration_micros: u64,
    pub status_code: Option<u16>,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LatencySummary {
    pub samples: usize,
    pub min_ms: f64,
    pub mean_ms: f64,
    pub stddev_ms: f64,
    pub p50_ms: f64,
    pub p90_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
}

impl LatencySummary {
    pub fn from_micros(values: &[u64]) -> Option<Self> {
        if values.is_empty() {
            return None;
        }
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        let mean_micros =
            sorted.iter().map(|value| *value as f64).sum::<f64>() / sorted.len() as f64;
        let variance = sorted
            .iter()
            .map(|value| {
                let delta = *value as f64 - mean_micros;
                delta * delta
            })
            .sum::<f64>()
            / sorted.len() as f64;
        Some(Self {
            samples: sorted.len(),
            min_ms: micros_to_ms(*sorted.first().unwrap_or(&0)),
            mean_ms: mean_micros / 1_000.0,
            stddev_ms: variance.sqrt() / 1_000.0,
            p50_ms: percentile_micros(&sorted, 0.50) / 1_000.0,
            p90_ms: percentile_micros(&sorted, 0.90) / 1_000.0,
            p95_ms: percentile_micros(&sorted, 0.95) / 1_000.0,
            p99_ms: percentile_micros(&sorted, 0.99) / 1_000.0,
            max_ms: micros_to_ms(*sorted.last().unwrap_or(&0)),
        })
    }

    pub fn from_histogram(histogram: &Histogram<u64>) -> Option<Self> {
        if histogram.is_empty() {
            return None;
        }
        Some(Self {
            samples: usize::try_from(histogram.len()).unwrap_or(usize::MAX),
            min_ms: micros_to_ms(histogram.min()),
            mean_ms: histogram.mean() / 1_000.0,
            stddev_ms: histogram.stdev() / 1_000.0,
            p50_ms: micros_to_ms(histogram.value_at_quantile(0.50)),
            p90_ms: micros_to_ms(histogram.value_at_quantile(0.90)),
            p95_ms: micros_to_ms(histogram.value_at_quantile(0.95)),
            p99_ms: micros_to_ms(histogram.value_at_quantile(0.99)),
            max_ms: micros_to_ms(histogram.max()),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpPhaseReport {
    pub name: String,
    pub attempted_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub rate_limited_requests: usize,
    pub transport_errors: usize,
    pub wall_duration_ms: f64,
    pub active_load_duration_ms: f64,
    pub attempted_requests_per_second: f64,
    pub successful_requests_per_second: f64,
    pub active_attempted_requests_per_second: f64,
    pub active_successful_requests_per_second: f64,
    pub rate_limited_percent: f64,
    pub status_codes: BTreeMap<String, usize>,
    pub target_requests: BTreeMap<String, usize>,
    pub retained_request_samples: usize,
    pub dropped_request_samples: usize,
    pub latency_measurement: String,
    pub all_latency_ms: Option<LatencySummary>,
    pub successful_latency_ms: Option<LatencySummary>,
}

impl HttpPhaseReport {
    pub fn from_samples(
        name: impl Into<String>,
        wall_duration: Duration,
        samples: &[RequestSample],
    ) -> Self {
        let successful_requests = samples.iter().filter(|sample| sample.success).count();
        let rate_limited_requests = samples
            .iter()
            .filter(|sample| sample.status_code == Some(429))
            .count();
        let transport_errors = samples
            .iter()
            .filter(|sample| sample.status_code.is_none())
            .count();
        let mut status_codes = BTreeMap::new();
        let mut target_requests = BTreeMap::new();
        for status in samples.iter().filter_map(|sample| sample.status_code) {
            *status_codes.entry(status.to_string()).or_default() += 1;
        }
        for sample in samples {
            *target_requests.entry(sample.target.clone()).or_default() += 1;
        }
        let all_latencies = samples
            .iter()
            .map(|sample| sample.duration_micros)
            .collect::<Vec<_>>();
        let successful_latencies = samples
            .iter()
            .filter(|sample| sample.success)
            .map(|sample| sample.duration_micros)
            .collect::<Vec<_>>();
        let seconds = wall_duration.as_secs_f64();
        let rate = |count: usize| {
            if seconds > 0.0 {
                count as f64 / seconds
            } else {
                0.0
            }
        };
        Self {
            name: name.into(),
            attempted_requests: samples.len(),
            successful_requests,
            failed_requests: samples.len().saturating_sub(successful_requests),
            rate_limited_requests,
            transport_errors,
            wall_duration_ms: wall_duration.as_secs_f64() * 1_000.0,
            active_load_duration_ms: wall_duration.as_secs_f64() * 1_000.0,
            attempted_requests_per_second: rate(samples.len()),
            successful_requests_per_second: rate(successful_requests),
            active_attempted_requests_per_second: rate(samples.len()),
            active_successful_requests_per_second: rate(successful_requests),
            rate_limited_percent: percent(rate_limited_requests, samples.len()),
            status_codes,
            target_requests,
            retained_request_samples: samples.len(),
            dropped_request_samples: 0,
            latency_measurement: "exact".to_string(),
            all_latency_ms: LatencySummary::from_micros(&all_latencies),
            successful_latency_ms: LatencySummary::from_micros(&successful_latencies),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_histograms(
        name: impl Into<String>,
        wall_duration: Duration,
        active_load_duration: Duration,
        attempted_requests: usize,
        successful_requests: usize,
        rate_limited_requests: usize,
        transport_errors: usize,
        status_codes: BTreeMap<String, usize>,
        target_requests: BTreeMap<String, usize>,
        retained_request_samples: usize,
        all_latencies: &Histogram<u64>,
        successful_latencies: &Histogram<u64>,
    ) -> Self {
        let seconds = wall_duration.as_secs_f64();
        let wall_rate = |count: usize| {
            if seconds > 0.0 {
                count as f64 / seconds
            } else {
                0.0
            }
        };
        let active_seconds = active_load_duration.as_secs_f64();
        let active_rate = |count: usize| {
            if active_seconds > 0.0 {
                count as f64 / active_seconds
            } else {
                0.0
            }
        };
        Self {
            name: name.into(),
            attempted_requests,
            successful_requests,
            failed_requests: attempted_requests.saturating_sub(successful_requests),
            rate_limited_requests,
            transport_errors,
            wall_duration_ms: wall_duration.as_secs_f64() * 1_000.0,
            active_load_duration_ms: active_seconds * 1_000.0,
            attempted_requests_per_second: wall_rate(attempted_requests),
            successful_requests_per_second: wall_rate(successful_requests),
            active_attempted_requests_per_second: active_rate(attempted_requests),
            active_successful_requests_per_second: active_rate(successful_requests),
            rate_limited_percent: percent(rate_limited_requests, attempted_requests),
            status_codes,
            target_requests,
            retained_request_samples,
            dropped_request_samples: attempted_requests.saturating_sub(retained_request_samples),
            latency_measurement: "hdr_histogram_3_significant_digits".to_string(),
            all_latency_ms: LatencySummary::from_histogram(all_latencies),
            successful_latency_ms: LatencySummary::from_histogram(successful_latencies),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WebSocketBenchmarkReport {
    pub token_mint: HttpPhaseReport,
    pub handshake: HttpPhaseReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct JobBenchmarkReport {
    pub action: String,
    pub job_id: Option<String>,
    pub status: String,
    pub artifact_id: Option<String>,
    pub artifact_size_bytes: Option<u64>,
    pub queue_latency_ms: Option<f64>,
    pub running_observed_after_ms: Option<f64>,
    pub total_duration_ms: f64,
    pub server_duration_ms: Option<f64>,
    pub throughput_mib_per_second: Option<f64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceSample {
    pub elapsed_ms: u64,
    pub phase: String,
    pub daemon_cpu_percent: Option<f64>,
    pub daemon_rss_bytes: Option<u64>,
    pub benchmark_cpu_percent: Option<f64>,
    pub benchmark_rss_bytes: Option<u64>,
    pub instance_id: Option<String>,
    pub instance_protocol: Option<String>,
    pub instance_sample_failed: bool,
    pub instance_cpu_percent: Option<f64>,
    pub instance_memory_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct InstanceResourcePeak {
    pub protocol: String,
    pub attempted_samples: usize,
    pub successful_samples: usize,
    pub failed_samples: usize,
    pub peak_cpu_percent: Option<f64>,
    pub peak_memory_bytes: Option<u64>,
}

impl InstanceResourcePeak {
    fn include(&mut self, sample: &ResourceSample) {
        self.attempted_samples += 1;
        if sample.instance_sample_failed {
            self.failed_samples += 1;
            return;
        }
        self.successful_samples += 1;
        max_f64(&mut self.peak_cpu_percent, sample.instance_cpu_percent);
        max_u64(&mut self.peak_memory_bytes, sample.instance_memory_bytes);
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ResourcePeak {
    pub daemon_cpu_percent: Option<f64>,
    pub daemon_rss_bytes: Option<u64>,
    pub benchmark_cpu_percent: Option<f64>,
    pub benchmark_rss_bytes: Option<u64>,
    pub instance_cpu_percent: Option<f64>,
    pub instance_memory_bytes: Option<u64>,
}

impl ResourcePeak {
    fn include(&mut self, sample: &ResourceSample) {
        max_f64(&mut self.daemon_cpu_percent, sample.daemon_cpu_percent);
        max_u64(&mut self.daemon_rss_bytes, sample.daemon_rss_bytes);
        max_f64(
            &mut self.benchmark_cpu_percent,
            sample.benchmark_cpu_percent,
        );
        max_u64(&mut self.benchmark_rss_bytes, sample.benchmark_rss_bytes);
        max_f64(&mut self.instance_cpu_percent, sample.instance_cpu_percent);
        max_u64(
            &mut self.instance_memory_bytes,
            sample.instance_memory_bytes,
        );
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceSummary {
    pub sample_count: usize,
    pub daemon_pid: Option<u32>,
    pub benchmark_pid: u32,
    pub instance_sampling_enabled: bool,
    pub failed_instance_samples: usize,
    pub overall_peak: ResourcePeak,
    pub peak_by_phase: BTreeMap<String, ResourcePeak>,
    pub peak_by_instance: BTreeMap<String, InstanceResourcePeak>,
}

impl ResourceSummary {
    pub fn from_samples(
        samples: &[ResourceSample],
        daemon_pid: Option<u32>,
        benchmark_pid: u32,
        instance_sampling_enabled: bool,
        failed_instance_samples: usize,
    ) -> Self {
        let mut overall_peak = ResourcePeak::default();
        let mut peak_by_phase = BTreeMap::<String, ResourcePeak>::new();
        let mut peak_by_instance = BTreeMap::<String, InstanceResourcePeak>::new();
        for sample in samples {
            overall_peak.include(sample);
            peak_by_phase
                .entry(sample.phase.clone())
                .or_default()
                .include(sample);
            if let Some(instance_id) = &sample.instance_id {
                let peak = peak_by_instance.entry(instance_id.clone()).or_default();
                if peak.protocol.is_empty() {
                    peak.protocol = sample
                        .instance_protocol
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string());
                }
                peak.include(sample);
            }
        }
        Self {
            sample_count: samples.len(),
            daemon_pid,
            benchmark_pid,
            instance_sampling_enabled,
            failed_instance_samples,
            overall_peak,
            peak_by_phase,
            peak_by_instance,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchmarkReport {
    pub schema_version: u32,
    pub benchmark_id: String,
    pub started_at: String,
    pub finished_at: String,
    pub total_duration_ms: f64,
    pub status: String,
    pub options: BenchmarkOptionsReport,
    pub environment: EnvironmentReport,
    pub http_phases: Vec<HttpPhaseReport>,
    pub websocket: Option<WebSocketBenchmarkReport>,
    pub jobs: Vec<JobBenchmarkReport>,
    pub resources: Option<ResourceSummary>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

fn micros_to_ms(value: u64) -> f64 {
    value as f64 / 1_000.0
}

fn percent(part: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 / total as f64 * 100.0
    }
}

fn percentile_micros(sorted: &[u64], percentile: f64) -> f64 {
    if sorted.len() == 1 {
        return sorted[0] as f64;
    }
    let position = percentile.clamp(0.0, 1.0) * (sorted.len() - 1) as f64;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    if lower == upper {
        return sorted[lower] as f64;
    }
    let weight = position - lower as f64;
    sorted[lower] as f64 * (1.0 - weight) + sorted[upper] as f64 * weight
}

fn max_f64(target: &mut Option<f64>, candidate: Option<f64>) {
    if let Some(candidate) = candidate.filter(|value| value.is_finite()) {
        *target = Some(target.map_or(candidate, |current| current.max(candidate)));
    }
}

fn max_u64(target: &mut Option<u64>, candidate: Option<u64>) {
    if let Some(candidate) = candidate {
        *target = Some(target.map_or(candidate, |current| current.max(candidate)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_summary_interpolates_percentiles() {
        let summary = LatencySummary::from_micros(&[1_000, 2_000, 3_000, 4_000]).unwrap();

        assert_eq!(summary.samples, 4);
        assert_eq!(summary.min_ms, 1.0);
        assert_eq!(summary.p50_ms, 2.5);
        assert_eq!(summary.max_ms, 4.0);
    }

    #[test]
    fn phase_report_separates_successes_and_rate_limits() {
        let samples = vec![
            RequestSample {
                phase: "load".to_string(),
                target: "/api/heartbeat".to_string(),
                index: 0,
                duration_micros: 1_000,
                status_code: Some(200),
                success: true,
                error: None,
            },
            RequestSample {
                phase: "load".to_string(),
                target: "/api/heartbeat".to_string(),
                index: 1,
                duration_micros: 2_000,
                status_code: Some(429),
                success: false,
                error: Some("HTTP 429".to_string()),
            },
        ];

        let report = HttpPhaseReport::from_samples("load", Duration::from_millis(10), &samples);

        assert_eq!(report.successful_requests, 1);
        assert_eq!(report.failed_requests, 1);
        assert_eq!(report.rate_limited_requests, 1);
        assert_eq!(report.status_codes["429"], 1);
    }
}
