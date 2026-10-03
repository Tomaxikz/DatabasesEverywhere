use std::time::{Duration, Instant};

use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use super::{BYTES_PER_MIB, BenchClient, ImportExportRun, JOB_POLL_INTERVAL};
use crate::commands::bench::metrics::{JobBenchmarkReport, RequestSample};

impl BenchClient {
    pub(in crate::commands::bench) async fn benchmark_import_export(
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

        if !export_succeeded {
            jobs.push(skipped_import_report(
                "import was skipped because benchmark export failed",
            ));
        } else if let Some(artifact_id) = artifact_id.as_deref() {
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
            if !import_succeeded {
                warnings.push(format!(
                    "retained benchmark artifact {artifact_id} because its import failed"
                ));
            } else if !keep_artifact {
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
            }
        } else {
            jobs.push(skipped_import_report(
                "successful export did not return an artifact_id; import was skipped",
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
                throughput_mib_per_second: throughput_mib_per_second(
                    size,
                    server_duration_ms,
                    total,
                ),
                error: public_job_error(&value),
            };
        }
    }
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

fn skipped_import_report(reason: &str) -> JobBenchmarkReport {
    failed_job_report(
        "import",
        "skipped",
        Duration::ZERO,
        None,
        Some(reason.to_string()),
    )
}

fn throughput_mib_per_second(
    size_bytes: Option<u64>,
    server_duration_ms: Option<f64>,
    total: Duration,
) -> Option<f64> {
    size_bytes.and_then(|bytes| {
        let seconds = server_duration_ms
            .map(|duration_ms| duration_ms / 1_000.0)
            .filter(|seconds| *seconds > 0.0)
            .unwrap_or(total.as_secs_f64());
        (seconds > 0.0).then_some(bytes as f64 / BYTES_PER_MIB / seconds)
    })
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

pub(super) fn rfc3339_duration_ms(start: &str, end: &str) -> Option<f64> {
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};

    let start = OffsetDateTime::parse(start, &Rfc3339).ok()?;
    let end = OffsetDateTime::parse(end, &Rfc3339).ok()?;
    let duration = end - start;
    (!duration.is_negative()).then_some(duration.as_seconds_f64() * 1_000.0)
}
