use super::*;

pub(super) fn initial_report(
    args: &BenchArgs,
    config: &Config,
    benchmark_id: String,
    started_at: String,
    api_url: String,
    host_header: Option<String>,
) -> BenchmarkReport {
    let timed_requests_per_minute = args
        .bench_time_minutes
        .filter(|_| !args.bench_unthrottled)
        .map(|_| timed_request_budget(args, config));
    let options = BenchmarkOptionsReport {
        warmup_requests: args.bench_warmup_requests,
        latency_samples: args.bench_latency_samples,
        concurrent_requests: args
            .bench_time_minutes
            .is_none()
            .then_some(args.bench_requests),
        concurrent_duration_minutes: args.bench_time_minutes,
        concurrent_load_mode: concurrent_load_mode(args).to_string(),
        timed_requests_per_minute,
        concurrency: args.bench_concurrency,
        websocket_connections: args.bench_websockets,
        max_instances: args.bench_max_instances,
        retained_request_sample_limit: MAX_RETAINED_REQUEST_SAMPLES,
        timeout_seconds: args.bench_timeout_seconds,
        sample_interval_ms: args.bench_sample_interval_ms,
        import_export_enabled: args.bench_import_export,
        recommend_manual_active_jobs: args.bench_recommend_manual_active_jobs,
        keep_artifact: args.bench_keep_artifact,
    };
    BenchmarkReport {
        schema_version: REPORT_SCHEMA_VERSION,
        benchmark_id,
        started_at,
        finished_at: String::new(),
        total_duration_ms: 0.0,
        status: "running".to_string(),
        options,
        environment: EnvironmentReport {
            benchmark_client_version: env!("CARGO_PKG_VERSION").to_string(),
            operating_system: std::env::consts::OS.to_string(),
            architecture: std::env::consts::ARCH.to_string(),
            logical_cpu_count: std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1),
            api_url,
            host_header,
            configured_api_rate_limit_per_minute: config.security.api_rate_limit_per_minute,
            api_rate_limit_scope: None,
            server_version: None,
            api_version: None,
            node_uuid: None,
            daemon_engine: None,
            target_instance: None,
            selected_instances: Vec::new(),
        },
        http_phases: Vec::new(),
        websocket: None,
        jobs: Vec::new(),
        manual_active_jobs_recommendation: None,
        resources: None,
        warnings: Vec::new(),
        errors: Vec::new(),
    }
}

pub(super) fn concurrent_load_mode(args: &BenchArgs) -> &'static str {
    match (args.bench_time_minutes, args.bench_unthrottled) {
        (Some(_), true) => "timed_unthrottled",
        (Some(_), false) => "timed_rate_limit_aware_bursts",
        (None, _) => "fixed_request_burst",
    }
}

pub(super) fn final_report_status(report: &BenchmarkReport) -> &'static str {
    if !report.errors.is_empty() {
        "failed"
    } else if !report.warnings.is_empty() {
        "completed_with_warnings"
    } else {
        "completed"
    }
}

pub(super) fn record_recommendation(
    report: &mut BenchmarkReport,
    recommendation: ManualActiveJobsRecommendationReport,
) {
    if recommendation.status != "available" {
        report.warnings.push(format!(
            "manual active-job recommendation unavailable: {}",
            recommendation
                .unavailable_reason
                .as_deref()
                .unwrap_or("no diagnostic")
        ));
    }
    report.manual_active_jobs_recommendation = Some(recommendation);
}

pub(super) fn record_unsuccessful_jobs(jobs: &[JobBenchmarkReport], errors: &mut Vec<String>) {
    for job in jobs.iter().filter(|job| job.status != "succeeded") {
        errors.push(format!(
            "{} benchmark did not succeed (status={}): {}",
            job.action,
            job.status,
            job.error.as_deref().unwrap_or("no diagnostic")
        ));
    }
}

pub(super) async fn validate_final_instance_statuses(
    client: &BenchClient,
    args: &BenchArgs,
    report: &mut BenchmarkReport,
) {
    let selected_ids = report
        .environment
        .selected_instances
        .iter()
        .map(|instance| instance.instance_id.clone())
        .collect::<Vec<_>>();
    for instance_id in selected_ids {
        let status_response = client
            .required_json(
                &format!("/api/instances/{instance_id}/status"),
                "final instance validation",
            )
            .await;
        match status_response {
            Ok(value) => {
                let final_status = value["status"].as_str().map(str::to_string);
                record_final_status(args, report, &instance_id, final_status);
            }
            Err(error) => report.warnings.push(format!(
                "final status check for instance {instance_id} failed: {error}"
            )),
        }
    }
    if let Some(explicit) = &mut report.environment.target_instance
        && let Some(selected) = report
            .environment
            .selected_instances
            .iter()
            .find(|selected| selected.instance_id == explicit.instance_id)
    {
        explicit.final_status = selected.final_status.clone();
    }
}

pub(super) fn record_final_status(
    args: &BenchArgs,
    report: &mut BenchmarkReport,
    instance_id: &str,
    final_status: Option<String>,
) {
    let is_running = final_status.as_deref() == Some("running");
    let status_label = final_status.as_deref().unwrap_or("unknown");
    if args.bench_import_export && !is_running {
        report.errors.push(format!(
            "target instance did not return to running after benchmark (status={status_label})"
        ));
    } else if !is_running && args.bench_max_instances > 0 {
        report.warnings.push(format!(
            "automatically selected instance {instance_id} ended in status {status_label}"
        ));
    }
    if let Some(target) = report
        .environment
        .selected_instances
        .iter_mut()
        .find(|target| target.instance_id == instance_id)
    {
        target.final_status = final_status;
    }
}

pub(super) fn populate_server_env(environment: &mut EnvironmentReport, system: &serde_json::Value) {
    environment.server_version = system["version"].as_str().map(str::to_string);
    environment.api_version = system["api_version"].as_str().map(str::to_string);
    environment.node_uuid = system["uuid"].as_str().map(str::to_string);
    environment.daemon_engine = system["daemon_engine"].as_str().map(str::to_string);
    if let Some(limit) = system["api_rate_limit_per_minute"].as_u64()
        && let Ok(limit) = u32::try_from(limit)
    {
        environment.configured_api_rate_limit_per_minute = limit;
    }
    environment.api_rate_limit_scope = system["api_rate_limit_scope"].as_str().map(str::to_string);
}

pub(super) fn warn_rate_limit(args: &BenchArgs, config: &Config, warnings: &mut Vec<String>) {
    if let Some(minutes) = args.bench_time_minutes {
        if args.bench_unthrottled {
            warnings.push(format!(
                "the unthrottled {minutes}-minute phase can exceed the production API limit ({} requests/minute per credential/IP), generate many HTTP 429 responses, and create heavy audit logging",
                config.security.api_rate_limit_per_minute
            ));
        }
        return;
    }
    let planned_node_token_requests = args
        .bench_warmup_requests
        .saturating_add(args.bench_latency_samples)
        .saturating_add(args.bench_requests)
        .saturating_add(args.bench_websockets)
        .saturating_add(3)
        .saturating_add(usize::from(args.bench_recommend_manual_active_jobs) * 2);
    let limit = config.security.api_rate_limit_per_minute as usize;
    if planned_node_token_requests > limit {
        warnings.push(format!(
            "planned authenticated requests ({planned_node_token_requests}) exceed the configured per-minute API limit ({limit}); HTTP 429 responses are expected and reported separately"
        ));
    }
}

pub(super) fn evaluate_phase(
    phase: &HttpPhaseReport,
    warnings: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    if phase.attempted_requests == 0 {
        warnings.push(format!("{} made no attempts", phase.name));
        return;
    }
    if phase.successful_requests == 0 {
        errors.push(format!("{} produced no successful requests", phase.name));
    }
    let non_rate_limited_failures = phase
        .failed_requests
        .saturating_sub(phase.rate_limited_requests);
    if non_rate_limited_failures > 0 {
        warnings.push(format!(
            "{} had {} non-rate-limit failures out of {} attempts",
            phase.name, non_rate_limited_failures, phase.attempted_requests
        ));
    }
    if phase.rate_limited_requests > 0 {
        warnings.push(format!(
            "{} received {} HTTP 429 responses ({:.2}%); accepted req/s reflects the configured production throttle",
            phase.name, phase.rate_limited_requests, phase.rate_limited_percent
        ));
    }
}
