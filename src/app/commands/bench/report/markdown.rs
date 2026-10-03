use std::fmt::Write as _;

use super::format::{format_optional_f64, format_percent, human_bytes};
use crate::commands::bench::metrics::{BenchmarkReport, HttpPhaseReport, ResourcePeak};

pub(super) fn markdown_report(report: &BenchmarkReport) -> String {
    let mut output = String::new();
    markdown_summary(&mut output, report);
    markdown_instances_section(&mut output, report);
    markdown_http_section(&mut output, report);
    markdown_jobs_section(&mut output, report);
    markdown_recommendation_section(&mut output, report);
    markdown_resources_section(&mut output, report);
    markdown_diagnostics_section(&mut output, report);
    output
}

fn markdown_summary(output: &mut String, report: &BenchmarkReport) {
    let _ = writeln!(output, "# DatabasesEverywhere benchmark\n");
    let _ = writeln!(output, "- Status: `{}`", report.status);
    let _ = writeln!(output, "- Benchmark ID: `{}`", report.benchmark_id);
    let _ = writeln!(output, "- Started: `{}`", report.started_at);
    let _ = writeln!(output, "- Finished: `{}`", report.finished_at);
    let _ = writeln!(
        output,
        "- Total wall time: `{:.3} s`",
        report.total_duration_ms / 1_000.0
    );
    let _ = writeln!(
        output,
        "- Client/server: `{}` / `{}`",
        report.environment.benchmark_client_version,
        report
            .environment
            .server_version
            .as_deref()
            .unwrap_or("unknown")
    );
    let _ = writeln!(
        output,
        "- API contract: `{}`",
        report
            .environment
            .api_version
            .as_deref()
            .unwrap_or("unknown")
    );
    let _ = writeln!(output, "- Target: `{}`", report.environment.api_url);
    let _ = writeln!(
        output,
        "- Concurrent load mode: `{}`",
        report.options.concurrent_load_mode
    );
    let _ = writeln!(
        output,
        "- API rate limit: `{}/minute` (`{}`)",
        report.environment.configured_api_rate_limit_per_minute,
        report
            .environment
            .api_rate_limit_scope
            .as_deref()
            .unwrap_or("scope not reported")
    );
    if let Some(requests) = report.options.timed_requests_per_minute {
        let _ = writeln!(
            output,
            "- Timed load budget: `{requests}` requests per 60-second window (configured limit `{}`)",
            report.environment.configured_api_rate_limit_per_minute
        );
    }
    if let Some(host) = &report.environment.host_header {
        let _ = writeln!(output, "- Host header: `{host}`");
    }
    if let Some(target) = &report.environment.target_instance {
        let _ = writeln!(
            output,
            "- Explicit instance: `{}` (`{}`, initial `{}`, final `{}`)",
            target.instance_id,
            target.protocol,
            target.initial_status,
            target.final_status.as_deref().unwrap_or("unknown")
        );
    }
}

fn markdown_instances_section(output: &mut String, report: &BenchmarkReport) {
    if report.environment.selected_instances.is_empty() {
        return;
    }
    let _ = writeln!(output, "\n## Selected running instances\n");
    let _ = writeln!(
        output,
        "| Instance | Protocol | Initial status | Final status |"
    );
    let _ = writeln!(output, "| --- | --- | --- | --- |");
    for target in &report.environment.selected_instances {
        let _ = writeln!(
            output,
            "| `{}` | {} | {} | {} |",
            target.instance_id,
            target.protocol,
            target.initial_status,
            target.final_status.as_deref().unwrap_or("unknown")
        );
    }
}

fn markdown_http_section(output: &mut String, report: &BenchmarkReport) {
    let _ = writeln!(output, "\n## HTTP results\n");
    let _ = writeln!(
        output,
        "| Phase | Attempts | Success | Fail | 429 | 429 % | Offered req/s | Accepted req/s | Active accepted req/s | p50 ms | p95 ms | p99 ms | Max ms | Raw retained |"
    );
    let _ = writeln!(
        output,
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
    );
    for phase in report
        .http_phases
        .iter()
        .filter(|phase| !phase.name.starts_with("http_concurrent"))
    {
        write_http_row(output, phase);
    }
    if let Some(websocket) = &report.websocket {
        write_http_row(output, &websocket.token_mint);
        write_http_row(output, &websocket.handshake);
    }
    for phase in report
        .http_phases
        .iter()
        .filter(|phase| phase.name.starts_with("http_concurrent"))
    {
        write_http_row(output, phase);
    }
    for phase in report.http_phases.iter().chain(
        report
            .websocket
            .iter()
            .flat_map(|websocket| [&websocket.token_mint, &websocket.handshake]),
    ) {
        if phase.target_requests.len() > 1 {
            let routes = phase
                .target_requests
                .iter()
                .map(|(target, count)| format!("`{target}`: {count}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(output, "\n- `{}` route mix: {routes}", phase.name);
        }
        if phase.dropped_request_samples > 0 {
            let _ = writeln!(
                output,
                "- `{}` used `{}` for all latency/rate aggregates and retained a uniform reservoir of {} raw rows ({} omitted from CSV).",
                phase.name,
                phase.latency_measurement,
                phase.retained_request_samples,
                phase.dropped_request_samples
            );
        }
    }
}

fn markdown_jobs_section(output: &mut String, report: &BenchmarkReport) {
    if report.jobs.is_empty() {
        return;
    }
    let _ = writeln!(output, "\n## Import/export results\n");
    let _ = writeln!(
        output,
        "| Action | Status | Size | Enqueue HTTP ms | Running seen ms | Server elapsed ms | Wall ms | MiB/s | Job ID |"
    );
    let _ = writeln!(
        output,
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |"
    );
    for job in &report.jobs {
        let _ = writeln!(
            output,
            "| {} | {} | {} | {} | {} | {} | {:.2} | {} | `{}` |",
            job.action,
            job.status,
            job.artifact_size_bytes
                .map(human_bytes)
                .unwrap_or_else(|| "n/a".to_string()),
            format_optional_f64(job.queue_latency_ms),
            format_optional_f64(job.running_observed_after_ms),
            format_optional_f64(job.server_duration_ms),
            job.total_duration_ms,
            format_optional_f64(job.throughput_mib_per_second),
            job.job_id.as_deref().unwrap_or("n/a")
        );
        if let Some(error) = &job.error {
            let _ = writeln!(output, "\n`{}` error: {}\n", job.action, error);
        }
    }
}

fn markdown_recommendation_section(output: &mut String, report: &BenchmarkReport) {
    let Some(recommendation) = &report.manual_active_jobs_recommendation else {
        return;
    };
    let _ = writeln!(output, "\n## Manual active-job recommendation\n");
    let _ = writeln!(output, "- Method: `{}`", recommendation.method);
    let _ = writeln!(output, "- Status: `{}`", recommendation.status);
    let _ = writeln!(
        output,
        "- Daemon identity verified: `{}` (configured `{}`, server `{}`)",
        recommendation.identity_verified,
        recommendation.configured_node_uuid,
        recommendation
            .server_node_uuid
            .as_deref()
            .unwrap_or("unknown")
    );
    if let Some(reason) = &recommendation.unavailable_reason {
        let _ = writeln!(output, "- Unavailable reason: {reason}");
    }
    if let Some(capacity) = &recommendation.scheduler_capacity {
        let _ = writeln!(
            output,
            "- Scheduler capacity used by the model: mode `{}`, active ceiling `{}`, memory `{}` MiB, I/O `{}` MiB, CPU units `{}`.",
            capacity.mode,
            capacity.max_active_jobs,
            capacity.memory_budget_mib,
            capacity.io_budget_mib,
            capacity.cpu_units
        );
    }
    if let (Some(global), Some(per_instance)) = (
        recommendation.max_queued_jobs,
        recommendation.max_queued_jobs_per_instance,
    ) {
        let _ = writeln!(
            output,
            "- Queue admission limits: `{global}` node-wide, `{per_instance}` per instance."
        );
    }
    if recommendation.configured_max_upload_worst_case.is_some()
        || recommendation.representative_exported_dump.is_some()
    {
        let _ = writeln!(
            output,
            "\n| Workload | Protocol | Mode | Compressed | Input | Estimated RAM MiB | Estimated I/O MiB | CPU units | RAM ceiling | I/O ceiling | CPU ceiling | Active ceiling | Recommended `manual_max_active_jobs` |"
        );
        let _ = writeln!(
            output,
            "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
        );
        if let Some(workload) = &recommendation.configured_max_upload_worst_case {
            write_recommendation_row(output, workload);
        }
        if let Some(workload) = &recommendation.representative_exported_dump {
            write_recommendation_row(output, workload);
        }
    }
    if let Some(reason) = &recommendation.representative_unavailable_reason {
        let _ = writeln!(output, "\n- Representative estimate unavailable: {reason}");
    }
    if !recommendation.caveats.is_empty() {
        let _ = writeln!(output, "\n### Recommendation caveats\n");
        for caveat in &recommendation.caveats {
            let _ = writeln!(output, "- {caveat}");
        }
    }
    let _ = writeln!(
        output,
        "\nThe benchmark did not modify daemon configuration."
    );
}

fn markdown_resources_section(output: &mut String, report: &BenchmarkReport) {
    let Some(resources) = &report.resources else {
        return;
    };
    let _ = writeln!(output, "\n## Peak resources\n");
    let _ = writeln!(
        output,
        "CPU percentages use 100% per fully occupied CPU core. {} samples were collected.",
        resources.sample_count
    );
    let _ = writeln!(
        output,
        "\n| Phase | Daemon CPU | Daemon RAM | Bench CPU | Bench RAM | Instance CPU | Instance RAM |"
    );
    let _ = writeln!(output, "| --- | ---: | ---: | ---: | ---: | ---: | ---: |");
    write_resource_row(output, "overall", &resources.overall_peak);
    for (phase, peak) in &resources.peak_by_phase {
        write_resource_row(output, phase, peak);
    }
    if resources.failed_instance_samples > 0 {
        let _ = writeln!(
            output,
            "\nInstance sampling failed {} times, including expected gaps while a physical import stopped the container.",
            resources.failed_instance_samples
        );
    }
    if !resources.peak_by_instance.is_empty() {
        let _ = writeln!(output, "\n### Per-instance container peaks\n");
        let _ = writeln!(
            output,
            "| Instance | Protocol | Samples (ok/attempted) | Peak CPU | Peak RAM |"
        );
        let _ = writeln!(output, "| --- | --- | ---: | ---: | ---: |");
        for (instance_id, peak) in &resources.peak_by_instance {
            let _ = writeln!(
                output,
                "| `{}` | {} | {}/{} | {} | {} |",
                instance_id,
                peak.protocol,
                peak.successful_samples,
                peak.attempted_samples,
                format_percent(peak.peak_cpu_percent),
                peak.peak_memory_bytes
                    .map(human_bytes)
                    .unwrap_or_else(|| "n/a".to_string())
            );
        }
    }
}

fn markdown_diagnostics_section(output: &mut String, report: &BenchmarkReport) {
    if !report.warnings.is_empty() {
        let _ = writeln!(output, "\n## Warnings\n");
        for warning in &report.warnings {
            let _ = writeln!(output, "- {warning}");
        }
    }
    if !report.errors.is_empty() {
        let _ = writeln!(output, "\n## Errors\n");
        for error in &report.errors {
            let _ = writeln!(output, "- {error}");
        }
    }
}

pub(super) fn write_recommendation_row(
    output: &mut String,
    workload: &crate::commands::bench::metrics::ManualActiveJobsWorkloadReport,
) {
    let _ = writeln!(
        output,
        "| `{}` | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | **{}** |",
        workload.workload,
        workload.protocol,
        workload.mode,
        workload.compressed,
        human_bytes(workload.estimate.input_size_bytes),
        workload.estimate.memory_mib,
        workload.estimate.io_mib,
        workload.estimate.cpu_units,
        workload.memory_ceiling_jobs,
        workload.io_ceiling_jobs,
        workload.cpu_ceiling_jobs,
        workload.configured_active_ceiling_jobs,
        workload.recommended_manual_max_active_jobs
    );
}

fn write_http_row(output: &mut String, phase: &HttpPhaseReport) {
    let latency = phase.successful_latency_ms.as_ref();
    let _ = writeln!(
        output,
        "| {} | {} | {} | {} | {} | {:.2}% | {:.2} | {:.2} | {:.2} | {} | {} | {} | {} | {} |",
        phase.name,
        phase.attempted_requests,
        phase.successful_requests,
        phase.failed_requests,
        phase.rate_limited_requests,
        phase.rate_limited_percent,
        phase.attempted_requests_per_second,
        phase.successful_requests_per_second,
        phase.active_successful_requests_per_second,
        latency
            .map(|value| format!("{:.3}", value.p50_ms))
            .unwrap_or_else(|| "n/a".to_string()),
        latency
            .map(|value| format!("{:.3}", value.p95_ms))
            .unwrap_or_else(|| "n/a".to_string()),
        latency
            .map(|value| format!("{:.3}", value.p99_ms))
            .unwrap_or_else(|| "n/a".to_string()),
        latency
            .map(|value| format!("{:.3}", value.max_ms))
            .unwrap_or_else(|| "n/a".to_string()),
        phase.retained_request_samples,
    );
}

fn write_resource_row(output: &mut String, phase: &str, peak: &ResourcePeak) {
    let _ = writeln!(
        output,
        "| {} | {} | {} | {} | {} | {} | {} |",
        phase,
        format_percent(peak.daemon_cpu_percent),
        peak.daemon_rss_bytes
            .map(human_bytes)
            .unwrap_or_else(|| "n/a".to_string()),
        format_percent(peak.benchmark_cpu_percent),
        peak.benchmark_rss_bytes
            .map(human_bytes)
            .unwrap_or_else(|| "n/a".to_string()),
        format_percent(peak.instance_cpu_percent),
        peak.instance_memory_bytes
            .map(human_bytes)
            .unwrap_or_else(|| "n/a".to_string()),
    );
}
