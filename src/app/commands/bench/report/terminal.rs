use std::{fmt::Write as _, io::IsTerminal as _};

use super::{
    ReportPaths,
    format::{format_percent, human_bytes},
};
use crate::commands::bench::metrics::{BenchmarkReport, HttpPhaseReport};

const TERMINAL_RULE_WIDTH: usize = 120;

pub(in crate::commands::bench) fn print_terminal_report(
    report: &BenchmarkReport,
    paths: &ReportPaths,
) {
    let color = terminal_colors_enabled();
    println!("{}", terminal_report(report, paths, color));
}

fn terminal_colors_enabled() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    let forced = std::env::var("CLICOLOR_FORCE")
        .ok()
        .is_some_and(|value| !value.is_empty() && value != "0");
    forced || std::io::stdout().is_terminal()
}

fn terminal_report(report: &BenchmarkReport, paths: &ReportPaths, color: bool) -> String {
    let colors = TerminalColors { enabled: color };
    let mut output = String::new();
    let thin_rule = "-".repeat(TERMINAL_RULE_WIDTH);
    terminal_summary(&mut output, &colors, report);
    terminal_http_section(&mut output, &colors, report, &thin_rule);
    terminal_instances_section(&mut output, &colors, report, &thin_rule);
    terminal_resources_section(&mut output, &colors, report, &thin_rule);
    terminal_jobs_section(&mut output, &colors, report, &thin_rule);
    terminal_recommendation_section(&mut output, &colors, report, &thin_rule);
    terminal_diagnostics_section(&mut output, &colors, report, &thin_rule);
    terminal_files_section(&mut output, &colors, paths, &thin_rule);
    output
}

fn terminal_summary(output: &mut String, colors: &TerminalColors, report: &BenchmarkReport) {
    let wide_rule = "=".repeat(TERMINAL_RULE_WIDTH);
    let status_color = match report.status.as_str() {
        "completed" => TerminalColor::Green,
        "completed_with_warnings" => TerminalColor::Yellow,
        _ => TerminalColor::Red,
    };
    let _ = writeln!(output);
    let _ = writeln!(output, "+{wide_rule}");
    let _ = writeln!(
        output,
        "| {}  {}",
        colors.paint(TerminalColor::BoldCyan, "DBEV BENCHMARK RESULTS"),
        colors.paint(status_color, &report.status.to_ascii_uppercase())
    );
    let _ = writeln!(output, "+{wide_rule}");
    let _ = writeln!(output, "  {:<15} {}", "Benchmark ID", report.benchmark_id);
    let _ = writeln!(
        output,
        "  {:<15} {}  (wall {})",
        "Target",
        report.environment.api_url,
        format_elapsed(report.total_duration_ms)
    );
    let _ = writeln!(
        output,
        "  {:<15} client {} / server {} / API {}",
        "Versions",
        report.environment.benchmark_client_version,
        report
            .environment
            .server_version
            .as_deref()
            .unwrap_or("unknown"),
        report
            .environment
            .api_version
            .as_deref()
            .unwrap_or("unknown")
    );
    let _ = writeln!(output, "  {:<15} {}", "Load", load_shape(report));
    let _ = writeln!(
        output,
        "  {:<15} {}/min ({})",
        "Rate limit",
        report.environment.configured_api_rate_limit_per_minute,
        report
            .environment
            .api_rate_limit_scope
            .as_deref()
            .unwrap_or("scope not reported")
    );
    let _ = writeln!(
        output,
        "  {:<15} {} selected",
        "Instances",
        report.environment.selected_instances.len()
    );
}

fn load_shape(report: &BenchmarkReport) -> String {
    let Some(minutes) = report.options.concurrent_duration_minutes else {
        return format!(
            "{} requests, concurrency {}",
            report.options.concurrent_requests.unwrap_or_default(),
            report.options.concurrency
        );
    };
    match report.options.timed_requests_per_minute {
        Some(requests) => format!(
            "{minutes} minute rate-aware bursts, {requests}/{} requests per 60s, concurrency {}",
            report.environment.configured_api_rate_limit_per_minute, report.options.concurrency
        ),
        None => format!(
            "{minutes} minute unthrottled load, concurrency {}",
            report.options.concurrency
        ),
    }
}

fn terminal_http_section(
    output: &mut String,
    colors: &TerminalColors,
    report: &BenchmarkReport,
    thin_rule: &str,
) {
    terminal_section(output, colors, "HTTP & WEBSOCKET", thin_rule);
    let _ = writeln!(
        output,
        "  {:<24} {:>15} {:>11} {:>10} {:>12} {:>8} {:>10} {:>10} {:>10}",
        "PHASE", "SUCCESS", "OFFERED/s", "OK/s", "ACTIVE OK/s", "429 %", "P50", "P95", "P99"
    );
    let _ = writeln!(output, "  {}", ".".repeat(118));
    let is_concurrent = |phase: &&HttpPhaseReport| phase.name.starts_with("http_concurrent");
    for phase in report
        .http_phases
        .iter()
        .filter(|phase| !is_concurrent(phase))
    {
        terminal_http_row(output, colors, phase);
    }
    if let Some(websocket) = &report.websocket {
        terminal_http_row(output, colors, &websocket.token_mint);
        terminal_http_row(output, colors, &websocket.handshake);
    }
    for phase in report.http_phases.iter().filter(is_concurrent) {
        terminal_http_row(output, colors, phase);
    }
}

fn terminal_instances_section(
    output: &mut String,
    colors: &TerminalColors,
    report: &BenchmarkReport,
    thin_rule: &str,
) {
    if report.environment.selected_instances.is_empty() {
        return;
    }
    terminal_section(output, colors, "SELECTED INSTANCES", thin_rule);
    let _ = writeln!(
        output,
        "  {:<36} {:<12} {:<12} {:<12}",
        "INSTANCE", "PROTOCOL", "INITIAL", "FINAL"
    );
    let _ = writeln!(output, "  {}", ".".repeat(78));
    for instance in &report.environment.selected_instances {
        let final_status = instance.final_status.as_deref().unwrap_or("unknown");
        let final_color = if final_status == "running" {
            TerminalColor::Green
        } else {
            TerminalColor::Yellow
        };
        let _ = writeln!(
            output,
            "  {:<36} {:<12} {:<12} {}",
            truncate(&instance.instance_id, 36),
            instance.protocol,
            instance.initial_status,
            colors.paint(final_color, &format!("{final_status:<12}"))
        );
    }
}

fn terminal_resources_section(
    output: &mut String,
    colors: &TerminalColors,
    report: &BenchmarkReport,
    thin_rule: &str,
) {
    let Some(resources) = &report.resources else {
        return;
    };
    terminal_section(output, colors, "PEAK CPU & RAM", thin_rule);
    let _ = writeln!(output, "  {:<24} {:>14} {:>16}", "SCOPE", "CPU", "RAM");
    let _ = writeln!(output, "  {}", ".".repeat(58));
    terminal_resource_row(
        output,
        "daemon",
        resources.overall_peak.daemon_cpu_percent,
        resources.overall_peak.daemon_rss_bytes,
    );
    terminal_resource_row(
        output,
        "benchmark client",
        resources.overall_peak.benchmark_cpu_percent,
        resources.overall_peak.benchmark_rss_bytes,
    );
    if resources.peak_by_instance.is_empty() {
        terminal_resource_row(
            output,
            "database containers",
            resources.overall_peak.instance_cpu_percent,
            resources.overall_peak.instance_memory_bytes,
        );
    } else {
        for (instance_id, peak) in &resources.peak_by_instance {
            terminal_resource_row(
                output,
                &format!("{} ({})", truncate(instance_id, 18), peak.protocol),
                peak.peak_cpu_percent,
                peak.peak_memory_bytes,
            );
        }
    }
    let sampling_note = if resources.peak_by_instance.len() > 1 {
        format!(
            ", container telemetry round-robin across {} instances",
            resources.peak_by_instance.len()
        )
    } else {
        String::new()
    };
    let _ = writeln!(
        output,
        "\n  samples: {} process ticks, {} failed container reads{}",
        grouped_usize(resources.sample_count),
        grouped_usize(resources.failed_instance_samples),
        sampling_note
    );
}

fn terminal_jobs_section(
    output: &mut String,
    colors: &TerminalColors,
    report: &BenchmarkReport,
    thin_rule: &str,
) {
    if report.jobs.is_empty() {
        return;
    }
    terminal_section(output, colors, "IMPORT & EXPORT", thin_rule);
    let _ = writeln!(
        output,
        "  {:<12} {:<14} {:>12} {:>14} {:>14}",
        "ACTION", "STATUS", "DURATION", "SIZE", "THROUGHPUT"
    );
    let _ = writeln!(output, "  {}", ".".repeat(72));
    for job in &report.jobs {
        let job_color = if job.status == "succeeded" {
            TerminalColor::Green
        } else {
            TerminalColor::Red
        };
        let _ = writeln!(
            output,
            "  {:<12} {} {:>12} {:>14} {:>14}",
            job.action,
            colors.paint(job_color, &format!("{:<14}", job.status)),
            format_elapsed(job.total_duration_ms),
            job.artifact_size_bytes
                .map(human_bytes)
                .unwrap_or_else(|| "n/a".to_string()),
            job.throughput_mib_per_second
                .map(|value| format!("{value:.2} MiB/s"))
                .unwrap_or_else(|| "n/a".to_string())
        );
    }
}

fn terminal_recommendation_section(
    output: &mut String,
    colors: &TerminalColors,
    report: &BenchmarkReport,
    thin_rule: &str,
) {
    let Some(recommendation) = &report.manual_active_jobs_recommendation else {
        return;
    };
    terminal_section(
        output,
        colors,
        "MANUAL ACTIVE-JOB RECOMMENDATION",
        thin_rule,
    );
    let _ = writeln!(output, "  {:<24} {}", "Method", recommendation.method);
    let _ = writeln!(output, "  {:<24} {}", "Status", recommendation.status);
    if let Some(reason) = &recommendation.unavailable_reason {
        let _ = writeln!(output, "  {:<24} {reason}", "Unavailable");
    }
    if let Some(capacity) = &recommendation.scheduler_capacity {
        let _ = writeln!(
            output,
            "  {:<24} {} (active ceiling {}, memory {} MiB, I/O {} MiB, CPU units {})",
            "Scheduler model",
            capacity.mode,
            capacity.max_active_jobs,
            capacity.memory_budget_mib,
            capacity.io_budget_mib,
            capacity.cpu_units
        );
    }
    if recommendation.configured_max_upload_worst_case.is_some()
        || recommendation.representative_exported_dump.is_some()
    {
        let _ = writeln!(
            output,
            "\n  {:<34} {:>12} {:>9} {:>9} {:>9} {:>11}",
            "WORKLOAD", "INPUT", "MEM MAX", "I/O MAX", "CPU MAX", "RECOMMEND"
        );
        let _ = writeln!(output, "  {}", ".".repeat(92));
        if let Some(workload) = &recommendation.configured_max_upload_worst_case {
            final_recommendation_row(output, workload);
        }
        if let Some(workload) = &recommendation.representative_exported_dump {
            final_recommendation_row(output, workload);
        }
    }
    if let Some(reason) = &recommendation.representative_unavailable_reason {
        let _ = writeln!(output, "\n  Representative estimate unavailable: {reason}");
    }
    let _ = writeln!(
        output,
        "\n  Model only: no concurrent saturation test was performed and configuration was not changed."
    );
}

fn terminal_diagnostics_section(
    output: &mut String,
    colors: &TerminalColors,
    report: &BenchmarkReport,
    thin_rule: &str,
) {
    if report.warnings.is_empty() && report.errors.is_empty() {
        return;
    }
    terminal_section(output, colors, "DIAGNOSTICS", thin_rule);
    for error in &report.errors {
        let _ = writeln!(
            output,
            "  {} {error}",
            colors.paint(TerminalColor::Red, "x")
        );
    }
    for warning in &report.warnings {
        let _ = writeln!(
            output,
            "  {} {warning}",
            colors.paint(TerminalColor::Yellow, "!")
        );
    }
}

fn terminal_files_section(
    output: &mut String,
    colors: &TerminalColors,
    paths: &ReportPaths,
    thin_rule: &str,
) {
    terminal_section(output, colors, "REPORT FILES", thin_rule);
    let _ = writeln!(output, "  {:<18} {}", "JSON", paths.json.display());
    let _ = writeln!(output, "  {:<18} {}", "Markdown", paths.markdown.display());
    let _ = writeln!(
        output,
        "  {:<18} {}",
        "Request samples",
        paths.request_samples.display()
    );
    let _ = writeln!(
        output,
        "  {:<18} {}",
        "Resource samples",
        paths.resource_samples.display()
    );
    let _ = writeln!(
        output,
        "  {:<18} {}",
        "Diagnostics",
        paths.diagnostics.display()
    );
}

fn terminal_section(output: &mut String, colors: &TerminalColors, title: &str, rule: &str) {
    let _ = writeln!(output, "\n{}", colors.paint(TerminalColor::Dim, rule));
    let _ = writeln!(output, "{}", colors.paint(TerminalColor::BoldCyan, title));
}

fn terminal_http_row(output: &mut String, colors: &TerminalColors, phase: &HttpPhaseReport) {
    let latency = phase.successful_latency_ms.as_ref();
    let success = format!(
        "{}/{}",
        grouped_usize(phase.successful_requests),
        grouped_usize(phase.attempted_requests)
    );
    let result_color = if phase.failed_requests == 0 {
        TerminalColor::Green
    } else if phase.successful_requests > 0 {
        TerminalColor::Yellow
    } else {
        TerminalColor::Red
    };
    let _ = writeln!(
        output,
        "  {:<24} {} {} {} {} {} {:>10} {:>10} {:>10}",
        truncate(&phase.name, 24),
        colors.paint(result_color, &format!("{success:>15}")),
        colors.paint(
            TerminalColor::Cyan,
            &format!("{:>11.2}", phase.attempted_requests_per_second)
        ),
        colors.paint(
            result_color,
            &format!("{:>10.2}", phase.successful_requests_per_second)
        ),
        colors.paint(
            TerminalColor::Cyan,
            &format!("{:>12.2}", phase.active_successful_requests_per_second)
        ),
        format_args!("{:>7.2}%", phase.rate_limited_percent),
        format_latency(latency.map(|value| value.p50_ms)),
        format_latency(latency.map(|value| value.p95_ms)),
        format_latency(latency.map(|value| value.p99_ms))
    );
    if phase.dropped_request_samples > 0 {
        let _ = writeln!(
            output,
            "    raw CSV keeps a {}-row reservoir; {} rows omitted (full aggregates preserved)",
            grouped_usize(phase.retained_request_samples),
            grouped_usize(phase.dropped_request_samples)
        );
    }
}

fn terminal_resource_row(output: &mut String, scope: &str, cpu: Option<f64>, memory: Option<u64>) {
    let _ = writeln!(
        output,
        "  {:<24} {:>14} {:>16}",
        truncate(scope, 24),
        format_percent(cpu),
        memory.map(human_bytes).unwrap_or_else(|| "n/a".to_string())
    );
}

pub(super) fn final_recommendation_row(
    output: &mut String,
    workload: &crate::commands::bench::metrics::ManualActiveJobsWorkloadReport,
) {
    let _ = writeln!(
        output,
        "  {:<34} {:>12} {:>9} {:>9} {:>9} {:>11}",
        truncate(&workload.workload, 34),
        human_bytes(workload.estimate.input_size_bytes),
        grouped_usize(workload.memory_ceiling_jobs),
        grouped_usize(workload.io_ceiling_jobs),
        grouped_usize(workload.cpu_ceiling_jobs),
        grouped_usize(workload.recommended_manual_max_active_jobs)
    );
}

#[derive(Clone, Copy)]
pub(super) enum TerminalColor {
    Red,
    Green,
    Yellow,
    Cyan,
    BoldCyan,
    Dim,
}

pub(super) struct TerminalColors {
    pub(super) enabled: bool,
}

impl TerminalColors {
    pub(super) fn paint(&self, color: TerminalColor, value: &str) -> String {
        if !self.enabled {
            return value.to_string();
        }
        let code = match color {
            TerminalColor::Red => "31",
            TerminalColor::Green => "32",
            TerminalColor::Yellow => "33",
            TerminalColor::Cyan => "36",
            TerminalColor::BoldCyan => "1;36",
            TerminalColor::Dim => "2",
        };
        format!("\x1b[{code}m{value}\x1b[0m")
    }
}

pub(super) fn truncate(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let shortened = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_none() || max_chars <= 3 {
        shortened
    } else {
        let prefix = shortened
            .chars()
            .take(max_chars.saturating_sub(3))
            .collect::<String>();
        format!("{prefix}...")
    }
}

pub(super) fn grouped_usize(value: usize) -> String {
    let digits = value.to_string();
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            output.push(',');
        }
        output.push(character);
    }
    output
}

pub(super) fn format_elapsed(milliseconds: f64) -> String {
    let seconds = milliseconds / 1_000.0;
    if seconds >= 60.0 {
        format!(
            "{}m {:.1}s",
            (seconds / 60.0).floor() as u64,
            seconds % 60.0
        )
    } else {
        format!("{seconds:.3}s")
    }
}

fn format_latency(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:>8.3}ms"))
        .unwrap_or_else(|| format!("{:>10}", "n/a"))
}
