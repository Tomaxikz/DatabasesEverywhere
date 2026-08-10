use std::{
    fmt::Write as _,
    io::IsTerminal as _,
    path::{Path, PathBuf},
};

use anyhow::Context;
use tokio::io::AsyncWriteExt;

use super::metrics::{
    BenchmarkReport, HttpPhaseReport, RequestSample, ResourcePeak, ResourceSample,
};

pub struct ReportPaths {
    pub directory: PathBuf,
    pub json: PathBuf,
    pub markdown: PathBuf,
    pub request_samples: PathBuf,
    pub resource_samples: PathBuf,
    pub diagnostics: PathBuf,
}

pub fn reserve_report_directory(output_dir: &Path) -> anyhow::Result<()> {
    if let Some(parent) = output_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create benchmark report parent {}",
                parent.display()
            )
        })?;
    }
    match std::fs::create_dir(output_dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            anyhow::bail!(
                "benchmark refuses to reuse report directory {}",
                output_dir.display()
            );
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to create benchmark report directory {}",
                    output_dir.display()
                )
            });
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(output_dir, std::fs::Permissions::from_mode(0o700)).with_context(
            || {
                format!(
                    "failed to secure benchmark report directory {}",
                    output_dir.display()
                )
            },
        )?;
    }
    Ok(())
}

pub async fn write_reports(
    output_dir: &Path,
    report: &BenchmarkReport,
    request_samples: &[RequestSample],
    resource_samples: &[ResourceSample],
) -> anyhow::Result<ReportPaths> {
    let metadata = tokio::fs::symlink_metadata(output_dir)
        .await
        .with_context(|| {
            format!(
                "failed to inspect benchmark report directory {}",
                output_dir.display()
            )
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "benchmark report path is not a real directory: {}",
            output_dir.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        tokio::fs::set_permissions(output_dir, std::fs::Permissions::from_mode(0o700))
            .await
            .with_context(|| {
                format!(
                    "failed to secure benchmark report directory {}",
                    output_dir.display()
                )
            })?;
    }

    let paths = ReportPaths {
        directory: output_dir.to_path_buf(),
        json: output_dir.join("report.json"),
        markdown: output_dir.join("report.md"),
        request_samples: output_dir.join("request-samples.csv"),
        resource_samples: output_dir.join("resource-samples.csv"),
        diagnostics: output_dir.join("diagnostics.log"),
    };
    let json = serde_json::to_vec_pretty(report).context("failed to serialize benchmark report")?;
    let markdown = markdown_report(report);
    let request_csv = request_samples_csv(request_samples);
    let resource_csv = resource_samples_csv(resource_samples);
    let diagnostics = diagnostics_log(report);

    write_private(&paths.json, &json).await?;
    write_private(&paths.markdown, markdown.as_bytes()).await?;
    write_private(&paths.request_samples, request_csv.as_bytes()).await?;
    write_private(&paths.resource_samples, resource_csv.as_bytes()).await?;
    write_private(&paths.diagnostics, diagnostics.as_bytes()).await?;
    Ok(paths)
}

async fn write_private(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await
        .with_context(|| format!("refused to overwrite {}", path.display()))?;
    file.write_all(contents)
        .await
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.flush()
        .await
        .with_context(|| format!("failed to flush {}", path.display()))?;
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .await
            .with_context(|| format!("failed to secure {}", path.display()))?;
    }
    Ok(())
}

pub fn print_terminal_report(report: &BenchmarkReport, paths: &ReportPaths) {
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
    let wide_rule = "=".repeat(120);
    let thin_rule = "-".repeat(120);
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
    let load_shape = if let Some(minutes) = report.options.concurrent_duration_minutes {
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
    } else {
        format!(
            "{} requests, concurrency {}",
            report.options.concurrent_requests.unwrap_or_default(),
            report.options.concurrency
        )
    };
    let _ = writeln!(output, "  {:<15} {load_shape}", "Load");
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

    terminal_section(&mut output, &colors, "HTTP & WEBSOCKET", &thin_rule);
    let _ = writeln!(
        output,
        "  {:<24} {:>15} {:>11} {:>10} {:>12} {:>8} {:>10} {:>10} {:>10}",
        "PHASE", "SUCCESS", "OFFERED/s", "OK/s", "ACTIVE OK/s", "429 %", "P50", "P95", "P99"
    );
    let _ = writeln!(output, "  {}", ".".repeat(118));
    for phase in report
        .http_phases
        .iter()
        .filter(|phase| !phase.name.starts_with("http_concurrent"))
    {
        terminal_http_row(&mut output, &colors, phase);
    }
    if let Some(websocket) = &report.websocket {
        terminal_http_row(&mut output, &colors, &websocket.token_mint);
        terminal_http_row(&mut output, &colors, &websocket.handshake);
    }
    for phase in report
        .http_phases
        .iter()
        .filter(|phase| phase.name.starts_with("http_concurrent"))
    {
        terminal_http_row(&mut output, &colors, phase);
    }

    if !report.environment.selected_instances.is_empty() {
        terminal_section(&mut output, &colors, "SELECTED INSTANCES", &thin_rule);
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

    if let Some(resources) = &report.resources {
        terminal_section(&mut output, &colors, "PEAK CPU & RAM", &thin_rule);
        let _ = writeln!(output, "  {:<24} {:>14} {:>16}", "SCOPE", "CPU", "RAM");
        let _ = writeln!(output, "  {}", ".".repeat(58));
        terminal_resource_row(
            &mut output,
            "daemon",
            resources.overall_peak.daemon_cpu_percent,
            resources.overall_peak.daemon_rss_bytes,
        );
        terminal_resource_row(
            &mut output,
            "benchmark client",
            resources.overall_peak.benchmark_cpu_percent,
            resources.overall_peak.benchmark_rss_bytes,
        );
        if resources.peak_by_instance.is_empty() {
            terminal_resource_row(
                &mut output,
                "database containers",
                resources.overall_peak.instance_cpu_percent,
                resources.overall_peak.instance_memory_bytes,
            );
        } else {
            for (instance_id, peak) in &resources.peak_by_instance {
                terminal_resource_row(
                    &mut output,
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

    if !report.jobs.is_empty() {
        terminal_section(&mut output, &colors, "IMPORT & EXPORT", &thin_rule);
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

    if let Some(recommendation) = &report.manual_active_jobs_recommendation {
        terminal_section(
            &mut output,
            &colors,
            "MANUAL ACTIVE-JOB RECOMMENDATION",
            &thin_rule,
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
                terminal_recommendation_row(&mut output, workload);
            }
            if let Some(workload) = &recommendation.representative_exported_dump {
                terminal_recommendation_row(&mut output, workload);
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

    if !report.warnings.is_empty() || !report.errors.is_empty() {
        terminal_section(&mut output, &colors, "DIAGNOSTICS", &thin_rule);
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

    terminal_section(&mut output, &colors, "REPORT FILES", &thin_rule);
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
    output
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

fn terminal_recommendation_row(
    output: &mut String,
    workload: &crate::bench::metrics::ManualActiveJobsWorkloadReport,
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
enum TerminalColor {
    Red,
    Green,
    Yellow,
    Cyan,
    BoldCyan,
    Dim,
}

struct TerminalColors {
    enabled: bool,
}

impl TerminalColors {
    fn paint(&self, color: TerminalColor, value: &str) -> String {
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

fn truncate(value: &str, max_chars: usize) -> String {
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

fn grouped_usize(value: usize) -> String {
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

fn format_elapsed(milliseconds: f64) -> String {
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

fn markdown_report(report: &BenchmarkReport) -> String {
    let mut output = String::new();
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
    if !report.environment.selected_instances.is_empty() {
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
        write_http_row(&mut output, phase);
    }
    if let Some(websocket) = &report.websocket {
        write_http_row(&mut output, &websocket.token_mint);
        write_http_row(&mut output, &websocket.handshake);
    }
    for phase in report
        .http_phases
        .iter()
        .filter(|phase| phase.name.starts_with("http_concurrent"))
    {
        write_http_row(&mut output, phase);
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

    if !report.jobs.is_empty() {
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

    if let Some(recommendation) = &report.manual_active_jobs_recommendation {
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
                write_recommendation_row(&mut output, workload);
            }
            if let Some(workload) = &recommendation.representative_exported_dump {
                write_recommendation_row(&mut output, workload);
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

    if let Some(resources) = &report.resources {
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
        write_resource_row(&mut output, "overall", &resources.overall_peak);
        for (phase, peak) in &resources.peak_by_phase {
            write_resource_row(&mut output, phase, peak);
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
    output
}

fn write_recommendation_row(
    output: &mut String,
    workload: &crate::bench::metrics::ManualActiveJobsWorkloadReport,
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

fn request_samples_csv(samples: &[RequestSample]) -> String {
    let mut output =
        "phase,target,index,duration_micros,duration_ms,status_code,success,error\n".to_string();
    for sample in samples {
        let _ = writeln!(
            output,
            "{},{},{},{},{:.3},{},{},{}",
            csv_field(&sample.phase),
            csv_field(&sample.target),
            sample.index,
            sample.duration_micros,
            sample.duration_micros as f64 / 1_000.0,
            sample
                .status_code
                .map(|status| status.to_string())
                .unwrap_or_default(),
            sample.success,
            csv_field(sample.error.as_deref().unwrap_or_default())
        );
    }
    output
}

fn resource_samples_csv(samples: &[ResourceSample]) -> String {
    let mut output = "elapsed_ms,phase,daemon_cpu_percent,daemon_rss_bytes,benchmark_cpu_percent,benchmark_rss_bytes,instance_id,instance_protocol,instance_sample_failed,instance_cpu_percent,instance_memory_bytes\n".to_string();
    for sample in samples {
        let _ = writeln!(
            output,
            "{},{},{},{},{},{},{},{},{},{},{}",
            sample.elapsed_ms,
            csv_field(&sample.phase),
            csv_optional_f64(sample.daemon_cpu_percent),
            csv_optional_u64(sample.daemon_rss_bytes),
            csv_optional_f64(sample.benchmark_cpu_percent),
            csv_optional_u64(sample.benchmark_rss_bytes),
            csv_field(sample.instance_id.as_deref().unwrap_or_default()),
            csv_field(sample.instance_protocol.as_deref().unwrap_or_default()),
            sample.instance_sample_failed,
            csv_optional_f64(sample.instance_cpu_percent),
            csv_optional_u64(sample.instance_memory_bytes),
        );
    }
    output
}

fn diagnostics_log(report: &BenchmarkReport) -> String {
    let mut output = String::new();
    for warning in &report.warnings {
        let _ = writeln!(output, "WARN {warning}");
    }
    for error in &report.errors {
        let _ = writeln!(output, "ERROR {error}");
    }
    if output.is_empty() {
        output.push_str("No benchmark warnings or errors.\n");
    }
    output
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn csv_optional_f64(value: Option<f64>) -> String {
    value.map(|value| format!("{value:.6}")).unwrap_or_default()
}

fn csv_optional_u64(value: Option<u64>) -> String {
    value.map(|value| value.to_string()).unwrap_or_default()
}

fn format_optional_f64(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.2}"))
        .unwrap_or_else(|| "n/a".to_string())
}

fn format_percent(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.2}%"))
        .unwrap_or_else(|| "n/a".to_string())
}

fn human_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes / KIB)
    } else {
        format!("{} B", bytes as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_fields_escape_delimiters_and_quotes() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn byte_format_uses_binary_units() {
        assert_eq!(human_bytes(1024), "1.00 KiB");
        assert_eq!(human_bytes(1024 * 1024), "1.00 MiB");
    }

    #[test]
    fn terminal_helpers_keep_counts_and_elapsed_time_readable() {
        assert_eq!(grouped_usize(12_345_678), "12,345,678");
        assert_eq!(format_elapsed(90_250.0), "1m 30.2s");
        assert!(
            !TerminalColors { enabled: false }
                .paint(TerminalColor::Green, "ok")
                .contains('\u{1b}')
        );
        assert!(
            TerminalColors { enabled: true }
                .paint(TerminalColor::Green, "ok")
                .contains("\u{1b}[32m")
        );
        assert_eq!(truncate("a-very-long-instance-name", 12), "a-very-lo...");
        assert!(truncate("a-very-long-instance-name", 12).is_ascii());
    }

    #[test]
    fn manual_active_job_recommendation_rows_expose_model_inputs_and_result() {
        let workload = crate::bench::metrics::ManualActiveJobsWorkloadReport {
            workload: "configured maximum upload".to_string(),
            protocol: "mongodb".to_string(),
            mode: "wipe".to_string(),
            compressed: true,
            estimate: crate::bench::metrics::SchedulerJobCostReport {
                input_size_bytes: 4 * 1024 * 1024 * 1024,
                memory_mib: 1024,
                io_mib: 4096,
                cpu_units: 2,
            },
            memory_ceiling_jobs: 8,
            io_ceiling_jobs: 4,
            cpu_ceiling_jobs: 6,
            configured_active_ceiling_jobs: 12,
            recommended_manual_max_active_jobs: 4,
        };

        let mut terminal = String::new();
        terminal_recommendation_row(&mut terminal, &workload);
        assert!(terminal.contains("configured maximum upload"));
        assert!(terminal.contains("4.00 GiB"));
        assert!(terminal.trim_end().ends_with('4'));

        let mut markdown = String::new();
        write_recommendation_row(&mut markdown, &workload);
        assert!(markdown.contains("| `configured maximum upload` | mongodb | wipe | true |"));
        assert!(markdown.contains("| 1024 | 4096 | 2 | 8 | 4 | 6 | 12 | **4** |"));
    }

    #[tokio::test]
    async fn report_directory_and_files_refuse_reuse() {
        let directory =
            std::env::temp_dir().join(format!("dbev-bench-report-test-{}", uuid::Uuid::new_v4()));
        reserve_report_directory(&directory).unwrap();
        assert!(reserve_report_directory(&directory).is_err());

        let report = directory.join("report.json");
        write_private(&report, b"first").await.unwrap();
        assert!(write_private(&report, b"second").await.is_err());
        assert_eq!(tokio::fs::read(&report).await.unwrap(), b"first");

        tokio::fs::remove_file(report).await.unwrap();
        tokio::fs::remove_dir(directory).await.unwrap();
    }
}
