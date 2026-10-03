mod args;
mod http;
mod instances;
mod metrics;
mod recommendation;
mod report;
mod reporting;
mod resources;
#[cfg(test)]
mod tests;

use std::{
    net::IpAddr,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, anyhow};
use serde::Deserialize;

use crate::config::load::load_config;
use crate::{
    config::{Config, load::ConfigLoadError},
    databases::protocol::Protocol,
    runtime::docker::DockerRuntime,
    utils::{ids::validate_instance_id, time::now_rfc3339},
};

pub use self::args::BenchArgs;
use self::{
    args::*,
    http::{BenchClient, FixedWindowPacing, LoadTarget, MAX_RETAINED_REQUEST_SAMPLES},
    instances::*,
    metrics::{
        BenchmarkOptionsReport, BenchmarkReport, EnvironmentReport, HttpPhaseReport,
        JobBenchmarkReport, ManualActiveJobsRecommendationReport, RequestSample, ResourceSample,
        TargetInstanceReport,
    },
    recommendation::recommend_job_limit,
    report::{print_terminal_report, reserve_report_directory, write_reports},
    reporting::*,
    resources::{InstanceSampleTarget, ResourceSampler},
};

pub async fn run(config_path: PathBuf, args: BenchArgs) -> anyhow::Result<()> {
    let run_started = Instant::now();
    validate_args(&args)?;
    let config = load_benchmark_config(&config_path)
        .with_context(|| format!("failed to load benchmark config {}", config_path.display()))?;
    if config.token.trim().is_empty() {
        return Err(anyhow!("benchmark config token must not be empty"));
    }
    let benchmark_id = uuid::Uuid::new_v4().to_string();
    let started_at = now_rfc3339();
    let output_dir = report_directory(&args, &benchmark_id, &started_at);

    let base_url = args
        .bench_url
        .clone()
        .unwrap_or_else(|| default_api_url(&config));
    let host_header = benchmark_host_header(&config, &args);
    let client = BenchClient::new(
        &base_url,
        host_header.as_deref(),
        &config.token,
        args.bench_concurrency,
        args.bench_insecure_tls,
    )?;
    let mut report = initial_report(
        &args,
        &config,
        benchmark_id.clone(),
        started_at,
        base_url.clone(),
        host_header,
    );
    let mut request_samples = Vec::<RequestSample>::new();
    let mut resource_samples = Vec::<ResourceSample>::new();
    let mut sampler = None;

    reserve_report_directory(&output_dir)?;
    println!("dbev benchmark {}", report.benchmark_id);
    println!("target API: {base_url}");
    println!("reports: {}", output_dir.display());
    if args.bench_import_export {
        println!(
            "destructive import/export benchmark enabled for instance {}",
            args.bench_instance.as_deref().unwrap_or_default()
        );
    }

    let execution = async {
        let api_rate_window_started = Instant::now();
        let system = client
            .required_json("/api/system", "system preflight")
            .await?;
        populate_server_env(&mut report.environment, &system);
        if args.bench_time_minutes.is_some() && !args.bench_unthrottled {
            report.options.timed_requests_per_minute = Some(request_budget(
                &args,
                report.environment.configured_api_rate_limit_per_minute,
            ));
        }
        if system["api_readiness"].as_str() != Some("ready") {
            return Err(anyhow!("daemon API did not report ready"));
        }

        let selected_instances = if let Some(instance_id) = args.bench_instance.as_deref() {
            vec![select_explicit_instance(&client, &args, instance_id).await?]
        } else if args.bench_max_instances > 0 {
            select_random_instances(&client, &args, &benchmark_id, &mut report.warnings).await?
        } else {
            Vec::new()
        };

        report.environment.selected_instances = selected_instances
            .iter()
            .map(SelectedBenchmarkInstance::report)
            .collect();
        if args.bench_instance.is_some() {
            report.environment.target_instance =
                report.environment.selected_instances.first().cloned();
        }
        if !selected_instances.is_empty() {
            println!(
                "selected instances: {}",
                selected_instances
                    .iter()
                    .map(|instance| instance.instance_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        let instance_targets = selected_instances
            .iter()
            .map(|instance| InstanceSampleTarget {
                instance_id: instance.instance_id.clone(),
                protocol: instance.protocol,
            })
            .collect::<Vec<_>>();
        let load_targets = selected_instances
            .iter()
            .map(|instance| LoadTarget::instance_status(&instance.instance_id))
            .collect::<Vec<_>>();

        let docker = if instance_targets.is_empty() {
            None
        } else {
            container_sampling_runtime(&config, &mut report.warnings)
        };
        let sample_interval = Duration::from_millis(args.bench_sample_interval_ms);
        let (resource_sampler, sampler_warnings) = ResourceSampler::start(
            &config.paths.locks,
            sample_interval,
            docker,
            instance_targets,
        );
        report.warnings.extend(sampler_warnings);
        sampler = Some(resource_sampler);

        warn_rate_limit(&args, &config, &mut report.warnings);
        set_sampler_phase(&sampler, "warmup", sample_interval).await;
        client
            .warm_up(args.bench_warmup_requests)
            .await
            .context("benchmark warmup failed")?;

        set_sampler_phase(&sampler, "http_sequential", sample_interval).await;
        let sequential = client
            .benchmark_sequential(args.bench_latency_samples)
            .await;
        evaluate_phase(&sequential.report, &mut report.warnings, &mut report.errors);
        report.http_phases.push(sequential.report);
        request_samples.extend(sequential.samples);

        if args.bench_websockets > 0 {
            set_sampler_phase(&sampler, "websocket", sample_interval).await;
            let websocket = client
                .benchmark_websockets(args.bench_websockets, args.bench_concurrency, &benchmark_id)
                .await;
            evaluate_phase(
                &websocket.report.token_mint,
                &mut report.warnings,
                &mut report.errors,
            );
            evaluate_phase(
                &websocket.report.handshake,
                &mut report.warnings,
                &mut report.errors,
            );
            report.websocket = Some(websocket.report);
            request_samples.extend(websocket.samples);
        }

        if args.bench_import_export {
            let instance_id = args
                .bench_instance
                .as_deref()
                .ok_or_else(|| anyhow!("--bench-import-export requires --bench-instance"))?;
            set_sampler_phase(&sampler, "import_export", sample_interval).await;
            let import_export = client
                .benchmark_import_export(
                    instance_id,
                    Duration::from_secs(args.bench_timeout_seconds),
                    args.bench_keep_artifact,
                )
                .await;
            if args.bench_recommend_manual_active_jobs {
                let target = selected_instances.first().ok_or_else(|| {
                    anyhow!("manual active-job recommendation requires a selected instance")
                })?;
                let recommendation = recommend_job_limit(
                    &client,
                    &config,
                    &system,
                    target.protocol,
                    target.disk_mib,
                    &import_export.jobs,
                )
                .await;
                record_recommendation(&mut report, recommendation);
            }
            record_unsuccessful_jobs(&import_export.jobs, &mut report.errors);
            report.jobs.extend(import_export.jobs);
            report.warnings.extend(import_export.warnings);
            request_samples.extend(import_export.samples);
        }

        if !report.environment.selected_instances.is_empty() {
            set_sampler_phase(&sampler, "final_validation", sample_interval).await;
            validate_final_instance_statuses(&client, &args, &mut report).await;
        }

        // Run saturation last. WebSocket token minting, import/export control
        // traffic, and final instance validation must not inherit an exhausted
        // production rate-limit window from the throughput phase.
        let concurrent_phase = if args.bench_time_minutes.is_some() {
            "http_concurrent_timed"
        } else {
            "http_concurrent"
        };
        set_sampler_phase(&sampler, concurrent_phase, sample_interval).await;
        let concurrent = if let Some(minutes) = args.bench_time_minutes {
            let pacing = report
                .options
                .timed_requests_per_minute
                .map(|requests_per_window| FixedWindowPacing {
                    window_started: api_rate_window_started,
                    requests_per_window,
                });
            client
                .benchmark_concurrency(
                    Duration::from_secs(minutes.saturating_mul(60)),
                    args.bench_concurrency,
                    load_targets,
                    benchmark_seed(&benchmark_id),
                    pacing,
                )
                .await
        } else {
            client
                .benchmark_concurrent(
                    args.bench_requests,
                    args.bench_concurrency,
                    load_targets,
                    benchmark_seed(&benchmark_id),
                )
                .await
        };
        evaluate_phase(&concurrent.report, &mut report.warnings, &mut report.errors);
        report.http_phases.push(concurrent.report);
        request_samples.extend(concurrent.samples);
        Ok::<(), anyhow::Error>(())
    }
    .await;

    if let Some(resource_sampler) = sampler {
        resource_sampler.set_phase("finalization");
        tokio::time::sleep(Duration::from_millis(args.bench_sample_interval_ms)).await;
        let (summary, samples, warnings) = resource_sampler.finish().await;
        report.resources = Some(summary);
        resource_samples = samples;
        report.warnings.extend(warnings);
    }
    if let Err(error) = &execution {
        report.errors.push(format!("{error:#}"));
    }
    report.finished_at = now_rfc3339();
    report.total_duration_ms = run_started.elapsed().as_secs_f64() * 1_000.0;
    report.status = final_report_status(&report).to_string();

    let paths = write_reports(&output_dir, &report, &request_samples, &resource_samples).await?;
    print_terminal_report(&report, &paths);
    if let Err(error) = execution {
        return Err(error.context(format!(
            "benchmark failed; partial report written to {}",
            paths.directory.display()
        )));
    }
    if !report.errors.is_empty() {
        return Err(anyhow!(
            "benchmark completed with failed phases; report written to {}",
            paths.directory.display()
        ));
    }
    Ok(())
}

fn container_sampling_runtime(
    config: &Config,
    warnings: &mut Vec<String>,
) -> Option<DockerRuntime> {
    match DockerRuntime::new(&config.daemon, false) {
        Ok(docker) => Some(docker),
        Err(error) => {
            warnings.push(format!(
                "could not initialize direct container resource sampling: {error}"
            ));
            None
        }
    }
}

fn load_benchmark_config(path: &std::path::Path) -> Result<Config, ConfigLoadError> {
    load_config(path)
}

fn timed_request_budget(args: &BenchArgs, config: &Config) -> usize {
    request_budget(args, config.security.api_rate_limit_per_minute)
}

fn request_budget(args: &BenchArgs, limit_per_minute: u32) -> usize {
    let percent = if args.bench_import_export {
        TIMED_LOAD_IMPORT_EXPORT_BUDGET_PERCENT
    } else {
        TIMED_LOAD_RATE_BUDGET_PERCENT
    };
    let budget = u64::from(limit_per_minute).saturating_mul(percent) / 100;
    usize::try_from(budget.max(1)).unwrap_or(usize::MAX)
}

fn default_api_url(config: &Config) -> String {
    let scheme = if config.api.ssl.enabled {
        "https"
    } else {
        "http"
    };
    let configured = config.api.host.trim();
    let connect_host = if is_wildcard_listener(configured) {
        "127.0.0.1".to_string()
    } else if configured
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_ipv6())
    {
        format!("[{}]", configured.trim_matches(['[', ']']))
    } else {
        configured.to_string()
    };
    format!("{scheme}://{connect_host}:{}", config.api.port)
}

fn benchmark_host_header(config: &Config, args: &BenchArgs) -> Option<String> {
    if let Some(host) = &args.bench_host {
        return Some(host.trim().to_string());
    }
    if args.bench_url.is_some() {
        return None;
    }
    let configured = config.api.host.trim();
    if is_wildcard_listener(configured) {
        return None;
    }
    Some(configured.trim_matches(['[', ']']).to_string())
}

fn is_wildcard_listener(host: &str) -> bool {
    matches!(host, "0.0.0.0" | "::" | "[::]")
}

fn report_directory(args: &BenchArgs, benchmark_id: &str, started_at: &str) -> PathBuf {
    args.bench_output.clone().unwrap_or_else(|| {
        let timestamp = started_at
            .replace([':', '.'], "-")
            .trim_end_matches('Z')
            .to_string();
        let short_id = benchmark_id.split('-').next().unwrap_or(benchmark_id);
        PathBuf::from("dbev-benchmarks").join(format!("{timestamp}-{short_id}"))
    })
}

async fn set_sampler_phase(
    sampler: &Option<ResourceSampler>,
    phase: &str,
    sample_interval: Duration,
) {
    if let Some(sampler) = sampler {
        sampler.set_phase(phase);
        tokio::time::sleep(sample_interval).await;
    }
}
