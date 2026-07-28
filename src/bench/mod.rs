mod http;
mod metrics;
mod report;
mod resources;

use std::{
    net::IpAddr,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, anyhow};
use clap::{ArgAction, Args};
use serde::Deserialize;

#[cfg(not(windows))]
use crate::config::load::load_config;
use crate::{
    config::{Config, load::ConfigLoadError},
    runtime::docker::DockerRuntime,
    shared::{ids::validate_instance_id, protocol::Protocol, time::now_rfc3339},
};

use self::{
    http::{BenchClient, FixedWindowPacing, LoadTarget, MAX_RETAINED_REQUEST_SAMPLES},
    metrics::{
        BenchmarkOptionsReport, BenchmarkReport, EnvironmentReport, HttpPhaseReport, RequestSample,
        ResourceSample, TargetInstanceReport,
    },
    report::{print_terminal_report, reserve_report_directory, write_reports},
    resources::{InstanceSampleTarget, ResourceSampler},
};

const REPORT_SCHEMA_VERSION: u32 = 3;
const DEFAULT_WARMUP_REQUESTS: usize = 10;
const DEFAULT_LATENCY_SAMPLES: usize = 50;
const DEFAULT_CONCURRENT_REQUESTS: usize = 400;
const DEFAULT_CONCURRENCY: usize = 32;
const DEFAULT_WEBSOCKET_CONNECTIONS: usize = 10;
const DEFAULT_TIMEOUT_SECONDS: u64 = 15 * 60;
const DEFAULT_SAMPLE_INTERVAL_MS: u64 = 250;
const MAX_AUTO_INSTANCES: usize = 32;
const MAX_BENCHMARK_MINUTES: u64 = 24 * 60;
const TIMED_LOAD_RATE_BUDGET_PERCENT: u64 = 80;
const TIMED_LOAD_IMPORT_EXPORT_BUDGET_PERCENT: u64 = 50;

#[derive(Debug, Clone, Args)]
pub struct BenchArgs {
    /// Benchmark an already-running DatabasesEverywhere daemon and write reports.
    #[arg(long, env = "DBEV_BENCH", action = ArgAction::SetTrue)]
    pub bench: bool,

    /// API origin to benchmark. Defaults to the configured local API listener.
    #[arg(long, env = "DBEV_BENCH_URL", requires = "bench")]
    pub bench_url: Option<String>,

    /// Override the HTTP Host header when connecting through loopback or a proxy.
    #[arg(long, env = "DBEV_BENCH_HOST", requires = "bench")]
    pub bench_host: Option<String>,

    /// Existing running instance to sample and optionally exercise with import/export.
    #[arg(long, env = "DBEV_BENCH_INSTANCE", requires = "bench")]
    pub bench_instance: Option<String>,

    /// Randomly select up to this many running instances for mixed load and telemetry.
    #[arg(
        long = "bench-max-instances",
        visible_aliases = ["max-instances", "max_instances"],
        env = "DBEV_BENCH_MAX_INSTANCES",
        default_value_t = 0,
        requires = "bench",
        conflicts_with = "bench_instance"
    )]
    pub bench_max_instances: usize,

    /// Number of unmeasured warmup requests.
    #[arg(
        long,
        env = "DBEV_BENCH_WARMUP_REQUESTS",
        default_value_t = DEFAULT_WARMUP_REQUESTS,
        requires = "bench"
    )]
    pub bench_warmup_requests: usize,

    /// Number of sequential requests used for latency percentiles.
    #[arg(
        long,
        env = "DBEV_BENCH_LATENCY_SAMPLES",
        default_value_t = DEFAULT_LATENCY_SAMPLES,
        requires = "bench"
    )]
    pub bench_latency_samples: usize,

    /// Total requests sent during the concurrent throughput phase.
    #[arg(
        long,
        env = "DBEV_BENCH_REQUESTS",
        default_value_t = DEFAULT_CONCURRENT_REQUESTS,
        requires = "bench"
    )]
    pub bench_requests: usize,

    /// Run the concurrent phase for this many minutes instead of a fixed request count.
    #[arg(
        long = "bench-time-minutes",
        visible_aliases = ["time", "time-minutes", "time_minutes"],
        env = "DBEV_BENCH_TIME_MINUTES",
        requires = "bench"
    )]
    pub bench_time_minutes: Option<u64>,

    /// Disable safe fixed-window pacing for timed load and send as fast as possible.
    #[arg(
        long,
        env = "DBEV_BENCH_UNTHROTTLED",
        action = ArgAction::SetTrue,
        requires_all = ["bench", "bench_time_minutes"]
    )]
    pub bench_unthrottled: bool,

    /// Maximum concurrent HTTP and WebSocket handshakes.
    #[arg(
        long,
        env = "DBEV_BENCH_CONCURRENCY",
        default_value_t = DEFAULT_CONCURRENCY,
        requires = "bench"
    )]
    pub bench_concurrency: usize,

    /// Number of real authenticated WebSocket upgrades to measure. Set to zero to skip.
    #[arg(
        long,
        env = "DBEV_BENCH_WEBSOCKETS",
        default_value_t = DEFAULT_WEBSOCKET_CONNECTIONS,
        requires = "bench"
    )]
    pub bench_websockets: usize,

    /// Export and then destructively re-import a fresh full artifact into --bench-instance.
    #[arg(
        long,
        env = "DBEV_BENCH_IMPORT_EXPORT",
        action = ArgAction::SetTrue,
        requires_all = ["bench", "bench_instance"]
    )]
    pub bench_import_export: bool,

    /// Retain the fresh export artifact after a successful benchmark import.
    #[arg(
        long,
        env = "DBEV_BENCH_KEEP_ARTIFACT",
        action = ArgAction::SetTrue,
        requires_all = ["bench", "bench_import_export"]
    )]
    pub bench_keep_artifact: bool,

    /// Accept an invalid HTTPS certificate. Intended only for an explicit local test target.
    #[arg(
        long,
        env = "DBEV_BENCH_INSECURE_TLS",
        action = ArgAction::SetTrue,
        requires = "bench"
    )]
    pub bench_insecure_tls: bool,

    /// Per import/export job timeout.
    #[arg(
        long,
        env = "DBEV_BENCH_TIMEOUT_SECONDS",
        default_value_t = DEFAULT_TIMEOUT_SECONDS,
        requires = "bench"
    )]
    pub bench_timeout_seconds: u64,

    /// Process and container resource sampling interval.
    #[arg(
        long,
        env = "DBEV_BENCH_SAMPLE_INTERVAL_MS",
        default_value_t = DEFAULT_SAMPLE_INTERVAL_MS,
        requires = "bench"
    )]
    pub bench_sample_interval_ms: u64,

    /// Report directory. Defaults to a unique directory below ./dbev-benchmarks.
    #[arg(long, env = "DBEV_BENCH_OUTPUT", requires = "bench")]
    pub bench_output: Option<PathBuf>,
}

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
    let timed_requests_per_minute = args
        .bench_time_minutes
        .filter(|_| !args.bench_unthrottled)
        .map(|_| timed_request_budget(&args, &config));
    let concurrent_load_mode = match (args.bench_time_minutes, args.bench_unthrottled) {
        (Some(_), true) => "timed_unthrottled",
        (Some(_), false) => "timed_rate_limit_aware_bursts",
        (None, _) => "fixed_request_burst",
    }
    .to_string();
    let options = BenchmarkOptionsReport {
        warmup_requests: args.bench_warmup_requests,
        latency_samples: args.bench_latency_samples,
        concurrent_requests: args
            .bench_time_minutes
            .is_none()
            .then_some(args.bench_requests),
        concurrent_duration_minutes: args.bench_time_minutes,
        concurrent_load_mode,
        timed_requests_per_minute,
        concurrency: args.bench_concurrency,
        websocket_connections: args.bench_websockets,
        max_instances: args.bench_max_instances,
        retained_request_sample_limit: MAX_RETAINED_REQUEST_SAMPLES,
        timeout_seconds: args.bench_timeout_seconds,
        sample_interval_ms: args.bench_sample_interval_ms,
        import_export_enabled: args.bench_import_export,
        keep_artifact: args.bench_keep_artifact,
    };
    let mut report = BenchmarkReport {
        schema_version: REPORT_SCHEMA_VERSION,
        benchmark_id: benchmark_id.clone(),
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
            api_url: base_url.clone(),
            host_header: host_header.clone(),
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
        resources: None,
        warnings: Vec::new(),
        errors: Vec::new(),
    };
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
        populate_server_environment(&mut report.environment, &system);
        if args.bench_time_minutes.is_some() && !args.bench_unthrottled {
            report.options.timed_requests_per_minute = Some(timed_request_budget_for_limit(
                &args,
                report.environment.configured_api_rate_limit_per_minute,
            ));
        }
        if system["api_readiness"].as_str() != Some("ready") {
            return Err(anyhow!("daemon API did not report ready"));
        }

        let mut selected_instances = Vec::<SelectedBenchmarkInstance>::new();
        if let Some(instance_id) = args.bench_instance.as_deref() {
            validate_instance_id(instance_id)
                .map_err(|error| anyhow!("invalid --bench-instance: {error}"))?;
            let instance = client
                .required_json(
                    &format!("/api/instances/{instance_id}"),
                    "instance preflight",
                )
                .await?;
            let protocol = instance["protocol"]
                .as_str()
                .ok_or_else(|| anyhow!("instance response did not contain protocol"))?
                .parse::<Protocol>()
                .context("instance response contained an unsupported protocol")?;
            let status = instance["status"]
                .as_str()
                .ok_or_else(|| anyhow!("instance response did not contain status"))?
                .to_string();
            if args.bench_import_export && status != "running" {
                return Err(anyhow!(
                    "destructive import/export benchmark requires a running instance; {instance_id} is {status}"
                ));
            }
            selected_instances.push(SelectedBenchmarkInstance {
                instance_id: instance_id.to_string(),
                protocol,
                initial_status: status,
            });
        } else if args.bench_max_instances > 0 {
            let value = client
                .required_json("/api/instances", "instance discovery")
                .await?;
            let mut running = serde_json::from_value::<Vec<InstanceListEntry>>(value)
                .context("instance discovery response was not a valid instance list")?
                .into_iter()
                .filter(|instance| instance.status == "running")
                .map(|instance| SelectedBenchmarkInstance {
                    instance_id: instance.instance_id,
                    protocol: instance.protocol,
                    initial_status: instance.status,
                })
                .collect::<Vec<_>>();
            if running.is_empty() {
                return Err(anyhow!(
                    "--max_instances {} requested automatic selection, but the daemon has no running instances",
                    args.bench_max_instances
                ));
            }
            shuffle_instances(&mut running, benchmark_seed(&benchmark_id));
            if running.len() < args.bench_max_instances {
                report.warnings.push(format!(
                    "--max_instances requested {}, but only {} running instances were available; all available instances were selected",
                    args.bench_max_instances,
                    running.len()
                ));
            }
            running.truncate(args.bench_max_instances);
            for instance in &running {
                validate_instance_id(&instance.instance_id).map_err(|error| {
                    anyhow!(
                        "daemon returned invalid instance ID {}: {error}",
                        instance.instance_id
                    )
                })?;
            }
            selected_instances = running;
        }

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

        let docker = if !instance_targets.is_empty() {
            match DockerRuntime::new(&config.daemon, false) {
                Ok(docker) => Some(docker),
                Err(error) => {
                    report.warnings.push(format!(
                        "could not initialize direct container resource sampling: {error}"
                    ));
                    None
                }
            }
        } else {
            None
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

        warn_about_rate_limit(&args, &config, &mut report.warnings);
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
                .benchmark_websockets(
                    args.bench_websockets,
                    args.bench_concurrency,
                    &benchmark_id,
                )
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
            for job in &import_export.jobs {
                if job.status != "succeeded" {
                    report.errors.push(format!(
                        "{} benchmark did not succeed (status={}): {}",
                        job.action,
                        job.status,
                        job.error.as_deref().unwrap_or("no diagnostic")
                    ));
                }
            }
            report.jobs.extend(import_export.jobs);
            report.warnings.extend(import_export.warnings);
            request_samples.extend(import_export.samples);
        }

        if !report.environment.selected_instances.is_empty() {
            set_sampler_phase(&sampler, "final_validation", sample_interval).await;
            let selected_ids = report
                .environment
                .selected_instances
                .iter()
                .map(|instance| instance.instance_id.clone())
                .collect::<Vec<_>>();
            for instance_id in selected_ids {
                match client
                    .required_json(
                        &format!("/api/instances/{instance_id}/status"),
                        "final instance validation",
                    )
                    .await
                {
                    Ok(value) => {
                        let final_status = value["status"].as_str().map(str::to_string);
                        if args.bench_import_export && final_status.as_deref() != Some("running") {
                            report.errors.push(format!(
                                "target instance did not return to running after benchmark (status={})",
                                final_status.as_deref().unwrap_or("unknown")
                            ));
                        } else if final_status.as_deref() != Some("running")
                            && args.bench_max_instances > 0
                        {
                            report.warnings.push(format!(
                                "automatically selected instance {instance_id} ended in status {}",
                                final_status.as_deref().unwrap_or("unknown")
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
            let pacing = report.options.timed_requests_per_minute.map(
                |requests_per_window| FixedWindowPacing {
                    window_started: api_rate_window_started,
                    requests_per_window,
                },
            );
            client
                .benchmark_concurrent_for_duration(
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
    report.status = if !report.errors.is_empty() {
        "failed"
    } else if !report.warnings.is_empty() {
        "completed_with_warnings"
    } else {
        "completed"
    }
    .to_string();

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

#[cfg(not(windows))]
fn load_benchmark_config(path: &std::path::Path) -> Result<Config, ConfigLoadError> {
    load_config(path)
}

#[cfg(windows)]
fn load_benchmark_config(path: &std::path::Path) -> Result<Config, ConfigLoadError> {
    crate::config::load::parse_config_file(path)
}

#[derive(Debug, Deserialize)]
struct InstanceListEntry {
    instance_id: String,
    protocol: Protocol,
    status: String,
}

#[derive(Debug)]
struct SelectedBenchmarkInstance {
    instance_id: String,
    protocol: Protocol,
    initial_status: String,
}

impl SelectedBenchmarkInstance {
    fn report(&self) -> TargetInstanceReport {
        TargetInstanceReport {
            instance_id: self.instance_id.clone(),
            protocol: self.protocol.to_string(),
            initial_status: self.initial_status.clone(),
            final_status: None,
        }
    }
}

fn benchmark_seed(benchmark_id: &str) -> u64 {
    uuid::Uuid::parse_str(benchmark_id)
        .map(|id| {
            let value = id.as_u128();
            (value as u64) ^ ((value >> 64) as u64)
        })
        .unwrap_or_else(|_| {
            benchmark_id
                .bytes()
                .fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
                    (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
                })
        })
}

fn timed_request_budget(args: &BenchArgs, config: &Config) -> usize {
    timed_request_budget_for_limit(args, config.security.api_rate_limit_per_minute)
}

fn timed_request_budget_for_limit(args: &BenchArgs, limit_per_minute: u32) -> usize {
    let percent = if args.bench_import_export {
        TIMED_LOAD_IMPORT_EXPORT_BUDGET_PERCENT
    } else {
        TIMED_LOAD_RATE_BUDGET_PERCENT
    };
    let budget = u64::from(limit_per_minute).saturating_mul(percent) / 100;
    usize::try_from(budget.max(1)).unwrap_or(usize::MAX)
}

fn shuffle_instances(instances: &mut [SelectedBenchmarkInstance], seed: u64) {
    let mut state = if seed == 0 {
        0x9e37_79b9_7f4a_7c15
    } else {
        seed
    };
    for index in (1..instances.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        instances.swap(index, state as usize % (index + 1));
    }
}

fn validate_args(args: &BenchArgs) -> anyhow::Result<()> {
    if args.bench_warmup_requests > 10_000 {
        return Err(anyhow!("--bench-warmup-requests must not exceed 10000"));
    }
    if !(1..=1_000_000).contains(&args.bench_latency_samples) {
        return Err(anyhow!(
            "--bench-latency-samples must be between 1 and 1000000"
        ));
    }
    if !(1..=10_000_000).contains(&args.bench_requests) {
        return Err(anyhow!("--bench-requests must be between 1 and 10000000"));
    }
    if args.bench_max_instances > MAX_AUTO_INSTANCES {
        return Err(anyhow!(
            "--bench-max-instances must not exceed {MAX_AUTO_INSTANCES}"
        ));
    }
    if let Some(minutes) = args.bench_time_minutes
        && !(1..=MAX_BENCHMARK_MINUTES).contains(&minutes)
    {
        return Err(anyhow!(
            "--bench-time-minutes/--time must be between 1 and {MAX_BENCHMARK_MINUTES}"
        ));
    }
    if args.bench_instance.is_some() && args.bench_max_instances > 0 {
        return Err(anyhow!(
            "--bench-instance cannot be combined with --bench-max-instances"
        ));
    }
    if args.bench_unthrottled && args.bench_time_minutes.is_none() {
        return Err(anyhow!(
            "--bench-unthrottled requires --bench-time-minutes/--time"
        ));
    }
    if !(1..=1_024).contains(&args.bench_concurrency) {
        return Err(anyhow!("--bench-concurrency must be between 1 and 1024"));
    }
    if args.bench_websockets > 10_000 {
        return Err(anyhow!("--bench-websockets must not exceed 10000"));
    }
    if !(10..=86_400).contains(&args.bench_timeout_seconds) {
        return Err(anyhow!(
            "--bench-timeout-seconds must be between 10 and 86400"
        ));
    }
    if !(100..=60_000).contains(&args.bench_sample_interval_ms) {
        return Err(anyhow!(
            "--bench-sample-interval-ms must be between 100 and 60000"
        ));
    }
    if args.bench_import_export && args.bench_instance.is_none() {
        return Err(anyhow!(
            "--bench-import-export requires an exact --bench-instance target"
        ));
    }
    Ok(())
}

fn default_api_url(config: &Config) -> String {
    let scheme = if config.api.ssl.enabled {
        "https"
    } else {
        "http"
    };
    let configured = config.api.host.trim();
    let connect_host = if matches!(configured, "0.0.0.0" | "::" | "[::]") {
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
    if !matches!(configured, "0.0.0.0" | "::" | "[::]") {
        return Some(configured.trim_matches(['[', ']']).to_string());
    }
    config.request_allowed_hosts().into_iter().next()
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

fn populate_server_environment(environment: &mut EnvironmentReport, system: &serde_json::Value) {
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

fn warn_about_rate_limit(args: &BenchArgs, config: &Config, warnings: &mut Vec<String>) {
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
        .saturating_add(3);
    let limit = config.security.api_rate_limit_per_minute as usize;
    if planned_node_token_requests > limit {
        warnings.push(format!(
            "planned authenticated requests ({planned_node_token_requests}) exceed the configured per-minute API limit ({limit}); HTTP 429 responses are expected and reported separately"
        ));
    }
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

fn evaluate_phase(phase: &HttpPhaseReport, warnings: &mut Vec<String>, errors: &mut Vec<String>) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Debug, Parser)]
    struct BenchCli {
        #[command(flatten)]
        bench: BenchArgs,
    }

    #[test]
    fn benchmark_options_require_benchmark_mode() {
        let defaults = BenchCli::try_parse_from(["dbev"]).unwrap();
        assert!(!defaults.bench.bench);
        assert!(BenchCli::try_parse_from(["dbev", "--bench-instance", "perf-postgres"]).is_err());
        let enabled = BenchCli::try_parse_from([
            "dbev",
            "--bench",
            "--bench-instance",
            "perf-postgres",
            "--bench-import-export",
        ])
        .unwrap();
        assert!(enabled.bench.bench_import_export);
    }

    #[test]
    fn benchmark_accepts_friendly_time_and_instance_aliases() {
        let parsed =
            BenchCli::try_parse_from(["dbev", "--bench", "--time", "5", "--max_instances", "3"])
                .unwrap();

        assert_eq!(parsed.bench.bench_time_minutes, Some(5));
        assert_eq!(parsed.bench.bench_max_instances, 3);
    }

    #[test]
    fn unthrottled_timed_load_requires_an_explicit_duration() {
        assert!(BenchCli::try_parse_from(["dbev", "--bench", "--bench-unthrottled"]).is_err());
        let parsed =
            BenchCli::try_parse_from(["dbev", "--bench", "--time", "2", "--bench-unthrottled"])
                .unwrap();
        assert!(parsed.bench.bench_unthrottled);
    }

    #[test]
    fn automatic_and_explicit_instance_selection_are_mutually_exclusive() {
        assert!(
            BenchCli::try_parse_from([
                "dbev",
                "--bench",
                "--bench-instance",
                "perf-postgres",
                "--max_instances",
                "2",
            ])
            .is_err()
        );
    }

    #[test]
    fn wildcard_listener_uses_loopback_and_an_allowed_host_header() {
        let mut config = Config::default();
        config.api.host = "0.0.0.0".to_string();
        config.api.port = 8090;
        config.remote = "https://panel.example.com".to_string();
        let args = test_args();

        assert_eq!(default_api_url(&config), "http://127.0.0.1:8090");
        assert_eq!(
            benchmark_host_header(&config, &args).as_deref(),
            Some("panel.example.com")
        );
    }

    #[test]
    fn explicit_url_uses_its_own_host_unless_overridden() {
        let config = Config::default();
        let mut args = test_args();
        args.bench_url = Some("https://node.example.com".to_string());

        assert_eq!(benchmark_host_header(&config, &args), None);
        args.bench_host = Some("proxy.example.com".to_string());
        assert_eq!(
            benchmark_host_header(&config, &args).as_deref(),
            Some("proxy.example.com")
        );
    }

    #[cfg(windows)]
    #[test]
    fn benchmark_loader_accepts_a_linux_daemon_config() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.yml");
        std::fs::write(
            &path,
            r#"
uuid: node-uuid
token_id: node-token
token: benchmark-api-token
jwt_signing_key: unused-by-the-remote-benchmark-client
paths:
  data: /var/lib/dbev
  sockets: /run/dbev/sockets
  locks: /run/dbev/locks
  logs: /var/log/dbev
  artifacts: /var/lib/dbev/artifacts
"#,
        )
        .unwrap();

        let config = load_benchmark_config(&path).unwrap();

        assert_eq!(config.token, "benchmark-api-token");
        assert_eq!(config.paths.locks, "/run/dbev/locks");
    }

    fn test_args() -> BenchArgs {
        BenchArgs {
            bench: true,
            bench_url: None,
            bench_host: None,
            bench_instance: None,
            bench_max_instances: 0,
            bench_warmup_requests: DEFAULT_WARMUP_REQUESTS,
            bench_latency_samples: DEFAULT_LATENCY_SAMPLES,
            bench_requests: DEFAULT_CONCURRENT_REQUESTS,
            bench_time_minutes: None,
            bench_unthrottled: false,
            bench_concurrency: DEFAULT_CONCURRENCY,
            bench_websockets: DEFAULT_WEBSOCKET_CONNECTIONS,
            bench_import_export: false,
            bench_keep_artifact: false,
            bench_insecure_tls: false,
            bench_timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
            bench_sample_interval_ms: DEFAULT_SAMPLE_INTERVAL_MS,
            bench_output: None,
        }
    }
}
