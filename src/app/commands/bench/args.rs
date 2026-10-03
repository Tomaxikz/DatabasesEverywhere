use std::path::PathBuf;

use anyhow::anyhow;
use clap::{ArgAction, Args};

pub(super) const REPORT_SCHEMA_VERSION: u32 = 4;
pub(super) const DEFAULT_WARMUP_REQUESTS: usize = 10;
pub(super) const DEFAULT_LATENCY_SAMPLES: usize = 50;
pub(super) const DEFAULT_CONCURRENT_REQUESTS: usize = 400;
pub(super) const DEFAULT_CONCURRENCY: usize = 32;
pub(super) const DEFAULT_WEBSOCKET_CONNECTIONS: usize = 10;
pub(super) const DEFAULT_TIMEOUT_SECONDS: u64 = 15 * 60;
pub(super) const DEFAULT_SAMPLE_INTERVAL_MS: u64 = 250;
pub(super) const MAX_AUTO_INSTANCES: usize = 32;
pub(super) const MAX_BENCHMARK_MINUTES: u64 = 24 * 60;
pub(super) const TIMED_LOAD_RATE_BUDGET_PERCENT: u64 = 80;
pub(super) const TIMED_LOAD_IMPORT_EXPORT_BUDGET_PERCENT: u64 = 50;

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

    /// Report model-based manual active-job recommendations without changing configuration.
    #[arg(
        long,
        env = "DBEV_BENCH_RECOMMEND_MANUAL_ACTIVE_JOBS",
        action = ArgAction::SetTrue,
        requires_all = ["bench", "bench_instance", "bench_import_export"]
    )]
    pub bench_recommend_manual_active_jobs: bool,

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

pub(super) fn validate_args(args: &BenchArgs) -> anyhow::Result<()> {
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
    if args.bench_recommend_manual_active_jobs
        && (!args.bench_import_export || args.bench_instance.is_none())
    {
        return Err(anyhow!(
            "--bench-recommend-manual-active-jobs requires --bench-import-export and an exact --bench-instance target"
        ));
    }
    Ok(())
}
