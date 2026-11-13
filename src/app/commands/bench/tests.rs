use super::args::{
    DEFAULT_CONCURRENCY, DEFAULT_CONCURRENT_REQUESTS, DEFAULT_LATENCY_SAMPLES,
    DEFAULT_SAMPLE_INTERVAL_MS, DEFAULT_TIMEOUT_SECONDS, DEFAULT_WARMUP_REQUESTS,
    DEFAULT_WEBSOCKET_CONNECTIONS,
};
use super::*;
use clap::Parser;

#[derive(Debug, Parser)]
struct BenchCli {
    #[command(flatten)]
    bench: BenchArgs,
}

#[test]
fn benchmark_arguments_enforce_mode_duration_and_selection_constraints() {
    let rejected: [&[&str]; 4] = [
        &["--bench-instance", "perf-postgres"],
        &["--bench", "--bench-recommend-manual-active-jobs"],
        &["--bench", "--bench-unthrottled"],
        &[
            "--bench",
            "--bench-instance",
            "perf-postgres",
            "--max_instances",
            "2",
        ],
    ];
    for arguments in rejected {
        assert!(
            BenchCli::try_parse_from(std::iter::once("dbev").chain(arguments.iter().copied()))
                .is_err(),
            "accepted {arguments:?}"
        );
    }

    let parse = |arguments: &[&str]| {
        BenchCli::try_parse_from(std::iter::once("dbev").chain(arguments.iter().copied()))
            .unwrap()
            .bench
    };
    assert!(!parse(&[]).bench);
    assert!(
        parse(&[
            "--bench",
            "--bench-instance",
            "perf-postgres",
            "--bench-import-export",
        ])
        .bench_import_export
    );
    assert!(
        parse(&[
            "--bench",
            "--bench-instance",
            "perf-mongodb",
            "--bench-import-export",
            "--bench-recommend-manual-active-jobs",
        ])
        .bench_recommend_manual_active_jobs
    );
    let timed = parse(&["--bench", "--time", "5", "--max_instances", "3"]);
    assert_eq!(timed.bench_time_minutes, Some(5));
    assert_eq!(timed.bench_max_instances, 3);
    assert!(parse(&["--bench", "--time", "2", "--bench-unthrottled"]).bench_unthrottled);
}

#[test]
fn wildcard_listener_uses_loopback_without_overriding_the_host_header() {
    let mut config = Config::default();
    config.api.host = "0.0.0.0".to_string();
    config.api.port = 8090;
    config.remote = "https://panel.example.com".to_string();
    let args = test_args();

    assert_eq!(default_api_url(&config), "http://127.0.0.1:8090");
    assert_eq!(benchmark_host_header(&config, &args), None);
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
        bench_recommend_manual_active_jobs: false,
        bench_keep_artifact: false,
        bench_insecure_tls: false,
        bench_timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
        bench_sample_interval_ms: DEFAULT_SAMPLE_INTERVAL_MS,
        bench_output: None,
    }
}
