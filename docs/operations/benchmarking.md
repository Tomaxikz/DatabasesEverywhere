# Benchmarking a running node

[Documentation index](../README.md)

Run the benchmark client as a second `dbev` process on the same node as the
already-running daemon:

```bash
sudo dbev --config /etc/databases-everywhere/config.yml --bench
```

The safe default benchmark does not create, stop, or mutate database
instances. It performs:

- warmup requests followed by sequential authenticated heartbeat requests;
- a bounded concurrent heartbeat phase with attempted and successful
  requests/second plus min, mean, standard deviation, p50, p90, p95, p99, and
  maximum latency;
- real HTTP/1.1 WebSocket upgrades to `/ws/monitoring`, each using a fresh
  single-use JWT;
- `/proc` sampling of the running daemon and benchmark client, including peak
  CPU and resident RAM.

For a sustained test, specify the concurrent-phase duration in minutes and let
the client randomly choose a bounded set of currently running instances:

```bash
sudo dbev --config /etc/databases-everywhere/config.yml \
  --bench \
  --time 5 \
  --max_instances 4
```

`--time 5` is the friendly alias for `--bench-time-minutes 5`.
`--max_instances 4` (also `--max-instances` or
`--bench-max-instances`) fetches the daemon's instance list, filters it to
`running`, randomly chooses up to four, and records the exact selection in the
report. Half of the concurrent requests remain heartbeat requests; the other
half are distributed evenly over the selected instances' read-only status
endpoints. Automatic selection never starts, stops, imports, exports, or
otherwise mutates an instance.

Timed mode is rate-limit-aware by default. It sends concurrent bursts using at
most 80% of `security.api_rate_limit_per_minute` in each 60-second window and
reserves the rest for benchmark control calls and normal panel traffic. The
report separates wall-clock accepted req/s from active-burst accepted req/s,
so pacing does not hide the API's service capacity. WebSocket, import/export,
and final validation phases run before the throughput phase and therefore
cannot fail merely because the load phase exhausted a window.

On an isolated stress node, `--bench-unthrottled` disables this pacing. It
requires `--time` and can intentionally create large numbers of HTTP 429
responses. Raise the daemon's configured limit first; repeated rejections are
log-suppressed within each identity/window to prevent audit-log amplification.

Use a dedicated running instance when container resource sampling or
import/export throughput is required:

```bash
sudo dbev --config /etc/databases-everywhere/config.yml \
  --bench \
  --bench-instance perf-postgres \
  --bench-import-export
```

`--bench-import-export` is explicit destructive authorization. It queues a full
native export, waits for it to succeed, then imports that fresh artifact back
into the named instance. Logical imports are not transactional and may leave a
partially modified database if the native client fails. Redis, Valkey, and Qdrant stop
temporarily for their physical-volume import. Never target customer data; use
a disposable performance instance with representative data. After a successful
re-import the benchmark deletes only the export artifact it created. Add
`--bench-keep-artifact` to retain it. Failed imports retain it for diagnosis.

Add `--bench-recommend-manual-active-jobs` to that destructive, single-instance
run to request two report-only estimates from the daemon's live scheduler: a
worst-case compressed wipe at the configured upload maximum and the freshly
exported representative artifact. The report labels the method
`model_based_single_job_v1`, shows the separate memory/I/O/CPU ceilings, and
never writes configuration. It verifies that the benchmark config UUID and
token ID match the target daemon before making a recommendation. This is a
conservative single-job model, not an empirical concurrent saturation test;
dynamic mode remains preferable for mixed dump sizes. A reported recommendation
of `0` is preserved as a blocked-headroom signal and is not a valid value for
`manual_max_active_jobs`; do not apply it as a configuration change. A zero
raw CPU or I/O ratio may still produce a recommendation of one because those
weights permit exactly one isolated, memory-safe operation.

When instances are selected, the benchmark samples their containers directly
through the configured Docker or Podman socket. Multiple containers are
sampled round-robin, one per interval, to keep the stats observer from
distorting the load. Per-instance peaks and failed sample counts are reported.
CPU percentages use 100% for one fully occupied CPU core. Sampling can fail
temporarily while a physical import has intentionally stopped its container;
these gaps are counted in the report.

Useful controls:

| CLI option | Environment variable | Default |
| --- | --- | --- |
| `--bench-url` | `DBEV_BENCH_URL` | Configured local API listener |
| `--bench-host` | `DBEV_BENCH_HOST` | Configured/allowed request host |
| `--bench-instance` | `DBEV_BENCH_INSTANCE` | None |
| `--bench-max-instances` (`--max_instances`) | `DBEV_BENCH_MAX_INSTANCES` | `0` (disabled; maximum `32`) |
| `--bench-warmup-requests` | `DBEV_BENCH_WARMUP_REQUESTS` | `10` |
| `--bench-latency-samples` | `DBEV_BENCH_LATENCY_SAMPLES` | `50` |
| `--bench-requests` | `DBEV_BENCH_REQUESTS` | `400` |
| `--bench-time-minutes` (`--time`) | `DBEV_BENCH_TIME_MINUTES` | None (maximum `1440`) |
| `--bench-unthrottled` | `DBEV_BENCH_UNTHROTTLED` | Disabled; requires `--time` |
| `--bench-concurrency` | `DBEV_BENCH_CONCURRENCY` | `32` |
| `--bench-websockets` | `DBEV_BENCH_WEBSOCKETS` | `10` |
| `--bench-import-export` | `DBEV_BENCH_IMPORT_EXPORT` | Disabled |
| `--bench-recommend-manual-active-jobs` | `DBEV_BENCH_RECOMMEND_MANUAL_ACTIVE_JOBS` | Disabled; requires `--bench-instance` and `--bench-import-export` |
| `--bench-keep-artifact` | `DBEV_BENCH_KEEP_ARTIFACT` | Disabled |
| `--bench-timeout-seconds` | `DBEV_BENCH_TIMEOUT_SECONDS` | `900` |
| `--bench-sample-interval-ms` | `DBEV_BENCH_SAMPLE_INTERVAL_MS` | `250` |
| `--bench-output` | `DBEV_BENCH_OUTPUT` | Unique directory under `./dbev-benchmarks` |

`DBEV_BENCH=true` enables benchmark mode when an environment-only launch is
preferred. `--bench-insecure-tls` / `DBEV_BENCH_INSECURE_TLS=true` is available
for an explicitly selected local endpoint with a test certificate; it should
not be used against an untrusted network.

The benchmark deliberately goes through normal authentication, host policy,
request admission, and rate limiting. HTTP 429 responses are counted rather
than hidden. Raise `security.api_rate_limit_per_minute` on an isolated
performance node if the goal is measuring the server above the production
throttle.

The API rate limit is applied independently per authenticated
credential/transport-peer IP, rather than globally per token. IPv4 uses the
individual address and IPv6 uses a `/64` peer group. Unauthenticated requests
remain in bounded IP-derived buckets. Forwarding headers are intentionally not
trusted, so deployments behind a local reverse proxy are limited by the
proxy's transport IP unless the proxy uses separate source addresses.

Metric math is intentionally transparent:

- latency is measured through full HTTP response-body completion. Percentile
  `p` sorts the successful samples, places the rank at `(n - 1) * p`, and
  linearly interpolates adjacent samples for fixed phases. The concurrent phase
  uses an HDR histogram with three significant digits, allowing a multi-minute
  run to retain full-run percentiles, mean, and population standard deviation
  without memory growing with request count;
- wall HTTP throughput is `responses / phase wall seconds`. Active throughput
  excludes intentional fixed-window pacing waits and is
  `responses / time actively dispatching and completing bursts`. Offered,
  accepted, active accepted, 429 percentage, status-code counts, transport
  failures, and successful-only latency are all retained so neither pacing nor
  rate limiting can make a run look faster;
- WebSocket time starts immediately before the upgrade request and ends only
  after a valid `101`, upgrade headers, RFC 6455 accept value, and `dbe.jwt`
  subprotocol are received. JWT mint latency is a separate phase;
- import/export MiB/s is `artifact bytes / persisted job elapsed seconds`,
  using the job's server-side `created_at` and `updated_at`. Client wall time
  and enqueue HTTP latency are reported separately, so polling cadence and
  queue delay remain visible;
- Linux process CPU is
  `process tick delta / host tick delta * logical CPUs * 100`. Container CPU
  uses the equivalent runtime counters. Thus `100%` means one fully occupied
  core and values above `100%` are valid. RAM is resident process memory or
  runtime-reported container memory, and every peak is the maximum sampled
  value rather than an average.

After the run, an organized ASCII-safe dashboard is printed to the terminal,
avoiding locale-dependent box-drawing corruption. Status, failures, throughput,
latency, and diagnostics are colored when stdout is an interactive terminal.
Set `NO_COLOR=1` to disable ANSI color, or `CLICOLOR_FORCE=1` to retain it when
piping output.

Each run writes owner-only files and refuses to overwrite an existing report:

- `report.json` — machine-readable options, environment, summaries, and peaks;
- `report.md` — human-readable comparison tables;
- `request-samples.csv` — measured requests and WebSocket handshakes. At most
  100,000 concurrent-phase rows are retained as a uniform reservoir; JSON
  counters and HDR latency aggregates still cover every request;
- `resource-samples.csv` — timestamped daemon, client, and container samples;
- `diagnostics.log` — warnings and failures without API tokens or host paths.
