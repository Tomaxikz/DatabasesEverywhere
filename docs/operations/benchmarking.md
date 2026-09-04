# Benchmarking a running node

Run a second `dbev` process on the same node as the running daemon:

```bash
sudo dbev --config /etc/databases-everywhere/config.yml --bench
```

The default is read-only: authenticated heartbeat latency and throughput,
real WebSocket upgrades with fresh tokens, and daemon/client CPU and resident
memory samples. It never creates, stops, or changes a database.

## Sustained API test

```bash
sudo dbev --config /etc/databases-everywhere/config.yml \
  --bench --time 5 --max_instances 4
```

This runs the concurrent phase for five minutes. Half the requests target
heartbeat; half target status endpoints for up to four randomly selected
running instances, recorded in the report. Selection does not mutate them.

Timed mode uses at most 80% of the configured API rate limit per minute,
leaving room for control calls and panel traffic. Reports distinguish paced
wall-clock throughput from active-burst throughput. WebSocket and validation
phases run before the load phase.

On an isolated stress node, `--bench-unthrottled` disables pacing; it requires
`--time` and can produce many HTTP 429 responses. Authentication, admission,
and rate limits still apply. Rejections are counted, not hidden.

## Import/export test — disposable data only

```bash
sudo dbev --config /etc/databases-everywhere/config.yml \
  --bench --bench-instance perf-postgres --bench-import-export
```

`--bench-import-export` explicitly authorizes replacing data in the named
running instance: export it, then import that artifact back. Logical imports
can leave partial changes on failure; physical Redis, Valkey, and Qdrant
imports temporarily stop the database. Never target customer data.

After success, the benchmark deletes only its own export artifact unless
`--bench-keep-artifact` is set. Failed imports retain it for diagnosis.

Optionally add `--bench-recommend-manual-active-jobs` for report-only
scheduler estimates using the representative export and a worst-case
compressed wipe. These are model-based single-job estimates, not concurrent
saturation measurements; they never update config. A recommendation of
`0` means insufficient headroom, not a valid `manual_max_active_jobs`
setting. Prefer dynamic scheduling for mixed dump sizes.

## Interpreting results

- HTTP latency includes reading the full response body. Reports keep accepted
  and offered throughput, successful-request latency, status counts, and
  transport failures separate.
- WebSocket timing measures a validated `101` upgrade; token minting is timed
  separately.
- Import/export throughput uses artifact bytes divided by persisted server
  job time. Client wall time and enqueue latency are reported separately.
- CPU `100%` means one busy core; higher values are valid. Memory and CPU
  peaks are sampled maxima, so brief spikes can be missed.
- Selected containers are sampled directly through Docker/Podman, round-robin
  to limit observer overhead. Failed samples, including intentional stops
  during physical imports, are counted.

Use `dbev --help` for all flags and environment variables, including
`--bench-url`, `--bench-concurrency`, and `--bench-output`.
`--bench-insecure-tls` is only for an explicitly selected local test
endpoint, never an untrusted network.

## Reports

Each run creates owner-only files in a unique directory under
`./dbev-benchmarks` by default and refuses to overwrite an existing report:

| File | Contents |
| --- | --- |
| `report.json` | Options, environment, summaries, and peaks |
| `report.md` | Human-readable comparison |
| `request-samples.csv` | Requests and WebSocket handshakes |
| `resource-samples.csv` | Daemon, client, and container samples |
| `diagnostics.log` | Warnings and failures, excluding tokens and host paths |

The concurrent CSV retains at most 100,000 sampled rows; counters and latency
aggregates still cover the full run. A terminal summary is also printed.
