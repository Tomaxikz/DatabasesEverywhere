# System endpoints

[Documentation index](../README.md) · [OpenAPI](openapi.yml)

| Method | Path | Scope | Purpose |
| --- | --- | --- | --- |
| GET | `/api/system` | `system:read` | Identity, versions, capabilities, API/gateway readiness |
| GET | `/api/heartbeat` | `system:read` | Cheap management liveness check |
| PATCH | `/api/system/config` | `config:admin` | Persist allowed configuration changes |
| GET | `/metrics` | `metrics:read` | Prometheus metrics |

See [monitoring](monitoring.md) for resources, shared pools, and placement data.

## Readiness and restart

Heartbeat returns `{"status":"ok"}` when its authenticated handler is reachable.
It does not prove that a gateway or database is ready. Use `api_readiness`,
`gateways.status`, and individual instance status separately.

The API opens after critical metadata, recovery, runtime, and disk checks.
Desired-running instances start in a bounded background phase; gateway
publication waits for startup and required hardening. A broken instance is
isolated rather than blocking every management endpoint.

Existing dedicated containers and shared pools whose desired state is running
auto-start on node/daemon boot. Intentional stops, quarantine and pending
destructive recovery remain authoritative; missing containers are not recreated.
Two consecutive unconfirmed starts block further automatic activation, including
command-timeout recovery. The runtime-owned count survives daemon restarts and
is cleared only by successful startup readiness. After repairing the cause, use
the existing instance/pool `power` endpoint with `start` or `restart` to retry.
Readiness polls do not consume attempts or restart containers themselves.

Docker/Podman restart policies are disabled for managed containers, including
existing ones at boot. DBEV owns activation so quotas and stop intent are checked
first; there is no second unbounded container-engine restart loop.

Daemon restart normally leaves containers and healthy quota mounts running.
Shutdown closes mutation admission and uses bounded drains for mutations/jobs,
API connections, WebSockets, and gateway sessions. WebSockets receive close
1012; clients must reconnect. Heartbeat has separate bounded admission;
non-streaming handlers have a 15-minute deadline.

Successful PostgreSQL/MySQL hardening is privately attested against container
start identity, credentials, route identity, and hardening revision. Unchanged
daemon restarts reuse it; container restarts/replacements, credential changes,
or missing/invalid attestations rerun checks. Attestation failures never bypass
hardening.

## Configuration changes

Patches merge JSON objects; null removes a key. Successful responses report
`restart_required: true`: the file changes immediately, running services do not.

Protected fields include node identity/secrets, paths, images, the S3 endpoint,
and executable backup/Fuse helpers. Replacing/nulling their ancestors is also
rejected. Edit these deliberately on the host instead.

API self-upgrade is unsupported. Keep `security.self_upgrade_enabled: false`
and use the normal host/release deployment process.

## Recovery states

Quarantine preserves metadata/data while stopping the instance and blocking its
route. Inspect the cause before deletion or an explicit recovery action.

| Condition | Behavior / operator action |
| --- | --- |
| Legacy bridge/TCP backend | Quarantined; preserve data, recreate with private sockets, then import |
| PostgreSQL tenant is the bootstrap superuser | Gateway blocked; export/preserve data and recreate with a restricted tenant |
| Missing/unverifiable protected credentials | Keep isolated; recover known credentials/key or use the documented reset/recreation path |
| Duplicate route identity | First deterministic claimant survives; others are quarantined |
| Unclean exit during running import/export | Failed job and quarantined instance; verify database integrity offline |
| Queued job interrupted before execution | Failed job; no quarantine solely for waiting |
| Retained physical-restore workspace | Quarantine until the replacement/recovery state is verified |
| Interrupted creation cleanup | Normal retry refuses stale resources; preserve data before explicit purge |

`purge_stale_resources: true` irreversibly removes the exact instance ID's
orphaned container/paths before recreation. It is not a routine retry option.
Use the [recovery API](transfers.md#recovery) and
[maintenance guide](../operations/setup.md#upgrades-and-maintenance) as appropriate.

Job queues and history are bounded: queue settings live under
`artifacts.import_export_scheduler`; the cache retains at most 2,048 completed
jobs and SQLite the latest 10,000. Queued/running records are not pruned.
