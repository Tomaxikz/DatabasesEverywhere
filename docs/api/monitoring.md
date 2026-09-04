# Monitoring

[Documentation index](../README.md) · [OpenAPI](openapi.yml)

| Endpoint | Scope | Purpose |
| --- | --- | --- |
| `GET /api/instances/{id}/resources` | `resources:read` | One tenant's resource report |
| `GET /api/instances/{id}/activity` | `resources:read` | Live attributed activity |
| `GET /api/instances/{id}/activity/history` | `resources:read` | Durable activity buckets |
| `GET /api/admin/resources` | `resources:admin` | Node-wide resource reports |
| `GET /api/admin/shared-pools` | `resources:admin` | Physical pool capacity and health |
| `GET /api/admin/resources/summary` | `resources:admin` | Node placement/admission view |

Use [WebSockets](websockets.md) for live dashboards rather than polling each DB.

## Resource scope

| Value | Dedicated instance | Shared tenant |
| --- | --- | --- |
| Scope | `dedicated_instance` | `shared_tenant` |
| CPU/RAM usage | Container measurement, or null if unavailable | Null; not individually attributable |
| Configured CPU/RAM | Runtime limits | Reservations against shared pool capacity, not tenant cgroup ceilings |
| Disk | Instance boundary | Tenant boundary; inspect reported enforcement strength |
| RX/TX | Routed gateway bytes | Routed gateway bytes for this tenant |

Example dedicated report:

```json
{
  "instance_id": "cust-42-db",
  "runtime_id": "cust-42-db",
  "protocol": "postgres",
  "deployment_mode": "dedicated",
  "scope": "dedicated_instance",
  "status": "running",
  "cpu": { "configured_cores": 1.0, "usage_percent": 12.5 },
  "memory": { "configured_mib": 2048, "usage_bytes": 104857600, "limit_bytes": 2147483648 },
  "disk": {
    "configured_mib": 10240, "limit_bytes": 10737418240, "used_bytes": 52428800,
    "enforced": true, "enforcement_method": "fuse_quota", "enforcement_strength": "hard"
  },
  "network": { "rx_bytes": 1234, "tx_bytes": 5678 }
}
```

### Rendering rules

- CPU is percentage points: `11.0` means 11%. One fully used core is 100%;
  multi-core usage can exceed 100%.
- CPU uses container CPU-time delta divided by elapsed wall time. Each running
  physical runtime is sampled independently of clients, normally once per second.
- Linux memory is the Docker-compatible working set: cgroup usage minus inactive
  file cache.
- RX is bytes delivered to the backend; TX is bytes returned. Counters start at
  daemon boot and may include routed authentication attempts. They are not billing
  totals and do not include traffic outside the gateway.
- Null means unavailable, not zero. Preserve the last chart point and show a gap
  or unavailable state rather than fabricating a zero.
- Only admin reports expose whole-pool CPU/RAM. Deduplicate by `runtime_id`;
  never show pool values as one tenant's usage or limits.

Pool CPU, memory, and disk reports include `sample` metadata: source, timestamp,
age, freshness, and state (`fresh`, `warming`, `stale`, `stopped`, `failed`).
Non-fresh usage is null and includes a public diagnostic.

Disk fields distinguish hard quotas from soft enforcement. Scanner reports can
include logical/physical bytes, growth, predicted time to limit, stop/recovery
thresholds, restart blocking, and sample age. See [disk limits](../operations/disk-limits.md)
for the actual boundaries and shared-engine restrictions.

## Tenant activity and history

Live activity includes classified `read`, `write`, `ddl`, and `other`
operations, connections, network bytes, a `stats_epoch`, and source labels.

For gateway observations, `accepted` means forwarded, not successfully executed
by the database. `rejected` means DBEV blocked it before forwarding. Label
charts **forwarded / DBEV-rejected**, not successful/failed queries.

Optional `cpu_time_micros` and `peak_query_memory_bytes` are engine query-cost
observations, not cgroup CPU/RSS or limits. Honor `sources` on every sample:

- Unsupported or unavailable collection yields null, not a measured zero.
- MySQL reports advances in a per-user memory high-water mark after a startup/
  recovery baseline; smaller queries below that mark cannot be distinguished.
- ClickHouse query memory is an interval observation. Shared ClickHouse counts
  completed query-log entries as `engine_query_log_observed`; dedicated
  ClickHouse or a failed collector reports unavailable operation telemetry.
- MongoDB sessions are counted only after successful authentication to the exact
  tenant; unauthenticated discovery sockets do not become tenant sessions.

History targets one-minute intervals. Use each bucket's `duration_seconds`
when sampling is delayed. `limit` defaults to 240 and is clamped to 1–1,440;
`before` is an exclusive Unix timestamp. At most 1,440 buckets are retained
per tenant (normally about 24 hours).

Use deltas for cumulative live counters and reset baselines on epoch changes.
Break chart lines at `gap: true`. `operations_observed: false` means unavailable
telemetry, not zero operations. History survives restarts and is deleted with
the instance; sub-minute shutdown intervals are not promoted to full buckets.

### Privacy

SQLite and public activity responses contain aggregates only—no SQL text, bind
values, client addresses, or engine errors.

Shared ClickHouse's protected engine-side query log temporarily holds records
to derive aggregates. Query text is truncated to 1 KiB, volume is subject to a
per-tenant hourly quota, and a two-hour TTL is an asynchronous retention target,
not an exact deletion deadline. Tenants cannot read or change this logging.
Only aggregates leave the collector.

## Node scheduling

`/api/admin/resources/summary` separates reserved allocations, actual managed
container usage, and whole-host pressure.

- Stopped/failed instances retain reservations until deleted.
- Shared tenants plus the unreserved pool remainder count the pool only once.
- Host CPU uses `/proc/stat`; memory uses `MemAvailable`; disk uses the
  filesystem backing `paths.volumes`. Host pressure includes unrelated workloads.
- Managed CPU/RAM totals are null if a required runtime sample is unavailable,
  rather than reporting a misleading partial sum.
- `allocation_limit_bytes` and `reserved_bytes` expose memory/disk admission
  limits; CPU admission uses `total_cores`. Guard switches come from `/api/system`.

Poll the summary every 10–30 seconds for placement. Prefer reservation capacity,
then consider host pressure. Always handle a create/resize rejection: capacity
can change after the panel's last sample.
