# Resource reports

[Documentation index](../README.md)

`GET /api/admin/resources` and `GET /api/instances/{id}/resources` return:

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
  "disk": { "configured_mib": 10240, "limit_bytes": 10737418240, "used_bytes": 52428800,
            "enforced": true, "enforcement_method": "fuse_quota", "enforcement_strength": "hard" },
  "network": { "rx_bytes": 1234, "tx_bytes": 5678 }
}
```

For a shared tenant, `scope` is `shared_tenant`; its CPU and memory usage/limit
fields are `null` because the runtime cgroup cannot attribute them to one
logical database. `cpu.configured_cores` and `memory.configured_mib` are that
tenant's reservations against aggregate pool capacity, not per-tenant cgroup
measurements or ceilings. Only administrator-scoped resource reports and
`/api/admin/shared-pools` add the physical pool values:

```json
"pool": {
  "runtime_id": "pool_mysql_01",
  "cpu_limit_cores": 8.0,
  "cpu_usage_percent": 225.0,
  "memory_limit_bytes": 17179869184,
  "memory_usage_bytes": 4294967296
}
```

Tenant-scoped REST and WebSocket responses never contain this object. Those are
whole-pool values; panels must deduplicate them by `runtime_id` and
must not relabel them as tenant usage. CPU and memory usage fields are `null`
when the physical runtime isn't running or container stats aren't available
yet. CPU usage is reported in percentage points:
`11.0` means 11%, not `0.11`; panels must not divide or multiply it by 100. DBEV
uses the Calagopus wings-rs sampling model: one non-streaming Docker counter
snapshot per running physical runtime per second. CPU is the change in container CPU
time divided by the real wall-clock time between snapshots, so one fully used
core is 100% and multi-core workloads can exceed 100%. Sampling is independent
from REST and WebSocket delivery, so client activity cannot change the readings.
On Linux, memory usage is the Docker-compatible working set (raw cgroup usage
minus inactive file cache), not raw cgroup usage. Network counters are measured after DBE selects
the tenant's gateway route and can therefore include a routed authentication attempt. Managed containers use
`network_mode=none`; RX is traffic delivered to the database and TX is traffic
returned by it. The counters start at zero on daemon boot. For continuous
monitoring use the WebSocket instead of polling this.

Each CPU, memory, and disk object returned by
`/api/admin/shared-pools` also contains a `sample` object. Its `source`,
`sampled_at_unix`, `sample_age_seconds`, and `fresh` fields describe the
physical measurement rather than the HTTP response time. `state` is one of
`fresh`, `warming`, `stale`, `stopped`, or `failed`; a non-fresh usage value is
always `null`, never a fabricated zero. Non-fresh samples include a bounded
public `diagnostic` code/message, while the underlying runtime or filesystem
error remains in daemon logs. Panels should preserve the last chart point and
show this state instead of dropping the whole pool or resetting it to zero.

## Tenant activity and history

`GET /api/instances/{id}/activity` returns counters attributed at the DBEV
gateway: authenticated sessions where the wire protocol permits exact
post-authentication tracking, forwarded and DBEV-rejected operation categories, and
exact bytes after a gateway route is selected. It stores only `read`, `write`, `ddl`, and `other`
counts—never SQL text, prepared values, client addresses, or database errors.
The monitoring WebSocket includes the same cumulative `activity` fields for
live charts.

For gateway-sourced protocols, `accepted` means DBEV accepted and forwarded the
operation to the backend; it does **not** prove that the database executed it
successfully. Syntax errors, constraint failures, and transaction conflicts can
therefore still appear under `accepted`. `rejected` counts only operations DBEV
blocked before the backend. Panels must label these as forwarded/DBEV-rejected,
not successful/failed queries. ClickHouse's separately source-labelled engine
observer counts completed query-log entries.

The optional `cpu_time_micros` and `peak_query_memory_bytes` fields are
engine-observed query costs, not tenant cgroup CPU, RSS, or enforceable limits.
They remain `null` when a database cannot expose a defensible per-user value;
zero is returned only after a supported collector has measured a real zero.
MySQL exposes a cumulative per-user memory high-water mark. DBEV baselines the
first value after startup or collector recovery and reports only later advances,
so work that predates monitoring is never charged to a live or history interval.
Queries below an existing MySQL high-water mark cannot be distinguished by that
engine counter. ClickHouse query-memory values are interval observations.
Shared ClickHouse operation categories come from its bounded aggregate query
log. Dedicated ClickHouse and a shared pool without a working collector report
them as unavailable rather than inventing zero activity.
Each current response includes a `sources` object so a panel can label exact,
observed, partial, and unavailable data honestly.

`GET /api/instances/{id}/activity/history` targets a 60-second sampling cadence.
If the sampler is delayed, it emits one aggregate for the complete elapsed
interval instead of inventing smaller buckets; `duration_seconds` is the
authoritative interval width. `limit` is clamped to 1–1440 (default 240), `before` is an exclusive
Unix timestamp, and at most 1440 buckets—24 hours—are retained per tenant.
Buckets use deltas for cumulative counters. A `gap: true` bucket means a reset
or discontinuity was detected; panels must break the chart line instead of
inventing a spike. `operations_observed` distinguishes a measured all-zero
interval from one where operation telemetry was unavailable. History
contains aggregates only and is deleted with the instance. On a clean daemon
shutdown DBEV retries any already-prepared SQLite
batch and persists a final bucket when at least the target minute is due. A
sub-minute partial interval is intentionally discarded rather than stretched
or presented as a complete minute.

Shared tenant disk capacity is enforced independently whenever the host can
provide safe native directory project quotas. On XFS, ext4, or F2FS volumes
mounted with project quotas, new PostgreSQL, MySQL, and MariaDB shared tenants
receive their own hard byte boundary. PostgreSQL stores each tenant in a
daemon-owned tablespace; MySQL and MariaDB use their encoded schema directory
with file-per-table enabled. Gateway policy rejects database recreation and
table-storage clauses that could move a MySQL-family tenant outside that
directory. The quota is restored before the tenant route is opened at boot,
start, migration cutover, or rollback, and a hard-quota tenant is never fenced
by the periodic catalog sampler: the kernel returns the engine's normal
disk-quota error while reads and deletions remain possible. Hard-tenant usage
comes from the filesystem's project-quota counter in constant time; DBE does
not recursively walk every tenant directory for periodic metrics. Recursive
physical measurement is reserved for a fenced disk-shrink admission check.

The pool root quota is derived rather than double-counted. It covers engine
overhead plus soft, unattached, and recovery reservations; a tenant is removed
from that root charge only after its hard child quota and exact placement
identity are durable. Boot temporarily restores the conservative aggregate,
revalidates every child boundary while routes are closed, then lowers the root
to the derived value before publishing routes. Project-ID claims likewise move
from pending to active only after path adoption and the kernel limit succeed,
and released IDs are tombstoned instead of being reused. The root also keeps
`ceil(5%)` of all tenant disk reservations, capped at 8 GiB per pool, for WAL,
redo/undo logs, journals, and other tenant-induced files that the engine stores
outside tenant child projects. Node admission charges the same spill reserve,
including its marginal growth when adding a tenant to an existing pool.

MongoDB and ClickHouse do not currently expose a stable per-database directory
boundary in DBE's supported layouts. They therefore retain the catalog-measured
soft guard. The same truthful soft fallback is used for every tenant when the
node uses FuseQuota, the soft scanner, Btrfs, ZFS, or a filesystem without
native project quotas. The shared runtime still has its aggregate pool limit,
and placement admission never reserves more tenant capacity than that pool.
Existing PostgreSQL shared databases created in `pg_default` remain soft until
they are recreated or migrated into a managed tenant tablespace; DBE never
relabels the whole PostgreSQL data directory as one tenant.

Shared PostgreSQL tenants are deliberately not granted the database-level
`TEMPORARY` privilege or CREATE access to global/default tablespaces. Explicit
temporary tables and alternate tablespaces would otherwise create uncharged
ways to consume pool storage. Engine-global files remain pool overhead rather
than tenant-attributed usage. This includes PostgreSQL WAL and MySQL/MariaDB
redo, undo, dictionary, and server temporary files; the hard tenant boundary
covers each tenant's persistent relation/table/index files, while the aggregate
pool limit and admission budget cover those shared engine files. PostgreSQL
pools reserve 2 GiB at the root so the default WAL/checkpoint cycle has
headroom independently of every tenant tablespace quota.

Shared ClickHouse tenants intentionally cannot run whole-table `DROP`/`DETACH`,
`FREEZE`, partition moves/fetches, or change table settings. ClickHouse uses the
same `DROP TABLE` privilege for whole-table detach, and detached/frozen files can
otherwise escape live catalog accounting. DBEV's administrator-scoped import,
restore, and tenant-deletion paths retain the required destructive privileges;
ordinary tenants keep bounded table creation, reads, writes, views, truncation,
and row/column/index/TTL alterations. Detached partition bytes are included in
the soft disk measurement.

One-time adoption of an existing soft-limited shared pool into native project
quotas stops the engine before relabelling any inode. A pool containing symlinks,
special files, foreign project IDs, or another ambiguous layout is left stopped
and quarantined instead of being followed or partially adopted. Keep that pool
on its prior soft mode, or migrate it through a tenant-scoped export into a new
shared pool.

Logical imports are route-fenced, session-drained, verified again after restore,
and rolled back before reopening the route if the restored tenant is too large.
Soft-guard tenants can still overshoot between samples. Use `dedicated` whenever
an independent cgroup or a hard boundary on a protocol/filesystem combination
outside the native shared support above is required.

The MongoDB gateway keeps credential-free monitoring sockets on a bounded
standalone `hello` response until a tenant route is known. A
`saslSupportedMechs` capability query never selects a tenant. DBE selects a
pending route only from a real SCRAM `speculativeAuthenticate` request or the
subsequent ordinary `saslStart`, authenticates that exact identity against the
real `mongod`, and rechecks the route revision before opening its tenant session
or network meter. MongoDB is allowed to omit a failed speculative-auth reply;
DBE forwards that successful `hello` and supports the driver's ordinary
`saslStart` fallback without accounting the unauthenticated socket. Failed auth
creates no tenant session. Once authenticated, identity-changing auth commands
on the same socket are rejected so a connection cannot gain or switch tenant
access after its route and accounting identity have been fixed.

Soft-scanner reports additionally expose nullable `scanner_logical_bytes`,
`scanner_physical_bytes`, current and peak `scanner_growth_bytes_per_second`,
`scanner_predicted_seconds_to_limit`, stop and recovery thresholds,
`scanner_restart_blocked`, and `scanner_sample_age_seconds`. These fields let a
panel show prediction and recovery state without presenting a soft stop as a
kernel quota.

`GET /api/admin/resources/summary` (scope: `resources:admin`) is the
node-scheduler view. It reports limits reserved by every managed instance,
actual usage by DBE containers, and pressure from the entire Linux host:

```json
{
  "node_uuid": "node-db-1",
  "sampled_at": "2026-07-12T12:45:00Z",
  "cpu": {
    "total_cores": 16,
    "allocated_cores": 9.5,
    "host_usage_percent": 42.7,
    "managed_usage_cores": 4.2
  },
  "memory": {
    "total_bytes": 68719476736,
    "allocation_limit_bytes": 68182605824,
    "reserved_bytes": 536870912,
    "allocated_bytes": 34359738368,
    "host_used_bytes": 28991029248,
    "managed_used_bytes": 12884901888,
    "available_bytes": 39728447488
  },
  "disk": {
    "total_bytes": 1099511627776,
    "allocation_limit_bytes": 1097364144128,
    "reserved_bytes": 2147483648,
    "allocated_bytes": 536870912000,
    "host_used_bytes": 429496729600,
    "managed_used_bytes": 268435456000,
    "available_bytes": 670014898176
  },
  "instances": {
    "total": 42,
    "creating": 0,
    "booting": 2,
    "running": 34,
    "stopped": 3,
    "failed": 1,
    "quarantined": 1,
    "deleting": 1
  }
}
```

Allocation includes stopped and failed instances because their limits remain
reserved and they may be restarted. Shared allocation counts every tenant
reservation plus only the unreserved remainder of each pool, so the physical
pool is counted exactly once. CPU is sampled from `/proc/stat`, memory
uses Linux `MemAvailable`, and disk capacity is measured on the filesystem
backing `paths.volumes`. Host usage includes DBE plus every other process on the
server. Managed CPU or memory usage is `null` if a running/booting container
could not be sampled; the endpoint does not return a misleading partial sum.
`allocation_limit_bytes` and `reserved_bytes` expose the daemon's authoritative
memory/disk admission policy, while CPU admission uses `total_cores`. The
current guard switches are returned by `GET /api/system` as
`prevent_cpu_overallocation`, `prevent_memory_overallocation`, and
`prevent_disk_overallocation`. Poll this endpoint every 10–30 seconds for
placement decisions and use allocation pressure as the primary scheduling
signal, with host pressure as a secondary signal. The panel's check is only an
optimization: it must handle a capacity rejection because host availability can
change between sampling and creation.
