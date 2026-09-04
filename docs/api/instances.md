# Instances

[Documentation index](../README.md)

An instance is one logical database tenant. In `dedicated` mode it owns one
engine runtime; in `shared` mode it is isolated inside a managed engine runtime
used by other tenants. The `InstanceMetadata` object returned by most instance
endpoints looks like:

```json
{
  "schema_version": 1,
  "instance_id": "cust-42-db",
  "deployment_mode": "dedicated",
  "runtime_id": "cust-42-db",
  "protocol": "postgres",
  "status": "running",
  "public": { "host": "db.example.com", "port": 5432 },
  "backend": { "...": "internal endpoint info" },
  "runtime": { "kind": "docker", "container_name": "...", "network_mode": "none" },
  "database": { "name": "app_db", "username": "app_user" },
  "limits": {
    "cpu_cores": 1.0, "memory_mib": 2048, "disk_mib": 10240,
    "disk_enforced": true, "disk_enforcement_method": "fuse_quota"
  },
  "image": {
    "current": "postgres:18.4",
    "configured": "postgres:18.4",
    "update_available": false
  },
  "database_version": {
    "current": "18.4",
    "error": null
  },
  "created_at": "2026-07-01T12:00:00Z",
  "updated_at": "2026-07-01T12:00:00Z"
}
```

`status` is one of `creating`, `booting`, `running`, `stopped`, `failed`, `quarantined`, `deleting`. Instance reads refresh durably running instances from the container runtime, and the daemon subscribes to managed-container lifecycle events so starts, stops, exits, pauses, restarts, destruction, and OOM failures update durable routing state without polling every database. A container process alone never promotes a pre-ready, failed, quarantined, deleting, desired-stopped, or temporarily route-fenced maintenance state to `running`. A bounded real database query confirms readiness only during create/start/restart; no scheduled query continues after startup. `protocol` is one of `postgres`, `mariadb`, `mysql`, `redis`, `valkey`, `mongodb`, `clickhouse`, `qdrant`.
Power actions also persist an internal desired state without adding a field to the API response. Explicitly stopped or killed instances remain stopped across daemon and container-engine restarts; desired-running instances are reattached when already running and are started only when the runtime reports them stopped or failed. Quarantined instances are always desired-stopped and never enter gateway routing.
For dedicated instances, `image.update_available` compares the running image
with the configured protocol default. Shared instance reads report the
authoritative pool image and keep `update_available` false because a tenant
cannot update the pool image through the instance image endpoint.
`database_version.current` comes from a durable compatibility attestation bound to the exact managed container ID, immutable image ID, and DBEV probe revision. Read endpoints never execute commands in database containers. DBEV probes once at creation and for legacy unattested containers, then only after reconstruction, image update/migration, or password reset. An ordinary daemon restart or stop/start reuses the attestation when the container and image are unchanged. A missing/failed proof leaves `current` null with a short diagnostic; an unsupported detected version is isolated before its gateway route is published.

DBEV v0.8.0 tests and admits these engine families: PostgreSQL 14-18; MySQL 8.0.11+, 9.x, and 26.x; MariaDB 10.11/11.4/11.8/12.3; MongoDB 7-8; Redis 6.2/7.2/7.4/8.x; Valkey 7.2/8.x/9.x; ClickHouse 25-26; and Qdrant 1.17-1.18. The live probe is authoritative—the image tag is only an upgrade hint. The shared gateways advertise client-compatible baselines (`8.0.11` for MySQL and MariaDB's standard `5.5.5-10.11.0-MariaDB` compatibility form) because the target instance is unknown until the client sends its username. Neither carries a DBEV suffix; backend authentication and actual `SELECT VERSION()` traffic still go to the attested engine. Cluster, replication, Sentinel, `mongos`, load-balanced MongoDB, MySQL X Protocol, PostgreSQL replication/GSS encryption, ClickHouse compatibility listeners, and distributed Qdrant routing remain deliberately outside the single-instance gateway model.

The normal Rust suite includes fragmented, malformed, and golden packet fixtures under `src/app/protocols/tests`. CI additionally runs the actual DBEV gateways against official MySQL 8.4/9.7/26.7 and MariaDB 10.11/11.4/11.8/12.3 containers using MariaDB CLI, Connector/J 8.4/9.2/9.7, MariaDB Connector/J, and HikariCP. It covers explicit and deferred catalog selection plus standard post-greeting `CLIENT_SSL`; release builds are gated on that matrix rather than trusting only DBEV-generated packets.

| Method | Path | Scope | What it does |
| --- | --- | --- | --- |
| GET | `/api/instances` | instances:read | List all instances with their live classified container statuses |
| POST | `/api/instances` | instances:write | Accept instance creation and return `202` immediately |
| GET | `/api/instances/{id}` | instances:read | Fetch one with its live classified container status |
| DELETE | `/api/instances/{id}?confirm=true&reason=customer%20requested%20deletion` | instances:write | Irreversibly delete the instance's job history, imports, exports, backups, recovery data, and database contents; dedicated placement removes its engine runtime, while shared placement removes only its tenant and removes the pool runtime only after its final tenant is gone; confirmation and an audit reason are required |
| GET | `/api/instances/{id}/status` | instances:read | Status plus creation progress while available |
| POST | `/api/instances/{id}/power` | instances:write | Unified power API: `{ "action": "start" | "stop" | "restart" | "kill" }` |
| POST | `/api/instances/{id}/reconcile` | instances:write | Re-sync stored status with the runtime |
| PATCH | `/api/instances/{id}/limits` | instances:write | Update CPU/memory/disk limits |
| PATCH | `/api/instances/{id}/password` | instances:write | Atomically rotate the tenant password/API key in place where supported, validate, and roll back on failure; `restarted` reports the limited recreation fallback |
| PATCH | `/api/instances/{id}/image` | instances:write | Move a dedicated instance to a new image; shared tenants return `409` |
| GET | `/api/instances/{id}/deployment-migrations` | instances:read | List durable dedicated/shared placement migration attempts |
| POST | `/api/instances/{id}/deployment-migrations` | instances:write | Accept a crash-recoverable placement migration and return `202` plus a status `Location` |
| GET | `/api/instances/{id}/deployment-migrations/{migration_id}` | instances:read | Read durable migration progress and a sanitized stable failure code/message when present |
| GET | `/api/instances/{id}/resources` | resources:read | Live resource report |
| GET | `/api/instances/{id}/activity` | resources:read | Current tenant-attributed connections, network, operation classes, and supported engine query-cost observations |
| GET | `/api/instances/{id}/activity/history?before=&limit=` | resources:read | Up to 24 hours of tenant activity buckets sampled on a target one-minute cadence |
| GET | `/api/admin/resources` | resources:admin | Resource reports for everything |
| GET | `/api/admin/shared-pools` | resources:admin | Physical shared-pool capacity and current aggregate CPU, memory, and disk usage |
| GET | `/api/instances/{id}/logs?tail=200` | logs:read | One-shot logs for a dedicated instance; shared-pool logs return `409`; `tail` is clamped to 1-2000 lines |

Tenant activity storage contains aggregate counters only: DBEV never copies SQL
text, bind values, client addresses, or engine errors into SQLite or its API.
Shared ClickHouse pools are the narrow engine-side exception: their protected
`system.query_log` temporarily buffers query records so DBEV can derive CPU,
peak-memory, and operation aggregates. Query text is truncated to 1 KiB, query
volume has a hard per-tenant hourly quota, and the table has a two-hour TTL.
ClickHouse applies TTL cleanup asynchronously, so this is a retention target,
not an exact deletion deadline. Tenant roles cannot read the table or alter the
required logging settings; DBEV persists and exposes aggregates only.

Lifecycle calls are idempotent-ish: starting a running instance or stopping a stopped one is a no-op, not an error.
For shared tenants, power actions fence or reopen only that tenant's login, routes,
and sessions; they never stop or kill the physical pool used by other tenants.

Once an authenticated create request passes request/image validation, the daemon
returns `202 Accepted` and provisioning continues in a tracked background task.
The response contains an origin-relative `status_url`. Poll that URL or use the
monitoring WebSocket; failed creation remains observable there with its final
stage and message. SIGTERM closes creation admission and drains accepted creation
tasks before the process exits. The per-instance lock continues to serialize
operations, creation admission is bounded to 64 accepted tasks, and failed
provisioning still runs managed container/path cleanup.

## Creating an instance

```json
POST /api/instances
{
  "instance_id": "cust-42-db",
  "protocol": "postgres",
  "deployment_mode": "dedicated",
  "database": "app_db",
  "username": "app_user",
  "password": "generated-by-panel",
  "public_host": "db.example.com",
  "public_port": 5432,
  "project_id": "optional-grouping-id",
  "limits": { "cpu_cores": 1.0, "memory_mib": 2048, "disk_mib": 10240 }
}
```

Accepted response:

```json
{
  "instance_id": "cust-42-db",
  "status": "creating",
  "status_url": "/api/instances/cust-42-db/status"
}
```

Validation rules your panel should mirror so users get nice errors:

- `database` and `username`: 1–63 chars, must start with an ASCII letter, then letters/digits/`_`/`-` only. Reserved names are rejected (`postgres`, `mysql`, `admin`, `root`, `default`, `dbe_admin`, `dbe_health`, and a few more).
- `password` and `public_host` must be non-empty.
- `deployment_mode` may be omitted and defaults to `dedicated`. `shared` is
  supported for PostgreSQL, MySQL, MariaDB, MongoDB, and ClickHouse and is
  rejected for Redis, Valkey, and Qdrant.
- The selected protocol must have `enabled: true` in
  `GET /api/system.deployment_capabilities`; disabled protocols return `400`
  before provisioning starts.
- `cpu_cores` must be finite and between `0.01` and `1024`; `memory_mib` must be between `1` and `1048576` (1 TiB); and `disk_mib` must be greater than zero. MongoDB and ClickHouse additionally need at least 1024 `memory_mib` **and** 1024 `disk_mib` or they won't even boot.

On Linux hosts that expose CFS burst controls, DBE automatically lets each
CPU-limited managed container accumulate one quota window of unused CPU credit.
This reduces short quota-bound stalls without changing the sustained CPU limit.
The policy is fixed and has no API or configuration setting. DBE reapplies it
after starts, restarts, resource updates, external activations, and daemon boot.
Older kernels or restricted cgroup namespaces retain the ordinary CPU quota and
produce an operator warning; container startup is never blocked solely because
burst control is unavailable.

PostgreSQL clusters use a randomly protected internal `dbe_admin` bootstrap role
that is never registered as a gateway route. The requested username is created
separately as the database owner with `LOGIN` and without superuser, role-creation,
database-creation, replication, inheritance, or row-security bypass privileges.
The one-time PostgreSQL startup readiness check performs a real query against
`POSTGRES_DB`; it does not rely on `pg_isready`, which can report that the
temporary initialization server is accepting connections before the requested
database exists. The query is retried only during the bounded startup window and
is not installed as a permanent container healthcheck.

PostgreSQL instances created by older DBE builds may have used the tenant as the
immutable bootstrap superuser. DBE refuses to open gateways when it detects that
legacy layout because PostgreSQL cannot safely demote that role. Export the data
through the management API, recreate the instance with explicit stale-resource
purging, and import the dump to migrate it to the restricted tenant layout.

For recoverable legacy instances that have the restricted internal administrator
but still use `trust` or `peer` for local socket access, password reset verifies
the protected administrator password directly against PostgreSQL's SCRAM verifier.
It then rotates the tenant password, replaces the legacy local rules with
`scram-sha-256`, and confirms that an incorrect password is rejected before the
gateway route is restored. A password-bypassing socket connection is never treated
as proof that a maintenance credential is valid.

## Migrating between dedicated and shared placement

The panel chooses the target placement; DBEV owns the crash-recoverable data
move. Submit exactly one target mode:

```json
POST /api/instances/{id}/deployment-migrations
{ "target_mode": "shared" }
```

An accepted request returns `202`, the initial `DeploymentMigration` record,
and an origin-relative `Location` header. Poll that URL until `stage` is
`completed`, `failed`, or `cancelled`. The record's `revision` increases on each
durable transition. Optional `failure_code` and `failure_message` fields are
stable, sanitized operator guidance; raw engine output remains in daemon logs.
`manual_intervention` is deliberately nonterminal: the route stays fenced until
an operator repairs the recorded condition offline. Daemon startup recovery does
not automatically replay records in this stage.

Only PostgreSQL, MySQL, MariaDB, MongoDB, and ClickHouse accept a `shared`
target. Redis, Valkey, and Qdrant return `400`. A migration returns `409` when
the source is stopped, fenced, disk-blocked, missing its current encrypted
tenant credential, already in the target mode, or already has active data work
or a migration. Invalid JSON shape or an unknown `target_mode` returns `422`.
The source remains authoritative until atomic cutover. Existing backups are
not rewritten or deleted; their restore compatibility continues to be governed
by the `protocol` and `layout` fields described below.

## Updating limits

```json
PATCH /api/instances/{id}/limits
{ "cpu_cores": 2.0, "memory_mib": 4096, "disk_mib": 20480 }
```

All three fields are required. Same protocol floors apply as at create time.
For a shared tenant, reducing `disk_mib` briefly fences new sessions and drains
existing ones while DBE measures the tenant's physical data. The request returns
`409 conflict` and keeps the old limit when that data does not fit; successful
hard-quota resizes update the existing project limit without relabeling another
tenant's files.

## Changing the image

```json
PATCH /api/instances/{id}/image
{ "image": "postgres:18.4", "password": "the-instance-password" }
```

This pulls the image, deletes the old container, and recreates it on the same data volume. Current instances use the tenant credential from DBE's encrypted private metadata. The optional `password` field remains a compatibility fallback for legacy instances created before that credential was stored. Images must be pinned — a non-`latest` tag or a `@sha256:` digest; bare `postgres` or `postgres:latest` gets a `400`.

The requested image must also be allowed in `images.allowed.<protocol>`. The configured default image at `images.<protocol>` is always implicitly allowed. Keep the allowlist short and admin-controlled; do not pass arbitrary user input here.

At daemon boot, each desired-running dedicated instance is compared with its explicitly configured protocol image. A different pinned configured image is applied through the same rollback-aware update path as the API; a supported major change uses the existing export/import migration. Shared tenants cannot replace a pool image in place: existing pools keep their pinned image, while new creates or explicit deployment migrations select a compatible pool. DBEV never follows an arbitrary `latest` tag. Failures are isolated per instance so healthy listeners still start. Internal runtime-spec changes that require container reconstruction (for example, adding Qdrant's private REST socket) also run once through the same safe replacement path.

Patch/minor updates stay in-place. Major version changes are blocked unless the panel sends an explicit migration request:

```json
PATCH /api/instances/{id}/image
{
  "image": "mongo:8.3.4",
  "password": "the-instance-password",
  "major_upgrade": true
}
```

For Postgres, MariaDB, MySQL, MongoDB, and ClickHouse, `major_upgrade: true` runs a safer provider-style migration. DBEV first removes the gateway route and restarts the source once, which closes established client sessions before taking the logical dump; new writes therefore cannot race the snapshot and disappear at cutover. It then preserves the old volume, recreates the same instance id on a fresh target-version volume with the same database name, username, password, public endpoint, and limits, imports the dump, validates and hardens the replacement, and retains the old volume path plus export artifact for rollback. A failure before cutover republishes the old route only after the source is reverified; later failures restore the old container or quarantine uncertain state. Redis, Valkey, and Qdrant major upgrades are rejected for now because their current DBE backup path is physical/version-specific rather than a reliable cross-major logical migration.

The response includes `strategy`:

```json
{
  "strategy": "major_upgrade_migration",
  "export_artifact_id": "9c39d836-5f8e-4e48-94d6-ec6b1397fdda.postgres.sql",
  "old_volume_backup_retained": true,
  "warnings": ["..."]
}
```

## Pre-pulling images

```json
POST /api/admin/images/pull      (scope: images:admin)
{ "protocol": "postgres", "image": "postgres:18.4" }
```

Omit `image` to pull the node's configured default for that protocol. Handy for warming a node before creating instances on it.
