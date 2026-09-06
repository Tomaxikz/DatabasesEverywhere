# Instances

[Documentation index](../README.md) · [OpenAPI](openapi.yml)

An instance is one logical database tenant. `dedicated` owns an engine
container; `shared` runs inside a pool private to one game server. Different servers never share a pool.

## Placement and lifecycle

Discover enabled protocols and modes through `GET /api/system` →
`deployment_capabilities`. Omitted `deployment_mode` defaults to `dedicated`.

| Mode | Engines | Boundaries |
| --- | --- | --- |
| Dedicated | All eight | Own runtime, CPU/RAM/disk limits |
| Shared | PostgreSQL, MySQL, MariaDB, MongoDB, ClickHouse | Tenant credentials/routes/data; pool CPU/RAM and tenant disk enforcement |

Shared mode is rejected for Redis, Valkey, and Qdrant. CPU/RAM are fixed pool limits, not per-tenant reservations; see [monitoring](monitoring.md)
and [disk boundaries](../operations/disk-limits.md#shared-tenant-boundaries).

Statuses are `creating`, `booting`, `running`, `stopped`, `failed`,
`quarantined`, and `deleting`. A live container alone does not make a
pre-ready, failed, fenced, or quarantined tenant ready.

- Explicit stop/kill persists across daemon/runtime restarts.
- Desired-running instances are reattached or started after verification.
- Quarantined instances remain stopped and never route traffic.
- Shared power actions affect only the tenant's login/routes/sessions, not
  the physical pool.
- Start on running and stop on stopped are no-ops.
- Startup performs bounded readiness checks, not permanent container healthchecks.

| Method | Path | Scope | Purpose |
| --- | --- | --- | --- |
| GET / POST | `/api/instances` | `instances:read` / `instances:write` | List / create |
| GET | `/{id}` | `instances:read` | Metadata and live classified status |
| GET | `/{id}/status` | `instances:read` | Status and available creation progress |
| DELETE | `/{id}?confirm=true&reason=...` | `instances:write` | Permanent deletion |
| POST | `/{id}/power` | `instances:write` | `start`, `stop`, `restart`, `kill` action |
| POST | `/{id}/reconcile` | `instances:write` | Reconcile runtime status |
| PATCH | `/{id}/password` | `instances:write` | Rotate credentials; `restarted` indicates recreation fallback |
| PATCH | `/{id}/limits` | `instances:write` | Change resource limits |
| PATCH | `/{id}/image` | `instances:write` | Dedicated image change; shared returns `409` |
| GET | `/{id}/logs?tail=200` | `logs:read` | Dedicated logs; shared returns `409` |

Except for the first row, prefix paths with `/api/instances`.
Resource, activity, and pool endpoints are in [monitoring](monitoring.md).

Deletion requires confirmation and an audit reason. It irreversibly removes
that tenant's database, jobs, uploads, exports, backups, and recovery data.
Shared deletion does not remove other tenants; the pool is removed only after
its final tenant is gone.

## Creating an instance

`POST /api/instances`:

```json
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

Accepted creation returns `202` immediately with `instance_id`,
`status: "creating"`, and an origin-relative `status_url`. Follow that URL
or monitoring; HTTP acceptance is not successful provisioning. Admission is
bounded to 64 tasks and per-instance mutations are serialized.

Key validation:

- Database/username: 1–63 ASCII characters, leading letter, then letters,
  digits, underscores, or hyphens; reserved/internal names are rejected.
- Password and public host must be non-empty.
- CPU: 0.01–1,024 finite cores; memory: 1–1,048,576 MiB; disk: greater than zero.
- MongoDB and ClickHouse require at least 1,024 MiB memory and disk.
- Disabled protocols and unsupported placement modes fail before provisioning.

Node capacity checks are authoritative. Shared-pool admission runs in the background worker: an accepted HTTP 202 can become a failed creation with a public conflict diagnostic; acceptance never means the pool was usable. Do not automatically retry with
`purge_stale_resources`; it explicitly deletes orphaned data.

## Updating limits

`PATCH /api/instances/{id}/limits` requires all three fields for dedicated instances:

```json
{ "cpu_cores": 2.0, "memory_mib": 4096, "disk_mib": 20480 }
```

Shared tenants instead send only `{ "disk_mib": 20480 }`. Their disk allowances must fit inside the fixed pool budget, including engine overhead and spill; CPU/RAM are not resized by tenant requests.

Creation floors still apply to dedicated instances. A shared disk shrink fences/drains the tenant and
measures its physical data; `409` preserves the old limit if the data does not
fit. Hard-quota resizes retain the tenant's existing project identity.

On supported kernels, DBEV enables one quota window of unused CPU burst credit.
Sustained limits remain unchanged. Missing burst support warns rather than
blocking startup; there is no additional API/config field.

## Migrating between dedicated and shared placement

`POST /api/instances/{id}/deployment-migrations`:

```json
{ "target_mode": "shared", "server_id": "game-server-uuid", "pool_id": "pool_postgres_..." }
```

Use `dedicated` for the reverse direction; optional `limits` sets the new dedicated engine budget. Create the target [pool](pools.md) first. Ownership cannot change during migration. `202` returns a durable migration
record and a status `Location`. GET the collection to list attempts, or
`/deployment-migrations/{migration_id}` to read one.

- Terminal stages: `completed`, `failed`, `cancelled`.
- `revision` increases on durable transitions.
- `manual_intervention` is nonterminal and fenced; boot does not replay it.
- `failure_code`/`failure_message` are sanitized operator guidance.
- `409` rejects stopped/fenced/disk-blocked sources, missing current
  credentials, conflicting work, or an unchanged target mode.
- Unsupported shared protocols return `400`; invalid JSON shape/mode returns
  `422`.

The source stays authoritative until atomic cutover. Existing backups are not
rewritten; their [layout must match](transfers.md#backups) before restore.
[Shared import restrictions](transfers.md#shared-engine-restrictions) also
apply to migration.

## Changing the image

`PATCH /api/instances/{id}/image`:

```json
{ "image": "postgres:18.4" }
```

The image must be version-tagged or digest-pinned and allowed by the node.
Current credentials come from encrypted metadata; the optional `password`
field is a legacy fallback. Shared tenants cannot update the physical pool
through this endpoint.

Patch/minor changes recreate the container on its data volume. For supported
cross-major migration, explicitly add `major_upgrade: true`. PostgreSQL,
MySQL, MariaDB, MongoDB, and ClickHouse use export/import with preserved
credentials, identity, endpoint, limits, old volume, and rollback artifact.
Redis/Valkey/Qdrant major upgrades are rejected. Native project-quota layouts
also reject this cutover; use export/create/import instead.

Boot reconciles changed pinned defaults for desired-running dedicated
instances through the same guarded update path. Existing shared pools keep
their pinned image. Replacement failures are isolated and uncertain state is
quarantined; DBEV never follows `latest`.

To pre-pull an allowed image, call `POST /api/admin/images/pull`
(`images:admin`) with `protocol` and optional `image`.

## Engine compatibility

The current admission policy accepts these families. This is not a promise
that every client option/version combination has been tested.

| Engine | Admitted versions | Gateway interfaces |
| --- | --- | --- |
| PostgreSQL | 14–18 | Native protocol, negotiated/direct TLS, GSS-encryption fallback, session cancellation |
| MySQL | 8.x (8.0.11+), 9.x, 26.x | MySQL protocol with standard `CLIENT_SSL` upgrade |
| MariaDB | 10.11, 11.4, 11.8, 12.3 | MySQL/MariaDB protocol with `CLIENT_SSL` |
| MongoDB | 7–8 | Standalone wire protocol |
| Redis | 6.2, 7.2, 7.4, 8.x | RESP2/RESP3, ACL and legacy password-only authentication |
| Valkey | 7.2, 8.x, 9.x | Same RESP/authentication modes as Redis |
| ClickHouse | 25–26 | Native TCP and HTTP |
| Qdrant | 1.17–1.18 | gRPC/HTTP2 and REST/HTTP1.1 |

`database_version.current` comes from an attestation tied to the actual
container/image and probe revision. Reads do not execute probes. Creation,
missing attestations, reconstruction, image changes, and password reset can
refresh it; unchanged restarts reuse it. Missing proof yields null/diagnostic;
unsupported engines are isolated before gateway publication.

MySQL/MariaDB greetings use connector-compatible baselines without a DBEV
suffix; actual version queries reach the backend. SQL gateways accept explicit
database selection or deferred selection for a uniquely matching username.
Ambiguous routes fail closed.

Cluster/replication routing, Sentinel, MongoDB replica-set/`mongos`/load-balanced
modes, MySQL X Protocol, PostgreSQL replication/GSS encryption, and ClickHouse
compatibility listeners are outside this model.

[CI driver tests](../../.github/ci/README.md#real-database-tests) exercise selected
official MySQL/MariaDB images with CLI, Connector/J, MariaDB Connector/J,
HikariCP, deferred catalog selection, and native TLS negotiation. Keep that
matrix distinct from the broader version admission policy.

## Server-owned pools (API 0.17)

[Create the pool first](pools.md), then add databases to it. The pool owns
physical CPU, RAM, disk capacity, power, image and logs. Each child retains its
database account, disk allowance, gateway route, backups and import/export.

The generic create endpoint also accepts shared requests with explicit
`server_id`, `pool_id` and `limits: {"disk_mib":1024}`. It never creates a pool
implicitly. Redis, Valkey and Qdrant remain dedicated-only.
