# Server-owned database pools

[Documentation index](../README.md) · [OpenAPI](openapi.yml)

API **0.17.0** makes a pool a first-class engine resource. It can exist without
databases. One game server can own one pool of each supported engine on a node.
PostgreSQL, MySQL, MariaDB, MongoDB and ClickHouse support pools; Redis, Valkey
and Qdrant remain dedicated-only. Dedicated database provisioning is unchanged.

## Ownership and panel authorization

The panel backend derives `server_id` from the authorized game-server record.
DBEV combines it with the configured, authenticated `token_id` namespace.
Keep that token identifier stable when rotating its secret. Never let the
browser select another owner, and never expose the node token.

Persist the node, server, engine and `runtime_id` mapping. One pool cannot span
nodes. A full/unavailable pool returns a conflict; it never creates a second
pool, changes ownership or expands capacity automatically.

Pool controls and logs affect every child. Grant them only to users authorized
for the entire server-owned pool. Database-only subusers retain database-scoped
permissions and streams. Filter node-wide inventory on the panel backend.

## Create the parent, then its databases

`POST /api/pools` (`pools:write`):

```json
{
  "server_id": "game-server-uuid",
  "protocol": "postgres",
  "image": "postgres:18.4",
  "limits": {
    "cpu_cores": 2,
    "memory_mib": 2048,
    "disk_mib": 16384,
    "max_tenants": 16
  }
}
```

Image is optional and otherwise uses the node's allowed default. Engine startup
floors apply. The disk budget includes tenant allowances plus engine overhead
and spill space; do not offer its entire value as allocatable tenant disk.

The raw `202` body contains `runtime_id`, `status:"creating"`, and
`status_url`; the Location header points to the same status endpoint. Poll
that URL until ready or failed. Acceptance is not readiness. Duplicate owner/
engine creation can be rejected by the asynchronous worker, so inspect progress.

Then `POST /api/pools/{runtime_id}/instances` (`instances:write`):

```json
{
  "instance_id": "server-uuid-pg-main",
  "database": "main",
  "username": "server_main",
  "password": "<generated-password>",
  "public_host": "db.example.com",
  "disk_mib": 1024
}
```

`public_port` is optional. This returns the ordinary child `202`
`instance_id/status/status_url`. Parent ownership, protocol and image are
inherited. The generic `POST /api/instances` shared request also works, but
requires explicit `server_id`, `pool_id` and disk-only `limits`.
The old implicit `pool_limits` request field is removed.

CPU/RAM and the engine's physical disk budget belong to the pool. Each child
still has its own disk allowance and restricted database account. This is not
per-child hard CPU/RAM isolation. Dedicated databases remain the option for
that isolation.

## Pool dashboard and controls

| Endpoint | Purpose |
| --- | --- |
| GET /api/pools | Node pool inventory; filter by verified owner before exposing |
| GET /api/pools/{id} | Whole-engine CPU, memory, disk, state, owner and image |
| GET /api/pools/{id}/instances | Child databases and their individual metrics |
| GET /api/pools/{id}/status | Durable pool state and optional retained progress |
| PATCH /api/pools/{id} | PoolLimits body; fixed capacity and maximum child count |
| POST /api/pools/{id}/power | `{"action":"start\|stop\|restart\|kill"}` |
| GET /api/pools/{id}/logs?tail=100 | Recent redacted engine logs |
| GET /api/pools/{id}/backups | Existing backups grouped by each record's instance_id |
| PATCH /api/pools/{id}/image | Guarded image replacement described below |
| DELETE /api/pools/{id}?confirm=true&reason=... | Explicit empty-pool deletion |

Read operations require `pools:read`; mutations require `pools:write`.
Logs require `pools:logs`; backup inventory also requires `backups:read`.
Image changes also require `images:admin`. Child creation requires
`instances:write`. The backend node token has these scopes; it is not a
browser credential.

Show pool CPU/RAM graphs, a logs console, child database management and a backup
tab at the parent level. Label child power controls **Enable/Disable database
access**: they do not stop the shared engine. Parent Stop/Restart affects all
children, and an intentional Stop survives daemon restart.

Deleting the last child leaves the empty engine intact. Delete the parent
explicitly when no databases, reservations or active migrations remain.
Memory/disk capacity cannot shrink online; grow it or migrate data elsewhere.
CPU and max_tenants are editable within admission constraints.

Pool metrics use percentage points and bytes. Preserve null values and each
sample's freshness/source diagnostics. Do not label engine totals as a child's
CPU or RAM. Obsolete per-child CPU/RAM reservation totals were removed from
pool responses; disk.reserved_bytes remains meaningful.

## WebSockets

Mint a separate one-use token for each socket via `POST /api/ws-token`:

```json
{
  "subject": "panel-user-42",
  "server_id": "game-server-uuid",
  "pools": ["pool_postgres_..."],
  "scopes": ["pools:monitor"],
  "ttl_seconds": 900
}
```

Use `pools:logs` for logs. Tokens bind the exact owner and pool generation.
Do not mix `pools` with `instances`/`all_instances` or instance scopes.
Use `["dbe.jwt", token]` as WebSocket subprotocols, not a query token.

- `/ws/pools/{id}/monitoring`: `type:"pool_stats"`, `sequence`,
  `sampled_at_unix`, `pool` (same report as REST), `progress_reset`,
  `install_progress` changes and optional `install_progress_removed`.
  One unbatched snapshot per second. Pool progress reuses InstallProgress:
  its `instance_id` contains the **runtime_id**, not a child ID.
- `/ws/pools/{id}/logs?tail=100`: existing `type:"logs"`,
  `event:"reset|append|end"`, sequence and optional stream/data/error,
  identifying **runtime_id** instead of instance_id.

Merge progress reset, removals and updates in that order. Missing progress
does not mean installing. Use durable status for state. Reconnect with a fresh
JWT after gaps, expiry or replacement, and reset sequence state. Keep bounded
log buffers; append only new data. Instance monitoring and dedicated logs retain
the API 0.16 wire shapes described in [WebSockets](websockets.md).

## Data operations and images

Child accounts, password resets, disk limits, backups, export/import, recovery
and dedicated/shared migrations use the existing child instance endpoints.
Backups remain separate tenant-scoped logical archives; the pool inventory
does **not** promise an atomic backup of all databases. A panel's “back up all”
action must call each authorized child's backup endpoint and show each result.

For dedicated-to-shared migration create the destination pool first and send
`target_mode:"shared"`, `server_id`, and `pool_id`. Reverse migration uses
`target_mode:"dedicated"` and optional dedicated `limits`. Existing credentials
and endpoints are retained by the guarded migration path. Ownership cannot change.

Pool image requests use `{"image":"postgres:18.5","confirm":true,"reason":"..."}`.
Take backups first. DBEV permits non-downgrade updates only within the same
release line: PostgreSQL major; MySQL/MariaDB/MongoDB/ClickHouse major.minor.
It probes an isolated container without database mounts, records the immutable
image identity, retains volumes, and verifies the replacement before routing.
It does not make an automatic backup or guarantee arbitrary vendor upgrades.

Unfinished image updates are quarantined, not automatically resumed. Retry
the same immutable image; `pending_image` identifies it. Tenants quarantined
during recovery require operator review. Cross-release-line upgrades require
a planned data migration, not this image endpoint.

## Upgrade notes

The old `/api/admin/shared-pools` aliases and implicit pool creation/deletion
are removed. Check raw-root `GET /api/system` `api_version >= 0.17.0` and each
protocol's `enabled`, `server_private_pools:true`, `shared_pool_scope:"server"`.
Do not confuse the daemon binary version with this API contract.

Owned pools retain their data and identities. Historical unowned shared rows
remain quarantined; never guess their server owner or silently delete them.
No new configuration switches are needed.

This hierarchy follows the engine-with-child-databases model in
[Calagopus db-agent](https://github.com/calagopus/db-agent/blob/00edbda414a882606ff0f70d3f5d1b7b51157161/src/routes/api/instances/_instance_/mod.rs),
while keeping DBEV's restricted database accounts, private sockets and quota
checks. It is not a claim of complete Calagopus API feature parity.
