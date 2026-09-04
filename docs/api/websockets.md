# WebSockets

[Documentation index](../README.md)

WebSockets use short-lived JWTs instead of the node token, so you can hand them to a browser without exposing node credentials.

For a complete panel/AI implementation handoff covering event reducers,
reconnection, close codes, capacity, and daemon-restart state, see
[`panel-websocket-ai-handoff.md`](panel-websocket-ai-handoff.md).

## Step 1: mint a token (panel side)

```json
POST /api/ws-token     (scope: ws-tokens:write)
{
  "subject": "user-42",
  "scopes": ["monitor:read", "logs:read"],
  "instances": ["cust-42-db"],
  "ttl_seconds": 900
}
```

Response: `{ "token_type": "Bearer", "token": "…", "expires_at_unix": … }`. TTL defaults to 900s, max 3600. `instances` restricts the token to those exact instance generations resolved when it is minted; deleting and recreating the same ID does not grant access to the replacement. An empty list grants no instance access; node-wide access must be explicitly requested with `"all_instances": true`, and that flag cannot be combined with an allow-list. Each token ID is accepted for one WebSocket upgrade only, so mint a fresh token when reconnecting or after an instance replacement. WebSocket messages and frames are capped at 16 KiB, with bounded write buffering.

## Step 2: connect (browser side)

Browsers can't set an `Authorization` header on a WebSocket, so pass the JWT via the subprotocol:

```js
const ws = new WebSocket("wss://node.example.com/ws/instances/cust-42-db/logs",
                         ["dbe.jwt", token]);
```

Server-side clients can use either the subprotocol trick or a plain `Authorization: Bearer <jwt>` header.

## Endpoints and events

Every message is a JSON object with a `type` field.

**`/ws/monitoring`** (scope `monitor:read`) — one complete authorized snapshot
per second, split into bounded batches:

```json
{
  "type": "stats",
  "sequence": 42,
  "sampled_at_unix": 1788220800,
  "batch_index": 0,
  "batch_count": 2,
  "instances": [
    {
      "instance_id": "cust-42-db",
      "protocol": "postgres",
      "status": "running",
      "runtime": "docker",
      "activity": {
        "instance_id": "cust-42-db",
        "stats_epoch": "…",
        "sampled_at_unix": 1788220800,
        "accepted": { "read": 80, "write": 12, "ddl": 1, "other": 3 },
        "rejected": { "read": 0, "write": 0, "ddl": 1, "other": 0 },
        "active_connections": 2,
        "opened_connections": 14,
        "rx_bytes": 1234,
        "tx_bytes": 5678,
        "cpu_time_micros": null,
        "peak_query_memory_bytes": null,
        "sources": {
          "connections": "gateway_authenticated_exact",
          "network": "gateway_route_exact",
          "operations": "gateway_protocol_observed",
          "cpu_time": "unavailable",
          "peak_query_memory": "unavailable"
        }
      },
      "resources": { "…": "same shape as /api/instances/{id}/resources" },
      "resource_error": null
    }
  ],
  "install_progress": [
    {
      "instance_id": "cust-42-db",
      "protocol": "postgres",
      "action": "image_update",
      "status": "running",
      "stage": "pull_image",
      "message": "Downloading",
      "image": "postgres:18.4",
      "layer": "sha256:…",
      "current": 1048576,
      "total": 8388608,
      "percent": 12.5,
      "updated_at": "2026-07-07T18:30:00Z"
    }
  ]
}
```

All batches with the same `sequence` form one snapshot. Buffer indexes
`0..batch_count-1` and replace panel state only when the complete sequence is
present. Never interpret an individual batch as a deletion; discard an
incomplete older sequence when a newer one starts.

`resources.cpu.usage_percent` is already expressed as percentage points
(`11.0` is 11%).
The WebSocket does not rescale it, and the panel must not rescale it either.
Snapshot sequences are emitted every second from the latest independently sampled cache.
Sampling never runs inside the WebSocket send loop. Adjacent snapshots may
repeat the same one-shot Docker sample, and missed client ticks are skipped
instead of being emitted later as catch-up bursts.

Disk usage is sampled from quota accounting when available and cached per instance. Directory walking is only a fallback, and a background sampler keeps the cache warm so websocket ticks do not block on large database directories. Concurrent fallback walks are coalesced per instance and capped node-wide. Node-wide monitoring clients share each completed all-instance sample. Instance-scoped JWTs instead assemble only their generation-bound allow-list, so a tenant dashboard cannot trigger an O(all-node-instances) resource sweep.
`install_progress.action` is `create`, `image_update`, or `major_upgrade`. For image updates, listen for stages like `queued`, `prepare`, `pull_image`, `delete_container`, `create_container`, `start`, `healthcheck`, `backend`, `completed`, and `failed`. The existing `healthcheck` stage name is retained for API compatibility but represents the bounded startup-readiness check, not a permanent probe. Major upgrades also emit `export`, `snapshot`, `prepare_replacement`, `import`, and `validate`.

**`/ws/instances/{instance_id}/logs`** (scope `logs:read`, token must cover the instance) — a rolling snapshot whenever output arrives plus a 30-second heartbeat:

```json
{ "type": "logs", "instance_id": "cust-42-db", "sequence": 7,
  "stdout": "…", "stderr": "…", "error": null }
```

Connection URLs in log output are redacted before they leave the daemon. If fetching logs fails, `stdout`/`stderr` are null and `error` says why. The stdout/stderr fields are cumulative rolling buffers for the current connection, not deltas, and `sequence` resets whenever the socket reconnects.

**`/ws/instances/{instance_id}/import-export?job_id=…`** (scope `import-export:read`, token must cover the instance) — `job_id` is optional. On connect you get that instance's current state, then push updates as its jobs change:

```json
{ "type": "import_export_snapshot", "jobs": [ { …job fields…, "download": null } ] }
{ "type": "import_export_job", "job": { …job fields…, "download": { …temporary url… } } }
{ "type": "import_export_lagged", "skipped": 12 }
```

Job objects are the same shape as the REST job response. When an export succeeds, the event includes a `download` object — a single-use temporary URL valid for ~120 seconds, so your UI can show a download button the moment the export finishes. A `lagged` event means you missed messages; a fresh snapshot follows automatically.
