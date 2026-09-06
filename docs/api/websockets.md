# WebSockets

[Documentation index](../README.md) · [OpenAPI](openapi.yml)

DBEV has instance and pool management streams. Database clients use the protocol gateways,
not WebSockets; there is no raw SQL, table-change, or general CRUD event stream.

| Endpoint | JWT scope | Delivery |
| --- | --- | --- |
| `/ws/pools/{id}/monitoring` | `pools:monitor` | Whole-engine snapshots and pool progress |
| `/ws/pools/{id}/logs?tail=100` | `pools:logs` | Reset and whole-engine log appends |
| `/ws/monitoring` | `monitor:read` | Full instance snapshots + progress changes, normally once per second |
| `/ws/instances/{id}/logs?tail=100` | `logs:read` | Reset, then dedicated-container log appends |
| `/ws/instances/{id}/import-export?job_id=...` | `import-export:read` | Initial job snapshot, then updates; job filter optional |

## Authenticate and connect

The panel backend needs `ws-tokens:write` to call `POST /api/ws-token`:

```json
{
  "subject": "panel-user-42",
  "scopes": ["monitor:read"],
  "instances": ["cust-42-db"],
  "ttl_seconds": 900
}
```

The response contains `token_type`, `token`, and `expires_at_unix`.

- Subject and scopes must be non-empty. Instance scopes and pool scopes must not be mixed.
- TTL defaults to 900 seconds; range 1–3,600.
- Use an explicit allow-list of at most 256 existing instance IDs. Tokens bind
  to their current generations and cannot access a deleted/recreated replacement.
- Node-wide access requires `all_instances: true`, without an instance list.
  An empty list without this flag is rejected.
- Each JWT allows **one upgrade only**. Mint a new token for every socket,
  retry, or reconnect, after checking panel-side authorization.
- Never expose the long-lived node token, put a WebSocket JWT in a query
  string, or log JWT/subprotocol headers.

Browsers authenticate through the subprotocol:

```js
const socket = new WebSocket(
  "wss://node.example.com:8090/ws/monitoring",
  ["dbe.jwt", token],
);
```

The negotiated subprotocol is `dbe.jwt`. Non-browser clients may instead use
`Authorization: Bearer <jwt>`. Proxies must forward the upgrade and subprotocol
headers. Browser Origin checks still apply; see [authentication](auth.md).

Sockets close at JWT expiry. Incoming messages/frames are limited to 16 KiB;
write buffering is bounded and slow clients can be disconnected. Send no
application commands; let the client library answer WebSocket Ping frames.

## Pool streams

[Pool integration](pools.md) describes owner-bound JWTs and the `pool_stats`
event. Pool logs use the same reset/append/end protocol below, but identify
`runtime_id` instead of `instance_id`. Mint a fresh token for each socket;
a database-only subuser must not receive pool log access.

## Monitoring

A `stats` message contains:

```json
{
  "type": "stats",
  "sequence": 42,
  "sampled_at_unix": 1788220800,
  "batch_index": 0,
  "batch_count": 1,
  "instances": [],
  "progress_reset": false,
  "install_progress": [],
  "install_progress_removed": []
}
```

Instance entries identify `instance_id`, `runtime_id`, `deployment_mode`,
`resource_scope`, protocol, status, runtime, activity, resources, and
`resource_error`. In API 0.16, `resources` contains only `cpu`, `memory`,
and `disk`. Read identity/status from the outer item, and RX/TX only from
`activity.rx_bytes`/`activity.tx_bytes`. Activity has no repeated instance ID.
REST resource/activity responses remain self-contained.
See [monitoring](monitoring.md) for metric meanings.

Client state rules:

1. Collect indexes `0..batch_count-1` for the same sequence.
2. Replace the authorized instance list only when the whole sequence is present.
   For progress, first clear its cache if `progress_reset` is true, remove
   `install_progress_removed` IDs (default empty), then upsert `install_progress`
   by instance ID. Apply all of this atomically, never per batch.
3. If a sequence is missing or incomplete when a newer one starts, discard the
   partial batch and reconnect with a fresh JWT. Progress is now change-only;
   skipping a sequence and continuing could permanently lose an update.
4. Reset sequence tracking on reconnect; sequences are not replay cursors.
5. Keep instances with `resources: null` and show their diagnostic. Missing
   telemetry does not mean deletion, zero usage, or a stopped database.

Sampling runs independently of socket delivery. Consecutive snapshots may
reuse a cached measurement; missed ticks are skipped, not replayed in bursts.
CPU values are already percentage points. Shared-tenant CPU/RAM usage is null,
not the whole pool's usage. Reset activity-rate baselines on `stats_epoch`
changes; never turn a counter reset into a spike.

`install_progress` is in-memory progress for `create`, `image_update`, and
`major_upgrade`, with `running`, `completed`, or `failed` status. Render
stage/message and optional byte/percent progress without inventing steps.
The first complete sequence after connect has `progress_reset: true` and
includes all retained progress. Later sequences include only changed records;
an empty array does not clear pending progress. Missing progress never means
a database is installing: use its actual instance status.
The `healthcheck` stage is a startup-readiness check, not a permanent probe.
After a daemon restart, use REST instance state; progress history is not replayed.

## Logs

`tail` defaults to 100 and is clamped to 1–2,000 lines. Shared tenants cannot
read physical pool logs through their instance endpoint.

```json
{"type":"logs","instance_id":"cust-42-db","sequence":0,"event":"reset"}
```

```json
{"type":"logs","instance_id":"cust-42-db","sequence":1,"event":"append","stream":"stdout","data":"database ready\n"}
```

```json
{"type":"logs","instance_id":"cust-42-db","sequence":2,"event":"end"}
```

- Clear the console on `reset`; append only `data` to the named stream on
  `append`. The old cumulative `stdout`/`stderr` fields are gone.
- A single Docker follow request delivers the requested history and then live
  output. There is no separate history/live switch that can lose intervening logs.
- Each append is UTF-8 safe and below 16 KiB. Keep a bounded client history.
- Sequence numbers are local to the connection; reset them on reconnect and
  ignore duplicate/stale events. Refresh/reconnect after a detected gap.
- Heartbeats are Ping/Pong every 30 seconds, not repeated log text. Browsers
  handle control Pong automatically; other clients must answer it.
- Redaction buffers incomplete records across runtime chunks. An incomplete
  final secret assignment is omitted. A record exceeding 128 KiB ends the
  stream with `error.code: "log_record_limit"`; do not tightly retry the same tail.
- `end` optionally includes a public `error`. Refresh instance state and reconnect
  when appropriate. Reconnect clears the old console and recovers only the
  requested recent tail, not guaranteed lossless history.
- Open log sockets only while someone is viewing them.

## Import/export jobs

| Type | Client action |
| --- | --- |
| `import_export_snapshot` with `jobs` | Replace the subscription's job set |
| `import_export_job` with `job` | Upsert by `job_id` |
| `import_export_lagged` with `skipped` | Wait for the automatic fresh snapshot |

Without a job filter, the initial snapshot contains up to the latest 100 jobs,
newest first. With a filter, it contains that job or an empty list. Job fields
match [REST jobs](transfers.md#importexport-jobs).

The stream sends Ping every 30 seconds and closes if the next heartbeat finds
no Pong. Successful exports may include a roughly 120-second, single-use
`download` ticket. Obtain a fresh authorized ticket when needed; do not store
the URL as the artifact identity. Show public error messages and retain
`error_id` for support.

## Reconnection and daemon restart

Use one reconnect controller per logical subscription. Cancel sockets, token
requests, and timers on logout, component disposal, or permission removal.
Prefer one authorized monitoring subscription per node/session, not one per DB.

| Failure | Action |
| --- | --- |
| HTTP 401 | Obtain a fresh JWT; retry with bounded backoff |
| HTTP 403 | Fix scope/authorization; do not loop |
| HTTP 404 | Refresh instance state and remove stale subscriptions |
| HTTP 409 on logs | Shared-pool logs are not a tenant feature |
| HTTP 429 | Back off with jitter; node capacity is bounded |
| HTTP 503 or close 1012 `server restarting` | Wait for readiness, then obtain a fresh JWT |
| Close 1008 `JWT expired` | Obtain a fresh JWT |
| Close 1008 `heartbeat timeout`, or network break | Check connectivity and reconnect with a fresh JWT |

Cap exponential backoff (for example, at 30 seconds). Keep the last UI state
marked disconnected until a valid new snapshot arrives. Browsers may not expose
an upgrade's HTTP status directly; use panel REST diagnostics when necessary.

After restart:

- Snapshot sequences, log buffers, live counters, and install progress reset.
- SQLite job records survive; interrupted queued/running work is reconciled
  to failed, not silently resumed. The initial job snapshot is authoritative.
- Download URLs are ephemeral; request new tickets.
- Database containers normally remain running, but gateway connections close.
- Heartbeat proves API liveness only; check `/api/system` and instance status
  for gateway/database readiness.

## Panel checks

Test fresh-token reconnects, expiry and restart closes, bounded backoff,
atomic instance snapshots/progress merges, null metrics, counter resets, log reset/append, job upserts/lag recovery, expired downloads, and cleanup on logout.
REST command responses remain authoritative; a socket is not confirmation that
a mutation succeeded.
