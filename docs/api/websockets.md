# WebSockets

[Documentation index](../README.md) · [OpenAPI](openapi.yml)

DBEV has three management streams. Database clients use the protocol gateways,
not WebSockets; there is no raw SQL, table-change, or general CRUD event stream.

| Endpoint | JWT scope | Delivery |
| --- | --- | --- |
| `/ws/monitoring` | `monitor:read` | Complete authorized snapshots, normally once per second |
| `/ws/instances/{id}/logs?tail=100` | `logs:read` | Dedicated-container log snapshots |
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

- Subject and scopes must be non-empty. Only the three scopes above are accepted.
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
  "install_progress": []
}
```

Instance entries identify `instance_id`, `runtime_id`, `deployment_mode`,
`resource_scope`, protocol, status, runtime, activity, resources, and
`resource_error`. See [monitoring](monitoring.md) for field meanings.

Client state rules:

1. Collect indexes `0..batch_count-1` for the same sequence.
2. Replace the authorized instance/progress state only when the whole sequence
   is present. A single batch is not a deletion or a delta.
3. Discard an incomplete sequence when a newer one starts.
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
The `healthcheck` stage is a startup-readiness check, not a permanent probe.
After a daemon restart, use REST instance state; progress history is not replayed.

## Logs

`tail` defaults to 100 and is clamped to 1–2,000 lines. Shared tenants cannot
read physical pool logs through their instance endpoint.

```json
{
  "type": "logs",
  "instance_id": "cust-42-db",
  "sequence": 7,
  "stdout": "...",
  "stderr": "...",
  "error": null
}
```

- Messages arrive on output and on a 30-second snapshot heartbeat.
- Replace each non-null stdout/stderr buffer; they are cumulative rolling
  snapshots, **not deltas**. Each buffer retains at most 128 KiB.
- Sequence numbers apply only to this connection and reset on reconnect.
- Errors are public diagnostics; recognized secrets/URLs are redacted.
- `stream_ended` means the followed container stream ended. Refresh instance
  state, then reconnect if appropriate, particularly after image replacement.
- Reconnecting recovers only the requested recent tail, not lossless history.
  Open log sockets only while someone is viewing them.

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
complete batch replacement, null metrics, counter resets, log-buffer
replacement, job upserts/lag recovery, expired downloads, and cleanup on logout.
REST command responses remain authoritative; a socket is not confirmation that
a mutation succeeded.
