# DBEV WebSocket panel-AI handoff

This document is implementation guidance for an AI working on a panel that
connects to DatabasesEverywhere (DBEV) `0.5.5`, API contract `0.12.0`. It is
deliberately explicit about authentication, event shapes, reconnection, daemon
restart behavior, and client-side state. Do not invent a generic event bus:
DBEV exposes three separate WebSocket streams with different semantics.

The runtime implementation and `openapi.yml` remain authoritative if a later
release changes the contract.

## What exists

| Endpoint | Required WebSocket JWT scope | Instance rule | Delivery model |
| --- | --- | --- | --- |
| `/ws/monitoring` | `monitor:read` | JWT allow-list is applied to every snapshot | Full current snapshot every 500 ms |
| `/ws/instances/{instance_id}/logs?tail=100` | `logs:read` | JWT must allow the path instance | Docker log follow stream plus a rolling snapshot heartbeat |
| `/ws/instances/{instance_id}/import-export?job_id={optional}` | `import-export:read` | JWT must allow the path instance | Durable initial snapshot, then live job updates |

There is no WebSocket for arbitrary instance CRUD events, database queries,
table changes, database gateway traffic, or general audit events. After a REST
mutation, use its REST response as the command result and use monitoring or the
relevant job stream only for live state. Database clients connect to DBEV's
protocol gateways; those connections are not WebSockets.

## Authentication and opening a connection

The panel backend mints a short-lived WebSocket JWT with its normal DBEV API
credential:

```http
POST /api/ws-token
Authorization: Bearer <panel-to-node API credential>
Content-Type: application/json

{
  "subject": "panel-user-42",
  "scopes": ["monitor:read"],
  "instances": ["cust-42-db"],
  "all_instances": false,
  "ttl_seconds": 900
}
```

The caller of `/api/ws-token` needs `ws-tokens:write`. The only accepted JWT
scopes are `monitor:read`, `logs:read`, and `import-export:read`.

Rules:

- `subject` is required and must not be blank.
- `scopes` is required and must not be empty.
- `ttl_seconds` defaults to 900 and must be between 1 and 3600.
- `instances` is an explicit allow-list with at most 256 IDs.
- An empty `instances` list grants nothing. Node-wide access requires
  `all_instances: true`.
- `all_instances: true` cannot be combined with a non-empty allow-list.
- Use least privilege. Normally mint a separate, single-scope JWT for each
  socket.
- Every JWT ID is accepted for one WebSocket upgrade only. Never reuse a token
  for a second endpoint, retry, tab, or reconnect. Always mint a fresh token.
- Never expose the long-lived node API credential to the browser. Only return
  the short-lived WebSocket JWT to the authorized browser session.
- Never put a JWT in the query string. DBEV rejects query-string tokens.
- Do not log the JWT or the `Sec-WebSocket-Protocol` header.

Response:

```json
{
  "token_type": "Bearer",
  "token": "eyJ...",
  "expires_at_unix": 1786630000
}
```

Browser connection:

```ts
const socket = new WebSocket(
  `${nodeWsOrigin}/ws/instances/${encodeURIComponent(instanceId)}/logs?tail=200`,
  ["dbe.jwt", shortLivedJwt],
);
```

The server selects `dbe.jwt` as the negotiated subprotocol. A non-browser
client may instead send `Authorization: Bearer <jwt>`. A reverse proxy must
forward HTTP/1.1 WebSocket upgrade headers and `Sec-WebSocket-Protocol`
unchanged. Use `wss://` whenever the API is TLS-enabled.

Host and Origin policy still applies to the upgrade request. The browser origin
must be allowed by the node configuration.

## Common connection behavior

- The daemon admits at most 1,024 active management WebSockets node-wide.
- Each active WebSocket is one TCP socket and therefore normally one daemon file
  descriptor. Creating 100 databases does not create 100 WebSocket descriptors;
  descriptors are created only for active client subscriptions. A live log
  stream also holds a Docker log-follow transport while it is open.
- Incoming messages and frames are limited to 16 KiB. The panel should send no
  application messages. Let the WebSocket implementation answer Ping frames,
  and only send Close when ending the subscription.
- Writes are bounded. A slow or disconnected client is eventually dropped
  instead of buffering without limit.
- The JWT is checked at upgrade and the socket is also closed at its exact
  expiration time; there is no clock-skew allowance.
- Keep only one reconnect controller for each logical subscription. Cancel it
  when the component/session is destroyed so stale timers cannot create
  duplicate sockets.

Common upgrade failures:

| Result | Meaning | Panel action |
| --- | --- | --- |
| `401` | Missing, invalid, expired, or already-consumed JWT | Mint one fresh JWT and retry with backoff |
| `403` | JWT lacks the endpoint scope or instance permission | Do not loop; correct panel authorization/token request |
| `404` | Instance-scoped endpoint refers to a missing instance | Remove the stale subscription and refetch instance state |
| `429` | Node WebSocket/JWT admission capacity is full | Back off with jitter; do not reconnect in a tight loop |
| `503` | Daemon shutdown/restart is in progress | Wait for node readiness, mint a fresh JWT, reconnect |

The important close frames are:

| Close code | Reason | Meaning |
| --- | --- | --- |
| `1012` | `server restarting` | Planned daemon restart; reconnect with a fresh JWT after readiness returns |
| `1008` | `JWT expired` | Mint a fresh JWT and reconnect |
| `1008` | `heartbeat timeout` | Import/export client did not answer Ping; verify the network and reconnect with a fresh JWT |

A process crash or network break may produce an abnormal close without a code.
Treat it as retryable, but always mint a fresh JWT.

Recommended reconnect policy:

1. Mark the stream disconnected; do not erase durable UI state immediately.
2. Discard the JWT used for that connection.
3. Wait with exponential backoff and jitter, for example 0.5 s, 1 s, 2 s,
   4 s, then cap at 15-30 s.
4. Confirm the panel can reach the node (`/api/heartbeat` for liveness and
   `/api/system` when readiness/gateway details matter).
5. Mint a new least-privilege JWT.
6. Open a new socket.
7. Treat the first snapshot as authoritative and reset the backoff only after
   the socket opens and a valid message is received.

Do not reuse a token even if a daemon restart happens to clear in-memory replay
tracking. Token reuse is not part of the API contract.

## Monitoring stream

Endpoint: `/ws/monitoring`, scope `monitor:read`.

The server sends a complete authorized snapshot every 500 ms. It is not a
delta. Replace the panel's node-monitoring state from each message. Instances
outside the JWT allow-list never appear.

```ts
type PublicDiagnostic = {
  code: string;
  message: string;
  error_id?: string;
};

type MonitoringMessage = {
  type: "stats";
  instances: Array<{
    instance_id: string;
    protocol: string;
    status: string;
    runtime: string;
    cpu_cores: number;
    cpu_limit_cores: number;
    cpu_usage_percent: number | null;
    memory_mib: number;
    memory_usage_bytes: number | null;
    memory_limit_bytes: number | null;
    disk_mib: number;
    disk_limit_bytes: number;
    disk_used_bytes: number | null;
    disk_enforced: boolean;
    network_rx_bytes: number | null;
    network_tx_bytes: number | null;
    resources: ResourceReport | null;
    resource_error: PublicDiagnostic | null;
  }>;
  install_progress: Array<{
    instance_id: string;
    protocol: string;
    action: "create" | "image_update" | "major_upgrade";
    status: "running" | "completed" | "failed";
    stage: string;
    message: string;
    image: string | null;
    layer: string | null;
    current: number | null;
    total: number | null;
    percent: number | null;
    diagnostic?: PublicDiagnostic;
    updated_at: string;
  }>;
};
```

Important behavior:

- `resources` matches `GET /api/instances/{id}/resources`.
- `cpu_usage_percent` is expressed in percentage points. Render `11.0` as
  `11.0%`; do not divide or multiply it by 100. DBEV forwards the same value in
  the top-level field and nested resource report.
- CPU is based on Docker's primed two-sample interval and Linux memory is the
  Docker-compatible working set. Because snapshots are sent every 500 ms but a
  runtime sample spans a real interval, consecutive snapshots may legitimately
  repeat a value.
- If resource collection fails, the instance remains in the snapshot with
  nullable live values, `resources: null`, and a safe `resource_error`. Do not
  treat one metric failure as deletion or as an instance stop.
- Network RX/TX counts bytes observed at DBEV's authenticated gateway/backend
  boundary. They are cumulative only since the current daemon boot, not billing
  counters. They reset after daemon restart and do not include traffic that
  bypasses the gateway.
- `install_progress` is live, in-memory operation progress. It covers create,
  image update, and major upgrade. It is not durable history and is empty after
  a daemon restart. Use REST instance state as the durable truth.
- Monitoring has no sequence number and no backlog. A reconnect simply receives
  fresh full snapshots, so no replay protocol is needed.
- Prefer one monitoring socket per node per active panel session, not one socket
  per database. For a very large panel, a panel backend can maintain a smaller
  number of node sockets and fan authorized state out to its own users.

## Log stream

Endpoint: `/ws/instances/{instance_id}/logs?tail={lines}`, scope `logs:read`.
`tail` defaults to 100 and is clamped to 1-2,000 lines.

```ts
type LogMessage = {
  type: "logs";
  instance_id: string;
  sequence: number;
  stdout: string | null;
  stderr: string | null;
  error: PublicDiagnostic | null;
};
```

Important behavior:

- On connection, DBEV attaches to the currently managed container, requests the
  selected tail, and follows new Docker output.
- A message is sent when log output arrives and a rolling snapshot heartbeat is
  sent every 30 seconds. The first timer tick may arrive immediately.
- `stdout` and `stderr` are rolling, cumulative buffers for this connection,
  each bounded to its most recent 128 KiB. They are not deltas. Replace the
  displayed value from the latest non-null field; do not append the entire field
  on every message or logs will be duplicated.
- `sequence` is only monotonic inside one WebSocket connection. It starts over
  after reconnect or daemon restart. Use it to reject duplicate/out-of-order
  messages inside the current connection, never as a durable cursor.
- Connection URLs and recognized secrets are redacted before output leaves the
  daemon. Still treat logs as sensitive tenant data.
- `error.code === "stream_ended"` means the followed container log stream ended.
  Close that client socket, refetch the instance state, and reconnect if the
  instance is running. This commonly matters after container restart or image
  replacement because the old socket remains tied to the old container stream.
- There is no log replay cursor and no `lagged` event. Reconnecting with an
  appropriate `tail` recovers only the recent Docker log tail, not guaranteed
  lossless history. Use persistent external logging if lossless audit logs are
  required.
- Open a log socket only while a user is actively viewing logs. Do not keep one
  log socket open for every managed database.

## Import/export job stream

Endpoint: `/ws/instances/{instance_id}/import-export`, scope
`import-export:read`. Add `?job_id=<id>` to monitor only one job.

The first message is always an authoritative snapshot:

```ts
type DownloadTicket = {
  url: string;
  expires_at_unix: number;
  single_use: boolean;
};

type ImportExportJob = {
  job_id: string;
  instance_id: string;
  action: "import" | "export";
  status: "queued" | "running" | "succeeded" | "failed";
  artifact_id: string | null;
  artifact_size_bytes: number | null;
  error: PublicDiagnostic | null;
  created_at: string;
  updated_at: string;
  download: DownloadTicket | null;
};

type ImportExportSocketMessage =
  | { type: "import_export_snapshot"; jobs: ImportExportJob[] }
  | { type: "import_export_job"; job: ImportExportJob }
  | { type: "import_export_lagged"; skipped: number };
```

State rules:

- Without `job_id`, the initial snapshot contains up to the latest 100 durable
  jobs for that instance, newest first. With `job_id`, it contains that exact
  job or an empty array.
- Replace the local job set for this subscription when a snapshot arrives.
- Upsert `import_export_job` updates by `job_id`; do not append duplicates.
- The live broadcast buffer holds 256 updates. If the client falls behind, DBEV
  sends `import_export_lagged` with the number skipped and then automatically
  sends a fresh authoritative snapshot. Mark the view resynchronizing and wait
  for that snapshot. If the socket closes first, reconnect; its first snapshot
  performs the same recovery.
- The server sends Ping `dbe-heartbeat` every 30 seconds on this stream. Standard
  browser WebSocket implementations answer automatically. If no Pong is seen by
  the next heartbeat, DBEV closes with `1008 heartbeat timeout`.
- A successful export may include a `download` ticket. It is short-lived
  (normally about 120 seconds) and single-use. Never persist it as the artifact
  identity and never reuse it. If it expires, reconnect/refetch the job or use
  the artifact download-ticket REST flow to obtain a new authorized ticket.
- `error` is a safe public diagnostic. Show `message`; retain `error_id` for
  support correlation. Never expect raw daemon/container errors in this field.

## Exactly what happens across daemon restart

On a planned restart, DBEV closes management WebSockets with code `1012` and
reason `server restarting`. It gives sockets about two seconds to drain and
bounds API connection shutdown separately. A crash may give no close frame.

| State | After reconnect to the new daemon process |
| --- | --- |
| WebSocket TCP connection | Gone; create a new connection |
| WebSocket JWT | Treat as consumed; mint a fresh JWT |
| Monitoring instance list/status | Rebuilt from current daemon/instance state in the next full snapshot |
| CPU/memory/disk samples | Re-sampled; temporary null/error values are possible while caches warm |
| Network RX/TX counters | Reset because they are process-memory counters since daemon boot |
| Install/create/update progress | In-memory only; not replayed after restart |
| Log `sequence` and rolling buffer | Reset; a new log connection obtains the requested recent tail from the still-running container |
| Import/export completed jobs | Persisted in SQLite and returned by the initial snapshot, subject to retention limits |
| Import/export queued/running job interrupted by restart | Reconciled to `failed` with a restart diagnostic; it is not silently resumed |
| Live job broadcast backlog | Gone; the durable initial snapshot is the recovery mechanism |
| Download ticket | Ephemeral; obtain a newly issued ticket instead of reusing an old URL |

A clean DBEV daemon restart does not normally stop managed database containers
or unmount healthy quota filesystems. This is why a reconnected log stream can
usually tail the existing container. Database gateway connections are separate
from WebSockets: during daemon shutdown they receive their own bounded natural
drain and forced proxy-close process.

## Panel implementation architecture

Build one reusable WebSocket manager with endpoint-specific reducers:

```ts
type SubscriptionState =
  | "idle"
  | "minting_token"
  | "connecting"
  | "connected"
  | "resynchronizing"
  | "backing_off"
  | "stopped";
```

The manager should:

1. Ask the authenticated panel backend for a fresh DBEV WebSocket JWT.
2. Open exactly one socket for the logical subscription.
3. Validate every incoming JSON object and its `type` before updating state.
4. Use a snapshot reducer for monitoring and import/export snapshots.
5. Use an upsert reducer for individual job updates.
6. Use replacement, not append, for cumulative log buffers.
7. Discard unknown message types safely and report contract mismatches to panel
   telemetry without crashing the UI.
8. Reconnect with jittered backoff and a newly minted JWT.
9. Stop reconnecting on logout, permission removal, component disposal, or
   instance deletion.
10. Avoid duplicate node subscriptions across rerenders/tabs where practical.

REST remains the fallback and durable source of truth:

- Use `/api/system` after restart to confirm API and gateway readiness.
- Use instance REST endpoints to restore instance detail state.
- Use `GET /api/instances/{id}/import-export/jobs` or the exact job endpoint if
  the job WebSocket is unavailable.
- Use REST logs only for explicit one-shot retrieval if supported by the panel;
  the WebSocket log sequence is not durable history.

## Acceptance tests for the panel AI

At minimum, implement tests proving that:

- one JWT cannot accidentally be reused for two sockets;
- a reconnect always requests a fresh JWT;
- a `1012` restart close reconnects and replaces state from the first snapshot;
- `1008 JWT expired` triggers token renewal;
- `403` does not cause an infinite reconnect loop;
- `429` uses capped jittered backoff;
- monitoring snapshots remove stale authorized instances and tolerate
  `resource_error`;
- network counters decreasing after daemon restart is treated as reset, not a
  negative-usage bug;
- log snapshots replace buffers rather than duplicate them;
- log sequence resets are accepted after reconnect;
- `stream_ended` causes state refresh/reconnect rather than a tight loop;
- job snapshots replace local state and job events upsert by `job_id`;
- `import_export_lagged` waits for the automatic snapshot;
- download tickets are treated as expiring single-use credentials;
- unmounting/logging out cancels sockets, pending token requests, and reconnect
  timers.

Do not change DBEV endpoint shapes from this panel task. If generated types are
available from `openapi.yml`, reuse the REST `ResourceReport`,
`PublicDiagnostic`, and `ImportExportJob` fields and add only the WebSocket
envelope/discriminator types locally.
