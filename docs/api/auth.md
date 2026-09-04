# Authentication and API basics

[Documentation index](../README.md)

## Auth

Every HTTP request needs the node token from `config.yml`:

```
Authorization: Bearer <token>
```

The config token has the `*` scope, so it can do everything. Things to know:

- Putting a token in the query string (`?token=...`) gets you a `401` — headers only. The one exception is a temporary download URL returned by the download endpoint; it carries its own short-lived JWT.
- The panel owns the daemon's public IP or hostname; `api.host` only controls the local listener. DBEV does not restrict authenticated server-to-server calls by their HTTP `Host` header. If an `Origin` header is present, it is checked against the exact browser-origin allow-list made from `remote` plus `api.trusted_origins`; scheme, hostname, and effective port must all match (for example, implicit HTTPS port 443 equals explicit `:443`). This keeps browser access restricted without duplicating the panel's public-address state inside the daemon.
- Rate limit: 600 requests per minute per authenticated credential and
  transport-peer IP by default. IPv6 peers share a `/64`. Exceed it and you get
  `429`.
- Request bodies are capped at `security.api_body_limit_bytes`.
- The listener caps active TCP/TLS/header connections at 2048 node-wide and
  256 per IPv4 address or native IPv6 `/64` (including idle pre-request
  connections), and caps in-flight requests at 1024. IPv4-mapped IPv6 peers
  retain their individual IPv4 identity. This transport admission ceiling is
  separate from the per-credential-and-peer request-rate quota. It allows 30
  seconds for HTTP headers and 10 seconds for a TLS handshake, and aborts a
  request body after 60 seconds without another frame. These inactivity limits
  do not impose a 60-second total upload duration.

WebSockets don't use the node token directly — see [WebSockets](websockets.md).

## Errors

Every error is the same shape:

```json
{ "error": "what went wrong", "code": "bad_request" }
```

Daemon-side failures return the generic message `internal server error`, the code
`internal_error`, and an opaque `error_id` also present in `X-Error-Id`. Use that
ID to find the full internal cause in daemon logs; paths, container output, and
database errors are never returned to clients.

| Status | Meaning |
| --- | --- |
| 400 | Bad request — validation failed, the message says why |
| 401 | Missing/wrong token, disallowed host/origin, or token in query string |
| 403 | Token is valid but lacks the required scope |
| 404 | Instance, job, or file doesn't exist |
| 408 | Request body or upload exceeded its configured deadline |
| 409 | Conflict (usually from the container runtime) |
| 413 | Request or import upload is too large |
| 415 | Request media type is unsupported |
| 422 | JSON is syntactically valid but does not match the endpoint schema (for example, an unknown enum value or missing required field) |
| 429 | Rate limited |
| 500 | Something broke on the daemon side |
| 501 | Endpoint not implemented yet |
| 503 | The daemon is draining/shutting down or a bounded admission queue is unavailable |

## API contract version

`GET /api/system` returns both the daemon binary `version` and the independently
advertised `api_version`. A panel must verify `api_version` before enabling node
actions. Binary patch/minor releases can change without changing this contract
version. The canonical endpoint and schema definitions live in
[`api/openapi.yml`](openapi.yml). Its `deployment_capabilities` array is the source of truth for which
enabled protocols accept each placement mode. Contract `0.14.0` adds explicit `dedicated`/`shared` placement,
per-protocol deployment capability discovery, physical-runtime IDs, honest
shared-pool resource metrics, durable asynchronous deployment migrations, and
privacy-bounded tenant activity/history with source-labelled query-cost data.
Contract `0.12.0` adds MongoDB upload source-database discovery and a
live import/export scheduler recommendation endpoint. Contract `0.11.0` adds
instance-scoped temporary dump uploads, lazy bounded catalog inspection,
upload lifecycle endpoints, and the `upload` import
source. Contract `0.8.0` adds Valkey as a first-class protocol with an isolated
RESP gateway, lifecycle, imports, exports, backups, and capability reporting.
Contract `0.7.0` adds pluggable local/S3/Kopia backup storage, storage
status fields, and bounded backup-catalog browsing. Contract `0.6.0` adds typed credential-based remote imports with
verified TLS, SSRF controls, per-protocol acquisition, merge/wipe modes, and
rollback-first target handling. Contract `0.5.0` exposes the API rate-limit allowance and its
credential-plus-peer-IP scope through `/api/system`. Contract `0.4.0` emits
monitoring snapshots every second, sources
per-instance RX/TX after gateway route selection for network-isolated
containers, and removes the redundant raw `docker_stats` string from monitoring
messages. Contract `0.3.0` added MySQL as a distinct protocol and exposed
`mysql_enabled` from `/api/system`. The API retains the scoped route design
introduced by contract `0.2.0`: heartbeat is `GET`,
instance lifecycle uses only `/power`, jobs/artifacts/backups and their
WebSockets are instance-scoped, import archive settings live inside `source`,
temporary downloads use authenticated `POST` and capability-authenticated `GET`
on the same instance-scoped `/download` path, download URL responses expose only
`url`, `expires_at_unix`, and `single_use`, and backup/restore calls return
synchronous operation records rather than fake job IDs.

## Scopes

Each endpoint requires one scope. The node token has `*`; scoped tokens matter mostly for WebSocket JWTs.

`system:read`, `instances:read`, `instances:write`, `resources:read`, `resources:admin`, `logs:read`, `metrics:read`, `artifacts:read`, `artifacts:write`, `backups:read`, `backups:write`, `backups:admin`, `import-export:read`, `import-export:write`, `recovery:admin`, `images:admin`, `ws-tokens:write`, `monitor:read`, `config:admin`
