# Authentication and API basics

[Documentation index](../README.md) · [OpenAPI contract](openapi.yml)

## Authentication

Keep the long-lived node token on the panel backend. Send it in the header:

```http
Authorization: Bearer <token>
```

The config token has scope `*`. Ordinary API requests reject query-string
tokens. Temporary [download URLs](transfers.md#downloads) use their own
short-lived capability token; [WebSockets](websockets.md) use separate JWTs.

DBEV does not filter authenticated calls by HTTP Host. If an Origin header is
present, it must exactly match `remote` or `api.trusted_origins`, including
scheme and effective port. With neither set, no browser origin is allowed.

### Local socket

The daemon always serves the same API on a Unix socket, `api.socket_path`
(default `/run/dbev/api.sock`), alongside any TCP listener. The socket is
root-only (mode 0600, in a 0700 directory) and never uses TLS; requests still
need the bearer token. `dbev --cli` uses the socket when it exists and falls
back to TCP otherwise. Any HTTP client that speaks over a Unix socket works:

```bash
curl --unix-socket /run/dbev/api.sock \
  -H "Authorization: Bearer $TOKEN" http://localhost/api/system
```

Socket clients have no IP address. They all count as one peer, `127.0.0.1`,
for connection limits, rate limits, and request logs. At startup the daemon
replaces a socket file left by an earlier run, but refuses to replace a
symlink, any other file, or a socket another process still serves.

### Disabling the network API

A standalone node has no panel. Set `api.enabled: false` to open no TCP
listener at all; `remote` may then be omitted. `api.host`, `api.port`, and
`api.ssl` go unused, and the daemon logs a startup warning that the panel
cannot reach the node. Manage it with `sudo dbev --cli` over the socket.

### Request limits

- Default rate: 600 requests/minute per authenticated credential and transport
  peer. IPv6 peers share a /64; IPv4-mapped IPv6 retains its IPv4 identity.
- Active connections: 2,048 node-wide, 256 per peer; in-flight requests: 1,024.
- HTTP headers: 30 seconds; TLS handshake: 10 seconds; body inactivity:
  60 seconds. Uploads have their own size and total-transfer limits.
- Normal bodies use `security.api_body_limit_bytes`.
- Forwarding headers do not change the transport-peer identity.

## Errors

```json
{ "error": "what went wrong", "code": "bad_request" }
```

Internal failures use `internal_error` and a generic message. Their `error_id`
also appears in `X-Error-Id`; use it to locate the cause in daemon logs.
Do not expect raw paths, container output, or database errors in public responses.

| Status | Meaning |
| --- | --- |
| 400 | Validation failed |
| 401 | Missing/invalid credentials, rejected origin, or forbidden query token |
| 403 | Insufficient scope |
| 404 | Resource missing |
| 408 | Body/upload deadline exceeded |
| 409 | State, capacity, or ownership conflict |
| 413 / 415 / 422 | Oversized body / unsupported media type / invalid JSON shape |
| 429 | Rate or admission limit reached |
| 500 / 501 | Internal failure / unsupported operation |
| 503 | Draining, unavailable admission, or temporarily unavailable operation |

## Contract discovery

Call `GET /api/system` before enabling node actions. Check `api_version`
independently of the daemon's binary `version`, and use
`deployment_capabilities` to discover enabled protocols and placement modes.
The current contract is `0.17.0`; [OpenAPI](openapi.yml) defines request,
response, and scope requirements. Successful JSON is the raw response body,
not a `{data: ...}` envelope.

The panel owns customer authorization and the mapping to DBEV instance IDs.
A successful heartbeat proves management liveness, not database readiness;
check instance status and gateway readiness separately.

## Scopes

Endpoint scopes are listed in OpenAPI and the relevant guides. Browser JWTs
accept instance scopes `monitor:read`, `logs:read`, and `import-export:read`,
or pool scopes `pools:monitor` and `pools:logs`. Never mix the two target types.
Pool tokens require explicit pool IDs plus an authorized `server_id`.
Mint them through `POST /api/ws-token` using a credential with
`ws-tokens:write`; never send the node token to a browser.
