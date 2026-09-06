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
scheme and effective port.

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
