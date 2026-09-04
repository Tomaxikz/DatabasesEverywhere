# DatabasesEverywhere documentation

## Running a node

- [Setup and configuration](operations/setup.md): install, upgrade compatibility, config fields, and startup.
- [Disk limits](operations/disk-limits.md): quota backends, prerequisites, and verification.
- [Benchmarking](operations/benchmarking.md): measure a running node and interpret the reports.
- [Docker deployment](../deploy/docker/README.md): Compose setup and image build layout.
- [Complete example configuration](../config/example.yml).

## Integrating with the daemon

- [Authentication and API basics](api/auth.md): tokens, scopes, errors, and contract versioning.
- [Instances](api/instances.md): dedicated/shared creation, migrations, limits, and images.
- [Monitoring](api/monitoring.md): resource reports, tenant activity, and history.
- [Exports, imports, and backups](api/transfers.md): uploads, jobs, recovery, and download URLs.
- [WebSockets](api/websockets.md): tokens, connections, endpoints, and events.
- [Panel WebSocket handoff](api/panel-websocket-ai-handoff.md): detailed panel integration behavior.
- [System endpoints](api/system.md): node settings, readiness, and administration.
- [OpenAPI contract](api/openapi.yml): machine-readable request and response schemas.

## Integration checklist

Rough order for wiring up a panel:

1. Generate `uuid`, `token_id`, a random API `token`, and a different random `jwt_signing_key`; both secrets must be at least 32 bytes. Render the node's `config.yml`; admin runs setup.
2. Call `GET /api/system` to verify connectivity and see what the node supports.
3. Create/manage instances via `/api/instances`; store `instance_id` ↔ your customer records on the panel side (the daemon doesn't know about your users).
4. Poll `GET /api/heartbeat` for node health.
5. For live dashboards, mint per-user JWTs with `/api/ws-token` and connect to `/ws/monitoring` and `/ws/instances/{instance_id}/logs`.
6. For "download my data", queue an export, watch `/ws/instances/{instance_id}/import-export`, and surface the `download` URL it hands you.
7. Point Prometheus at `/metrics` if you run one.

## Contributing

See the [repository layout and development guide](development.md).
Report vulnerabilities privately as described in [SECURITY.md](../SECURITY.md).
