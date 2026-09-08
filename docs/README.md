# Documentation

## Run a node

- [Setup](operations/setup.md): configuration, upgrades, and logs.
- [Disk limits](operations/disk-limits.md): enforcement and host preparation.
- [Docker](../deploy/docker/README.md): Compose deployment.
- [Benchmarking](operations/benchmarking.md): read-only checks and opt-in load tests.
- [Example configuration](../config/example.yml): settings and defaults.

## Panel integration

Keep node credentials on the panel backend and authorize each tenant before
calling DBEV. [OpenAPI](api/openapi.yml) is the canonical API contract.

- [Authentication](api/auth.md) and [system readiness](api/system.md)
- [Instances](api/instances.md) and [server-owned pools](api/pools.md)
- [Monitoring](api/monitoring.md) and [WebSockets](api/websockets.md)
- [Imports, exports, backups, and recovery](api/transfers.md)

## Development

[Build and test](development.md) · [Security reporting](../SECURITY.md)
