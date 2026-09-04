# Documentation

## Run a node

- [Setup](operations/setup.md): installation, configuration, upgrades, and logs.
- [Disk limits](operations/disk-limits.md): enforcement choices and host preparation.
- [Docker deployment](../deploy/docker/README.md): Compose requirements.
- [Benchmarking](operations/benchmarking.md): safe checks and opt-in load tests.
- [Example configuration](../config/example.yml): complete settings and defaults.

## Build a panel integration

Start with authentication and capability discovery. Keep node credentials on
the panel backend; authorize each tenant before calling its instance endpoints.

- [Authentication](api/auth.md): credentials, scopes, errors, and version checks.
- [Instances](api/instances.md): placement, creation, lifecycle, limits, and migrations.
- [Monitoring](api/monitoring.md): resource metrics, tenant activity, and history.
- [Transfers](api/transfers.md): uploads, import/export jobs, backups, and downloads.
- [WebSockets](api/websockets.md): event handling, reconnection, and restart state.
- [System](api/system.md): readiness, configuration changes, and recovery states.
- [OpenAPI](api/openapi.yml): canonical endpoint and schema reference.

## Develop and report issues

- [Repository layout and checks](development.md)
- [Security policy](../SECURITY.md)
