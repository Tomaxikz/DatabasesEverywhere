# DatabasesEverywhere

A Linux daemon for hosting databases behind a control panel.

Run each database in a **dedicated container** or place multiple tenants in a
**shared engine pool**. The panel chooses placement; DBEV handles provisioning,
credentials, gateway routing, limits, and recovery.

## Features

- PostgreSQL, MySQL, MariaDB, MongoDB, ClickHouse, Redis, Valkey, and Qdrant.
- Dedicated deployments for all engines; shared pools for the five SQL/document engines.
- Authenticated protocol gateways over private container sockets.
- CPU, memory, and disk limits for dedicated instances; shared-pool limits and tenant disk enforcement.
- Imports, exports, scheduled backups, and dedicated/shared migrations.
- REST management and live WebSocket monitoring.

See [engine compatibility and placement](docs/api/instances.md) for supported
versions and limitations.

## Get started

Requires Linux with glibc 2.35+, Docker or Podman, and the
[storage prerequisites](docs/operations/disk-limits.md).
Release binaries support x86-64, ARM64, and RISC-V 64.

1. Install a reviewed binary from [Releases](https://github.com/Tomaxikz/DatabasesEverywhere/releases).
2. Save the panel-generated configuration to
   `/etc/databases-everywhere/config.yml`; see the [example config](config/example.yml).
3. Install and start the systemd service:

```bash
sudo dbev --setup
sudo journalctl -u databases-everywhere -f
```

Setup runs the manager as root and starts or restarts the service. Database
containers remain network-isolated. Protect management access and use TLS
across untrusted networks.

Follow [node setup](docs/operations/setup.md) for installation, configuration,
upgrades, and logs, or [Docker deployment](deploy/docker/README.md) for Compose.

## Documentation

- [Documentation index](docs/README.md)
- [API contract](docs/api/openapi.yml) and [panel authentication](docs/api/auth.md)
- [Development and checks](docs/development.md)
- [Private security reporting](SECURITY.md)
