This repository is still in development please do not use this in production yet

# DatabasesEverywhere

Hand out databases without handing out whole servers.

DatabasesEverywhere is a database hosting daemon built to sit behind a panel. Each instance runs in its own isolated container, the daemon routes public ports to the right one, and your panel drives it all over a simple API.

## Features

- 7 supported databases
- Database imports
- Database exports
- Database backups
- Automatic backups
- Live WebSocket monitoring
- Image updating
- Major version upgrades
- Per-database resource limits
- Node-wide capacity and host-pressure metrics for panel schedulers
- Node-wide memory and disk admission reserves to protect host availability

## Status

| Runtime | Status |
| --- | --- |
| Docker | Works |
| Podman | In progress |
| systemd | Planned |

## Supported Databases

| Database | Status | Protocol |
| --- | --- | --- |
| PostgreSQL | Works | Native PostgreSQL TCP |
| MariaDB | Works | MySQL/MariaDB TCP |
| MySQL | Works | MySQL TCP |
| Redis | Works | RESP |
| MongoDB | Works | MongoDB wire protocol |
| ClickHouse | Works | Native TCP and HTTP |
| Qdrant | Works | gRPC |

## What it does

- One public gateway listener per database protocol — no port-per-instance chaos.
- Database containers have no network interface (`network_mode=none`) and never publish backend ports.
- The daemon reaches each instance through a private Unix socket; ClickHouse and Qdrant use a hash-verified, statically linked, loopback-only socket bridge inside their isolated containers.
- Legacy bridge-network/TCP instances are stopped and quarantined on upgrade; preserve required data, delete them explicitly, and recreate them before serving traffic again.
- Per-instance CPU, memory, PID, and disk limits, so one noisy instance can't eat the whole box.
- Disk enforcement via FuseQuota when your host doesn't have native project quotas.
- Automatic per-boot filesystem detection selects native quotas when available
  and otherwise selects FuseQuota; there is no manual disk-mode switch.
- Native logical dumps for SQL/document stores and physical archive exports for Redis/Qdrant.
- Physical backups and restores.
- Signed artifact downloads.
- WebSocket monitoring for instance status and resource usage.
- Metadata lives in a local SQLite db. No extra infra needed.

## Install

Official release artifacts currently target x86-64 Linux with glibc 2.35 or
newer. Choose a
versioned release, verify its published SHA-256, and install it to
`/usr/local/bin`:

```bash
DBEV_VERSION=v0.2.0 # replace with the reviewed release
test "$(uname -m)" = x86_64
sudo curl --fail --location "https://github.com/Tomaxikz/DatabasesEverywhere/releases/download/${DBEV_VERSION}/dbev-x86_64-linux" -o /usr/local/bin/dbev
sha256sum /usr/local/bin/dbev # compare with the release checksum
sudo chmod +x /usr/local/bin/dbev
```

Write your config at `/etc/databases-everywhere/config.yml`, then run setup:

```bash
sudo dbev --setup
sudo systemctl enable --now databases-everywhere
```

For the default Docker and FuseQuota configuration, `dbev --setup` writes the
following complete unit to
`/etc/systemd/system/databases-everywhere.service`:

```ini
[Unit]
Description=DatabasesEverywhere
After=docker.service
Requires=docker.service
PartOf=docker.service

[Service]
User=root
ExecStart=/usr/local/bin/dbev daemon
KillMode=process
Restart=on-failure
RestartSec=5s
TimeoutStopSec=21min
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

The daemon runs as root by default, matching other container-management agents.
This gives it direct access to Docker or Podman, filesystem quotas, FUSE mounts,
and managed database storage without service-account groups or sudoers rules.
DBE still applies its restrictive process umask and validates managed paths in
code. Setup substitutes `podman.socket` when Podman is configured and places a
custom config path in `ExecStart`. Run `dbev --setup` again after changing those
settings or installing a release with an updated unit.

By default the daemon reads its config from:

```text
/etc/databases-everywhere/config.yml
```

To use a different config file, pass the `--config` flag:

```bash
sudo dbev --config /path/to/config.yml daemon
```

Runtime data lives in:

```text
/var/lib/dbev
/var/log/dbev
/run/dbev
```

On daemon boot these runtime directories and their subdirectories are created
automatically if missing. Compose installs still need
`/etc/databases-everywhere/config.yml` in place before startup.

The configuration requires two distinct secrets of at least 32 random bytes:
`token` for API authentication and `jwt_signing_key` for WebSocket and download
JWTs. The API may remain on loopback behind a reverse proxy or bind directly to
a public interface when its native TLS certificate and key are enabled;
cleartext public API binds are rejected. Database gateways may bind to
non-loopback addresses with or without TLS and continue to enforce each
database protocol's native credentials. Cleartext public gateways emit a
startup warning because credentials, queries, and results are not protected
from network interception. Remote credential imports are intentionally
unavailable in the network-none model; stage a trusted local artifact first.

## Docs

Everything else lives in [docs.md](docs.md): node setup, config fields, paths, and a full integration guide for panel developers — every REST endpoint, WebSocket event, auth flow, and temporary download URL.

## Security

Found a vulnerability? Don't post it publicly — report it via GitHub Security Advisories or a private ticket on our [Discord](https://discord.com/invite/FJGQAbtyWN), and make sure it reproduces on the latest release first. Details in [SECURITY.md](SECURITY.md).

## Hacking on it

```bash
cargo test --all-targets
cargo build --release
```

For messing around locally there's `config.local.yml`:

```bash
cargo run -- --config config.local.yml check-config
cargo run -- --config config.local.yml daemon
```
