# DatabasesEverywhere

Hand out databases without handing out whole servers.

DatabasesEverywhere is a database hosting daemon built to sit behind a panel. Each instance runs in its own isolated container, the daemon routes public ports to the right one, and your panel drives it all over a simple API.

## Features

- 8 supported databases
- Database imports
- Database exports
- Database backups
- Automatic backups
- Live WebSocket monitoring
- Image updating
- Major version upgrades
- Per-database resource limits
- Node-wide capacity and host-pressure metrics for panel schedulers
- Node-wide memory and disk reserves to protect host availability

## Status

| Runtime | Status |
| --- | --- |
| Docker | Works |
| Podman | Ready for testing |
| systemd | Planned |

## Supported Databases

| Database | Status | Protocol |
| --- | --- | --- |
| PostgreSQL | Works | Native PostgreSQL TCP |
| MariaDB | Works | MySQL/MariaDB TCP |
| MySQL | Works | MySQL TCP |
| Redis | Works | RESP |
| Valkey | Works | RESP |
| MongoDB | Works | MongoDB wire protocol |
| ClickHouse | Works | Native TCP and HTTP |
| Qdrant | Works | gRPC |

## What it does

- One public gateway listener per database protocol — no port-per-instance chaos.
- Database containers have no network interface (`network_mode=none`) and never publish backend ports.
- The daemon reaches each instance through a private Unix socket; ClickHouse and Qdrant use a hash-verified, statically linked, loopback-only socket bridge inside their isolated containers.
- Legacy bridge-network/TCP instances are stopped and quarantined on upgrade; preserve required data, delete them explicitly, and recreate them before serving traffic again.
- Per-instance CPU, memory, PID, and disk limits, with bounded unused-CPU burst
  credit to reduce short quota stalls without changing sustained CPU allocation.
- Automatic disk enforcement selects native quotas when available and otherwise
  uses FuseQuota; Qdrant uses predictive soft scanning instead of unsafe FUSE storage.
- Explicit project-quota, FuseQuota, and soft-scanner modes for unusual hosts.
  See [disk-limit setup](docs/disk-limits.md).
- Native logical dumps for SQL/document stores and physical archive exports for Redis/Valkey/Qdrant.
- Physical backups and restores.
- Signed artifact downloads.
- WebSocket monitoring for instance status and resource usage.
- Metadata lives in a local SQLite db. No extra infra needed.

## Install

Official releases target x86-64, ARM64, and RISC-V 64 Linux with glibc 2.35 or
newer. This installs the latest release and automatically selects the artifact
for the host architecture:

```bash
case "$(uname -m)" in
  x86_64|amd64) DBEV_ARCH=x86_64 ;;
  aarch64|arm64) DBEV_ARCH=arm64 ;;
  riscv64) DBEV_ARCH=riscv64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

sudo curl --fail --location \
  "https://github.com/Tomaxikz/DatabasesEverywhere/releases/latest/download/dbev-${DBEV_ARCH}-linux" \
  -o /usr/local/bin/dbev
sudo chmod 0755 /usr/local/bin/dbev
```

Write your config at `/etc/databases-everywhere/config.yml`, then run setup:

```bash
sudo dbev --setup
```

Setup installs the current binary and systemd unit, enables the service, and
starts or restarts it so managed resource limits take effect immediately. It
also installs `/etc/sysctl.d/99-dbev-memory.conf` and applies
`vm.overcommit_memory=1`, which Redis and Valkey require for reliable
background persistence.

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
TimeoutStopSec=4min30s
LimitNOFILE=1048576:1048576

[Install]
WantedBy=multi-user.target
```

The daemon runs as root by default, matching other container-management agents.
This gives it direct access to Docker or Podman, filesystem quotas, FUSE mounts,
and managed database storage without service-account groups or sudoers rules.
DBE still applies its restrictive process umask and validates managed paths in
code. Database containers have no container network, use private Unix sockets
or loopback bridges, and enable their native authentication. PostgreSQL local
connections are SCRAM-authenticated except for the peer-mapped internal
maintenance role; MySQL tenant accounts use `caching_sha2_password`. Podman may
use the rootful system socket or an explicitly configured
`/run/user/<uid>/podman/podman.sock`; setup enables lingering and the user
socket for the latter. Run `dbev --setup` again after changing the engine,
socket, config path, or installing a release with an updated unit.

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
/var/lib/dbev/logs
/run/dbev
```

On daemon boot these runtime directories and their subdirectories are created
automatically if missing. Compose installs still need
`/etc/databases-everywhere/config.yml` in place before startup.
During `--setup`, an old `/var/log/dbev` setting is moved to
`/var/lib/dbev/logs` if the shared `/var/log` parent does not satisfy the
runtime path safety policy. Existing legacy log files are left untouched.
Every existing ancestor of a configured runtime path must be a real,
non-symlink directory that is not writable by untrusted users. This prevents a
local account from redirecting daemon-owned data while the service starts.

The configuration requires two distinct secrets of at least 32 random bytes:
`token` for API authentication and `jwt_signing_key` for WebSocket and download
JWTs. The API may use HTTP or HTTPS on loopback or public interfaces, matching
Wings. Plaintext non-loopback binds emit a prominent startup warning because
the API bearer token and request data can be intercepted. Database gateways may
bind to non-loopback addresses with or without TLS and continue to enforce each
database protocol's native credentials. Cleartext public gateways emit a startup
warning because credentials, queries, and results are not protected from network
interception. Remote imports use temporary acquisition workers; target database
containers stay network-isolated. Daemon file logs rotate daily and retain the
latest 14 files.

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

On an x86-64 Linux host, a normal release build produces
`target/release/dbev`:

```bash
cargo build --release
```

Explicit check/test/build aliases are also available, and CI runs
`cargo check-linux` on every push:

```bash
cargo check-linux
cargo test-linux
cargo build-linux
```
