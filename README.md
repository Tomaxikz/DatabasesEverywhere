# DatabasesEverywhere

Hand out databases without handing out whole servers.

DatabasesEverywhere is a database hosting daemon built to sit behind a panel. Each instance runs in its own isolated container, the daemon routes public ports to the right one, and your panel drives it all over a simple API.

## Status

| Runtime | Status |
| --- | --- |
| Docker | Works |
| Podman | In progress |
| systemd services | Someday |

## Supported Databases

| Database | Status | Protocol |
| --- | --- | --- |
| PostgreSQL | Works | Native PostgreSQL TCP |
| MariaDB | Works | MySQL/MariaDB TCP |
| Redis | Works | RESP |
| MongoDB | Works | MongoDB wire protocol |
| ClickHouse | Works | Native TCP and HTTP |
| Qdrant | Works | gRPC |

## What it does

- One public gateway listener per database protocol — no port-per-instance chaos.
- Backend containers are private and don't publish any database ports by default.
- Per-instance CPU, memory, PID, and disk limits, so one noisy instance can't eat the whole box.
- Disk enforcement via FuseQuota when your host doesn't have native project quotas.
- Logical imports and exports.
- Physical backups and restores.
- Signed artifact downloads.
- WebSocket monitoring for instance status and resource usage.
- Metadata lives in a local SQLite db. No extra infra needed.

## Install

Download the latest release for your architecture and install it to `/usr/local/bin`:

```bash
case "$(uname -m)" in
  x86_64) TARGET=x86_64-linux ;;
  aarch64|arm64) TARGET=aarch64-linux ;;
  ppc64le|powerpc64le) TARGET=ppc64le-linux ;;
  riscv64) TARGET=riscv64-linux ;;
  *) echo "unsupported architecture: $(uname -m)"; exit 1 ;;
esac
VERSION=$(curl -s https://api.github.com/repos/Tomaxikz/DatabasesEverywhere/releases/latest | grep '"tag_name"' | cut -d '"' -f4)
curl -L -o /tmp/dbev \
  "https://github.com/Tomaxikz/DatabasesEverywhere/releases/download/${VERSION}/dbev-${TARGET}"
sha256sum /tmp/dbev
sudo install -m 0755 /tmp/dbev /usr/local/bin/dbev
```

Compare the printed SHA256 with the checksum table in the GitHub release notes.

Write your config at `/etc/databases-everywhere/config.yml`, then run setup:

```bash
sudo dbev --setup
sudo systemctl enable --now databases-everywhere
```

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

## Docs

Everything else lives in [docs.md](docs.md): node setup, config fields, paths, and a full integration guide for panel developers — every REST endpoint, WebSocket events, auth, signed downloads, the lot.

## Security

Found a vulnerability? Don't post it publicly — report it via GitHub Security Advisories or a private ticket on our [Discord](https://discord.com/invite/FJGQAbtyWN), and make sure it reproduces on the latest release first. Details in [SECURITY.md](SECURITY.md).

## Hacking on it

```bash
cargo test --lib
cargo build --release
```

For messing around locally there's `config.local.yml`:

```bash
cargo run -- --config config.local.yml check-config
cargo run -- --config config.local.yml daemon
```
