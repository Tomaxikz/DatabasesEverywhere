# DatabasesEverywhere

Ever wanted to hand out databases to people without giving them a whole VPS? That's basically what this is.

DatabasesEverywhere is a daemon that hosts database instances for you, made to be plugged into a panel. Every instance runs in its own container, fully isolated from the others, and the daemon routes the public database ports to whichever backend container should get the traffic. The panel stays in charge of the "business" side — users, customer records, generating the daemon config — and just talks to the daemon over its API.

## Status

Where things stand runtime-wise:

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

Grab the release binary and drop it in `/usr/local/bin`:

```bash
sudo curl -L \
  -o /usr/local/bin/dbev \
  https://github.com/calagopus/DatabasesEverywhere/releases/latest/download/dbev-linux-amd64
sudo chmod 0755 /usr/local/bin/dbev
```

Write your config at `/etc/databases-everywhere/config.yml`, then let setup do its thing:

```bash
sudo dbev --setup
sudo systemctl enable --now databases-everywhere
```

By default the daemon looks for its config here:

```text
/etc/databases-everywhere/config.yml
```

And it keeps its stuff in:

```text
/var/lib/dbev
/var/log/dbev
/run/dbev
```

## Docs

Everything else lives in [docs.md](docs.md): node setup, config fields, paths, and a full integration guide for panel developers — every REST endpoint, WebSocket events, auth, signed downloads, the lot.

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
