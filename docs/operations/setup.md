# Node setup

## Requirements

- Linux, glibc 2.35+, and an x86-64, ARM64, or RISC-V 64 binary.
- Docker or Podman with its Docker-compatible API available.
- A dedicated host/VM: DBEV runs as root; runtime-socket access is host-root-equivalent.
- A supported [disk-enforcement backend](disk-limits.md).

For Docker on Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y docker.io curl fuse3
sudo systemctl enable --now docker
```

## Install

Use the README's [verified download](../../README.md#download-and-install),
the [Compose guide](../../deploy/docker/README.md), or [build from source](../development.md).
Pin a reviewed version for automated deployments.

## Configure

Save the panel-generated config to `/etc/databases-everywhere/config.yml`.
The [example config](../../config/example.yml) lists settings and defaults.
Never deploy placeholder secrets or commit real credentials. Generate `token`
and `jwt_signing_key` independently, for example with `openssl rand -base64 32`.

### Addresses and TLS

- `api.host` / `api.port` bind the management listener; the panel stores its public URL.
- Use loopback behind a local proxy. Configure `api.ssl` when DBEV terminates TLS.
- Database clients use protocol gateway ports, not the API port. Their address
  must reach those listeners directly.
- Browser origins must match `remote` or `api.trusted_origins`; authenticated
  server-to-server calls are not filtered by HTTP Host.
- Use TLS across untrusted networks. Public plaintext listeners warn but are allowed.

Database containers use `network_mode=none`; private sockets or isolated
loopback bridges connect them to DBEV.

### Images and storage

Use versioned tags or digests in `images.<protocol>`; bare references and
`latest` are rejected. Keep `images.allowed.<protocol>` admin-controlled.
See [engine compatibility](../api/instances.md#engine-compatibility).

Keep allocation guards and host reserves enabled. Stopped/failed instances
remain allocated until deleted. Prepare [disk enforcement](disk-limits.md)
before starting the node.

Runtime directories are created at boot. Existing ancestors must be real
directories owned by root or the daemon user, without other-user write access
(root-owned sticky directories are allowed). Symlinks are rejected.
Default data lives under `/var/lib/dbev`; sockets and locks use `/run/dbev`.

## Podman

Set `daemon.engine: podman`. Rootful Podman uses `/run/podman/podman.sock`
when `socket_path` is empty; setup enables the system socket.

For rootless Podman, choose an existing account and its explicit socket:

```yaml
daemon:
  engine: podman
  socket_path: /run/user/1000/podman/podman.sock
```

Setup enables lingering and the account's socket, checks ownership, and prepares
private mounts. Resource limits require cgroup v2. Custom storage ancestors
must allow account traversal; setup does not loosen unrelated permissions.
Operators must supervise custom socket paths.

Do not switch Docker/Podman on a node with managed instances.

## Setup and start

```bash
sudo dbev --setup
sudo journalctl -u databases-everywhere -f
```

Setup installs the systemd unit, prepares storage, starts/restarts the service,
and sets `vm.overcommit_memory=1` for Redis/Valkey persistence.
For another config, use `sudo dbev --config /path/to/config.yml --setup`.
Rerun setup after changing runtime/socket/config paths, quota mount options,
or the service unit.

Daemon restarts normally keep containers and healthy quota mounts running,
but disconnect gateway/WebSocket clients. Updates that replace containers or
unsafe quota mounts can restart databases; plan a maintenance window.
See [readiness and recovery](../api/system.md) and [FuseQuota upgrades](disk-limits.md#fusequota-memory).

## Upgrades and maintenance

Back up database data, SQLite metadata, and its encryption key together.
Encrypted metadata remains authoritative after password rotation.

Direct upgrades are supported from v0.6.0 onward. Older nodes must pass through
v0.6 and create current, manifested backups first; manifestless pre-v0.4
backups and pre-v0.6 internal formats are unsupported.

Quarantine preserves data and blocks access. Check [recovery states](../api/system.md#recovery-states)
before deleting or retrying an instance.

Stop the daemon and managed containers before moving paths:

```bash
sudo dbev migrate-paths --dry-run
sudo dbev migrate-paths
```

Maintenance commands share the daemon's exclusive lock. Never use `--force`
on live data.

For `protected_secret_recovery_required` caused by an old plaintext value
beginning with `dbev1:`, stop the daemon and supply the exact known value:

```bash
read -rsp 'Exact known value: ' DBEV_REPAIR_SECRET
printf '%s' "$DBEV_REPAIR_SECRET" | sudo dbev repair-protected-secret \
  --instance-id INSTANCE_ID --field tenant-password --confirm-legacy-plaintext
unset DBEV_REPAIR_SECRET
```

This repairs one verified field and leaves the instance stopped; a mismatch
changes nothing. For corrupt ciphertext or a lost key, restore the key/metadata backup.

## Daemon logs

```bash
sudo journalctl -u databases-everywhere -b --no-pager -o cat
sudo journalctl -u databases-everywhere -f
```

- Daemon output goes to journald and `paths.logs/dbev.log`. The file rotates at
  10 MiB with four archives (50 MiB total); old dated logs and journald are separate.
- Database console history stays with Docker/Podman, bounded to approximately
  5 MiB per container plus runtime bookkeeping. REST/WebSockets read that tail
  and stream new output; DBEV keeps no duplicate per-instance log archive.
- ClickHouse emits warning/error console output rather than separate text logs.
  Database transaction logs and shared-tenant accounting are separate.

Adopting the console policy recreates compatible containers while keeping data
and credentials; old console history is discarded. Stopped containers stay
stopped and adopt it on their next start. Ambiguous state is reported.
After a healthy ClickHouse replacement, only standard legacy
`clickhouse-server.log` / `clickhouse-server.err.log` files and their numbered/gzip
rotations are removed; unknown files, links, data, and backups are preserved.

Routine API requests are DEBUG-only. For temporary tracing, set this service
environment value and restart; remove it after diagnosis:

```text
RUST_LOG=databases_everywhere=info,databases_everywhere::api::http::trace=debug
```

Read-only storage checks (adjust the first path if `paths.logs` differs):

```bash
sudo du -h --max-depth=2 /var/lib/dbev/logs | sort -h
sudo journalctl --disk-usage
```

Journal usage includes all services, not only DBEV.
