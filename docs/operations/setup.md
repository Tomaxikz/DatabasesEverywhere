# Node setup

[Documentation index](../README.md)

## Requirements

- Linux, glibc 2.35+, and an x86-64, ARM64, or RISC-V 64 release binary.
- Docker or Podman with its Docker-compatible API available.
- A dedicated host or VM: the manager runs as root and runtime-socket access
  is host-root-equivalent.
- A supported [disk-enforcement backend](disk-limits.md).

For Docker on Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y docker.io curl fuse3
sudo systemctl enable --now docker
```

## Install

Use the README's [download and install commands](../../README.md#download-and-install).
They select the host architecture and verify the binary's build attestation.
Pin a reviewed release in automated deployments rather than following `latest`.

For container deployment, use the [Compose guide](../../deploy/docker/README.md).
For source builds, use the [development guide](../development.md).

## Configure

Save the panel-generated file at `/etc/databases-everywhere/config.yml`.
The [example configuration](../../config/example.yml) lists all settings and
defaults; do not copy its placeholder secrets into production.

Essential node identity and API settings:

```yaml
remote: https://panel.example.com
uuid: replace-with-panel-generated-node-uuid
token_id: replace-with-panel-generated-token-id
token: replace-with-at-least-32-random-bytes
jwt_signing_key: replace-with-a-different-32-byte-random-key

api:
  host: 127.0.0.1
  port: 8090
  trusted_origins: []
```

Generate `token` and `jwt_signing_key` independently, for example by running
`openssl rand -base64 32` twice. Never reuse either value or commit real secrets.

### Addresses and TLS

- `api.host` and `api.port` bind the local management listener. Use loopback
  behind a local proxy, or `0.0.0.0` for a public listener.
- The panel stores the public API URL. Configure `api.ssl` only when DBEV
  terminates TLS; a proxy may terminate it separately.
- Database clients connect to protocol gateway ports, not the API port.
  Use an address that actually reaches those listeners.
- Server-to-server API calls are authenticated, not filtered by HTTP Host.
  Browser origins must match `remote` or an entry in `api.trusted_origins`.
- Legacy `api.fqdn` and `api.trusted_hosts` values are accepted but ignored.
- Public plaintext API/gateway listeners are allowed with warnings. Use TLS
  whenever credentials or database traffic cross an untrusted network.

Database containers always use `network_mode=none`. DBEV reaches them through
private sockets or isolated loopback bridges; this is not a configurable network mode.

### Images and credentials

Set a versioned tag or digest in `images.<protocol>` and keep
`images.allowed.<protocol>` admin-controlled. Bare references and `latest`
are rejected; the configured default is implicitly allowed.

See [engine compatibility](../api/instances.md#engine-compatibility) for the
admitted families and tested connector matrix. The detected engine version,
not the image tag alone, determines compatibility. Selected engine versions
may also have CPU/kernel requirements.

DBEV encrypts tenant and maintenance credentials in private SQLite metadata.
After password rotation, that store is authoritative; managed commands do
not fall back to stale container environment values. Back up the metadata
database and its encryption key together.

### Capacity and storage

The CPU, memory, and disk overallocation guards default to enabled. Memory and
disk admission preserve the configured host reserves; explicit maxima cannot
override those reserves. Stopped and failed instances stay allocated until
deleted. Leave the guards enabled on production nodes.

| Configuration | Purpose |
| --- | --- |
| `allocation` | Reservation ceilings and actual host headroom |
| `disk` | Native quotas, FuseQuota, or predictive soft enforcement |
| `paths` | Runtime storage roots |
| `artifacts` | Export retention, one-use spools, upload limits, job scheduler |
| `backups` | Schedule, retention, local/S3/Kopia storage, catalog previews |
| `security.remote_import` | Remote-source access, TLS, concurrency, and deadlines |

Use [disk setup](disk-limits.md) for quota prerequisites and
[transfers](../api/transfers.md) for upload, scheduler, and backup behavior.
Defaults live in the example config rather than being repeated here.

Runtime directories are created at boot. Their existing ancestors must be real
directories, owned by root or the daemon user, and not writable by other users;
root-owned sticky directories such as `/tmp` are allowed. Symlinked runtime
paths are rejected. Default persistent data is under `/var/lib/dbev`, with
sockets and locks under `/run/dbev`.

## Podman

Set `daemon.engine: podman`. For rootful Podman, leave `socket_path` empty or
use `/run/podman/podman.sock`; setup enables the system socket.

For rootless Podman, select an existing account and its explicit socket:

```yaml
daemon:
  engine: podman
  socket_path: /run/user/1000/podman/podman.sock
```

Setup enables that account's lingering and socket, validates ownership, and
prepares private mounts. Rootless resource limits require cgroup v2. Custom
storage ancestors must already allow the account directory traversal; setup
does not loosen unrelated permissions. Custom socket paths must be supervised
by the operator.

Do not switch Docker/Podman on a node with managed instances; DBEV rejects
mixed-runtime state.

## Setup and start

```bash
sudo dbev --setup
sudo journalctl -u databases-everywhere -f
```

Setup installs the root-run systemd unit, prepares private directories, and
starts or restarts the service. It also applies `vm.overcommit_memory=1` for
Redis/Valkey persistence. Run setup again after changing the runtime engine,
socket, config path, quota mount options, or installing an updated service unit.

To select another config:

```bash
sudo dbev --config /path/to/config.yml --setup
```

The service uses `KillMode=process`: normal daemon restarts leave database
containers and healthy FuseQuota mounts running. Gateway/WebSocket connections
still disconnect. See [readiness and recovery](../api/system.md).

## Upgrades and maintenance

Direct upgrades are supported from DBEV v0.6.0 onward. Older nodes must pass
through v0.6 and create current, manifested backups first. Preserve data,
metadata, and the encryption key before upgrading. Manifestless pre-v0.4
backups and pre-v0.6 internal formats are unsupported.

Unverifiable credentials, unsafe legacy networking, duplicate routes, or
interrupted destructive work can quarantine an instance. Quarantine preserves
data and blocks serving it; inspect [recovery states](../api/system.md#recovery-states)
before deleting or retrying anything.

Stop the daemon and managed containers before moving paths:

```bash
sudo dbev migrate-paths --dry-run
sudo dbev migrate-paths
```

`--move-new-config` is an alias. Maintenance commands share the daemon's
exclusive lock. Do not use `--force` on live data.

For `protected_secret_recovery_required` caused by an old plaintext value
beginning with `dbev1:`, stop the daemon and supply the exact known value:

```bash
read -rsp 'Exact known value: ' DBEV_REPAIR_SECRET
printf '%s' "$DBEV_REPAIR_SECRET" | sudo dbev repair-protected-secret \
  --instance-id INSTANCE_ID --field tenant-password --confirm-legacy-plaintext
unset DBEV_REPAIR_SECRET
```

This repairs one verified field and leaves the instance stopped. A mismatch
changes nothing. For corrupt ciphertext or a lost key, restore the key/database
backup instead.

## Daemon logs

Routine API traffic is DEBUG-only; startup, audit events, warnings, and errors
remain visible at the default level.

DBEV writes to stdout/journald and `paths.logs/dbev.log`. The file rotates at
10 MiB with four numbered archives: **50 MiB total** for those five files.
Old dated logs, instance/container logs, and the system journal are separate
and are not covered or deleted by that cap.

For temporary request tracing, set this service environment value and restart;
remove it after diagnosis:

```text
RUST_LOG=databases_everywhere=info,databases_everywhere::api::http::trace=debug
```

Read-only storage checks:

```bash
sudo du -h --max-depth=2 /var/lib/dbev/logs | sort -h
sudo journalctl --disk-usage
```

The journal command reports all services, not DBEV alone.
