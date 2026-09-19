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
  File writes use a 64 KiB buffer on the existing bounded background worker,
  flushed after each queue batch, before rotation, and on graceful shutdown.
  Full buffers flush during sustained traffic; idle logging adds no timer wakeups.
  Stdout remains immediate. The file queue remains lossy under overload, and
  abrupt termination can lose queued/buffered records; this is not a durable audit log.
  After 250 events passing `RUST_LOG` in a one-second window, further INFO events
  are suppressed for both outputs until the next window. Suppressed events still
  count; other levels are unchanged. This also applies to INFO audit messages and
  stdout-only CLI logging, but not database container logs.
  Daemon module targets now use `databases_everywhere::daemon`; update custom
  `RUST_LOG` filters that previously targeted `databases_everywhere::cli`.
  Crate-wide filters such as `databases_everywhere=info` are unchanged.
- Database console history stays with Docker/Podman, bounded to approximately
  5 MiB per container plus runtime bookkeeping. REST/WebSockets read that tail
  and stream new output; DBEV keeps no duplicate per-instance log archive.
- Shared-pool start/restart recreates a missing pool socket directory under
  `paths.sockets` (normally `/run/dbev/sockets`), which can disappear on reboot.
  DBEV verifies the existing container's mount and restores Docker or rootless
  Podman ownership without clearing live sockets or recreating persistent data.
  Failed and quarantined shared pools are checked automatically for safe recovery
  at boot, as described below.
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

## Failed versus quarantined shared pools

During shared-pool activation and runtime-health reconciliation, DBEV classifies
a failure by its stage and typed error, not by matching words in a Docker error
message. Both outcomes close database routes; neither
deletes metadata, reservations, credentials, volumes, or backups.

| Decision point | Result |
| --- | --- |
| Missing/unwritable temporary socket directory, full runtime filesystem | Keep down if stopping can be confirmed |
| Engine start error, readiness timeout, crash, startup-attempt limit | Keep down if stopping can be confirmed |
| Resource-limit API rejection or soft disk-capacity admission failure | Keep down if stopping can be confirmed |
| Wrong data/socket bind, unsafe path, foreign ownership, changed network isolation | Quarantine |
| Credential/isolation attestation, tenant-security replay, or uncertain metadata publication | Quarantine |
| Interrupted image change, unknown integrity error, or inability to persist/verify a stopped state | Quarantine |

**Keep down** means pool status `failed` with durable stopped intent. It stays down
during normal operation until an explicit start/restart or the next boot's single
validated recovery attempt. Existing
tenant intent is preserved so a successful, validated pool retry can restore the
previously running tenants. Status, logs, explicit power operations, and deletion
with the existing ownership/confirmation safeguards remain available. Resource
telemetry is separate: a stopped engine may still have no tenant disk sample.

**Quarantine** requires integrity recovery before starting. Boot recovery considers
existing quarantines but never just clears their flags. Other
quarantine paths, including incomplete provisioning, restore/migration ambiguity,
and storage-boundary recovery failures, retain their existing protections.

Decision logs include the failing phase and `keep_down` or `quarantine`:

```bash
sudo journalctl -u databases-everywhere -b --no-pager -o cat |
  grep 'shared_pool_failure_'
```

## Legacy credential recovery at boot

Boot also recovers missing legacy Qdrant/MariaDB **tenant** credentials from
DBEV-owned containers when they match the stored route/password verifier. This
does not reset any password or guess a missing administrator credential. A
successful recovery is encrypted in metadata before storage/image migration.
Conflicting, unavailable, or unverifiable credentials leave the current container
unchanged and require operator repair. Deferred image upgrades are reported
separately from failed compatibility checks.

## FUSE helpers across daemon restarts

The service intentionally uses `KillMode=process`: stopping DBEV must not kill
FUSE helpers serving database containers that remain running. Consequently,
systemd can report `fusequota` processes left over after a clean daemon restart.
These messages alone do not prove leaked processes. Do not switch the service to
`KillMode=control-group`, kill helpers by name, or lazily unmount database storage.

Before publishing the API, boot reconciles the private FUSE runtime directories.
Mounts referenced by saved instances/pools (including stopped/quarantined ones)
or **any** engine container, including stopped/foreign containers, are retained.
For unreferenced candidates, DBEV validates helper identity and performs a normal
unmount before requesting helper shutdown. Busy, unknown, or unverifiable state
is retained with a diagnostic. Only empty mount directories and control sockets
are removed; backing database files are never deleted by this cleanup.

Look for `fuse_helper_reconciliation`, `orphan_fuse_helper_removed`, and
`orphan_fuse_cleanup_deferred` in the journal. Live retained helpers may still
appear in systemd's leftover-process messages.

## Automatic shared-pool recovery at boot

Every daemon boot discovers **all failed and quarantined shared pools**. No IDs,
allowlist, or opt-in configuration are required. Healthy, creating, deleting, and
intentionally stopped pools are left alone. A quarantined pool with saved stopped
intent is also kept down. Ordinary desired-running stopped pools still use the
normal startup path.

There is at most one recovery attempt per eligible pool in each boot, before API
handlers or gateway workers start. Recovery checks panel ownership, stopped
container identity and image, network isolation, data/socket binds, reservations,
credentials, and quotas. Pending image changes, unresolved migrations, retained
restore manifests/workspaces, and credential/import recovery incidents still
block it. Even an older failed import blocks this path; resolve that incident
separately instead of deleting its records.

A container recreated using an immutable image ID may retain its original tag in
pool metadata. Recovery accepts that representation difference only when the
exact container/image identity still matches its saved compatibility attestation;
it does not approve a different image or change panel ownership.

A failed pool retries through the normal validated activation path, retaining
each tenant's saved running/stopped intent. Quarantine recovery keeps the durable
quarantine until all checks pass. Its tenants stay **stopped** afterward because
old containment erased their prior intent; start those tenants explicitly in the
panel. The daemon never invents credentials or restores/deletes database files.

The once-per-boot recovery pass may retry a pool whose old automatic-start budget
was exhausted, so a repaired pool is not permanently stranded by old failures.
This does not enable a background restart loop or the container engine's restart
policy. Failed attempts stay down; uncertain shutdown or persistence still fails
closed. Refused failed pools also stay down for the rest of that boot; the later
ordinary startup pass cannot bypass recovery checks. Manually stopping a failed
pool changes it to `stopped`, excluding it from
future automatic recovery. Repair refused cases using the persisted quarantine
causes and the service journal.

Old `daemon.recover_shared_pools` lists are accepted for config compatibility but
ignored and no longer serialized. They neither enable nor restrict this scan.

```bash
sudo systemctl restart databases-everywhere
sudo journalctl -u databases-everywhere -b --no-pager -o cat |
  grep 'shared_pool_recovery_'
```

This repairs runtime/access state, not lost or corrupted database data. It does
not delete volumes, restore a backup, or change the stored credentials.

## Quarantine causes and history

Quarantine causes are stored in the node's SQLite metadata, not just in logs.
Both shared pools and instances have records containing an entity ID and creation
generation, cause `code`, `recovery_class`, guidance, source, first/last recording
timestamps, and occurrence count. Several active causes can coexist; all of them
must be considered before recovery.

```bash
# Active causes; safe to run while the daemon is running.
sudo dbev quarantine

# Current and historical causes for one pool or instance.
sudo dbev quarantine --entity-id pool_clickhouse_example --history

# Page backwards using the last event_id returned by the previous page.
sudo dbev quarantine --history --limit 50 --before 123
```

The command prints JSON and opens existing metadata read-only. It does not start
databases, clear quarantine, create a database, or run migrations. Start the
upgraded daemon or use the existing offline `dbev migrate` workflow first.
No panel API or response-schema change is required.

| Recovery class | Meaning |
| --- | --- |
| `validated_retry` | Recovery may succeed after the underlying availability/shutdown problem is resolved; every safety check still applies. |
| `repair_required` | Repair credentials, isolation, storage, or the interrupted operation before attempting recovery. |
| `manual_review` | Ownership, metadata, a failed recovery, or an unknown cause requires operator investigation if boot validation cannot establish a safe state. |

Codes include `shutdown_unconfirmed`, `ownership_mismatch`, `isolation_mismatch`,
`storage_boundary`, `runtime_path_unsafe`, `credential_integrity`,
`security_attestation`, `provisioning_incomplete`, `image_change_incomplete`,
`import_restore_incomplete`, `metadata_uncertain`, and `recovery_failed`.
No class means that data is irretrievably lost, and none automatically restarts it.

Known decision points commit the cause and quarantined metadata in one transaction.
Database triggers also capture unclassified/direct SQL transitions as `unknown`,
so a committed quarantine cannot silently lack a record. Ordinary boot checks do
not overwrite the original causes. Repeated observations of the same active cause
update its count instead of growing history on every reconciliation.

When an entity leaves quarantine or is deleted, its records are closed with the
resulting status but kept in history. Reusing an ID does not inherit old active
records. A closed record means the state changed, not necessarily that data was
restored. Existing quarantines at upgrade are recorded as `legacy_unknown` with
`manual_review`; their observation timestamp is the upgrade time, not a guessed
original incident time. Consult the old journal for that missing context.

The history contains fixed diagnostic codes/guidance, not raw engine errors,
passwords, or tokens. Detailed errors remain in the service journal. If SQLite
cannot commit, the failure is logged and containment is still attempted; the
daemon cannot promise a durable incident record when its storage is unavailable.
