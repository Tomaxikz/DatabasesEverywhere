# Node setup and configuration

[Documentation index](../README.md)

## Upgrade compatibility

The supported direct-upgrade floor is DBEV v0.6.0. Current releases continue
to load official v0.6 configuration, SQLite metadata, API request defaults, and
manifested backups. The historical SQL migration chain remains embedded because
it is also how a new metadata database is built. Pre-v0.6 internal spellings and
manifestless local backups from before v0.4 are no longer supported. Upgrade an
older node through a v0.6 release and create current backups before moving it to
this release.

## Node setup

### Install

```bash
sudo apt update
sudo apt install -y docker.io sudo curl fuse3
sudo systemctl enable --now docker
```

Podman is supported through its Docker-compatible API in both rootful and
rootless modes. For a rootful service, install Podman, set
`daemon.engine: podman`, leave `daemon.socket_path` empty (or set it to
`/run/podman/podman.sock`), then let setup validate and enable the system
socket:

```yaml
daemon:
  engine: podman
  socket_path: /run/podman/podman.sock
```

For rootless Podman, choose the existing Linux account that will own the
containers and configure its standard socket path explicitly:

```yaml
daemon:
  engine: podman
  socket_path: /run/user/1000/podman/podman.sock
```

Running `sudo dbev --setup` enables login lingering and that account's
`podman.socket`, validates the socket owner and Podman identity, and prepares
the private bind-mount paths without making them publicly readable. Rootless
Podman requires cgroup v2 so DBE can preserve CPU, memory, and PID limits.
Custom Podman socket paths are accepted but must be started and supervised by
the operator. Do not switch an existing node between Docker and Podman while
it still has managed instances; DBE refuses the mixed-runtime state rather
than silently losing or recreating containers.

With custom storage paths, every ancestor above a DBE-managed bind-mount root
must already grant the selected rootless account execute-only traversal. Setup
checks this explicitly and reports the first blocking directory; it never
loosens permissions on unrelated parent directories.

Official releases contain x86-64, ARM64, and RISC-V 64 Linux daemons. Windows
is not a supported target because the daemon depends on Linux container,
filesystem, and Unix-socket facilities. Linux artifacts target glibc 2.35 or
newer. Choose a versioned release and the artifact matching your host. Do not
automate installation from the mutable `latest` URL.

```bash
DBEV_VERSION=v0.8.0 # replace with the reviewed release
case "$(uname -m)" in
  x86_64) DBEV_ARCH=x86_64 ;;
  aarch64|arm64) DBEV_ARCH=arm64 ;;
  riscv64) DBEV_ARCH=riscv64 ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
sudo curl --fail --location "https://github.com/Tomaxikz/DatabasesEverywhere/releases/download/${DBEV_VERSION}/dbev-${DBEV_ARCH}-linux" -o /usr/local/bin/dbev
sudo chmod +x /usr/local/bin/dbev
```

Release pages continue to publish SHA-256 checksums for automated consumers.
For optional provenance verification, install the GitHub CLI and verify the
binary's signed GitHub Actions attestation:

```bash
gh attestation verify /usr/local/bin/dbev --repo Tomaxikz/DatabasesEverywhere
```

Maintainers must configure the GitHub Actions environment named
`production-release` with required reviewers and restrict deployments to the
protected `main` branch and version tags. The release workflow rejects other
refs, requires the requested tag to match the Cargo package version, attests
release binaries, and publishes Docker provenance and an SBOM.

For local cross-release builds from Windows, install Zig and
`cargo-zigbuild 0.22.3`, then run `cargo b`. The command builds only the
static Linux target and writes it to Cargo's normal target tree:

```text
target/x86_64-unknown-linux-musl/release/dbev
```

No Windows executable is produced. Run both the daemon and `--bench` from
Linux.

### Config

Drop the panel-generated config in place before setup:

```bash
sudo mkdir -p /etc/databases-everywhere
sudo nano /etc/databases-everywhere/config.yml
```

The bits you actually need to change:

```yaml
remote: https://panel.example.com
uuid: replace-with-panel-generated-node-uuid
token_id: replace-with-panel-generated-token-id
token: replace-with-at-least-32-random-bytes
jwt_signing_key: replace-with-a-different-32-byte-random-key

api:
  host: 127.0.0.1
  port: 8090
  trusted_origins: [] # extra exact browser callers, if any
```

Also tweak gateway ports, `daemon.engine`, or `daemon.socket_path` if your host needs it. Database container networking is not configurable: every instance uses `network_mode=none` and private Unix sockets. ClickHouse and Qdrant receive a hash-verified, statically linked bridge helper because those engines expose TCP listeners internally; the helper can connect only to non-zero loopback targets and creates sockets only directly under `/run/dbev`. Qdrant's one configured public listener auto-detects HTTP/2 gRPC and HTTP/1.1 REST, then uses distinct private gRPC/REST sockets and checks the API key on every request or stream. Keep `api.host` on loopback when using a local reverse proxy. Direct HTTP and HTTPS binds are both supported; use `api.host: 0.0.0.0` for a normal public listener and configure `api.ssl` when DBEV terminates TLS itself. The panel stores the public IP or DNS hostname and constructs the HTTP/WebSocket URLs. Retired v0.6 `api.trusted_hosts` and later `api.fqdn` values are accepted on boot so managed configs keep loading, but are ignored and omitted when configuration is serialized.

`token` and `jwt_signing_key` are independent credentials and must each contain
at least 32 random bytes. Generate them with a cryptographically secure secret
generator, never copy one into the other, and never commit their real values.
The template placeholders are deliberately rejected by `check-config`.

For example, run `openssl rand -base64 32` twice and assign each output to one
of the two fields.

The API listener may run on loopback, behind a reverse proxy, or directly on a public interface using HTTP or native HTTPS, matching Wings. Plaintext non-loopback API binds emit a prominent warning because bearer tokens and request data are not encrypted. Database gateways may also use public binds with or without TLS and continue to enforce the database protocols' native credentials. Cleartext public gateways emit the same class of warning. Managed database containers remain network-isolated. Credential-based imports use short-lived, hardened acquisition helpers (or a bounded host client for Redis/Valkey/Qdrant) and never add a network interface to the target container.

Database images may use ordinary versioned Docker Hub, GHCR, or other
registry references. Bare references and the mutable `latest` tag are rejected;
an optional `@sha256:` digest can still be used when exact reproducibility is
desired:

```yaml
images:
  postgres: "postgres:18.4"
  redis: "redis:8.8.0"
  valkey: "valkey/valkey:9.1.1"
  mariadb: "mariadb:12.3.2"
  mysql: "mysql:8.4"
  mongodb: "mongo:8.3.4"
  clickhouse: "clickhouse/clickhouse-server:26.4.4.38"
  qdrant: "qdrant/qdrant:v1.18.2"
  allowed:
    postgres: ["postgres:18.4"]
    redis: ["redis:8.8.0"]
    valkey: ["valkey/valkey:9.1.1"]
    mariadb: ["mariadb:12.3.2"]
    mysql: ["mysql:8.4"]
    mongodb: ["mongo:8.3.4", "mongo:7.0.37"]
    clickhouse: ["clickhouse/clickhouse-server:26.4.4.38"]
    qdrant: ["qdrant/qdrant:v1.18.2"]
```

MongoDB 8.x has a known incompatibility with Linux kernel 6.19+ / 7.x
(`SERVER-121912`). If a node logs that MongoDB cannot start on that kernel,
switch only MongoDB back to the known working version: `mongo:7.0.37`.

References:

- <https://www.mongodb.com/docs/v8.2/release-notes/8.0/#mongodb-8-0-incompatible-with-kernel-6-19>
- <https://jira.mongodb.org/browse/SERVER-121912>

The supported MySQL baseline is the official `mysql:8.4` LTS image. DBE enables
the compatibility authentication plugin required by its credential-routing
gateway; do not substitute MySQL 9.x, where that plugin was removed. MySQL
containers have `network_mode=none`, expose only a per-instance Unix socket,
and never return tenant passwords through metadata or API responses. Runtime
secrets required by an image remain confined to its isolated container
configuration; DBE encrypts tenant and maintenance credentials plus routing
verifiers in the private metadata store and never serializes them in API
responses. Those protected metadata values are the authority after a password
rotation: DBE injects the current decrypted credential into each short-lived
managed client instead of trusting immutable container environment variables.
During an upgrade, DBE adopts an old container credential only when its field
pair is unambiguous and the live database cryptographically or actively proves
that it is correct; a missing plaintext that cannot be proved still requires one
explicit password reset. Enable the database gateway's native TLS whenever the
listener crosses an untrusted network.

PostgreSQL, MySQL, MariaDB, and ClickHouse gateways support both traditional
clients that name the database during their initial handshake and JDBC/Hikari
clients that connect before choosing a catalog. Explicit database names always
use exact username-plus-database routing. When the initial database is omitted
(or a driver supplies its conventional username/default placeholder), DBE may
infer it only when that protocol has exactly one running route for the supplied
username, then rewrites the backend startup request with the resolved database.
Ambiguous usernames fail closed and require the client URL to include the
database. This fallback never grants access to another tenant or bypasses the
database engine's own credentials and grants.

Keep CPU, memory, and disk reservations inside the node's safe capacity:

```yaml
allocation:
  prevent_cpu_overallocation: true
  prevent_memory_overallocation: true
  prevent_disk_overallocation: true
  max_memory_mib: null
  max_disk_mib: null
  reserved_memory_mib: 512
  reserved_disk_mib: 2048
```

All three `prevent_*_overallocation` guards default to `true`, including when an
older config omits them. CPU-limit reservations may not exceed the detected host
core count. When a memory or disk maximum is `null`, DBE uses detected physical
capacity minus its reserve. An explicit maximum can make the database pool
smaller but cannot override the safety reserve. New instances and limit
increases are rejected when their projected allocation exceeds an enabled
resource pool; memory and disk also require the configured reserve to remain
actually available. Capacity guards do not reject decreases. A shared tenant
disk decrease has a separate safety check: DBE briefly fences and drains the
tenant and rejects the shrink with `409 conflict` when its physical data does
not fit the requested boundary. A guard can be set to `false` independently
for deliberate test-node overcommit, but production nodes should leave every
guard enabled. Stopped and failed instances remain allocated until deleted.

Disk enforcement is resolved on every daemon boot. DBE inspects every
configured path and logs its backing mount, source, filesystem type, and mount
options. In the default `auto` mode, Btrfs qgroups, ZFS refquotas, and
project-quota-enabled XFS/ext4/f2fs mounts use native hard quotas; other
filesystems use FuseQuota. Qdrant is the exception: because Qdrant does not
consider FUSE safe for persistent vector storage, it uses native storage plus
the predictive soft scanner whenever a native quota is unavailable.

Use this disk section:

```yaml
disk:
  mode: auto
  fuse_quota_binary: embedded
  fuse_quota_binary_sha256: ""
  fuse_quota_rescan_interval_seconds: 150
  project_id_base: 200000
  soft_scanner:
    scan_interval_seconds: 15
    use_inotify: true
    full_scan_interval_seconds: 90
    inotify_debounce_milliseconds: 500
    max_dirty_paths_per_instance: 512
    max_concurrent_scans: 2
    max_entries_per_scan: 1000000
    scan_timeout_seconds: 30
    max_consecutive_scan_failures: 3
    safety_reserve_mib: 64
    recovery_percent: 85
    shutdown_grace_seconds: 30
```

`disk.mode` accepts `auto`, `project_quota`, `fuse_quota`, and
`soft_scanner`. The legacy value `none` is accepted as an alias for
`soft_scanner`; it does not disable enforcement. A scanner-enforced instance
reports `disk_enforced: false`, `disk_enforcement_method: "soft_scanner"`, and
`enforcement_strength: "soft"` so callers can distinguish predictive
stop/kill enforcement from a hard write-time quota.

The scanner uses a Wings-style hybrid: one recursive inotify watcher
coalesces changed paths and drives bounded subtree rescans, while periodic
full scans remain authoritative. Queue overflow, watcher errors, root changes,
or too many independent dirty paths force a full reconciliation. If inotify
is disabled or unavailable, DBE safely falls back to periodic full scans.
Incremental usage trees retain at most 4,096 directories per instance and
32,768 across the daemon; larger trees automatically use bounded-memory
streaming full scans. Qdrant always receives a full scan at the base interval
because mmap writes may not generate filesystem events. These intervals are
scheduling targets: completion can be later when fleet scan demand exceeds
`max_concurrent_scans`, so size concurrency for the number and size of managed
instances and treat scanner enforcement as soft rather than quota-equivalent.

Changing between a raw-data mode and FuseQuota cannot mutate an existing
container's bind mount. DBE detects that mismatch, stops the affected instance
fail-closed, and refuses to relabel or restart it until it is safely migrated
or recreated. Legacy Qdrant-on-Fuse instances receive a rollback-safe migration
to native storage during boot when their encrypted credentials and immutable
image identity are available.

For native XFS, ext4, or F2FS project quotas, DBE allocates from a bounded range of
at most 1,000,000 consecutive IDs starting at `project_id_base`. Reserve that
range exclusively for DBE on the host. XFS mode rejects conflicting entries in
`/etc/projects` or `/etc/projid` instead of replacing them.

The native systemd service runs as root, so it can configure project quotas and
FUSE mounts directly without a sudoers rule or a writable-filesystem override.
Rerun `--setup` after changing the filesystem or its quota mount options so DBE
rechecks host support for the selected enforcement mode. Detailed host setup
and verification instructions are in [Disk limits](disk-limits.md).

FuseQuota uses a helper that's bundled into the binary. When automatic
detection selects FuseQuota, `dbev` checks that `/dev/fuse` is usable and
enables `user_allow_other` in `/etc/fuse.conf` on startup. The host
still needs kernel FUSE support. Release binaries for x86-64, ARM64, and
RISC-V 64 contain the matching checked and verified helper. A source build for
another architecture must install a trusted helper, set its absolute path in
`disk.fuse_quota_binary`, and set `disk.fuse_quota_binary_sha256` to the
helper's lowercase SHA-256. External helpers must be root-owned, singly linked,
executable regular files in root-owned directories that are not writable by
group or others. The config administration API cannot change either helper
field, and builds never download executable code automatically.

The generated systemd unit uses `KillMode=process`, so FuseQuota helpers and
their mounts survive normal daemon restarts. DBE reconnects to healthy helpers
on boot without interrupting their containers. If an individual helper is
missing or stale after a crash or host reboot, DBE isolates only the affected
instance while restoring a truthful, usable enforcement path.

Recommended paths:

```yaml
paths:
  data: /var/lib/dbev
  metadata: /var/lib/dbev/metadata
  volumes: /var/lib/dbev/volumes
  backups: /var/lib/dbev/backups
  sockets: /run/dbev/sockets
  locks: /run/dbev/locks
  logs: /var/lib/dbev/logs
  artifacts: /var/lib/dbev/artifacts
  exports: /var/lib/dbev/artifacts/exports
  imports: /var/lib/dbev/artifacts/imports
  fuse: /var/lib/dbev/fuse
  tmp: /var/lib/dbev/tmp
```

When running with Docker Compose, create only the config directory and
`config.yml` before starting the container. On boot, `dbev` creates the
runtime tree under `paths.data`, `paths.logs`, `paths.sockets`, `paths.locks`,
`paths.artifacts`, `paths.fuse`, and `paths.tmp` if those directories are
missing.

Every existing ancestor of these runtime paths is checked before creation and
again after hardening. It must be a real directory (not a symlink), be owned by
root or the daemon user, and not be writable by group or other users. A
root-owned sticky directory such as `/tmp` is allowed. This validation applies
to runtime roots only; it does not change archive upload, import, export, or
backup path resolution.

Compose also requires an explicit immutable image selection:

```bash
export DBEV_IMAGE='ghcr.io/tomaxikz/databaseseverywhere:v0.8.0@sha256:REPLACE_ME'
docker compose --project-directory . -f deploy/docker/compose.yml up -d
```

The supplied FuseQuota profile retains `SYS_ADMIN`, `/dev/fuse`, host
networking, and write access to the Docker socket, but no longer uses blanket
privileged mode. Docker socket access is still host-root-equivalent. Deploy the
manager on a dedicated host or VM; if FuseQuota is not used, remove
`SYS_ADMIN`, `/dev/fuse`, and the AppArmor override too.

The supplied Compose file also selects the host cgroup namespace, mounts host
`/proc` read-only at `/host/proc`, and mounts host `/sys/fs/cgroup` at the same
in-container path. DBE uses the former to
bind an engine-reported container PID to its immutable container ID before
writing only that container's CPU burst control in the latter. Native systemd
installs already have this host view. Existing Compose deployments must adopt
these two mounts to receive CPU burst behavior; without them, ordinary CPU
quotas remain enforced and DBE logs that burst reconciliation is unavailable.

Before starting that profile, ensure the host `/etc/fuse.conf` contains an
uncommented `user_allow_other`; Compose mounts the file read-only so the daemon
cannot modify host configuration from inside the container.

Temporary import-upload limits are configured separately from generated
artifact retention:

```yaml
artifacts:
  retention_keep_latest: 20
  retention_max_age_days: 30
  stream_exports_only: false
  max_artifacts_per_instance: 20
  import_upload_max_bytes: 8589934592        # one upload; 8 GiB
  import_upload_max_total_bytes: 34359738368 # all active uploads; 32 GiB
  import_upload_max_per_instance: 4
  import_upload_max_concurrent: 2
  import_upload_ttl_hours: 24
  import_upload_timeout_seconds: 3600
  import_upload_idle_timeout_seconds: 30
  import_export_scheduler:
    dynamic_limiter_enabled: true
    max_queued_jobs: 1024
    max_queued_jobs_per_instance: 32
    manual_max_active_jobs: 16
    dynamic_max_active_jobs: 256
    dynamic_memory_budget_mib: 0
    dynamic_io_budget_mib: 0
    dynamic_cpu_units: 0
    starvation_timeout_seconds: 30
    max_bypass: 8
```

`stream_exports_only: false` keeps the existing retained-artifact behavior.
When true, client-requested exports use a private one-use spool, remain absent
from the artifact inventory, force a single-use download ticket, and are
durably removed when the HTTP download finishes or disconnects. Abandoned
spools expire after one hour and are swept at startup and every minute. Internal
upgrade/recovery exports remain retained because they are required for safe
rollback. `max_artifacts_per_instance` (1-10,000) is a hard combined cap over
retained artifacts and pending one-use exports; another export returns a
conflict until the client downloads or deletes one. Both fields default safely
when absent from an older configuration and take effect after daemon restart.

The node reserves the declared `Content-Length` before accepting the body and
also checks free disk space. The total timeout bounds the complete transfer;
the idle timeout rejects a stalled request without imposing the ordinary API
body limit on dump uploads. Expired uploads are removed by the background
sweeper.

Import/export execution uses a separate weighted scheduler. In dynamic mode,
DBEV estimates each job from its protocol, immutable input size, compression,
wipe/rollback work, and target disk allocation. Memory is a hard safety budget;
CPU and I/O are concurrency weights. A memory-safe job whose CPU or I/O weight
exceeds the whole budget may run only by itself, reserving the full weight so a
second job cannot overlap it. Small plain dumps can therefore run at higher
concurrency, while compressed, physical, or wipe imports are charged
conservatively. Jobs waiting in the durable queue do
not hold active-execution or staging-disk reservations, and mutations of the
same instance remain serialized.

Set a dynamic budget to `0` to derive it automatically. Memory uses a
conservative share of the effective host-or-cgroup available memory, CPU uses
the effective host-or-cgroup quota as its concurrency weight, and I/O covers
the configured upload capacity plus one maximum physical restore. Auto-detected CPU and memory headroom are refreshed
while the daemon runs; explicit nonzero budgets remain fixed. If the live
memory budget cannot safely fit one modelled job, the
recommendation endpoint returns `recommended_active_jobs: 0`; clients must not
clamp that safety result to one. A job that exceeds an explicit dynamic memory
budget is rejected immediately. CPU/I/O-only oversize runs exclusively. A job waiting for auto-detected memory
headroom is rejected if it still cannot fit after
`starvation_timeout_seconds`. The same timeout and `max_bypass` bound how long smaller fitting jobs
may pass an older job that can otherwise run.

Omitted scheduler fields use the documented defaults in memory. DBEV does not
rewrite the YAML, node identity, panel tokens, remote URL, or TLS paths. Copy
the block above into the managed configuration when you want every value to be
explicit.

To use a fixed active-job ceiling instead, set
`dynamic_limiter_enabled: false` and configure `manual_max_active_jobs`.
Manual mode still retains per-instance serialization, queue bounds, upload
validation, extraction limits, and free-space reservations; it disables only
weighted active-work admission. A configuration change takes effect after a
daemon restart.

Scheduler validation ranges are: `max_queued_jobs` 64-8,192;
`max_queued_jobs_per_instance` 1-256 and no greater than the global queue;
manual/dynamic active ceilings 1-1,024 and no greater than the global queue;
memory budget `0` or 128-16,777,216 MiB; I/O budget `0` or
256-67,108,864 MiB; CPU units 0-65,536; starvation timeout 1-3,600 seconds;
and bypass count 0-1,024. Replayable queued options are capped at 64 KiB, so a
large durable queue cannot retain unbounded selection payloads in memory.

Automatic backups:

```yaml
backups:
  enabled: true
  interval_minutes: 1440
  run_on_startup: false
  retention_keep_latest_per_instance: 7
  retention_max_age_days: 30
  storage:
    driver: local # local, s3, or kopia
  browsing:
    enabled: true
    max_objects: 256
    max_preview_objects: 32
    preview_rows_per_object: 10
    max_row_bytes: 4096
    max_catalog_bytes: 1048576
```

Retention is per instance and is enforced through the selected storage driver.
After each successful backup, the oldest owned backups are deleted until both
limits are satisfied. `local` is the default and stores archives below
`paths.backups`; existing manifested local archives remain readable.

`paths.artifacts`, `paths.exports`, and `paths.imports` configure the local
artifact staging roots independently from backup storage. Export artifacts must
remain locally seekable because imports and recovery consume them directly.
Backup archives may instead use S3 or Kopia as described in the Backups section.

Changed your path layout later? Migrate:

```bash
sudo dbev migrate-paths --dry-run
sudo dbev migrate-paths
```

`sudo dbev --move-new-config` is an alias for the same migration. Stop managed containers first — it refuses to move live data unless you pass `--force`.
The daemon and mutating maintenance commands hold an exclusive lock under
`paths.locks`; stop the service before running migrations, metadata reset, or
development cleanup commands.

If startup reports `protected_secret_recovery_required`, the affected instance
is preserved but quarantined while other instances and the API continue to
start. For a password that was stored by an old release as plaintext beginning
with `dbev1:`, stop the daemon and rewrap the exact known value from stdin:

```bash
read -rsp 'Exact known value: ' DBEV_REPAIR_SECRET
printf '%s' "$DBEV_REPAIR_SECRET" | sudo dbev --config /etc/databases-everywhere/config.yml repair-protected-secret --instance-id INSTANCE_ID --field tenant-password --confirm-legacy-plaintext
unset DBEV_REPAIR_SECRET
```

The command never accepts the secret as an argument, repairs one named field,
and leaves the instance stopped. A mismatch changes nothing. For genuine
ciphertext corruption or a lost `metadata.key`, restore the key/database backup
instead of reinterpreting ciphertext as plaintext.

### Setup and start

```bash
sudo dbev --setup
sudo journalctl -u databases-everywhere -f
```

`--setup` installs the root-run systemd unit, creates root-owned private
directories, enables and starts or restarts the service, and removes the
obsolete managed quota sudoers rule left by older releases. Restarting during
an upgrade makes updated resource limits take effect immediately.
Files end up here:

```text
/etc/databases-everywhere/config.yml
/usr/local/bin/dbev
/var/lib/dbev
/var/lib/dbev/logs
/run/dbev
```

### Daemon logs

Normal API polling and successful WebSocket upgrades are logged at DEBUG, not
INFO. Startup, lifecycle and audit events, warnings, and request failures remain
visible at the default level. To trace requests temporarily, set
`RUST_LOG=databases_everywhere=info,databases_everywhere::api::http::trace=debug`
in the service environment and restart it; remove the override after diagnosis.

The daemon writes to stdout (so `journalctl -u databases-everywhere -f` still
works) and to `paths.logs/dbev.log`. File output rotates at 10 MiB, retaining
four archives (`dbev.log.1` is newest, through `dbev.log.4`): at most 50 MiB for
these five files, regardless of request volume or debug logging. Normal log
records stay together; records larger than a whole file are split to respect
the cap. Rotation runs on the logging worker, and normal shutdown flushes the
queue. No configuration fields or container recreation are required.

Older `dbev.log.YYYY-MM-DD` files are not automatically deleted or counted in
this cap. Inspect and archive/remove those separately if disk space is already
low. Files under `paths.logs/instances`, Docker/Podman container logs, and the
systemd journal have separate storage and retention; the daemon's file cap
does not limit those. DBEV does not change global journal settings.

Read-only checks for the default paths:

```bash
sudo du -h --max-depth=2 /var/lib/dbev/logs | sort -h
sudo journalctl --disk-usage
```

`journalctl --disk-usage` reports the journal for all services, not just DBEV.

---
