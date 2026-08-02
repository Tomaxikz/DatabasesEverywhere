# DatabasesEverywhere Docs

Two things live in here: how to get a node running, and how to talk to it from your panel. If you just want the API, jump to [Integrating with the daemon](#integrating-with-the-daemon).

Security issue? See [SECURITY.md](SECURITY.md) — report privately via GitHub Security Advisories or a [Discord](https://discord.com/invite/FJGQAbtyWN) ticket, never in public issues.

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
DBEV_VERSION=v0.3.3 # replace with the reviewed release
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
  trusted_hosts: [node-api.example.com] # when different from `remote`
```

Also tweak gateway ports, `daemon.engine`, or `daemon.socket_path` if your host needs it. Database container networking is not configurable: every instance uses `network_mode=none` and a private Unix socket. ClickHouse and Qdrant receive a hash-verified, statically linked bridge helper because those engines expose TCP listeners internally; the helper can connect only to non-zero loopback targets and creates sockets only directly under `/run/dbev`. Keep `api.host` on loopback when using a local reverse proxy. To expose DBE's native HTTPS server directly instead, use `api.host: 0.0.0.0`, enable `api.ssl`, and configure the panel node URL with the public HTTPS port.

`token` and `jwt_signing_key` are independent credentials and must each contain
at least 32 random bytes. Generate them with a cryptographically secure secret
generator, never copy one into the other, and never commit their real values.
The template placeholders are deliberately rejected by `check-config`.

For example, run `openssl rand -base64 32` twice and assign each output to one
of the two fields.

The API listener may run on loopback behind a reverse proxy or directly on a public interface using its native TLS server. Non-loopback API binds require `api.ssl.enabled: true` with a valid certificate and key; cleartext public API exposure is rejected. Database gateways may use public binds with or without TLS and continue to enforce the database protocols' native credentials. Cleartext public gateways emit a warning because their traffic is not encrypted. Managed database containers remain network-isolated. Credential-based imports use short-lived, hardened acquisition helpers (or a bounded host client for Redis/Qdrant) and never add a network interface to the target container.

Database images may use ordinary versioned Docker Hub, GHCR, or other
registry references. Bare references and the mutable `latest` tag are rejected;
an optional `@sha256:` digest can still be used when exact reproducibility is
desired:

```yaml
images:
  postgres: "postgres:18.4"
  redis: "redis:8.8.0"
  mariadb: "mariadb:12.3.2"
  mysql: "mysql:8.4"
  mongodb: "mongo:8.3.4"
  clickhouse: "clickhouse/clickhouse-server:26.4.4.38"
  qdrant: "qdrant/qdrant:v1.18.2"
  allowed:
    postgres: ["postgres:18.4"]
    redis: ["redis:8.8.0"]
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
and persist no tenant password in their container environment. DBE encrypts the
maintenance credential and routing verifier in the metadata store. Enable the
database gateway's native TLS whenever the listener crosses an untrusted
network.

Keep memory and disk headroom outside the database allocation pool:

```yaml
allocation:
  max_memory_mib: null
  max_disk_mib: null
  reserved_memory_mib: 512
  reserved_disk_mib: 2048
```

When a maximum is `null`, DBE uses the detected physical capacity minus its
reserve. An explicit maximum can make the database pool smaller, but cannot
override the safety reserve. New instances and memory/disk limit increases are
rejected when either their projected allocations exceed the pool or the host's
actual available capacity would fall inside the reserve. Decreases are always
allowed. CPU remains a scheduling signal and per-instance runtime limit; it is
not part of node admission because CPU contention slows work without making the
host unbootable. Stopped and failed instances remain allocated until deleted.

Disk enforcement is selected automatically on every daemon boot. DBE inspects
every configured path and logs its backing mount, source, filesystem type, and
mount options. The filesystem backing `paths.volumes` determines enforcement:
Btrfs qgroups, ZFS refquotas, and project-quota-enabled XFS/ext4/f2fs mounts use
native quotas; other filesystems use FuseQuota. There is deliberately no
`disk.mode` setting and no unenforced fallback.

Use this disk section:

```yaml
disk:
  fuse_quota_binary: embedded
  fuse_quota_binary_sha256: ""
  fuse_quota_rescan_interval_seconds: 150
  project_id_base: 200000
```

For native XFS or ext4 project quotas, DBE allocates from a bounded range of
at most 1,000,000 consecutive IDs starting at `project_id_base`. Reserve that
range exclusively for DBE on the host. XFS mode rejects conflicting entries in
`/etc/projects` or `/etc/projid` instead of replacing them.

The native systemd service runs as root, so it can configure project quotas and
FUSE mounts directly without a sudoers rule or a writable-filesystem override.
Rerun `--setup` after changing the filesystem or its quota mount options so DBE
rechecks host support for the automatically detected enforcement mode.

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
missing or stale after a crash or host reboot, DBE stops only that instance,
rebuilds its quota mount, and starts the instance again.

Recommended paths:

```yaml
paths:
  data: /var/lib/dbev
  metadata: /var/lib/dbev/metadata
  volumes: /var/lib/dbev/volumes
  backups: /var/lib/dbev/backups
  sockets: /run/dbev/sockets
  locks: /run/dbev/locks
  logs: /var/log/dbev
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
export DBEV_IMAGE='ghcr.io/tomaxikz/databaseseverywhere:v0.3.3@sha256:REPLACE_ME'
docker compose up -d
```

The supplied FuseQuota profile retains `SYS_ADMIN`, `/dev/fuse`, host
networking, and write access to the Docker socket, but no longer uses blanket
privileged mode. Docker socket access is still host-root-equivalent. Deploy the
manager on a dedicated host or VM; if FuseQuota is not used, remove
`SYS_ADMIN`, `/dev/fuse`, and the AppArmor override too.

Before starting that profile, ensure the host `/etc/fuse.conf` contains an
uncommented `user_allow_other`; Compose mounts the file read-only so the daemon
cannot modify host configuration from inside the container.

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
limits are satisfied. `local` is the backwards-compatible default and stores
archives below `paths.backups`; existing local archives remain readable.

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

### Setup and start

```bash
sudo dbev --setup
sudo systemctl enable --now databases-everywhere
sudo journalctl -u databases-everywhere -f
```

`--setup` installs the root-run systemd unit, creates root-owned private
directories, and removes the obsolete managed quota sudoers rule left by older
releases.
Files end up here:

```text
/etc/databases-everywhere/config.yml
/usr/local/bin/dbev
/var/lib/dbev
/var/log/dbev
/run/dbev
```

---

# Integrating with the daemon

The mental model: the panel owns users and billing and customer-facing records; the daemon owns containers. Your panel talks to the daemon over a plain JSON HTTP API plus a few WebSockets for live data.

## Auth

Every HTTP request needs the node token from `config.yml`:

```
Authorization: Bearer <token>
```

The config token has the `*` scope, so it can do everything. Things to know:

- Putting a token in the query string (`?token=...`) gets you a `401` — headers only. The one exception is a temporary download URL returned by the download endpoint; it carries its own short-lived JWT.
- The request `Host` must match `remote`, a concrete `api.host`, or an entry in `api.trusted_hosts`. Add the daemon/reverse-proxy hostname there when it differs from the panel hostname. If an `Origin` header is present, it is checked independently against the browser-origin allow-list derived from `remote`. A mismatch in either value returns `401`.
- Rate limit: 600 requests per minute per authenticated credential and
  transport-peer IP by default. IPv6 peers share a `/64`. Exceed it and you get
  `429`.
- Request bodies are capped at `security.api_body_limit_bytes`.
- The listener caps active connections at 2048 and in-flight requests at 1024,
  allows 30 seconds for HTTP headers and TLS handshakes, and aborts a request
  body after 60 seconds without another frame. These inactivity limits do not
  impose a 60-second total upload duration.

WebSockets don't use the node token directly — see [WebSockets](#websockets).

## Errors

Every error is the same shape:

```json
{ "error": "what went wrong", "code": "bad_request" }
```

Daemon-side failures return the generic message `internal server error`, the code
`internal_error`, and an opaque `error_id` also present in `X-Error-Id`. Use that
ID to find the full internal cause in daemon logs; paths, container output, and
database errors are never returned to clients.

| Status | Meaning |
| --- | --- |
| 400 | Bad request — validation failed, the message says why |
| 401 | Missing/wrong token, disallowed host/origin, or token in query string |
| 403 | Token is valid but lacks the required scope |
| 404 | Instance, job, or file doesn't exist |
| 409 | Conflict (usually from the container runtime) |
| 429 | Rate limited |
| 501 | Endpoint not implemented yet |
| 500 | Something broke on the daemon side |

## API contract version

`GET /api/system` returns both the daemon binary `version` and the independently
advertised `api_version`. A panel must verify `api_version` before enabling node
actions. Binary patch/minor releases can change without changing this contract
version. Contract `0.7.0` adds pluggable local/S3/Kopia backup storage, storage
status fields, and bounded backup-catalog browsing. Contract `0.6.0` adds typed credential-based remote imports with
verified TLS, SSRF controls, per-protocol acquisition, merge/wipe modes, and
rollback-first target handling. Contract `0.5.0` exposes the API rate-limit allowance and its
credential-plus-peer-IP scope through `/api/system`. Contract `0.4.0` emits
monitoring snapshots every 500 ms, sources
per-instance RX/TX from the authenticated gateway used by network-isolated
containers, and removes the redundant raw `docker_stats` string from monitoring
messages. Contract `0.3.0` added MySQL as a distinct protocol and exposed
`mysql_enabled` from `/api/system`. The API retains the scoped route design
introduced by contract `0.2.0`: heartbeat is `GET`,
instance lifecycle uses only `/power`, jobs/artifacts/backups and their
WebSockets are instance-scoped, import archive settings live inside `source`,
temporary downloads use authenticated `POST` and capability-authenticated `GET`
on the same instance-scoped `/download` path, download URL responses expose only
`url`, `expires_at_unix`, and `single_use`, and backup/restore calls return
synchronous operation records rather than fake job IDs.

## Scopes

Each endpoint requires one scope. The node token has `*`; scoped tokens matter mostly for WebSocket JWTs.

`system:read`, `instances:read`, `instances:write`, `resources:read`, `resources:admin`, `logs:read`, `metrics:read`, `artifacts:read`, `artifacts:write`, `backups:read`, `backups:write`, `backups:admin`, `import-export:read`, `import-export:write`, `recovery:admin`, `images:admin`, `ws-tokens:write`, `monitor:read`, `config:admin`

## Instances

An instance = one database container. The `InstanceMetadata` object you get back from most instance endpoints looks like:

```json
{
  "schema_version": 1,
  "instance_id": "cust-42-db",
  "protocol": "postgres",
  "status": "running",
  "public": { "host": "db.example.com", "port": 5432 },
  "backend": { "...": "internal endpoint info" },
  "runtime": { "kind": "docker", "container_name": "...", "network_mode": "none" },
  "database": { "name": "app_db", "username": "app_user" },
  "limits": {
    "cpu_cores": 1.0, "memory_mib": 2048, "disk_mib": 10240,
    "disk_enforced": true, "disk_enforcement_method": "fuse_quota"
  },
  "image": {
    "current": "postgres:18.4",
    "configured": "postgres:18.4",
    "update_available": false
  },
  "database_version": {
    "current": "18.4",
    "error": null
  },
  "created_at": "2026-07-01T12:00:00Z",
  "updated_at": "2026-07-01T12:00:00Z"
}
```

`status` is one of `creating`, `booting`, `running`, `stopped`, `failed`, `quarantined`, `deleting`. Instance reads refresh this value from the container runtime, and the daemon subscribes to managed-container lifecycle events so starts, stops, exits, pauses, restarts, destruction, and OOM failures update durable routing state without polling every database. A bounded real database query confirms readiness only during create/start/restart; no scheduled query continues after startup. Creation work before a container exists remains `creating`; fail-closed and operation states remain `failed`, `quarantined`, or `deleting`. `protocol` is one of `postgres`, `mariadb`, `mysql`, `redis`, `mongodb`, `clickhouse`, `qdrant`.
`image.update_available` is computed from the running container image versus the configured default image for that protocol. If it is `true`, the panel should offer the image update action.
`database_version.current` is probed from the running database container for `GET /api/instances` and `GET /api/instances/{id}`. If the instance is stopped or the version probe fails, `current` is `null` and `error` contains a short non-fatal reason.

| Method | Path | Scope | What it does |
| --- | --- | --- | --- |
| GET | `/api/instances` | instances:read | List all instances with their live classified container statuses |
| POST | `/api/instances` | instances:write | Accept instance creation and return `202` immediately |
| GET | `/api/instances/{id}` | instances:read | Fetch one with its live classified container status |
| DELETE | `/api/instances/{id}?confirm=true&reason=customer%20requested%20deletion` | instances:write | Irreversibly delete the container, job history, imports, exports, backups, retained recovery/upgrade volumes, and all other managed instance data; confirmation and an audit reason are required |
| GET | `/api/instances/{id}/status` | instances:read | Status plus creation progress while available |
| POST | `/api/instances/{id}/power` | instances:write | Unified power API: `{ "action": "start" | "stop" | "restart" | "kill" }` |
| POST | `/api/instances/{id}/reconcile` | instances:write | Re-sync stored status with the runtime |
| PATCH | `/api/instances/{id}/limits` | instances:write | Update CPU/memory/disk limits |
| PATCH | `/api/instances/{id}/image` | instances:write | Move to a new image (recreates container) |
| GET | `/api/instances/{id}/resources` | resources:read | Live resource report |
| GET | `/api/admin/resources` | resources:admin | Resource reports for everything |
| GET | `/api/instances/{id}/logs?tail=200` | logs:read | One-shot logs for one instance; `tail` is clamped to 1-2000 lines |

Lifecycle calls are idempotent-ish: starting a running instance or stopping a stopped one is a no-op, not an error.

Once an authenticated create request passes request/image validation, the daemon
returns `202 Accepted` and provisioning continues in a tracked background task.
The response contains an origin-relative `status_url`. Poll that URL or use the
monitoring WebSocket; failed creation remains observable there with its final
stage and message. SIGTERM closes creation admission and drains accepted creation
tasks before the process exits. The per-instance lock continues to serialize
operations, creation admission is bounded to 64 accepted tasks, and failed
provisioning still runs managed container/path cleanup.

### Creating an instance

```json
POST /api/instances
{
  "instance_id": "cust-42-db",
  "protocol": "postgres",
  "database": "app_db",
  "username": "app_user",
  "password": "generated-by-panel",
  "public_host": "db.example.com",
  "public_port": 5432,
  "project_id": "optional-grouping-id",
  "limits": { "cpu_cores": 1.0, "memory_mib": 2048, "disk_mib": 10240 }
}
```

Accepted response:

```json
{
  "instance_id": "cust-42-db",
  "status": "creating",
  "status_url": "/api/instances/cust-42-db/status"
}
```

Validation rules your panel should mirror so users get nice errors:

- `database` and `username`: 1–63 chars, must start with an ASCII letter, then letters/digits/`_`/`-` only. Reserved names are rejected (`postgres`, `mysql`, `admin`, `root`, `default`, `dbe_admin`, `dbe_health`, and a few more).
- `password` and `public_host` must be non-empty.
- `cpu_cores` must be finite and between `0.01` and `1024`; `memory_mib` must be between `1` and `1048576` (1 TiB); and `disk_mib` must be greater than zero. MongoDB and ClickHouse additionally need at least 1024 `memory_mib` **and** 1024 `disk_mib` or they won't even boot.

PostgreSQL clusters use a randomly protected internal `dbe_admin` bootstrap role
that is never registered as a gateway route. The requested username is created
separately as the database owner with `LOGIN` and without superuser, role-creation,
database-creation, replication, inheritance, or row-security bypass privileges.
The one-time PostgreSQL startup readiness check performs a real query against
`POSTGRES_DB`; it does not rely on `pg_isready`, which can report that the
temporary initialization server is accepting connections before the requested
database exists. The query is retried only during the bounded startup window and
is not installed as a permanent container healthcheck.

PostgreSQL instances created by older DBE builds may have used the tenant as the
immutable bootstrap superuser. DBE refuses to open gateways when it detects that
legacy layout because PostgreSQL cannot safely demote that role. Export the data
through the management API, recreate the instance with explicit stale-resource
purging, and import the dump to migrate it to the restricted tenant layout.

### Updating limits

```json
PATCH /api/instances/{id}/limits
{ "cpu_cores": 2.0, "memory_mib": 4096, "disk_mib": 20480 }
```

All three fields are required. Same protocol floors apply as at create time.

### Changing the image

```json
PATCH /api/instances/{id}/image
{ "image": "postgres:18.4", "password": "the-instance-password" }
```

This pulls the image, deletes the old container, and recreates it on the same data volume. `password` is required for everything except Redis (the container needs it to re-provision the user). Images must be pinned — a non-`latest` tag or a `@sha256:` digest; bare `postgres` or `postgres:latest` gets a `400`.

The requested image must also be allowed in `images.allowed.<protocol>`. The configured default image at `images.<protocol>` is always implicitly allowed. Keep the allowlist short and admin-controlled; do not pass arbitrary user input here.

Patch/minor updates stay in-place. Major version changes are blocked unless the panel sends an explicit migration request:

```json
PATCH /api/instances/{id}/image
{
  "image": "mongo:8.3.4",
  "password": "the-instance-password",
  "major_upgrade": true
}
```

For Postgres, MariaDB, MySQL, MongoDB, and ClickHouse, `major_upgrade: true` runs a safer provider-style migration: export the old database, preserve the old volume, recreate the same instance id on a fresh target-version volume with the same database name, username, password, public endpoint, and limits, import the dump, validate the replacement, then keep the old volume path and export artifact for rollback. If any step fails, DBE tries to restore and restart the old container. Redis and Qdrant major upgrades are rejected for now because their current DBE backup path is physical/version-specific rather than a reliable cross-major logical migration.

The response includes `strategy`:

```json
{
  "strategy": "major_upgrade_migration",
  "export_artifact_id": "9c39d836-5f8e-4e48-94d6-ec6b1397fdda.postgres.sql",
  "old_volume_backup_retained": true,
  "warnings": ["..."]
}
```

### Pre-pulling images

```json
POST /api/admin/images/pull      (scope: images:admin)
{ "protocol": "postgres", "image": "postgres:18.4" }
```

Omit `image` to pull the node's configured default for that protocol. Handy for warming a node before creating instances on it.

## Resource reports

`GET /api/admin/resources` and `GET /api/instances/{id}/resources` return:

```json
{
  "instance_id": "cust-42-db",
  "protocol": "postgres",
  "status": "running",
  "cpu": { "configured_cores": 1.0, "usage_percent": 12.5 },
  "memory": { "configured_mib": 2048, "usage_bytes": 104857600, "limit_bytes": 2147483648 },
  "disk": { "configured_mib": 10240, "limit_bytes": 10737418240, "used_bytes": 52428800,
            "enforced": true, "enforcement_method": "fuse_quota" },
  "network": { "rx_bytes": 1234, "tx_bytes": 5678 }
}
```

CPU and memory fields are `null` when the container isn't running or container
runtime stats aren't available yet. Network counters are measured at DBE's authenticated
gateway-to-Unix-socket boundary because managed containers use
`network_mode=none`; RX is traffic delivered to the database and TX is traffic
returned by it. The counters start at zero on daemon boot. For continuous
monitoring use the WebSocket instead of polling this.

`GET /api/admin/resources/summary` (scope: `resources:admin`) is the
node-scheduler view. It reports limits reserved by every managed instance,
actual usage by DBE containers, and pressure from the entire Linux host:

```json
{
  "node_uuid": "node-db-1",
  "sampled_at": "2026-07-12T12:45:00Z",
  "cpu": {
    "total_cores": 16,
    "allocated_cores": 9.5,
    "host_usage_percent": 42.7,
    "managed_usage_cores": 4.2
  },
  "memory": {
    "total_bytes": 68719476736,
    "allocation_limit_bytes": 68182605824,
    "reserved_bytes": 536870912,
    "allocated_bytes": 34359738368,
    "host_used_bytes": 28991029248,
    "managed_used_bytes": 12884901888,
    "available_bytes": 39728447488
  },
  "disk": {
    "total_bytes": 1099511627776,
    "allocation_limit_bytes": 1097364144128,
    "reserved_bytes": 2147483648,
    "allocated_bytes": 536870912000,
    "host_used_bytes": 429496729600,
    "managed_used_bytes": 268435456000,
    "available_bytes": 670014898176
  },
  "instances": {
    "total": 42,
    "creating": 0,
    "booting": 2,
    "running": 34,
    "stopped": 3,
    "failed": 1,
    "quarantined": 1,
    "deleting": 1
  }
}
```

Allocation includes stopped and failed instances because their limits remain
reserved and they may be restarted. CPU is sampled from `/proc/stat`, memory
uses Linux `MemAvailable`, and disk capacity is measured on the filesystem
backing `paths.volumes`. Host usage includes DBE plus every other process on the
server. Managed CPU or memory usage is `null` if a running/booting container
could not be sampled; the endpoint does not return a misleading partial sum.
`allocation_limit_bytes` and `reserved_bytes` expose the daemon's authoritative
memory/disk admission policy. Poll this endpoint every 10–30 seconds for
placement decisions and use allocation pressure as the primary scheduling
signal, with host pressure as a secondary signal. The panel's check is only an
optimization: it must handle a capacity rejection because host availability can
change between sampling and creation.

## Exports, imports, backups

Three related but different things — don't mix them up:

- **Exports** are portable database-native dumps (`pg_dump` style). They are kept under `paths.exports/<instance_id>/` and exposed to clients only through opaque artifact IDs.
- **Imports** load one of that instance's trusted local artifacts or acquire a native dump/snapshot directly from a typed remote source. An operator can stage a file under `paths.imports/<instance_id>/` and reference its filename as the artifact ID. API clients never submit host filesystem paths, helper images, commands, or connection URLs.
- **Backups** are physical archives of the whole instance volume. The local driver stores them under `paths.backups/<instance_id>/`; S3 and Kopia store them in the configured remote repository. They're for disaster recovery on the same daemon, not portability.

### Import/export jobs

Exports and imports are async. You queue a job, then watch it via polling or the WebSocket. The job object:

```json
{
  "job_id": "…",
  "instance_id": "cust-42-db",
  "action": "export",
  "status": "queued",
  "artifact_id": "9c39d836-5f8e-4e48-94d6-ec6b1397fdda.postgres.sql",
  "error": null,
  "created_at": "…",
  "updated_at": "…",
  "artifact_size_bytes": null
}
```

`status` goes `queued` → `running` → `succeeded` or `failed`. `artifact_size_bytes` fills in once the file exists.
Queueing, safe retry, and recovery-restore endpoints return `202 Accepted` with a
`Location` header pointing at the instance-scoped job status endpoint.

| Method | Path | Scope | What it does |
| --- | --- | --- | --- |
| POST | `/api/instances/{id}/export` | import-export:write | Queue an export |
| POST | `/api/instances/{id}/import` | import-export:write | Queue an import |
| GET | `/api/instances/{id}/import-export/jobs` | import-export:read | List that instance's jobs (`?status=&limit=`) |
| GET | `/api/instances/{id}/import-export/jobs/{job_id}` | import-export:read | One job, after ownership verification |

Export body (all optional — empty body means a full plain dump):

```json
{
  "archive_format": "gzip",
  "selection": { "mode": "selective", "include": ["table_a"], "exclude": [], "fields": {} }
}
```

`archive_format` is `plain`, `gzip`, or `bzip2`. Omit it for Redis and Qdrant,
whose exports are already physical archives.

Export/import formats:

| Protocol | Export format | Import support |
| --- | --- | --- |
| PostgreSQL | `.postgres.sql` logical dump | Plain dump or gzip/bzip2/tar/zip-wrapped dump |
| MariaDB | `.mariadb.sql` logical dump | Plain dump or gzip/bzip2/tar/zip-wrapped dump |
| MySQL | `.mysql.sql` logical dump | Plain dump or gzip/bzip2/tar/zip-wrapped dump |
| MongoDB | `.mongodb.archive.gz` archive dump | MongoDB archive dump or gzip/tar/zip-wrapped archive |
| ClickHouse | `.clickhouse.sql` logical dump | Plain dump or gzip/bzip2/tar/zip-wrapped dump |
| Redis | `.redis.tar.gz` physical archive | Full physical archive only |
| Qdrant | `.qdrant.tar.gz` physical archive | Full physical archive only |

Redis and Qdrant artifact exports are full physical volume archives and are not
selective. Remote Redis imports copy binary-safe DUMP/RESTORE records; remote
Qdrant imports use collection snapshots. The target database container remains
in `network_mode=none` for every protocol.

Import one of the target instance's artifacts:

```json
{
  "source": {
    "type": "artifact",
    "artifact_id": "9c39d836-5f8e-4e48-94d6-ec6b1397fdda.postgres.sql.gz",
    "archive_format": "gzip"
  }
}
```

Import directly from credentials (the target instance determines the protocol):

```json
{
  "source": {
    "type": "remote",
    "host": "source-db.example.com",
    "port": 5432,
    "tls": true,
    "database": "app",
    "username": "migration_user",
    "password": "source-only-secret"
  },
  "mode": "merge"
}
```

For credential imports, `merge` replaces source-named
objects/keys/collections and preserves target-only data; `wipe` clears the
target first. Redis and Qdrant artifact imports are different: those archives
always replace the complete physical database, so `mode` does not change their
behavior. PostgreSQL, MariaDB, MySQL, MongoDB, and ClickHouse use their native
dump tools in a one-shot helper. Redis uses binary-safe
SCAN/DUMP/PTTL/RESTORE, and Qdrant uses collection snapshots.

Credential values are not stored in durable job records or job metadata.
PostgreSQL, MariaDB, MySQL, MongoDB, and ClickHouse acquisition writes the
required secret to a mode-`0600`, job-private temporary credential file, then
removes it immediately after the helper exits. After an unclean daemon stop,
startup removes known credential files and deletes generated staging that has
no durable recovery manifest; manifest-backed rollback data is retained.
Redis and Qdrant credentials remain in process memory. A failed
credential-based import must therefore be submitted again; the recovery retry
endpoint cannot replay it.

Remote `database`, `username`, and `authentication_database` values are
trimmed and cannot contain control characters. They are limited to 1-256 UTF-8
bytes unless a protocol applies a stricter rule. MongoDB database names are
limited to 63 UTF-8 bytes and reject slash, backslash, dot, space, double quote,
and dollar sign; an authentication database may instead be exactly
`$external`. MongoDB `authentication_database` is accepted only with both
`username` and `password`. A ClickHouse source database name must be at most
128 bytes and contain only ASCII letters, digits, underscores, or dashes. SQL
passwords also cannot contain NUL, CR, or LF. MySQL and MariaDB source database
names are limited to 64 characters. A Qdrant `api_key` must be a valid HTTP
header value; invalid values are rejected without echoing the secret.

MySQL and MariaDB logical imports structurally rebase qualified references from
the source database to the managed target database without changing quoted
strings, row data, or ordinary comments. MySQL object definers are rewritten
to the target tenant account; an unfamiliar or ambiguous dump form is rejected
instead of restoring a privileged or source-only definer.
ClickHouse likewise rebases structurally identifiable database-qualified table
and function references in its generated SQL; ambiguous qualified SQL is
rejected before the target is changed.

Qdrant collection snapshots do not contain aliases, so DBE reads aliases
separately and migrates those attached to the selected source collections.
Source aliases win same-name conflicts; target aliases attached to untouched
collections are otherwise preserved. Alias changes are applied atomically, and
an update error triggers rollback of the exact pre-import target alias map
together with the collection snapshots. Recovery snapshots are retained if
automatic rollback cannot complete. Qdrant snapshot imports require the same
major and minor version; the target cannot have an older patch release than
the source.

Credential imports reject Redis Cluster and distributed Qdrant endpoints.
SCAN and a Qdrant collection snapshot are node-local in those topologies and
could otherwise produce a silently partial migration. Use the database's
cluster-aware migration tooling or a verified standalone source instead.

Remote acquisition does not lock the source database. Quiesce source writes
when a single point-in-time migration is required, especially for MongoDB,
ClickHouse, Redis, and multi-collection Qdrant imports. MongoDB selective
imports acquire each requested collection before changing the target, then
apply all acquired archives under one rollback boundary. Because the source
collection dumps are captured sequentially, quiesce source writes when the
collections must represent one consistent point in time. As with artifact
imports, also quiesce client writes to target objects being replaced: DBE
serializes management jobs but cannot stop already-authorized database clients
from issuing native writes.

Remote TLS is verified by default. Plaintext requires both `"tls": false` and
`security.remote_import.allow_plaintext: true`. Private RFC1918/ULA/CGNAT
destinations require an exact entry in
`security.remote_import.allowed_private_hosts`; loopback, link-local, metadata,
multicast, reserved, and mixed public/private DNS answers are always rejected.

### Backups

| Method | Path | Scope | What it does |
| --- | --- | --- | --- |
| GET | `/api/instances/{id}/backups` | backups:read | List only that instance's backups |
| POST | `/api/instances/{id}/backups` | backups:write | Back up that instance now; returns the completed backup record |
| GET | `/api/instances/{id}/backups/{backup_id}/contents` | backups:read | List the stored schema catalog, or select one object's bounded captured row preview with `?object=&offset=&limit=` |
| POST | `/api/instances/{id}/backups/{backup_id}/restore` | recovery:admin | Restore the backup into its owning instance after explicit confirmation |
| DELETE | `/api/instances/{id}/backups/{backup_id}` | backups:write | Delete one owned backup |
| GET | `/api/admin/backups/status` | backups:admin | Node backup schedule and retention configuration |
| POST | `/api/admin/backups/run` | backups:admin | Back up every eligible instance; returns `backups` and `skipped` |

Backup list items remain `{id, instance_id, size_bytes, modified_at, sha256}`.
Host paths and remote object keys are never returned. Every driver binds a
backup to its instance ID; a backup from one instance cannot be restored,
downloaded, browsed, or deleted through another instance's route.

Storage driver behavior:

- `local` atomically publishes the archive, catalog, and metadata under
  `paths.backups/<instance_id>/`. It discovers pre-driver physical archives as
  legacy backups, so switching to this release does not strand existing files.
- `s3` uses direct SigV4-authenticated requests. Archives of 64 MiB and larger
  use bounded-memory multipart uploads; the small metadata object is written
  last, so incomplete uploads never appear in backup listings. Downloads and
  restores stream to a mode-`0600` temporary file and verify the recorded size
  and SHA-256 before use. AWS credentials may be set in config or supplied as
  `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optional
  `AWS_SESSION_TOKEN`. S3-compatible endpoints are supported with `endpoint`
  and `path_style`; plaintext HTTP requires the explicit `allow_http` opt-in.
- `kopia` snapshots one private bundle per backup, pins it against unrelated
  Kopia retention policies, and tags it with the DBEV instance, backup ID,
  protocol, size, hash, and creation time. Listing and retention use those
  tags. Restore/download materializes only the archive
  object and verifies it. Point `config_file` at an already connected Kopia
  repository; when omitted it defaults to
  `paths.backups/.kopia/repository.config`. The Kopia executable and repository
  config must be root/daemon-owned real files and must not be writable by group
  or others. Supply the repository password in config or the service's normal
  `KOPIA_PASSWORD` environment.

Changing `storage.driver` selects a different backup inventory; it does not
migrate or combine backups from the previous driver. Migrate the repository
separately or temporarily switch back to the old driver when an older backup
must be restored. S3 and Kopia backups still use `paths.backups/.staging` while
the stopped database volume is archived, and remote restores/downloads use
`paths.tmp`, so both local filesystems need room for one complete backup.

Treat the remote repository as production database storage. For S3, use TLS,
least-privilege bucket credentials, bucket-side encryption and retention, and a
lifecycle rule that aborts incomplete multipart uploads. Kopia encrypts its
repository, but its config and repository password still need the same secret
handling as database credentials.

Example S3 selection (the full option set is in `config.example.yml`):

```yaml
backups:
  storage:
    driver: s3
    s3:
      bucket: customer-node-backups
      region: eu-central-1
      endpoint: ""       # leave empty for AWS
      prefix: dbev
      access_key_id: ""  # empty uses AWS_ACCESS_KEY_ID
      secret_access_key: ""
      session_token: ""
      path_style: false
      allow_http: false
      request_timeout_seconds: 900
      max_retries: 3
```

Example Kopia selection:

```yaml
backups:
  storage:
    driver: kopia
    kopia:
      executable: /usr/local/bin/kopia
      config_file: /var/lib/dbev/backups/.kopia/repository.config
      repository_password: ""
      operation_timeout_seconds: 3600
```

When browsing is enabled, each new backup carries a size-bounded catalog
captured immediately before its physical archive. PostgreSQL, MariaDB, MySQL,
MongoDB, and ClickHouse catalogs contain object/schema information plus a
configurable, truncated row preview. Redis and Qdrant are schema-less physical
stores, so they return a descriptive object without record previews. This is a
safe catalog view: the endpoint does not boot an untrusted clone or parse live
database files. Existing backups return `catalog_available: false`. Row
previews are database content and must be protected with the same access and
encryption policy as the backup itself. Set `preview_rows_per_object: 0` to
retain schema browsing without storing row previews.

Backup restore follows the same destructive-action policy as artifact recovery
and requires an audit reason:

```json
{ "confirm": true, "reason": "customer ticket #123" }
```

### Letting users download files (temporary URLs)

Your panel authenticates with the node token, but end users' browsers can't. The flow:

1. Panel asks the daemon to create a temporary download URL:

```json
POST /api/instances/{id}/artifacts/{artifact_id}/download  (scope: artifacts:read)
POST /api/instances/{id}/backups/{backup_id}/download      (scope: backups:read)
{ "expires_in_seconds": 120, "single_use": true }
```

2. The daemon answers with a ready-to-use URL:

```json
{
  "url": "/api/instances/cust-42-db/artifacts/export.postgres.sql/download?token=…",
  "expires_at_unix": 1751900000,
  "single_use": true
}
```

3. Panel resolves the origin-relative `url` against its trusted daemon origin and hands it to the browser. No auth header is needed — the JWT in the query is the whole credential. It expires fast and single-use tokens burn after the first hit, so hand them out at click time, don't store them. The daemon deliberately does not derive an absolute URL from client-controlled `Host` or forwarding headers. Downloads are streamed with bounded buffers and capped at 128 active streams node-wide and 32 per transport peer; admission failure returns `429` without consuming a single-use ticket.

### Artifact housekeeping

| Method | Path | Scope | What it does |
| --- | --- | --- | --- |
| GET | `/api/instances/{id}/artifacts` | artifacts:read | List that instance's export artifacts |
| DELETE | `/api/instances/{id}/artifacts/{artifact_id}` | artifacts:write | Delete one owned artifact |
| POST | `/api/instances/{id}/artifacts/retention` | artifacts:write | Apply retention to that instance only |

Artifact list items have the same path-free `{id, instance_id, size_bytes, modified_at, sha256}` shape as backups. New exports are stored under `paths.exports/<instance_id>/`.

### Recovery

For your admin panel's "something went wrong" page. Scope: `recovery:admin`.

| Method | Path | What it does |
| --- | --- | --- |
| GET | `/api/admin/recovery/failed-jobs` | All failed import/export jobs |
| POST | `/api/instances/{id}/recovery/jobs/{job_id}/retry` | Re-queue a failed export or artifact import with its stored non-secret mode/archive/selection options; credential imports and jobs created before replay metadata was added return `400` and must be resubmitted |
| POST | `/api/instances/{id}/recovery/restore` | Force-import one of that instance's artifacts |

Restore requires explicit intent — `confirm` and a `reason` (it's audit-logged):

```json
{ "artifact_id": "9c39d836-5f8e-4e48-94d6-ec6b1397fdda.postgres.sql", "confirm": true, "reason": "customer ticket #123" }
```

## WebSockets

WebSockets use short-lived JWTs instead of the node token, so you can hand them to a browser without exposing node credentials.

### Step 1: mint a token (panel side)

```json
POST /api/ws-token     (scope: ws-tokens:write)
{
  "subject": "user-42",
  "scopes": ["monitor:read", "logs:read"],
  "instances": ["cust-42-db"],
  "ttl_seconds": 900
}
```

Response: `{ "token_type": "Bearer", "token": "…", "expires_at_unix": … }`. TTL defaults to 900s, max 3600. `instances` restricts the token to those instances. An empty list grants no instance access; node-wide access must be explicitly requested with `"all_instances": true`, and that flag cannot be combined with an allow-list. Each token ID is accepted for one WebSocket upgrade only, so mint a fresh token when reconnecting. WebSocket messages and frames are capped at 16 KiB, with bounded write buffering.

### Step 2: connect (browser side)

Browsers can't set an `Authorization` header on a WebSocket, so pass the JWT via the subprotocol:

```js
const ws = new WebSocket("wss://node.example.com/ws/instances/cust-42-db/logs",
                         ["dbe.jwt", token]);
```

Server-side clients can use either the subprotocol trick or a plain `Authorization: Bearer <jwt>` header.

### Endpoints and events

Every message is a JSON object with a `type` field.

**`/ws/monitoring`** (scope `monitor:read`) — a full snapshot every 500 ms:

```json
{
  "type": "stats",
  "instances": [
    {
      "instance_id": "cust-42-db",
      "protocol": "postgres",
      "status": "running",
      "runtime": "docker",
      "cpu_cores": 1.0,
      "cpu_usage_percent": 12.5,
      "memory_mib": 2048,
      "memory_usage_bytes": 104857600,
      "memory_limit_bytes": 2147483648,
      "disk_mib": 10240,
      "disk_limit_bytes": 10737418240,
      "disk_used_bytes": 52428800,
      "disk_enforced": true,
      "network_rx_bytes": 1234,
      "network_tx_bytes": 5678,
      "resources": { "…": "same shape as /api/instances/{id}/resources" },
      "resource_error": null
    }
  ],
  "install_progress": [
    {
      "instance_id": "cust-42-db",
      "protocol": "postgres",
      "action": "image_update",
      "status": "running",
      "stage": "pull_image",
      "message": "Downloading",
      "image": "postgres:18.4",
      "layer": "sha256:…",
      "current": 1048576,
      "total": 8388608,
      "percent": 12.5,
      "updated_at": "2026-07-07T18:30:00Z"
    }
  ]
}
```

Disk usage is sampled from quota accounting when available and cached per instance. Directory walking is only a fallback, and a background sampler keeps the cache warm so websocket ticks do not block on large database directories. Concurrent fallback walks are coalesced per instance and capped node-wide. Monitoring clients share each completed all-instance sample, which is then filtered against each JWT before serialization.
`install_progress.action` is `create`, `image_update`, or `major_upgrade`. For image updates, listen for stages like `queued`, `prepare`, `pull_image`, `delete_container`, `create_container`, `start`, `healthcheck`, `backend`, `completed`, and `failed`. The existing `healthcheck` stage name is retained for API compatibility but represents the bounded startup-readiness check, not a permanent probe. Major upgrades also emit `export`, `snapshot`, `prepare_replacement`, `import`, and `validate`.

**`/ws/instances/{instance_id}/logs`** (scope `logs:read`, token must cover the instance) — a snapshot every 3 seconds:

```json
{ "type": "logs", "instance_id": "cust-42-db", "sequence": 7,
  "stdout": "…", "stderr": "…", "error": null }
```

Connection URLs in log output are redacted before they leave the daemon. If fetching logs fails, `stdout`/`stderr` are null and `error` says why.

**`/ws/instances/{instance_id}/import-export?job_id=…`** (scope `import-export:read`, token must cover the instance) — `job_id` is optional. On connect you get that instance's current state, then push updates as its jobs change:

```json
{ "type": "import_export_snapshot", "jobs": [ { …job fields…, "download": null } ] }
{ "type": "import_export_job", "job": { …job fields…, "download": { …temporary url… } } }
{ "type": "import_export_lagged", "skipped": 12 }
```

Job objects are the same shape as the REST job response. When an export succeeds, the event includes a `download` object — a single-use temporary URL valid for ~120 seconds, so your UI can show a download button the moment the export finishes. A `lagged` event means you missed messages; a fresh snapshot follows automatically.

## System and monitoring endpoints

| Method | Path | Scope | What it does |
| --- | --- | --- | --- |
| GET | `/api/system` | system:read | Node identity, version, explicit API readiness, enabled protocols, and separate database-gateway readiness |
| PATCH | `/api/system/config` | config:admin | Merge a runtime config patch into `config.yml`; returns `restart_required: true` |
| GET | `/api/heartbeat` | system:read | `{"status":"ok"}` — cheap liveness check for the panel |
| GET | `/metrics` | metrics:read | Prometheus text: instance counts by protocol/status, job counts, disk enforcement flag |

`/api/system` is the right first call after registering a node — it tells you the daemon `version`, contract `api_version`, `api_readiness`, `api_rate_limit_per_minute`, `api_rate_limit_scope`, `daemon_engine`, socket, `disk_mode`, fixed `database_container_network_mode`, backend transport, `remote_import_enabled`, and per-protocol `*_enabled` flags so the panel knows what it can offer. `api_readiness: "ready"` describes the management API only; `gateways.status` independently describes database listeners.

The API listener becomes available after critical metadata, crash-recovery,
container-engine, socket-isolation, and disk checks complete. Existing managed database
containers then auto-start in a lock-protected, bounded-concurrent background
phase, so a slow or broken container does not hold node heartbeat or management
endpoints offline. FuseQuota shutdown uses the same bounded concurrency for
container stops and safe unmounts, reducing normal service restart time without
skipping graceful active-job draining. API connections, including monitoring
WebSockets, receive up to 10 seconds to drain before they are closed, so a
long-lived client cannot hold `systemctl restart` open indefinitely.
Heartbeat reports management API liveness only. It always returns
`{"status":"ok"}` once an authenticated request reaches the handler, regardless
of database instance or gateway state. Clients should use each instance's status
for instance readiness and `/api/system.gateways` for listener startup state.
Database gateways open after background startup and legacy PostgreSQL role
hardening complete.

Config patches are JSON object merges against the current config. `null` removes a key. The daemon rejects edits to `uuid`, `token_id`, `token`, `jwt_signing_key`, and the Fuse helper path/digest; those security boundaries must be changed deliberately in the host config. A successful patch writes the config file only — restart the daemon before expecting listener, TLS, path, image, or runtime changes to take effect.

API-triggered self-upgrade is intentionally unsupported: accepting an executable and its digest from the same administrative request does not provide an independent trust anchor. Keep `security.self_upgrade_enabled: false` and deploy signed packages or immutable, digest-pinned container images through the host's normal rollout mechanism.

Instances created by older builds with a bridge-network or `docker_tcp` backend are deliberately not converted in place. Startup stops and marks them `quarantined`, because changing a live container's network and entrypoint cannot be made atomic and DBE intentionally does not retain every tenant's plaintext credential. Preserve or export any required data offline, explicitly delete the quarantined instance, then recreate it and import the artifact. The gateway refuses legacy TCP metadata even before reconciliation, so it cannot silently reopen the old path.

If a legacy database contains duplicate route identities, startup preserves the deterministic first claimant and marks every other claimant `quarantined`. Quarantined containers are stopped before gateways open and cannot be started or restarted; their metadata and data remain available for inspection and explicit deletion.

An unclean daemon exit while an import/export job is durably `running` also quarantines the affected instance on the next startup. The container is stopped before gateways open, preventing a possibly orphaned dump or restore process from racing new work. Queued jobs that never started are marked failed without quarantining their instances. Inspect the failed job and database integrity, then recover or repair the quarantined instance offline.

If creation cleanup was interrupted, a normal retry fails closed rather than reusing orphaned files with new credentials. After preserving any required data, retry the create request with `"purge_stale_resources": true` to explicitly and irreversibly remove that instance ID's orphaned container and paths before creation.

Import/export admission is bounded to 64 jobs node-wide and two running-or-queued jobs per instance. The in-memory status cache retains at most 2,048 completed jobs, and SQLite retains the latest 10,000 completed records; queued/running records are never pruned.

## Benchmarking a running node

Run the benchmark client as a second `dbev` process on the same node as the
already-running daemon:

```bash
sudo dbev --config /etc/databases-everywhere/config.yml --bench
```

The safe default benchmark does not create, stop, or mutate database
instances. It performs:

- warmup requests followed by sequential authenticated heartbeat requests;
- a bounded concurrent heartbeat phase with attempted and successful
  requests/second plus min, mean, standard deviation, p50, p90, p95, p99, and
  maximum latency;
- real HTTP/1.1 WebSocket upgrades to `/ws/monitoring`, each using a fresh
  single-use JWT;
- `/proc` sampling of the running daemon and benchmark client, including peak
  CPU and resident RAM.

For a sustained test, specify the concurrent-phase duration in minutes and let
the client randomly choose a bounded set of currently running instances:

```bash
sudo dbev --config /etc/databases-everywhere/config.yml \
  --bench \
  --time 5 \
  --max_instances 4
```

`--time 5` is the friendly alias for `--bench-time-minutes 5`.
`--max_instances 4` (also `--max-instances` or
`--bench-max-instances`) fetches the daemon's instance list, filters it to
`running`, randomly chooses up to four, and records the exact selection in the
report. Half of the concurrent requests remain heartbeat requests; the other
half are distributed evenly over the selected instances' read-only status
endpoints. Automatic selection never starts, stops, imports, exports, or
otherwise mutates an instance.

Timed mode is rate-limit-aware by default. It sends concurrent bursts using at
most 80% of `security.api_rate_limit_per_minute` in each 60-second window and
reserves the rest for benchmark control calls and normal panel traffic. The
report separates wall-clock accepted req/s from active-burst accepted req/s,
so pacing does not hide the API's service capacity. WebSocket, import/export,
and final validation phases run before the throughput phase and therefore
cannot fail merely because the load phase exhausted a window.

On an isolated stress node, `--bench-unthrottled` disables this pacing. It
requires `--time` and can intentionally create large numbers of HTTP 429
responses. Raise the daemon's configured limit first; repeated rejections are
log-suppressed within each identity/window to prevent audit-log amplification.

Use a dedicated running instance when container resource sampling or
import/export throughput is required:

```bash
sudo dbev --config /etc/databases-everywhere/config.yml \
  --bench \
  --bench-instance perf-postgres \
  --bench-import-export
```

`--bench-import-export` is explicit destructive authorization. It queues a full
native export, waits for it to succeed, then imports that fresh artifact back
into the named instance. Logical imports are not transactional and may leave a
partially modified database if the native client fails. Redis and Qdrant stop
temporarily for their physical-volume import. Never target customer data; use
a disposable performance instance with representative data. After a successful
re-import the benchmark deletes only the export artifact it created. Add
`--bench-keep-artifact` to retain it. Failed imports retain it for diagnosis.

When instances are selected, the benchmark samples their containers directly
through the configured Docker or Podman socket. Multiple containers are
sampled round-robin, one per interval, to keep the stats observer from
distorting the load. Per-instance peaks and failed sample counts are reported.
CPU percentages use 100% for one fully occupied CPU core. Sampling can fail
temporarily while a physical import has intentionally stopped its container;
these gaps are counted in the report.

Useful controls:

| CLI option | Environment variable | Default |
| --- | --- | --- |
| `--bench-url` | `DBEV_BENCH_URL` | Configured local API listener |
| `--bench-host` | `DBEV_BENCH_HOST` | Configured/allowed request host |
| `--bench-instance` | `DBEV_BENCH_INSTANCE` | None |
| `--bench-max-instances` (`--max_instances`) | `DBEV_BENCH_MAX_INSTANCES` | `0` (disabled; maximum `32`) |
| `--bench-warmup-requests` | `DBEV_BENCH_WARMUP_REQUESTS` | `10` |
| `--bench-latency-samples` | `DBEV_BENCH_LATENCY_SAMPLES` | `50` |
| `--bench-requests` | `DBEV_BENCH_REQUESTS` | `400` |
| `--bench-time-minutes` (`--time`) | `DBEV_BENCH_TIME_MINUTES` | None (maximum `1440`) |
| `--bench-unthrottled` | `DBEV_BENCH_UNTHROTTLED` | Disabled; requires `--time` |
| `--bench-concurrency` | `DBEV_BENCH_CONCURRENCY` | `32` |
| `--bench-websockets` | `DBEV_BENCH_WEBSOCKETS` | `10` |
| `--bench-import-export` | `DBEV_BENCH_IMPORT_EXPORT` | Disabled |
| `--bench-keep-artifact` | `DBEV_BENCH_KEEP_ARTIFACT` | Disabled |
| `--bench-timeout-seconds` | `DBEV_BENCH_TIMEOUT_SECONDS` | `900` |
| `--bench-sample-interval-ms` | `DBEV_BENCH_SAMPLE_INTERVAL_MS` | `250` |
| `--bench-output` | `DBEV_BENCH_OUTPUT` | Unique directory under `./dbev-benchmarks` |

`DBEV_BENCH=true` enables benchmark mode when an environment-only launch is
preferred. `--bench-insecure-tls` / `DBEV_BENCH_INSECURE_TLS=true` is available
for an explicitly selected local endpoint with a test certificate; it should
not be used against an untrusted network.

The benchmark deliberately goes through normal authentication, host policy,
request admission, and rate limiting. HTTP 429 responses are counted rather
than hidden. Raise `security.api_rate_limit_per_minute` on an isolated
performance node if the goal is measuring the server above the production
throttle.

The API rate limit is applied independently per authenticated
credential/transport-peer IP, rather than globally per token. IPv4 uses the
individual address and IPv6 uses a `/64` peer group. Unauthenticated requests
remain in bounded IP-derived buckets. Forwarding headers are intentionally not
trusted, so deployments behind a local reverse proxy are limited by the
proxy's transport IP unless the proxy uses separate source addresses.

Metric math is intentionally transparent:

- latency is measured through full HTTP response-body completion. Percentile
  `p` sorts the successful samples, places the rank at `(n - 1) * p`, and
  linearly interpolates adjacent samples for fixed phases. The concurrent phase
  uses an HDR histogram with three significant digits, allowing a multi-minute
  run to retain full-run percentiles, mean, and population standard deviation
  without memory growing with request count;
- wall HTTP throughput is `responses / phase wall seconds`. Active throughput
  excludes intentional fixed-window pacing waits and is
  `responses / time actively dispatching and completing bursts`. Offered,
  accepted, active accepted, 429 percentage, status-code counts, transport
  failures, and successful-only latency are all retained so neither pacing nor
  rate limiting can make a run look faster;
- WebSocket time starts immediately before the upgrade request and ends only
  after a valid `101`, upgrade headers, RFC 6455 accept value, and `dbe.jwt`
  subprotocol are received. JWT mint latency is a separate phase;
- import/export MiB/s is `artifact bytes / persisted job elapsed seconds`,
  using the job's server-side `created_at` and `updated_at`. Client wall time
  and enqueue HTTP latency are reported separately, so polling cadence and
  queue delay remain visible;
- Linux process CPU is
  `process tick delta / host tick delta * logical CPUs * 100`. Container CPU
  uses the equivalent runtime counters. Thus `100%` means one fully occupied
  core and values above `100%` are valid. RAM is resident process memory or
  runtime-reported container memory, and every peak is the maximum sampled
  value rather than an average.

After the run, an organized ASCII-safe dashboard is printed to the terminal,
avoiding locale-dependent box-drawing corruption. Status, failures, throughput,
latency, and diagnostics are colored when stdout is an interactive terminal.
Set `NO_COLOR=1` to disable ANSI color, or `CLICOLOR_FORCE=1` to retain it when
piping output.

Each run writes owner-only files and refuses to overwrite an existing report:

- `report.json` — machine-readable options, environment, summaries, and peaks;
- `report.md` — human-readable comparison tables;
- `request-samples.csv` — measured requests and WebSocket handshakes. At most
  100,000 concurrent-phase rows are retained as a uniform reservoir; JSON
  counters and HDR latency aggregates still cover every request;
- `resource-samples.csv` — timestamped daemon, client, and container samples;
- `diagnostics.log` — warnings and failures without API tokens or host paths.

## Integration checklist

Rough order for wiring up a panel:

1. Generate `uuid`, `token_id`, a random API `token`, and a different random `jwt_signing_key`; both secrets must be at least 32 bytes. Render the node's `config.yml`; admin runs setup.
2. Call `GET /api/system` to verify connectivity and see what the node supports.
3. Create/manage instances via `/api/instances`; store `instance_id` ↔ your customer records on the panel side (the daemon doesn't know about your users).
4. Poll `GET /api/heartbeat` for node health.
5. For live dashboards, mint per-user JWTs with `/api/ws-token` and connect to `/ws/monitoring` and `/ws/instances/{instance_id}/logs`.
6. For "download my data", queue an export, watch `/ws/instances/{instance_id}/import-export`, and surface the `download` URL it hands you.
7. Point Prometheus at `/metrics` if you run one.
