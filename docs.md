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

For Podman instead of Docker, install and enable the Podman API socket, then set `daemon.engine: podman` in `config.yml`. Only set `daemon.socket_path` if the default socket discovery doesn't find yours.

Official release artifacts currently target x86-64 Linux only. Choose a
versioned release, verify its SHA-256 against the checksum published in that
release, and then install it. Do not automate
installation from the mutable `latest` URL.

```bash
DBEV_VERSION=v0.2.0 # replace with the reviewed release
test "$(uname -m)" = x86_64
sudo curl --fail --location "https://github.com/Tomaxikz/DatabasesEverywhere/releases/download/${DBEV_VERSION}/dbev-x86_64-linux" -o /usr/local/bin/dbev
# Compare this value with the checksum shown on the GitHub release page.
sha256sum /usr/local/bin/dbev
sudo chmod +x /usr/local/bin/dbev
```

Maintainers must configure the GitHub Actions environment named
`production-release` with required reviewers and restrict deployments to the
protected `main` branch and version tags. The release workflow rejects other
refs, requires the requested tag to match the Cargo package version, attests
release binaries, and publishes Docker provenance and an SBOM.

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
```

Also tweak gateway ports, `daemon.engine`, `daemon.socket_path`, or `daemon.ipam.subnet` if your host needs it. Keep `api.host` on loopback when using a local reverse proxy. To expose DBE's native HTTPS server directly instead, use `api.host: 0.0.0.0`, enable `api.ssl`, and configure the panel node URL with the public HTTPS port.

`token` and `jwt_signing_key` are independent credentials and must each contain
at least 32 random bytes. Generate them with a cryptographically secure secret
generator, never copy one into the other, and never commit their real values.
The template placeholders are deliberately rejected by `check-config`.

For example, run `openssl rand -base64 32` twice and assign each output to one
of the two fields.

The API listener may run on loopback behind a reverse proxy or directly on a public interface using its native TLS server. Non-loopback API binds require `api.ssl.enabled: true` with a valid certificate and key; cleartext public API exposure is rejected. Database gateways may use public binds with or without TLS and continue to enforce the database protocols' native credentials. Cleartext public gateways emit a warning because their traffic is not encrypted. `security.allow_insecure_public_listeners` applies only to TLS-disabled remote credential imports and never permits a cleartext public management API.

Database images may use ordinary versioned Docker Hub, GHCR, or other
registry references. Bare references and the mutable `latest` tag are rejected;
an optional `@sha256:` digest can still be used when exact reproducibility is
desired:

```yaml
images:
  postgres: "postgres:18.4"
  redis: "redis:8.8.0"
  mariadb: "mariadb:12.3.2"
  mongodb: "mongo:8.3.4"
  clickhouse: "clickhouse/clickhouse-server:26.4.4.38"
  qdrant: "qdrant/qdrant:v1.18.2"
  allowed:
    postgres: ["postgres:18.4"]
    redis: ["redis:8.8.0"]
    mariadb: ["mariadb:12.3.2"]
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

Unless you've deliberately set up native filesystem quotas, use this disk section:

```yaml
disk:
  mode: fuse_quota
  fuse_quota_binary: embedded
  fuse_quota_binary_sha256: ""
  fuse_quota_rescan_interval_seconds: 150
  project_id_base: 200000
```

For native XFS or ext4 project quotas, DBE allocates from a bounded range of
at most 1,000,000 consecutive IDs starting at `project_id_base`. Reserve that
range exclusively for DBE on the host. XFS mode rejects conflicting entries in
`/etc/projects` or `/etc/projid` instead of replacing them.

The default systemd unit keeps `/etc` read-only. If you deliberately use XFS
project quotas, first grant the service account the narrow host permissions it
needs for `/etc/projects` and `/etc/projid`, then add a dedicated override:

```ini
# systemctl edit databases-everywhere
[Service]
ReadWritePaths=/etc
```

This override broadens the unit's writable filesystem surface and is not
needed for the default FuseQuota or container-storage modes. Keep it off hosts
that do not use XFS project quotas. Native project-quota mode is a privileged
exception: `--setup` installs a managed passwordless sudo rule for host quota
tools and enables `DBE_USE_SUDO` only in that mode. Use it on a dedicated host,
and rerun `--setup` after switching back to FuseQuota, advisory, or Docker
storage limits so the managed sudoers rule is removed.

FuseQuota uses a helper that's bundled into the binary. When
`disk.mode: fuse_quota` is configured, `dbev` checks that `/dev/fuse` is
usable and enables `user_allow_other` in `/etc/fuse.conf` on startup. The host
still needs kernel FUSE support. The checked-in, hash-verified helper currently
targets x86-64 Linux. Other architectures must build `dbev` from reviewed
source, install a trusted helper, set its absolute path in
`disk.fuse_quota_binary`, and set `disk.fuse_quota_binary_sha256` to the
helper's lowercase SHA-256. External helpers must be root-owned, singly linked,
executable regular files in root-owned directories that are not writable by
group or others. The config administration API cannot change either helper
field, and builds never download executable code automatically.

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

Compose also requires an explicit immutable image selection:

```bash
export DBEV_IMAGE='ghcr.io/tomaxikz/databaseseverywhere:v0.2.0@sha256:REPLACE_ME'
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
```

Retention is per instance: after each successful backup, the oldest files in that instance's backup directory get deleted until the limits are satisfied.

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

`--setup` creates the service user, private directories, and hardened systemd
unit. It installs a quota sudoers rule only for native project-quota mode.
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
- If your request includes an `Origin` header (i.e. it comes from a browser), the origin must match the allowed hosts derived from `remote` — otherwise `401`.
- Rate limit: 600 requests per minute per token. Exceed it and you get `429`.
- Request bodies are capped at `security.api_body_limit_bytes`.

WebSockets don't use the node token directly — see [WebSockets](#websockets).

## Errors

Every error is the same shape:

```json
{ "error": "what went wrong" }
```

| Status | Meaning |
| --- | --- |
| 400 | Bad request — validation failed, the message says why |
| 401 | Missing/wrong token, disallowed origin, or token in query string |
| 403 | Token is valid but lacks the required scope |
| 404 | Instance, job, or file doesn't exist |
| 409 | Conflict (usually from the container runtime) |
| 429 | Rate limited |
| 501 | Endpoint not implemented yet |
| 500 | Something broke on the daemon side |

## API contract version

`GET /api/system` returns both the daemon binary `version` and the independently
advertised `api_version`. A panel must verify `api_version` before enabling node
actions. Contract `0.2.0` is intentionally breaking: heartbeat is now `GET`,
instance lifecycle uses only `/power`, jobs/artifacts/backups and their
WebSockets are instance-scoped, import archive settings live inside `source`,
temporary downloads use authenticated `POST` and capability-authenticated `GET`
on the same instance-scoped `/download` path, download URL responses expose only
`url`, `expires_at_unix`, and `single_use`, and backup/restore calls return
synchronous operation records rather than fake job IDs.

## Scopes

Each endpoint requires one scope. The node token has `*`; scoped tokens matter mostly for WebSocket JWTs.

`system:read`, `instances:read`, `instances:write`, `instances:admin`, `resources:read`, `resources:admin`, `logs:read`, `metrics:read`, `artifacts:read`, `artifacts:write`, `backups:read`, `backups:write`, `backups:admin`, `import-export:read`, `import-export:write`, `recovery:admin`, `images:admin`, `ws-tokens:write`, `monitor:read`, `config:admin`

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
  "runtime": { "kind": "docker", "container_name": "...", "network": "..." },
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

`status` is one of `creating`, `running`, `stopped`, `failed`, `quarantined`, `deleting`. `protocol` is one of `postgres`, `mariadb`, `redis`, `mongodb`, `clickhouse`, `qdrant`.
`image.update_available` is computed from the running container image versus the configured default image for that protocol. If it is `true`, the panel should offer the image update action.
`database_version.current` is probed from the running database container for `GET /api/instances` and `GET /api/instances/{id}`. If the instance is stopped or the version probe fails, `current` is `null` and `error` contains a short non-fatal reason.

| Method | Path | Scope | What it does |
| --- | --- | --- | --- |
| GET | `/api/instances` | instances:read | List all instances |
| POST | `/api/instances` | instances:write | Create an instance |
| GET | `/api/instances/{id}` | instances:read | Fetch one |
| DELETE | `/api/instances/{id}?purge=true` | instances:write | Delete; `purge` also wipes data dirs |
| GET | `/api/instances/{id}/status` | instances:read | Just `{instance_id, status}` |
| POST | `/api/instances/{id}/power` | instances:write | Unified power API: `{ "action": "start" | "stop" | "restart" | "kill" }` |
| POST | `/api/instances/{id}/reconcile` | instances:write | Re-sync stored status with the runtime |
| PATCH | `/api/instances/{id}/limits` | instances:write | Update CPU/memory/disk limits |
| PATCH | `/api/instances/{id}/image` | instances:write | Move to a new image (recreates container) |
| GET | `/api/instances/{id}/resources` | resources:read | Live resource report |
| GET | `/api/admin/resources` | resources:admin | Resource reports for everything |
| GET | `/api/admin/runtime-instances` | instances:admin | Container-level view (name, runtime, status) |
| GET | `/api/instances/{id}/logs?tail=200` | logs:read | One-shot logs for one instance; `tail` is clamped to 1-2000 lines |

Lifecycle calls are idempotent-ish: starting a running instance or stopping a stopped one is a no-op, not an error.

Once an authenticated create request is accepted, provisioning continues in a
detached daemon task even if the HTTP client disconnects. The per-instance lock
continues to serialize operations and failed provisioning still runs managed
container/path cleanup, preventing a short panel timeout from leaving an orphaned
volume behind.

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

Validation rules your panel should mirror so users get nice errors:

- `database` and `username`: 1–63 chars, must start with an ASCII letter, then letters/digits/`_`/`-` only. Reserved names are rejected (`postgres`, `mysql`, `admin`, `root`, `default`, `dbe_admin`, `dbe_health`, and a few more).
- `password` and `public_host` must be non-empty.
- `cpu_cores` must be finite and between `0.01` and `1024`; `memory_mib` must be between `1` and `1048576` (1 TiB); and `disk_mib` must be greater than zero. MongoDB and ClickHouse additionally need at least 1024 `memory_mib` **and** 1024 `disk_mib` or they won't even boot.

PostgreSQL clusters use a randomly protected internal `dbe_admin` bootstrap role
that is never registered as a gateway route. The requested username is created
separately as the database owner with `LOGIN` and without superuser, role-creation,
database-creation, replication, inheritance, or row-security bypass privileges.
The container health check performs a real query against `POSTGRES_DB`; it does
not rely on `pg_isready`, which can report that the temporary initialization
server is accepting connections before the requested database exists.

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

For Postgres, MariaDB, MongoDB, and ClickHouse, `major_upgrade: true` runs a safer provider-style migration: export the old database, preserve the old volume, recreate the same instance id on a fresh target-version volume with the same database name, username, password, public endpoint, and limits, import the dump, validate the replacement, then keep the old volume path and export artifact for rollback. If any step fails, DBE tries to restore and restart the old container. Redis and Qdrant major upgrades are rejected for now because their current DBE backup path is physical/version-specific rather than a reliable cross-major logical migration.

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

Usage fields are `null` when the container isn't running or stats aren't available yet. For continuous monitoring use the WebSocket instead of polling this.

## Exports, imports, backups

Three related but different things — don't mix them up:

- **Exports** are portable database-native dumps (`pg_dump` style). They are kept under `paths.exports/<instance_id>/` and exposed to clients only through opaque artifact IDs.
- **Imports** load one of that instance's artifacts or copy data directly from a remote database. An operator can also stage a file under `paths.imports/<instance_id>/` and reference its filename as the artifact ID. API clients never submit host filesystem paths.
- **Backups** are physical archives of the whole instance volume, stored under `paths.backups/<instance_id>/`. They're for disaster recovery on the same daemon, not portability.

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

| Method | Path | Scope | What it does |
| --- | --- | --- | --- |
| POST | `/api/instances/{id}/export` | import-export:write | Queue an export |
| POST | `/api/instances/{id}/import` | import-export:write | Queue an import |
| GET | `/api/instances/{id}/import-export/jobs` | import-export:read | List that instance's jobs (`?status=&limit=`) |
| GET | `/api/instances/{id}/import-export/jobs/{job_id}` | import-export:read | One job, after ownership verification |

Export body (all optional — empty body means a full plain dump):

```json
{
  "archive": true,
  "archive_format": "gzip",
  "selection": { "mode": "selective", "include": ["table_a"], "exclude": [], "fields": {} }
}
```

`archive_format` is `plain`, `gzip`, or `bzip2`.

Export/import formats:

| Protocol | Export format | Import support |
| --- | --- | --- |
| PostgreSQL | `.postgres.sql` logical dump | Plain dump, gzip/bzip2/tar/zip/rar-wrapped dump, remote PostgreSQL |
| MariaDB | `.mariadb.sql` logical dump | Plain dump, gzip/bzip2/tar/zip/rar-wrapped dump, remote MariaDB/MySQL |
| MongoDB | `.mongodb.archive.gz` archive dump | MongoDB archive dump, gzip/tar/zip/rar-wrapped archive, remote MongoDB |
| ClickHouse | `.clickhouse.sql` logical dump | Plain dump, gzip/bzip2/tar/zip/rar-wrapped dump, remote ClickHouse |
| Redis | `.redis.tar.gz` physical archive | Full physical archive only |
| Qdrant | `.qdrant.tar.gz` physical archive | Full physical archive only |

Redis and Qdrant exports are full physical volume archives. They are not selective and are not remote-credential imports.

Import one of the target instance's artifacts:

```json
{
  "source": {
    "type": "artifact",
    "artifact_id": "9c39d836-5f8e-4e48-94d6-ec6b1397fdda.postgres.sql.gz",
    "unarchive": true
  }
}
```

Import straight from another server:

```json
{
  "source": {
    "type": "remote",
    "protocol": "postgres",
    "host": "old-host.example.com",
    "port": 5432,
    "database": "legacy_db",
    "username": "migrator",
    "password": "…",
    "tls": true
  }
}
```

Remote TLS defaults to `true`; `tls: false` is rejected unless the isolated-development insecure-listener override is enabled. DNS answers are checked and pinned to prevent rebinding. PostgreSQL can pin the address while verifying the original hostname. For MariaDB, MongoDB, and ClickHouse, use an IP literal whose certificate contains that IP SAN; hostname-based TLS imports are rejected until those client tools can preserve independent hostname verification while using a pinned address.

### Backups

| Method | Path | Scope | What it does |
| --- | --- | --- | --- |
| GET | `/api/instances/{id}/backups` | backups:read | List only that instance's backups |
| POST | `/api/instances/{id}/backups` | backups:write | Back up that instance now; returns the completed backup record |
| POST | `/api/instances/{id}/backups/{backup_id}/restore` | backups:write | Restore the backup into its owning instance |
| DELETE | `/api/instances/{id}/backups/{backup_id}` | backups:write | Delete one owned backup |
| GET | `/api/admin/backups/status` | backups:admin | Node backup schedule and retention configuration |
| POST | `/api/admin/backups/run` | backups:admin | Back up every eligible instance; returns `backups` and `skipped` |

Backup list items are `{id, instance_id, size_bytes, modified_at, sha256}`. Host paths are never returned. A backup ID is resolved only below `paths.backups/<instance_id>/`; a backup from one instance cannot be restored, downloaded, or deleted through another instance's route.

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

3. Panel resolves the origin-relative `url` against its trusted daemon origin and hands it to the browser. No auth header is needed — the JWT in the query is the whole credential. It expires fast and single-use tokens burn after the first hit, so hand them out at click time, don't store them. The daemon deliberately does not derive an absolute URL from client-controlled `Host` or forwarding headers.

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
| POST | `/api/instances/{id}/recovery/jobs/{job_id}/retry` | Re-queue a failed job after checking its instance |
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

Response: `{ "token_type": "Bearer", "token": "…", "expires_at_unix": … }`. TTL defaults to 900s, max 3600. `instances` restricts the token to those instances. An empty list grants no instance access; node-wide access must be explicitly requested with `"all_instances": true`, and that flag cannot be combined with an allow-list. Each token ID is accepted for one WebSocket upgrade only, so mint a fresh token when reconnecting.

### Step 2: connect (browser side)

Browsers can't set an `Authorization` header on a WebSocket, so pass the JWT via the subprotocol:

```js
const ws = new WebSocket("wss://node.example.com/ws/instances/cust-42-db/logs",
                         ["dbe.jwt", token]);
```

Server-side clients can use either the subprotocol trick or a plain `Authorization: Bearer <jwt>` header.

### Endpoints and events

Every message is a JSON object with a `type` field.

**`/ws/monitoring`** (scope `monitor:read`) — a full snapshot every second:

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

Disk usage is sampled from quota accounting when available and cached per instance. Directory walking is only a fallback, and a background sampler keeps the cache warm so websocket ticks do not block on large database directories.
`install_progress.action` is `create`, `image_update`, or `major_upgrade`. For image updates, listen for stages like `queued`, `prepare`, `pull_image`, `delete_container`, `create_container`, `start`, `healthcheck`, `backend`, `completed`, and `failed`. Major upgrades also emit `export`, `snapshot`, `prepare_replacement`, `import`, and `validate`.

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
| GET | `/api/system` | system:read | Node identity, version, engine, which protocols are enabled |
| PATCH | `/api/system/config` | config:admin | Merge a runtime config patch into `config.yml`; returns `restart_required: true` |
| GET | `/api/heartbeat` | system:read | `{"status":"ok"}` — cheap liveness check for the panel |
| GET | `/metrics` | metrics:read | Prometheus text: instance counts by protocol/status, job counts, disk enforcement flag |

`/api/system` is the right first call after registering a node — it tells you the daemon `version`, contract `api_version`, `daemon_engine`, socket, `disk_mode`, `daemon_internal_network`, and per-protocol `*_enabled` flags so the panel knows what it's allowed to offer.

The API listener becomes available after critical metadata, crash-recovery,
container-engine, network, and disk checks complete. Existing managed database
containers then auto-start in a lock-protected background phase, so a slow or
broken container does not hold node heartbeat or management endpoints offline.
Heartbeat reports management API liveness, not that every database instance is
ready; clients should check each instance's status before presenting it as ready.
Database gateways open after background startup and legacy PostgreSQL role
hardening complete.

Config patches are JSON object merges against the current config. `null` removes a key. The daemon rejects edits to `uuid`, `token_id`, `token`, `jwt_signing_key`, Fuse helper path/digest, public-listener development override, and private-import trust settings; those security boundaries must be changed deliberately in the host config. A successful patch writes the config file only — restart the daemon before expecting listener, TLS, path, image, or runtime changes to take effect.

API-triggered self-upgrade is intentionally unsupported: accepting an executable and its digest from the same administrative request does not provide an independent trust anchor. Keep `security.self_upgrade_enabled: false` and deploy signed packages or immutable, digest-pinned container images through the host's normal rollout mechanism.

If a legacy database contains duplicate route identities, startup preserves the deterministic first claimant and marks every other claimant `quarantined`. Quarantined containers are stopped before gateways open and cannot be started or restarted; their metadata and data remain available for inspection and explicit deletion.

An unclean daemon exit while an import/export job is durably `running` also quarantines the affected instance on the next startup. The container is stopped before gateways open, preventing a possibly orphaned dump or restore process from racing new work. Queued jobs that never started are marked failed without quarantining their instances. Inspect the failed job and database integrity, then recover or repair the quarantined instance offline.

If creation cleanup was interrupted, a normal retry fails closed rather than reusing orphaned files with new credentials. After preserving any required data, retry the create request with `"purge_stale_resources": true` to explicitly and irreversibly remove that instance ID's orphaned container and paths before creation.

Import/export admission is bounded to 64 jobs node-wide and two running-or-queued jobs per instance. The in-memory status cache retains at most 2,048 completed jobs, and SQLite retains the latest 10,000 completed records; queued/running records are never pruned.

## Integration checklist

Rough order for wiring up a panel:

1. Generate `uuid`, `token_id`, a random API `token`, and a different random `jwt_signing_key`; both secrets must be at least 32 bytes. Render the node's `config.yml`; admin runs setup.
2. Call `GET /api/system` to verify connectivity and see what the node supports.
3. Create/manage instances via `/api/instances`; store `instance_id` ↔ your customer records on the panel side (the daemon doesn't know about your users).
4. Poll `GET /api/heartbeat` for node health.
5. For live dashboards, mint per-user JWTs with `/api/ws-token` and connect to `/ws/monitoring` and `/ws/instances/{instance_id}/logs`.
6. For "download my data", queue an export, watch `/ws/instances/{instance_id}/import-export`, and surface the `download` URL it hands you.
7. Point Prometheus at `/metrics` if you run one.
