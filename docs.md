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

Download the latest release for your architecture and install it:

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
token: replace-with-long-random-panel-token

api:
  host: 0.0.0.0
  port: 8090
```

Also tweak gateway ports, `daemon.engine`, `daemon.socket_path`, or `daemon.ipam.subnet` if your host needs it. `api.host` and `api.port` are just the listener bind — the public API URL/domain belongs in the panel's node record.

Unless you've deliberately set up native filesystem quotas, use this disk section:

```yaml
disk:
  mode: fuse_quota
  fuse_quota_rescan_interval_seconds: 150
  project_id_base: 200000
```

FuseQuota uses a helper that's bundled into the binary. When
`disk.mode: fuse_quota` is configured, `dbev --setup` checks that `/dev/fuse`
is usable and enables `user_allow_other` in `/etc/fuse.conf`. The host still
needs kernel FUSE support.

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

### Setup and start

```bash
sudo dbev --setup
sudo systemctl enable --now databases-everywhere
sudo journalctl -u databases-everywhere -f
```

`--setup` creates the service user, directories, systemd unit, and the quota sudoers rule. Files end up here:

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

- Putting a token in the query string (`?token=...`) gets you a `401` — headers only. The one exception is signed download URLs, which carry their own short-lived JWT.
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

## Scopes

Each endpoint requires one scope. The node token has `*`; scoped tokens matter mostly for WebSocket JWTs.

`system:read`, `instances:read`, `instances:write`, `resources:read`, `logs:read`, `metrics:read`, `artifacts:read`, `artifacts:write`, `backups:read`, `backups:write`, `import-export:read`, `import-export:write`, `recovery:admin`, `images:admin`, `ws-tokens:write`, `monitor:read`, `config:admin`, `upgrades:admin`

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
  "created_at": "2026-07-01T12:00:00Z",
  "updated_at": "2026-07-01T12:00:00Z"
}
```

`status` is one of `creating`, `running`, `stopped`, `failed`, `deleting`. `protocol` is one of `postgres`, `mariadb`, `redis`, `mongodb`, `clickhouse`, `qdrant`.

| Method | Path | Scope | What it does |
| --- | --- | --- | --- |
| GET | `/api/instances` | instances:read | List all instances |
| POST | `/api/instances` | instances:write | Create an instance |
| GET | `/api/instances/{id}` | instances:read | Fetch one |
| DELETE | `/api/instances/{id}?purge=true` | instances:write | Delete; `purge` also wipes data dirs |
| GET | `/api/instances/{id}/status` | instances:read | Just `{instance_id, status}` |
| POST | `/api/instances/{id}/start` | instances:write | Start (waits until ready, up to 120s) |
| POST | `/api/instances/{id}/stop` | instances:write | Stop |
| POST | `/api/instances/{id}/restart` | instances:write | Restart (waits until ready) |
| POST | `/api/instances/{id}/power` | instances:write | Unified power API: `{ "action": "start" | "stop" | "restart" | "kill" }` |
| POST | `/api/instances/{id}/reconcile` | instances:write | Re-sync stored status with the runtime |
| PATCH | `/api/instances/{id}/limits` | instances:write | Update CPU/memory/disk limits |
| PATCH | `/api/instances/{id}/image` | instances:write | Move to a new image (recreates container) |
| GET | `/api/instances/{id}/resources` | resources:read | Live resource report |
| GET | `/api/resources` | resources:read | Resource reports for everything |
| GET | `/api/runtime-instances` | instances:read | Container-level view (name, runtime, status) |
| GET | `/api/instances/{id}/logs?tail=200` | logs:read | One-shot logs for one instance; `tail` is clamped to 1-2000 lines |
| GET | `/api/logs/{id}` | logs:read | One-shot logs `{instance_id, stdout, stderr}` |

Lifecycle calls are idempotent-ish: starting a running instance or stopping a stopped one is a no-op, not an error.

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

- `database` and `username`: 1–63 chars, must start with an ASCII letter, then letters/digits/`_`/`-` only. Reserved names are rejected (`postgres`, `mysql`, `admin`, `root`, `default`, `dbe_health`, and a few more).
- `password` and `public_host` must be non-empty.
- All limits must be > 0. MongoDB and ClickHouse additionally need at least 1024 `memory_mib` **and** 1024 `disk_mib` or they won't even boot.

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

### Pre-pulling images

```json
POST /api/images/pull            (scope: images:admin)
{ "protocol": "postgres", "image": "postgres:18.4" }
```

Omit `image` to pull the node's configured default for that protocol. Handy for warming a node before creating instances on it.

## Resource reports

`GET /api/resources` and `GET /api/instances/{id}/resources` return:

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

- **Exports** are portable database-native dumps (`pg_dump` style). They land under `paths.exports` and stay there until deleted or aged out by retention. Good for "download my database" buttons.
- **Imports** load a dump into an instance, from a staged file or straight from a remote database. Staging files belong under `paths.imports`; the daemon accepts imports from `paths.exports` or `paths.imports` after canonical path checks.
- **Backups** are physical archives of the whole instance volume, stored under `paths.backups/<instance_id>/`. They're for disaster recovery on the same daemon, not portability.

### Import/export jobs

Exports and imports are async. You queue a job, then watch it via polling or the WebSocket. The job object:

```json
{
  "job_id": "…",
  "instance_id": "cust-42-db",
  "action": "export",
  "status": "queued",
  "artifact_path": "/var/lib/dbev/artifacts/exports/…",
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
| GET | `/api/import-export` | import-export:read | List jobs (`?instance_id=&status=&limit=`) |
| GET | `/api/import-export/{job_id}` | import-export:read | One job |

Export body (all optional — empty body means a full plain dump):

```json
{
  "archive": true,
  "archive_format": "gzip",
  "selection": { "mode": "selective", "include": ["table_a"], "exclude": [], "fields": {} }
}
```

`archive_format` is `plain`, `gzip`, or `bzip2`.

Import from a staged artifact:

```json
{ "artifact_path": "/var/lib/dbev/artifacts/imports/dump.sql.gz", "unarchive": true }
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

### Backups

| Method | Path | Scope | What it does |
| --- | --- | --- | --- |
| GET | `/api/backups` | backups:read | List backup files (`{name, path, size_bytes, modified_at, sha256}`) |
| GET | `/api/backups/status` | backups:read | The node's backup schedule + retention config |
| POST | `/api/backups` | backups:write | Run now: `{"instance_id": "…"}` or `{"all": true}` |
| POST | `/api/backups/{name}/restore` | backups:write | Restore a backup into an instance: `{"instance_id": "…"}` |
| DELETE | `/api/backups/{name}` | backups:write | Delete a backup file |
| GET | `/api/backups/download/{name}` | backups:read | Direct download (Bearer auth) |

`POST /api/backups/run` also works — same handler as `POST /api/backups`. Running against `all` returns `{jobs: […], skipped: […]}` where skipped entries explain why (e.g. instance not running).

### Letting users download files (signed URLs)

Your panel authenticates with the node token, but end users' browsers can't. The flow:

1. Panel asks the daemon for a download token:

```json
POST /api/artifacts/{name}/download-token     (scope: artifacts:read)
POST /api/backups/{name}/download-token       (scope: backups:read)
{ "instance_id": "cust-42-db", "expires_in_seconds": 120, "single_use": true }
```

2. The daemon answers with a ready-to-use URL:

```json
{
  "token_type": "Bearer",
  "token": "…jwt…",
  "url": "https://node.example.com/api/artifacts/download-signed?token=…",
  "download_path": "/api/artifacts/download-signed?token=…",
  "expires_at_unix": 1751900000,
  "single_use": true
}
```

3. Panel hands `url` to the browser. No auth header needed — the JWT in the query is the whole credential. It expires fast and single-use tokens burn after the first hit, so hand them out at click time, don't store them.

### Artifact housekeeping

| Method | Path | Scope | What it does |
| --- | --- | --- | --- |
| GET | `/api/artifacts` | artifacts:read | List export/import artifacts |
| DELETE | `/api/artifacts/{name}` | artifacts:write | Delete one |
| POST | `/api/artifacts/retention` | artifacts:write | Apply retention now, returns `{deleted: […]}` |

### Recovery

For your admin panel's "something went wrong" page. Scope: `recovery:admin`.

| Method | Path | What it does |
| --- | --- | --- |
| GET | `/api/recovery/failed-jobs` | All failed import/export jobs |
| POST | `/api/recovery/jobs/{job_id}/retry` | Re-queue a failed job (only failed ones) |
| POST | `/api/recovery/restore` | Force-import an artifact into an instance |

Restore requires explicit intent — `confirm` and a `reason` (it's audit-logged):

```json
{ "instance_id": "cust-42-db", "artifact_path": "…", "confirm": true, "reason": "customer ticket #123" }
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

Response: `{ "token_type": "Bearer", "token": "…", "expires_at_unix": … }`. TTL defaults to 900s, max 3600. `instances` restricts the token to those instances — leave it empty for node-wide scopes like `monitor:read`, set it when minting for a specific user so they can't watch other people's logs.

### Step 2: connect (browser side)

Browsers can't set an `Authorization` header on a WebSocket, so pass the JWT via the subprotocol:

```js
const ws = new WebSocket("wss://node.example.com/ws/logs?instance_id=cust-42-db",
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
      "resources": { "…": "same shape as /api/resources" },
      "resource_error": null
    }
  ],
  "install_progress": []
}
```

Disk usage is sampled at most every 5s per instance (it's a directory walk), everything else is fresh each tick.

**`/ws/logs?instance_id=…`** (scope `logs:read`, token must cover the instance) — a snapshot every 3 seconds:

```json
{ "type": "logs", "instance_id": "cust-42-db", "sequence": 7,
  "stdout": "…", "stderr": "…", "error": null }
```

Connection URLs in log output are redacted before they leave the daemon. If fetching logs fails, `stdout`/`stderr` are null and `error` says why.

**`/ws/import-export?instance_id=…&job_id=…`** (scope `import-export:read`) — both query params optional. On connect you get the current state, then push updates as jobs change:

```json
{ "type": "import_export_snapshot", "jobs": [ { …job fields…, "download": null } ] }
{ "type": "import_export_job", "job": { …job fields…, "download": { …signed url… } } }
{ "type": "import_export_lagged", "skipped": 12 }
```

Job objects are the same shape as the REST job response. When an export succeeds, the event includes a `download` object — a signed, single-use download ticket valid for ~120 seconds, so your UI can show a download button the moment the export finishes. A `lagged` event means you missed messages; a fresh snapshot follows automatically.

## System and monitoring endpoints

| Method | Path | Scope | What it does |
| --- | --- | --- | --- |
| GET | `/api/system` | system:read | Node identity, version, engine, which protocols are enabled |
| PATCH | `/api/system/config` | config:admin | Merge a runtime config patch into `config.yml`; returns `restart_required: true` |
| POST | `/api/system/upgrade` | upgrades:admin | Download, verify, replace the daemon binary, then run the configured restart command |
| POST | `/api/heartbeat` | system:read | `{"status":"ok"}` — cheap liveness check for the panel |
| GET | `/metrics` | metrics:read | Prometheus text: instance counts by protocol/status, job counts, disk enforcement flag |

`/api/system` is the right first call after registering a node — it tells you the daemon version, runtime engine, socket, `daemon_internal_network`, and per-protocol `*_enabled` flags so the panel knows what it's allowed to offer.

Config patches are JSON object merges against the current config. `null` removes a key. The daemon rejects edits to `uuid`, `token_id`, and `token`; those must be rotated deliberately by writing the config file. A successful patch writes the config file only — restart the daemon before expecting listener, TLS, path, image, or runtime changes to take effect.

Self-upgrade is disabled unless `security.self_upgrade_enabled: true`. The request must use an HTTPS binary URL, include a 64-character SHA-256 digest, and provide a restart command plus args. The daemon does not run the command through a shell.

## Integration checklist

Rough order for wiring up a panel:

1. Generate `uuid`, `token_id`, and a long random `token`; render the node's `config.yml`; admin runs setup.
2. Call `GET /api/system` to verify connectivity and see what the node supports.
3. Create/manage instances via `/api/instances`; store `instance_id` ↔ your customer records on the panel side (the daemon doesn't know about your users).
4. Poll `POST /api/heartbeat` for node health.
5. For live dashboards, mint per-user JWTs with `/api/ws-token` and connect to `/ws/monitoring` and `/ws/logs`.
6. For "download my data", queue an export, watch `/ws/import-export`, and surface the `download` URL it hands you.
7. Point Prometheus at `/metrics` if you run one.
