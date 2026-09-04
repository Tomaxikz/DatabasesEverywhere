# Exports, imports, and backups

[Documentation index](../README.md) · [OpenAPI](openapi.yml)

| Operation | Purpose |
| --- | --- |
| Export | Native logical dump, or a physical archive for Redis/Valkey/Qdrant |
| Import | Restore an owned artifact, temporary upload, or typed remote source |
| Backup | Recovery copy: physical for dedicated placement, tenant-scoped logical for shared |

API clients use opaque IDs, never host paths, commands, helper images, or
connection URLs. Artifacts and backups are bound to their owning instance.

## Temporary dump uploads

`POST /api/instances/{id}/import` has two modes:

- `application/octet-stream`: upload bytes, return `201 Created`.
- `application/json`: queue an import, return `202 Accepted`.

Raw uploads require an exact `Content-Length` and `X-DBEV-Filename`
(percent-encoded UTF-8 flat filename, at most 180 decoded bytes).
`X-DBEV-SHA256` optionally supplies an expected lowercase SHA-256.
`Content-Encoding` must be absent or `identity`; compression belongs to the dump.

```bash
curl --fail-with-body --request POST \
  --header "Authorization: Bearer $DBEV_TOKEN" \
  --header 'Content-Type: application/octet-stream' \
  --header "Content-Length: $(wc -c < "$DUMP" | tr -d ' ')" \
  --header 'X-DBEV-Filename: customer.postgres.sql' \
  --data-binary "@$DUMP" \
  "$DBEV_ORIGIN/api/instances/$INSTANCE_ID/import"
```

The response includes `upload_id`, state, format, size, computed hash, and expiry.

| Method | Instance-relative path | Scope |
| --- | --- | --- |
| GET | `/import/uploads` | `import-export:read` |
| GET | `/import/uploads/{upload_id}` | `import-export:read` |
| POST | `/import/uploads/{upload_id}/catalog` | `import-export:write` |
| DELETE | `/import/uploads/{upload_id}` | `import-export:write` |

Prefix these paths with `/api/instances/{id}`.

Catalog inspection is optional for full imports and never executes the dump.
Enable selective controls only when `selective_supported` is true; submit the
returned object `selection_key` values. A preview catalog alone does not imply
selective import support. Catalog admission can return `429`; bounded resource/
timeout failures return `503` and leave the upload ready for a full import.

Queue a ready upload:

```json
{
  "source": { "type": "upload", "upload_id": "upl_0123456789abcdef0123456789abcdef" },
  "mode": "merge"
}
```

The persisted wrapper cannot be overridden. For MongoDB, add
`source.source_database` to select and remap the original namespace. A complete
catalog with one namespace allows inference; multiple namespaces require a
choice. Empty/incomplete discovery requires a manual value. Contradicting a
complete catalog returns `409` before queueing. Other protocols reject this field.

Delete unused uploads when a modal is cancelled. Successful imports consume
them; failures release them for retry/cancellation. Uploads expire after 24
hours by default, never enter the artifact inventory, and are not downloadable.

## Import/export jobs

| Method | Path | Scope |
| --- | --- | --- |
| POST | `/api/instances/{id}/export` | `import-export:write` |
| POST | `/api/instances/{id}/import` | `import-export:write` |
| GET | `/api/instances/{id}/import-export/jobs?status=&limit=` | `import-export:read` |
| GET | `/api/instances/{id}/import-export/jobs/{job_id}` | `import-export:read` |

Jobs transition `queued → running → succeeded/failed`. Accepted requests return
`202` and a `Location` status URL. Use that endpoint or the
[job WebSocket](websockets.md#importexport-jobs); store the job ID, not an expiring
download URL. Job errors are public diagnostics with optional support IDs.

### Export

Send `{}` for a full plain export when using JSON content type. A bodyless
request is accepted only without that content type. Optional selection:

```json
{
  "archive_format": "gzip",
  "selection": { "mode": "selective", "include": ["table_a"], "exclude": [], "fields": {} }
}
```

| Protocol | Native export | Import wrappers |
| --- | --- | --- |
| PostgreSQL / MySQL / MariaDB / ClickHouse | `.<protocol>.sql` | Plain, gzip, bzip2, tar, zip |
| MongoDB | `.mongodb.archive.gz` | Native archive or bzip2/tar/tar.gz/zip containing exactly one native archive |
| Redis / Valkey / Qdrant | `.<protocol>.tar.gz` | Full physical archive only |

Omit `archive_format` for physical exports. MongoDB is already gzip-compressed;
requesting `gzip` does not add a second wrapper. Physical exports are not selective.

Export disk admission excludes container image layers, adds a bounded dump
allowance, and checks real free space plus active reservations on the output
filesystems. Logical output is capped at 8 GiB. Same-filesystem plain dump
installation reserves once; compression reserves both files while they coexist.

### Import an artifact

```json
{
  "source": {
    "type": "artifact",
    "artifact_id": "export.postgres.sql.gz",
    "archive_format": "gzip"
  },
  "mode": "merge"
}
```

The artifact must belong to the target instance. Operators may stage supported
files under `paths.imports/<instance_id>/` and reference their filenames;
clients cannot submit arbitrary filesystem paths.

For logical imports, `merge` replaces source-named objects and preserves
target-only objects; `wipe` clears the target first. Redis/Valkey/Qdrant physical
archives always replace the complete database regardless of mode.
Native restores are not general-purpose transactions.

### Import a remote source

The target instance determines the protocol:

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

- TLS is verified by default. Plaintext needs both `tls: false` and
  `security.remote_import.allow_plaintext: true`.
- Private RFC1918/ULA/CGNAT hosts need exact entries in
  `allowed_private_hosts`. Loopback, link-local, metadata, multicast, reserved,
  and mixed public/private DNS results are rejected.
- Remote credentials are never persisted in job records. Helpers use private
  temporary credential files, removed after execution/reconciled on startup;
  Redis/Valkey/Qdrant use in-memory credentials. Failed remote imports must be
  resubmitted rather than replayed through the recovery endpoint.
- One credential-bearing job is admitted per instance; node concurrency uses
  `security.remote_import.max_concurrent_jobs`.
- SQL/document engines use native acquisition tools, Redis/Valkey use binary-safe
  DUMP/RESTORE, and Qdrant uses collection snapshots. Target containers remain
  network-isolated.
- Cluster Redis/Valkey and distributed Qdrant sources are rejected. Use
  cluster-aware tooling instead.
- Acquisition does not lock the source. Quiesce source writes for a consistent
  point-in-time migration, including sequential MongoDB collection dumps.
  Also quiesce target writes to objects being replaced.

Qdrant also transfers aliases for selected collections, preserving unrelated
target aliases. Alias/collection failures roll back together; failed rollback
retains recovery snapshots. Snapshot versions must match major/minor, and the
target patch cannot be older.

### Shared-engine restrictions

Shared imports/migrations accept portable tenant data, not arbitrary engine code:

| Engine | Rejected examples |
| --- | --- |
| PostgreSQL | Functions, procedures, extensions, foreign data, roles, grants |
| MySQL / MariaDB | Routines, functions, triggers, events, global settings, unsafe/foreign definers |
| ClickHouse | External/distributed engines, materialized/live/window views, table-function sources/sinks |
| MongoDB | Views, system collections, cross-database namespaces, code-bearing validators |

Qualified SQL references are structurally remapped to the target; row strings
are not rewritten. Ambiguous forms fail closed. MySQL definers become the
managed tenant where supported. Unsupported source objects are rejected before
mutation; destructive restores also require a complete rollback snapshot.
Choose dedicated placement when these engine features are required.

## Scheduler and retention

The [example config](../../config/example.yml) defines upload size, total
capacity, concurrency, expiry, and transfer deadlines separately from artifacts.

`artifacts.import_export_scheduler` bounds the durable queue and active work.
Dynamic mode treats memory as a hard budget and CPU/I/O as concurrency weights.
A memory-safe job larger than the CPU/I/O budget can run alone. Zero dynamic
budgets use live host/cgroup headroom; explicit budgets stay fixed. Per-instance
mutations remain serialized; queued work holds no active staging reservation.

`starvation_timeout_seconds` and `max_bypass` bound waiting. Fixed mode
(`dynamic_limiter_enabled: false`) uses `manual_max_active_jobs` but retains
queue, extraction, upload, and disk guards. Config changes require restart.

`GET /api/system/import-export-scheduler/recommendation` requires `system:read`.
It accepts protocol/action/size/target-disk/mode/compression inputs and returns
live budgets and a model-based recommendation—not a throughput guarantee.
**Zero is a valid blocked-headroom result; do not clamp it to one.**

`stream_exports_only: true` uses a private one-use spool, not a zero-disk stream.
It is absent from artifact listings, deleted after download/disconnect, and
expires after one hour if abandoned. Internal rollback exports remain retained.
`max_artifacts_per_instance` counts retained artifacts plus pending one-use
exports; reaching the cap returns a conflict until one is consumed or deleted.

## Backups

| Method | Path | Scope |
| --- | --- | --- |
| GET / POST | `/api/instances/{id}/backups` | `backups:read` / `backups:write` |
| GET | `/api/instances/{id}/backups/{backup_id}/contents?object=&offset=&limit=` | `backups:read` |
| POST | `/api/instances/{id}/backups/{backup_id}/restore` | `recovery:admin` |
| DELETE | `/api/instances/{id}/backups/{backup_id}` | `backups:write` |
| GET / POST | `/api/admin/backups/status` / `/api/admin/backups/run` | `backups:admin` |

Creation returns the completed backup record, not an import/export job ID.
Records expose ID, owner, size, timestamp, hash, protocol, and layout—not paths
or remote object keys.

After a placement migration, old backups stay downloadable but cannot restore
into an incompatible layout (`409`). Dedicated expects `physical`; shared
expects `logical`. Create a fresh backup after migration.

| Driver | Requirements |
| --- | --- |
| `local` | Archives and manifests under `paths.backups/<instance_id>` |
| `s3` | Bucket/region, least-privilege credentials, TLS; optional compatible endpoint/path style |
| `kopia` | Connected repository config and trusted executable; root/daemon-owned, non-group/world-writable files |

S3 credentials may come from `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and
`AWS_SESSION_TOKEN`; Kopia accepts `KOPIA_PASSWORD`. See the example config
for options. Remote materializations verify recorded size/hash before use.
Changing driver switches inventories; it does not migrate existing backups.

Keep local space for a complete backup in staging and for restore/download
materialization under `paths.tmp`. Protect remote stores as database data; for
S3 configure encryption and cleanup of incomplete multipart uploads.

Automatic retention is per instance and removes the oldest owned backups after
successful backup creation until count and age limits are satisfied.
Catalog browsing reads a bounded stored schema/row preview, not a running clone.
Missing catalogs report `catalog_available: false`. Row previews are sensitive;
set `preview_rows_per_object: 0` for schema-only browsing.

Restores are destructive and require `{ "confirm": true, "reason": "ticket #123" }`.

## Downloads

The panel backend requests a ticket using the appropriate read scope:

```http
POST /api/instances/{id}/artifacts/{artifact_id}/download
POST /api/instances/{id}/backups/{backup_id}/download
Content-Type: application/json

{ "expires_in_seconds": 120, "single_use": true }
```

Resolve the returned `url` against the trusted node origin. Its query JWT is the
browser's complete credential; never attach the node token or persist the URL.
Issue tickets at click time and honor `expires_at_unix`/`single_use`.

Downloads are bounded to 128 active streams node-wide and 32 per transport peer.
Admission `429` does not consume a single-use ticket.

## Artifact housekeeping

With `artifacts:read`, list `GET /api/instances/{id}/artifacts`.
With `artifacts:write`, delete `/artifacts/{artifact_id}` or
`POST /artifacts/retention`, under the same instance prefix.
Temporary uploads are separate and use upload TTL, not artifact retention.

## Recovery

These endpoints require `recovery:admin`:

| Method | Path | Action |
| --- | --- | --- |
| GET | `/api/admin/recovery/failed-jobs` | Inspect failed jobs |
| POST | `/api/instances/{id}/recovery/jobs/{job_id}/retry` | Retry replayable export/artifact work |
| POST | `/api/instances/{id}/recovery/restore` | Force-import an owned artifact |

Credential imports and records without replay options require resubmission.
Force restore needs `artifact_id`, `confirm: true`, and an audit `reason`.
Inspect retained recovery data before retrying or deleting anything.
