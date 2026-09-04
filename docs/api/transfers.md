# Exports, imports, backups

[Documentation index](../README.md)

Three related but different things — don't mix them up:

- **Exports** are portable database-native dumps (`pg_dump` style). By default they are kept under `paths.exports/<instance_id>/` and exposed to clients only through opaque artifact IDs. Stream-only mode instead exposes the completed job through the same download flow without retaining it in that inventory.
- **Imports** load one of that instance's trusted local artifacts, a temporary dump uploaded through the API, or a native dump/snapshot acquired directly from a typed remote source. An operator can stage a file under `paths.imports/<instance_id>/` and reference its filename as the artifact ID. API clients never submit host filesystem paths, helper images, commands, or connection URLs.
- **Backups** use the deployment's safe recovery layout. Dedicated instances use physical whole-volume archives where their protocol supports them; shared tenants use database-scoped logical dumps and never capture the pool filesystem or another tenant. The local driver stores them under `paths.backups/<instance_id>/`; S3 and Kopia store them in the configured remote repository. They're recovery artifacts for the same DBEV protocol and deployment layout, not general-purpose portability dumps.

Changing an instance between dedicated and shared placement does not rewrite or
delete its existing backups. A backup from the previous placement remains
downloadable, but restoring it into the new placement returns `409` because its
physical/logical layout no longer matches. Create a new backup after a successful
placement migration. Backup list and creation responses include `protocol` and
`layout`; panels should compare those fields with the instance's current protocol
and deployment mode before enabling restore (`dedicated` expects `physical`,
`shared` expects `logical`).

Before a logical export starts, DBEV measures the managed instance data
directory only; container image layers are not part of this measurement. It
adds a bounded protocol-specific allowance for logical-dump expansion, caps the
stream at 8 GiB, and checks that allowance against the current free bytes and
other active reservations on the actual staging and artifact filesystems. A
plain export whose staging and artifact directories share a filesystem is
reserved once because installation is an atomic rename. Compressed exports keep
separate bounded reservations for the source dump and compressed artifact while
both files coexist.

## Temporary dump uploads

DBEV can receive a user-provided dump without placing it in the artifact
inventory or starting an import immediately. The same import URL selects its
behavior by media type: `application/octet-stream` uploads raw bytes and
returns `201 Created`; `application/json` queues an import and returns
`202 Accepted`.

| Method | Path | Scope | What it does |
| --- | --- | --- | --- |
| POST | `/api/instances/{id}/import` | import-export:write | Upload raw dump bytes (`application/octet-stream`) or queue an import (`application/json`) |
| GET | `/api/instances/{id}/import/uploads` | import-export:read | List active temporary uploads for the instance |
| GET | `/api/instances/{id}/import/uploads/{upload_id}` | import-export:read | Read one upload's state and cached catalog |
| POST | `/api/instances/{id}/import/uploads/{upload_id}/catalog` | import-export:write | Validate and inspect the dump without executing it |
| DELETE | `/api/instances/{id}/import/uploads/{upload_id}` | import-export:write | Cancel and durably delete an upload that is not being imported |

The upload request must use raw, unencoded bytes and these headers:

- `Content-Type: application/octet-stream`
- `Content-Length`: required and exactly equal to the bytes sent
- `X-DBEV-Filename`: required, percent-encoded UTF-8 flat filename (maximum
  180 decoded bytes) with a supported dump extension
- `X-DBEV-SHA256`: optional expected SHA-256 as 64 lowercase hexadecimal
  characters

`Content-Encoding` must be absent or `identity`. Compression belongs in the
dump format itself. For an ASCII filename, a server-side upload looks like:

```bash
DUMP=/srv/panel-uploads/customer.postgres.sql
SIZE=$(wc -c < "$DUMP" | tr -d ' ')
SHA256=$(sha256sum -- "$DUMP" | cut -d ' ' -f 1)
curl --fail-with-body --request POST \
  --header "Authorization: Bearer $DBEV_TOKEN" \
  --header 'Content-Type: application/octet-stream' \
  --header "Content-Length: $SIZE" \
  --header 'X-DBEV-Filename: customer.postgres.sql' \
  --header "X-DBEV-SHA256: $SHA256" \
  --data-binary "@$DUMP" \
  "$DBEV_ORIGIN/api/instances/$INSTANCE_ID/import"
```

The response includes the daemon-computed hash and expiry:

```json
{
  "upload_id": "upl_0123456789abcdef0123456789abcdef",
  "instance_id": "cust-42-db",
  "original_filename": "customer.postgres.sql",
  "protocol": "postgres",
  "archive_format": "plain",
  "state": "ready",
  "size_bytes": 7340032,
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "created_at": "2026-08-10T12:00:00Z",
  "updated_at": "2026-08-10T12:00:01Z",
  "expires_at": "2026-08-11T12:00:00Z"
}
```

Catalog inspection is optional for a full import. It verifies the wrapper and
extracts bounded object metadata without booting the dump, executing SQL, or
returning row contents. Its `selective_supported` field is authoritative: show
selective controls only when it is true, and submit the exact `selection_key`
values returned in `catalog.objects`. SQL dumps can expose an object catalog
for preview, but uploaded formats that report no selective capability are full-import
only; the response explains why in `selective_unavailable_reason`. Inspection
is globally concurrency-limited. A `429` means retry later; a bounded timeout or
catalog resource ceiling returns `503` while leaving the upload ready for a
normal full import.

For MongoDB native archives, inspection also reads the bounded, published
archive prelude and returns source database candidates in `catalog.namespaces`.
It does not execute the archive or connect it to a database. When the catalog is
complete and non-empty, the panel should auto-fill a single candidate, offer an
explicit choice for multiple candidates, and reject a manually entered name
that is not listed. If discovery is empty or incomplete, keep the validated manual
`source_database` field available instead of guessing.

Queue the ready upload by ID. The archive wrapper is persisted by DBEV and
cannot be overridden by the client. MongoDB uploads use the original archive
database name as `source_database`; DBEV selects only that namespace and remaps
it to the target database. The field is rejected for other protocols:

```json
{
  "source": {
    "type": "upload",
    "upload_id": "upl_0123456789abcdef0123456789abcdef"
  },
  "mode": "merge"
}
```

MongoDB example:

```json
{
  "source": {
    "type": "upload",
    "upload_id": "upl_0123456789abcdef0123456789abcdef",
    "source_database": "legacy_tenant"
  },
  "mode": "wipe"
}
```

`source_database` is 1–63 UTF-8 bytes and follows MongoDB database-name
restrictions. If an inspected, complete catalog contains exactly one source
database, DBEV safely infers it when this field is omitted. Multiple candidates
require an explicit choice. An empty, incomplete, or unavailable catalog
requires a manual value. A provided value that contradicts a complete,
non-empty catalog returns `409` before DBEV queues a job or claims the upload.

The upload stays available while the panel modal is open. Closing or cancelling
the modal should call `DELETE`; merely navigating away does not count as a
successful import. A successful import consumes and deletes the upload and its
job has `artifact_id: null`. A failed import releases the upload for an explicit
retry or cancellation. Unused uploads expire after 24 hours by default and are
also reconciled after daemon restarts.

DBEV stores these files privately under
`paths.imports/<instance_id>/.uploads/` with managed names and restrictive
permissions. That directory is an implementation detail: it is never returned
as a host path, operator-staged files outside `.uploads` are not swept, and
temporary uploads never become downloadable artifacts.

## Import/export jobs

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

`GET /api/system/import-export-scheduler/recommendation` (scope
`system:read`) returns live active/waiting counts, configured resource budgets,
the modelled cost of a representative job, and a recommended active
concurrency. Query parameters are `protocol`, `action`, `size_bytes`,
`target_disk_mib`, `mode`, and `compressed`. `protocol` defaults to `postgres`,
`target_disk_mib` defaults to `size_bytes` rounded up to MiB, and
`action=export&mode=wipe` is rejected. MongoDB, Redis, Valkey, and Qdrant use
native compression and are modelled as compressed even when `compressed=false`.
Treat the result as a conservative planning model, not a measured throughput
guarantee. `recommended_active_jobs` may validly be `0` when current memory
capacity cannot safely fit one modelled job; display that as
blocked/unsafe and do not coerce it to `1`. Compressed logical imports
are charged at the configured prepared-data ceiling because their expansion
ratio is untrusted before bounded extraction. Redis, Valkey, and Qdrant
physical imports are instead charged at the target disk allocation, bounded by
the physical archive limit.

| Method | Path | Scope | What it does |
| --- | --- | --- | --- |
| POST | `/api/instances/{id}/export` | import-export:write | Queue an export |
| POST | `/api/instances/{id}/import` | import-export:write | Queue an import |
| GET | `/api/instances/{id}/import-export/jobs` | import-export:read | List that instance's jobs (`?status=&limit=`) |
| GET | `/api/instances/{id}/import-export/jobs/{job_id}` | import-export:read | One job, after ownership verification |

Export body (all optional): clients sending `Content-Type: application/json`
must serialize at least `{}`; a truly bodyless request is accepted only without
a JSON content type. Either form requests a full plain dump:

```json
{
  "archive_format": "gzip",
  "selection": { "mode": "selective", "include": ["table_a"], "exclude": [], "fields": {} }
}
```

`archive_format` is `plain`, `gzip`, or `bzip2`. Omit it for Redis, Valkey, and
Qdrant, whose exports are already physical archives. MongoDB's `plain` choice
already produces its native `.mongodb.archive.gz`; an explicit `gzip` choice is
normalized to `plain` rather than wrapping the native gzip stream a second time.

Export/import formats:

| Protocol | Export format | Import support |
| --- | --- | --- |
| PostgreSQL | `.postgres.sql` logical dump | Plain dump or gzip/bzip2/tar/zip-wrapped dump |
| MariaDB | `.mariadb.sql` logical dump | Plain dump or gzip/bzip2/tar/zip-wrapped dump |
| MySQL | `.mysql.sql` logical dump | Plain dump or gzip/bzip2/tar/zip-wrapped dump |
| MongoDB | `.mongodb.archive.gz` archive dump | Native gzip archive, or bzip2/tar/tar.gz/zip wrapper containing exactly one valid `.archive.gz` dump; upload imports use an auto-discovered or explicit original `source_database` for safe namespace remapping |
| ClickHouse | `.clickhouse.sql` logical dump | Plain dump or gzip/bzip2/tar/zip-wrapped dump |
| Redis | `.redis.tar.gz` physical archive | Full physical archive only |
| Valkey | `.valkey.tar.gz` physical archive | Full physical archive only |
| Qdrant | `.qdrant.tar.gz` physical archive | Full physical archive only |

Redis, Valkey, and Qdrant artifact exports are full physical volume archives and are not
selective. Remote Redis and Valkey imports copy binary-safe DUMP/RESTORE records; remote
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

For nonphysical imports, `merge` replaces source-named
objects/keys/collections and preserves target-only data; `wipe` clears the
target first. Redis, Valkey, and Qdrant artifact or upload imports are different:
those archives always replace the complete physical database, so `mode` does
not change their behavior. PostgreSQL, MariaDB, MySQL, MongoDB, and ClickHouse use their native
dump tools in a one-shot helper. Redis and Valkey use binary-safe
SCAN/DUMP/PTTL/RESTORE, and Qdrant uses collection snapshots.

Credential values are not stored in durable job records or job metadata.
PostgreSQL, MariaDB, MySQL, MongoDB, and ClickHouse acquisition writes the
required secret to a mode-`0600`, job-private temporary credential file, then
removes it immediately after the helper exits. After an unclean daemon stop,
startup removes known credential files and deletes generated staging that has
no durable recovery manifest; manifest-backed rollback data is retained.
Redis, Valkey, and Qdrant credentials remain in process memory. A failed
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
names are limited to 64 characters. Remote passwords and Qdrant API keys are
limited to 4,096 UTF-8 bytes so queued work cannot retain unbounded secrets. A
Qdrant `api_key` must also be a valid HTTP header value; invalid values are
rejected without echoing the secret. At most one credential-bearing remote job
is admitted per instance, and the node-wide admission/execution ceiling is
`security.remote_import.max_concurrent_jobs`.

MySQL and MariaDB logical imports structurally rebase qualified references from
the source database to the managed target database without changing quoted
strings, row data, or ordinary comments. MySQL object definers are rewritten
to the target tenant account; an unfamiliar or ambiguous dump form is rejected
instead of restoring a privileged or source-only definer.
ClickHouse likewise rebases structurally identifiable database-qualified table
and function references in its generated SQL; ambiguous qualified SQL is
rejected before the target is changed.

Shared-engine imports and placement migrations deliberately support the
portable tenant-data subset, not every engine-level object. PostgreSQL accepts
ordinary schemas, tables, sequences, types, indexes, views, and literal/COPY
data but rejects functions, procedures, extensions, foreign data, roles, and
grants. MySQL and MariaDB accept tables, indexes, tenant-owned views, and data
but reject routines, functions, triggers, events, global settings, and unsafe
or foreign definers. ClickHouse accepts the explicitly allowed local table
engines, ordinary views, and data but rejects materialized/live/window views,
distributed or external engines, and table-function sources or sinks. MongoDB
accepts ordinary collection data and safe indexes but rejects views, system
collections, cross-database namespaces, and code-bearing validator metadata.
Admission fails before target mutation when a dump contains one of these
objects. Existing unsupported objects also make destructive shared restores
fail closed when DBE cannot first prove that its rollback snapshot is complete.
Use `dedicated` mode when those database features are required.

Qdrant collection snapshots do not contain aliases, so DBE reads aliases
separately and migrates those attached to the selected source collections.
Source aliases win same-name conflicts; target aliases attached to untouched
collections are otherwise preserved. Alias changes are applied atomically, and
an update error triggers rollback of the exact pre-import target alias map
together with the collection snapshots. Recovery snapshots are retained if
automatic rollback cannot complete. Qdrant snapshot imports require the same
major and minor version; the target cannot have an older patch release than
the source.

Credential imports reject Redis/Valkey Cluster and distributed Qdrant endpoints.
SCAN and a Qdrant collection snapshot are node-local in those topologies and
could otherwise produce a silently partial migration. Use the database's
cluster-aware migration tooling or a verified standalone source instead.

Remote acquisition does not lock the source database. Quiesce source writes
when a single point-in-time migration is required, especially for MongoDB,
ClickHouse, Redis, Valkey, and multi-collection Qdrant imports. MongoDB selective
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

## Backups

| Method | Path | Scope | What it does |
| --- | --- | --- | --- |
| GET | `/api/instances/{id}/backups` | backups:read | List only that instance's backups |
| POST | `/api/instances/{id}/backups` | backups:write | Back up that instance now; returns the completed backup record |
| GET | `/api/instances/{id}/backups/{backup_id}/contents` | backups:read | List the stored schema catalog, or select one object's bounded captured row preview with `?object=&offset=&limit=` |
| POST | `/api/instances/{id}/backups/{backup_id}/restore` | recovery:admin | Restore the backup into its owning instance after explicit confirmation |
| DELETE | `/api/instances/{id}/backups/{backup_id}` | backups:write | Delete one owned backup |
| GET | `/api/admin/backups/status` | backups:admin | Node backup schedule and retention configuration |
| POST | `/api/admin/backups/run` | backups:admin | Back up every eligible instance; returns `backups` and `skipped` |

Backup list items retain `{id, instance_id, size_bytes, modified_at, sha256}`
and add `protocol` plus `layout`. `layout` is `physical` or `logical`.
Host paths and remote object keys are never returned. Every driver binds a
backup to its instance ID; a backup from one instance cannot be restored,
downloaded, browsed, or deleted through another instance's route.

Storage driver behavior:

- `local` atomically publishes the archive, catalog, and metadata under
  `paths.backups/<instance_id>/`. Archives must include the metadata sidecar
  required by the supported upgrade floor.
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

Example S3 selection (the full option set is in [`config/example.yml`](../../config/example.yml)):

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
configurable, truncated row preview. Redis, Valkey, and Qdrant are schema-less physical
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

## Letting users download files (temporary URLs)

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

## Artifact housekeeping

| Method | Path | Scope | What it does |
| --- | --- | --- | --- |
| GET | `/api/instances/{id}/artifacts` | artifacts:read | List that instance's export artifacts |
| DELETE | `/api/instances/{id}/artifacts/{artifact_id}` | artifacts:write | Delete one owned artifact |
| POST | `/api/instances/{id}/artifacts/retention` | artifacts:write | Apply retention to that instance only |

Artifact list items have the same path-free `{id, instance_id, size_bytes, modified_at, sha256}` shape as backups. New exports are stored under `paths.exports/<instance_id>/`.
User-provided temporary dumps are not artifacts, are never returned here, and
are governed by their upload TTL instead of artifact retention.

## Recovery

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
