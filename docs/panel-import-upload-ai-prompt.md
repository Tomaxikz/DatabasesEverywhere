# Panel implementation prompt: DBEV v0.5.1 temporary dump uploads

Copy the prompt below into the coding agent that owns the panel repository.

---

Implement the DatabasesEverywhere (DBEV) v0.5.1 temporary database-dump upload
flow in this panel, end to end. First inspect this repository's existing
instance authorization, node API client, import/export modal, job polling or
WebSocket code, CSRF handling, error components, and tests. Reuse those
patterns. Do not change DBEV itself and do not remove or regress existing
artifact and remote-source imports.

## DBEV compatibility

- `GET /api/system` is authoritative. Enable this feature only when
  `api_version` is semver-compatible with `>=0.11.0`.
- On older nodes, keep the current import UI and hide the PC-upload controls;
  do not issue speculative upload requests.
- If a nominally compatible node returns `404` or `415` for the new contract,
  mark the feature unavailable for that node for the current session and fall
  back to the old UI.
- Treat DBEV's OpenAPI document as the source of truth. Do not infer support
  from the daemon binary version alone.

## Security and request architecture

Never expose the DBEV node token to the browser. Add an authenticated,
CSRF-protected, instance-authorized panel backend route that proxies the file
to the already configured DBEV node. The browser-to-panel request should carry
the file as its raw `application/octet-stream` body, not JSON/base64 and not a
fully buffered multipart form. A browser `File`/`Blob` body lets the browser set
the request `Content-Length`; send the percent-encoded filename in a separate
panel header.

The panel backend must:

1. Resolve the target instance and DBEV node from trusted panel records. Never
   accept a node URL, filesystem path, or DBEV credential from the browser.
2. Verify the signed-in user can import into that exact instance before reading
   the body.
3. Require `application/octet-stream`, a positive exact body length, and a
   filename header. Reject unsupported sizes before opening the upstream
   request. Keep the panel/reverse-proxy maximum synchronized with the node's
   configured upload maximum.
4. Stream with backpressure directly to
   `POST /api/instances/{instance_id}/import`; do not call `bytes()`,
   `arrayBuffer()`, base64-encode, or retain a panel-side copy. Disable request
   decompression and automatic response/request retries.
5. Forward these DBEV headers:
   - `Content-Type: application/octet-stream`
   - `Content-Length`: exact raw-file byte count
   - `X-DBEV-Filename`: the original flat filename encoded as percent-encoded
     UTF-8, maximum 180 decoded bytes
   - `X-DBEV-SHA256`: optional, only when the panel already has a trustworthy
     lowercase 64-hex SHA-256 without buffering a large file
6. Use the existing server-side DBEV authorization header. Do not forward
   browser cookies, `Host`, forwarding headers, arbitrary content encodings,
   or arbitrary user headers to DBEV.
7. Propagate backpressure and cancellation in both directions. If the browser
   disconnects or cancels, abort the DBEV request immediately. Use bounded
   buffers and an upstream timeout slightly longer than the node's configured
   total upload timeout; do not use the panel's ordinary small JSON timeout.
8. Count bytes as they pass through when the framework permits it and fail on a
   browser length mismatch. DBEV independently rejects short/long bodies and
   computes the stored SHA-256.
9. Return only DBEV's safe JSON response and relevant status. Never log the
   body, DBEV bearer token, host storage path, or raw internal error. Preserve
   DBEV's `{ "error": string, "code": string, "error_id"?: string }` error
   contract and correlation ID.
10. Apply the panel's normal rate limiting and audit logging. Audit user,
    instance, node, declared size, result, and opaque upload ID; do not log a
    filesystem location.

If this stack cannot stream a browser body while supplying its exact length,
stop and report that limitation. Do not silently buffer multi-gigabyte files in
RAM. A mode-0600 bounded temporary spool with guaranteed cleanup is a last-resort
implementation and must be called out explicitly in the change summary.

## DBEV API contract

The existing import URL now has two request media types:

### Upload only

```http
POST /api/instances/{instance_id}/import
Content-Type: application/octet-stream
Content-Length: <exact bytes; required>
X-DBEV-Filename: <percent-encoded UTF-8 flat filename; required>
X-DBEV-SHA256: <optional 64 lowercase hex>
```

Send raw, unencoded dump bytes. `Content-Encoding` must be absent or `identity`.
The upload does not start an import. Success is `201 Created` with:

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

`catalog` and `error` are omitted when absent. `archive_format` and `sha256` can
be null in transitional records returned by list/get. Do not invent an
artifact ID for an upload.

### Upload lifecycle

```text
GET    /api/instances/{instance_id}/import/uploads
GET    /api/instances/{instance_id}/import/uploads/{upload_id}
POST   /api/instances/{instance_id}/import/uploads/{upload_id}/catalog
DELETE /api/instances/{instance_id}/import/uploads/{upload_id}
```

- List/get require DBEV scope `import-export:read`.
- Upload, catalog, delete, and import require `import-export:write`.
- Catalog inspection is lazy. It validates and inspects without executing dump
  contents and returns `200` with the updated upload record.
- Catalog inspection can return `429` when its small node-wide worker pool is
  busy, or `503` when bounded inspection times out/reaches a resource ceiling.
  In both cases the upload remains `ready` and full import remains available.
- Delete returns `200` with
  `{ "upload_id": "upl_...", "deleted": true }` and conflicts while an import
  owns the upload.
- Default expiry is 24 hours but is node-configurable. Expired records can
  disappear between requests; handle `404` normally.
- Temporary uploads are not artifacts and have no download endpoint.

The optional `catalog` has this shape:

```json
{
  "protocol": "postgres",
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "source_size_bytes": 7340032,
  "detected_archive_format": "plain",
  "selection_kind": "tables",
  "selective_supported": false,
  "catalog_complete": true,
  "namespaces": ["public"],
  "objects": [
    {
      "kind": "table",
      "name": "users",
      "namespace": "public",
      "selection_key": "public.users"
    }
  ],
  "unselectable_object_count": 0,
  "selective_unavailable_reason": "..."
}
```

Only `selective_supported` may enable selective controls. Never infer support
from protocol, extension, `selection_kind`, non-empty objects, or
`catalog_complete`. If support is true in a future DBEV version, submit exact
`selection_key` values; never construct SQL identifiers or regex filters in the
panel. In DBEV v0.5.1 all uploaded dump imports are full-only, although SQL
dumps may return an object catalog for preview. Display the server-provided
reason and keep the selection UI disabled.

### Queue the import

Use the same DBEV endpoint with JSON only after a `ready` upload exists:

```http
POST /api/instances/{instance_id}/import
Content-Type: application/json

{
  "source": {
    "type": "upload",
    "upload_id": "upl_0123456789abcdef0123456789abcdef"
  },
  "mode": "merge",
  "selection": { "mode": "full", "include": [], "exclude": [], "fields": {} }
}
```

For MongoDB only, require the user to provide the archive's original database
name and send it inside the upload source:

```json
{
  "source": {
    "type": "upload",
    "upload_id": "upl_0123456789abcdef0123456789abcdef",
    "source_database": "legacy_tenant"
  },
  "mode": "wipe",
  "selection": { "mode": "full", "include": [], "exclude": [], "fields": {} }
}
```

DBEV requires `source_database` for MongoDB uploads so it can select
`source_database.*` and remap it to the generated target database. It returns
`409` before queueing if the field is missing and `400` if it is supplied for
another protocol. Validate for fast feedback, but keep DBEV authoritative: 1–63
UTF-8 bytes and no NUL, `/`, `\\`, `.`, space, `"`, or `$`.

Do not send `archive_format` for an upload source; DBEV persists and validates
it. Success is `202 Accepted` with the normal import/export job and a relative
`Location` header. Resolve that URL only against the trusted DBEV origin on the
panel backend, or use the existing instance-scoped job route. For upload
imports, `artifact_id` and `artifact_size_bytes` remain null.

## Modal and UX behavior

Implement an explicit state machine rather than overlapping booleans:

```text
idle -> uploading -> ready -> inspecting -> ready
                         \-> queueing -> queued/running -> succeeded
                                                  \-> failed -> ready-for-retry
idle/uploading/ready -> cancelling -> closed
```

- File selection must validate the extension and displayed size locally for
  fast feedback, while treating DBEV validation as authoritative.
- Upload only after the user confirms. Show determinate browser-to-panel
  progress only if the HTTP client exposes real upload progress; otherwise show
  an honest indeterminate state. `100% sent` is not success until DBEV returns
  `201`.
- After `201`, show filename, formatted size, server hash, expiry, and `ready`
  state. Do not auto-start the import.
- Offer optional "Inspect contents" and show its bounded catalog. Keep the
  import button usable without catalog for a full import.
- Enable selective controls only from `catalog.selective_supported === true`.
  For v0.5.1, show the catalog as a read-only preview and submit full mode.
- If the user cancels after receiving an upload ID, call `DELETE` and wait for
  success before clearing it. If cancellation happens during streaming, abort
  the panel and DBEV requests; there may be no upload ID to delete.
- Closing a modal with a ready upload must either ask whether to discard it or
  leave a visible resumable entry backed by the list endpoint. Never silently
  claim it was deleted.
- Once import queueing returns `202`, do not call delete. Poll the returned job
  using the panel's existing job mechanism. On success, DBEV consumes and
  deletes the upload; remove it from the UI. On failure, DBEV returns it to a
  retryable ready state; offer Retry and Delete.
- Reconcile UI state with `GET .../uploads` when the modal opens and after a
  reconnect. Treat `404` as expired/already consumed and `409` as a real state
  conflict that requires refresh.
- Prevent duplicate Upload, Inspect, Import, and Delete clicks while each
  operation is active. Use stable opaque IDs as keys.

Give useful messages for `400` validation/hash/length errors, `404`
expired/consumed uploads, `408` stalled/timed-out uploads, `409` capacity or
lifecycle conflicts, `413` files that are too large, `415` wrong media
type/unsupported feature, `429` concurrency/rate limits, `503` bounded catalog
inspection exhaustion, and safe `500` errors with `error_id`. A `429`/`503`
catalog response must not disable full import. Never display or log a raw node
stack trace.

## Types

Add native types in this repository's language equivalent to:

```ts
type ImportUploadState =
  | "uploading" | "uploaded" | "processing" | "ready"
  | "failed" | "importing" | "consumed" | "deleting";

type ImportUpload = {
  upload_id: string;
  instance_id: string;
  original_filename: string;
  protocol: "postgres" | "redis" | "valkey" | "mariadb" | "mysql" |
    "mongodb" | "clickhouse" | "qdrant";
  archive_format: "plain" | "gzip" | "bzip2" | "tar" | "tar.gz" | "zip" | null;
  state: ImportUploadState;
  size_bytes: number;
  sha256: string | null;
  catalog?: DumpInspection;
  error?: string;
  created_at: string;
  updated_at: string;
  expires_at: string;
};

type UploadImportSource = {
  type: "upload";
  upload_id: string;
  source_database?: string; // required exactly when the target is MongoDB
};

type DumpInspection = {
  protocol: ImportUpload["protocol"];
  sha256: string;
  source_size_bytes: number;
  detected_archive_format: Exclude<ImportUpload["archive_format"], null>;
  selection_kind: "tables" | "collections" | "full_only";
  selective_supported: boolean;
  catalog_complete: boolean;
  namespaces: string[];
  objects: Array<{
    kind: "table" | "collection";
    name: string;
    namespace?: string;
    selection_key: string;
  }>;
  unselectable_object_count: number;
  selective_unavailable_reason?: string;
};
```

## Required tests

Add focused unit/integration tests for:

- API-version feature gating and the older-node fallback.
- Instance authorization and CSRF rejection before the upload body is read.
- Streaming a file larger than the panel's ordinary JSON limit without loading
  it wholly into memory; verify chunks/backpressure reach a mock DBEV server.
- Exact forwarding of content type, length, percent-encoded UTF-8 filename,
  optional hash, instance ID, and server-side DBEV authorization.
- Rejection of zero/unknown/oversized lengths, path-like filenames, malformed
  encoding, unsupported extensions, and arbitrary upstream URLs/headers.
- Browser abort propagating upstream and no automatic retry of a partial POST.
- `201` means uploaded but does not queue an import.
- Catalog loading, cached display, `selective_supported: false`, and no way to
  submit selective mode in v0.5.1.
- JSON import uses `source.type = "upload"`, sends no archive override, accepts
  `202`, and polls the instance-scoped job.
- MongoDB upload import requires and forwards `source_database`; other
  protocols omit it. Cover missing-Mongo (`409`), invalid-name (`400`), and
  non-Mongo-with-field (`400`) responses.
- Cancel-before-import calls delete; successful import does not; failed import
  offers retry/delete; `404`, `408`, `409`, `413`, `415`, and `429` refresh or
  message correctly.
- Modal close/reopen reconciliation via the upload-list endpoint and expiry.
- No temporary upload appears in artifact history or artifact download UI.

Run this repository's formatter, type checker, linter, unit tests, and relevant
integration tests. Finish with a concise list of changed files, the exact test
commands/results, any reverse-proxy size/timeout setting operators must update,
and confirmation that large files are streamed rather than buffered.

---
