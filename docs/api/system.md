# System and monitoring endpoints

[Documentation index](../README.md)

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
endpoints offline. A daemon restart does not stop database containers or unmount
healthy FuseQuota filesystems. Shutdown closes mutation admission, gives active
API and daemon-owned mutations up to three minutes, and durable jobs or creations up to three minutes
to finish, and then bounds API connection draining to 10 seconds. WebSockets
receive close code 1012, while database gateway connections get a five-second
natural drain followed by a two-second forced proxy close. A long-lived client
therefore cannot hold `systemctl restart` open indefinitely.
Heartbeat reports management API liveness only. It always returns
`{"status":"ok"}` once an authenticated request reaches the handler, regardless
of database instance or gateway state. Clients should use each instance's status
for instance readiness and `/api/system.gateways` for listener startup state.
Heartbeat uses a dedicated bounded concurrency pool, so saturation by ordinary API
requests cannot consume its admission capacity. Non-streaming handler execution is
bounded to 15 minutes; request-body streaming retains its separate body/upload deadlines.
Database gateways open after background startup and legacy PostgreSQL role
hardening complete.

Successful PostgreSQL and MySQL authentication hardening is recorded only in
DBEV's private SQLite metadata. The attestation is bound to the owned runtime's
full container ID, Docker/Podman start generation, a keyed fingerprint of the
current protected credentials and route identity, and DBEV's internal
hardening revision. A daemon-only restart can therefore skip repeat database
mutation and authentication probes for an unchanged running container. A real
container restart, replacement or image upgrade, a password or route change,
a missing/corrupt attestation, or a future hardening revision automatically
forces the complete fail-closed hardening flow again. Attestations contain no
plaintext passwords, are never returned by the API, and are deleted with their
instance metadata. Failure to read or write this optimization never bypasses
hardening: DBEV runs the full check and merely retries attestation persistence
on a later successful pass.

Config patches are JSON object merges against the current config. `null` removes a key. The daemon rejects edits to `uuid`, `token_id`, `token`, `jwt_signing_key`, managed paths, container images, the S3 endpoint, executable backup helpers, and the Fuse helper path/digest. Replacing or nulling an ancestor of any protected field is rejected as well. Those security boundaries must be changed deliberately in the host config. A successful patch writes the config file only — restart the daemon before expecting listener, TLS, or other permitted runtime changes to take effect.

API-triggered self-upgrade is intentionally unsupported: accepting an executable and its digest from the same administrative request does not provide an independent trust anchor. Keep `security.self_upgrade_enabled: false` and deploy signed packages or immutable, digest-pinned container images through the host's normal rollout mechanism.

Instances created by older builds with a bridge-network or `docker_tcp` backend are deliberately not converted in place. Startup stops and marks them `quarantined`, because changing a live container's network and entrypoint cannot be made atomic and DBE intentionally does not retain every tenant's plaintext credential. Preserve or export any required data offline, explicitly delete the quarantined instance, then recreate it and import the artifact. The gateway refuses legacy TCP metadata even before reconciliation, so it cannot silently reopen the old path.

If a legacy database contains duplicate route identities, startup preserves the deterministic first claimant and marks every other claimant `quarantined`. Quarantined containers are stopped before gateways open and cannot be started or restarted; their metadata and data remain available for inspection and explicit deletion.

An unclean daemon exit while an import/export job is durably `running` also quarantines the affected instance on the next startup. The container is stopped before gateways open, preventing a possibly orphaned dump or restore process from racing new work. Queued jobs that never started are marked failed without quarantining their instances. Inspect the failed job and database integrity, then recover or repair the quarantined instance offline.

Physical restores keep the previous data in a private sibling workspace until the replacement validates. Startup performs a bounded, non-symlink-following scan for retained generated restore workspaces and quarantines the matching instance before reconciliation, even if the job record was already made terminal.

If creation cleanup was interrupted, a normal retry fails closed rather than reusing orphaned files with new credentials. After preserving any required data, retry the create request with `"purge_stale_resources": true` to explicitly and irreversibly remove that instance ID's orphaned container and paths before creation.

Import/export admission is bounded by
`artifacts.import_export_scheduler.max_queued_jobs` node-wide (1,024 by
default) and
`max_queued_jobs_per_instance` per instance. Active execution is separately
bounded by the weighted dynamic scheduler or `manual_max_active_jobs`. The
in-memory status cache retains at most 2,048 completed jobs, and SQLite retains
the latest 10,000 completed records; queued/running records are never pruned.
