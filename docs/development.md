# Development

## Build and test

Run from the repository root on Linux or WSL with the pinned Rust toolchain:

```bash
cargo install --locked cargo-machete --version 0.9.2
bash .github/ci/check.sh pre-push
cargo build --release --locked
```

The check script runs unused-dependency detection, formatting, strict Clippy,
source-size checks, and workspace tests. The build creates `target/release/dbev`;
a build alone does not run tests. External-service tests are opt-in; see
[CI checks](../.github/ci/README.md).

For cross-release packaging, `cargo b` runs the workspace's
[release builder](../tools/release-builder/src/main.rs).

## Repository layout

| Path | Contents |
| --- | --- |
| `src/main.rs` | Process entry point |
| `src/app/` | Daemon code, grouped by API, engine, gateway, storage, and runtime |
| `src/app/cli/` | Argument parsing, command dispatch, and process umask |
| `src/app/daemon/` | Startup, host setup, maintenance, listeners, recovery, and shutdown |
| `src/app/state.rs` | Application composition, shared resources, and mutation draining |
| `src/app/api/http/` | Route wiring and shared HTTP policy/error adapters |
| `config/`, `deploy/` | Example configuration and deployment files |
| `docs/api/` | Integration guides and [OpenAPI](api/openapi.yml) |
| `migrations/` | SQLite schema migrations |
| `helpers/`, `tools/` | Embedded helpers and build tools |
| `tests/` | Contract tests and real-driver fixtures |
| `.github/` | CI scripts and workflows |

`target/`, `dist/`, `.local/`, and virtual environments are generated/local-only.

## Subsystem boundaries

The layout follows the same separation of transport, managed resources, and
runtime capabilities used by [Calagopus Wings](https://github.com/calagopus/wings/tree/34a1fe19ff30f273cac948b64b72e6d4f1cc4c63/application/src),
without copying its game-server-specific modules or adding unnecessary crates.

- `cli` parses user input and dispatches commands; `daemon` owns process services
  and their startup/shutdown ordering. Daemon services do not depend on CLI parsing.
  `daemon::services::BackgroundServices` owns maintenance and lifecycle task
  handles. Shutdown closes admission before aborting maintenance and draining
  lifecycle work; managed database containers are not stopped by daemon shutdown.
- `api` groups HTTP handlers by resource (`instances`, `pools`, `backups`, etc.).
  `api/http/router.rs` wires endpoints and middleware; `state.rs` owns application
  composition, shared resources, and mutation-drain coordination. Shared HTTP error adapters
  belong in `api/http/response.rs`, not in another resource's provisioning handler.
- `instances` owns instance metadata and coordination; `placement` owns dedicated
  and shared runtime placement, tenant lifecycle, and migration state.
- `runtime` owns container-engine interaction; `databases` and `protocols` own
  engine-specific operations and wire protocols. `gateway` owns ingress routing.
- `storage`, `backups`, `disk`, `jobs`, and `monitoring` retain their existing
  persistence, backup, quota, scheduling, and measurement responsibilities.

Keep behavior with its owner and expose only the capabilities callers need.
New code should import application state from `crate::state`; the previous
`api::http::state` and `api::http::router` exports remain available for library
compatibility. `AppState` is a composition object for handlers and coordinators,
not a backend interface. Backends receive the specific resources they need.

### Backend contracts and ownership

Subsystem facades own policy and orchestration; private backends implement the
variable engine or provider behavior. Traits are used at real interchangeable
boundaries, not as a mandatory wrapper around every module.

| Subsystem | Contract / entry point | Responsibility kept outside the backend |
| --- | --- | --- |
| Backups | `backups::drivers::BackupDriver`, selected by `BackupStorage` | ID validation, inventory sorting, materialization guards and cancellation ownership |
| Shared tenants | `placement::tenant::backends::TenantBackend` | Credential-validation order, verified reopening/refencing, strict storage-result validation |
| Engine telemetry | `monitoring::engine::backends::EngineTelemetry` | Tenant identity/generation checks, backoff, accounting baselines, committing successful checkpoints |
| Shared-pool safety | `placement::containment` | One fencing/quarantine/verified-stop sequence shared by HTTP and boot recovery |
| Soft disk enforcement | Existing `disk::soft::SoftDiskRuntime` | Scanning and quota policy remain owned by `disk::soft` |
| Import/export scheduling | Existing `SchedulerResourceProvider` | Queue admission, resource budgets, and job lifecycle remain owned by the scheduler |
| Output disk capacity | `disk::capacity::DiskCapacityService` | One reservation ledger shared by uploads, staging, and backups; HTTP error mapping remains in the upload adapter |

The new backend traits are internal. HTTP routes, JSON models, configuration,
public backup provider methods, and persisted metadata do not change. Async
backend calls return borrowed `Send` futures; they do not spawn independent
workers or transfer cleanup ownership just to implement an interface.

For a new provider, implement the relevant contract and register it in that
subsystem's selector. Test successful operations, rejected inputs, and failure
semantics through the facade. Engine-specific capabilities stay explicit:
PostgreSQL catalog hardening, MySQL rollback inspection, ClickHouse telemetry
windows, and backup materialization/purging must not become generic no-op
defaults. Unsupported shared engines continue to return errors.

This is an incremental architecture: API modules still contain some application
workflows and `AppState` still composes HTTP services. Move those workflows to
their owning subsystem when changing them; do not make lower-level providers
depend on HTTP response types or add a universal `Subsystem` trait. Container
runtime, storage repositories, gateway protocols, and configuration already have
concrete subsystem interfaces and do not need artificial alternate backends.
Resource monitoring and instance progress remain in their existing API modules
for now. Capacity accounting still calls the existing host-disk sampler; moving
that sampler and the remaining workflow services is a follow-up migration.

## Contributing

### Adding configuration and shared runtime limits

`config::Config` is the serializable YAML model. The daemon constructs one
`Arc<config::RuntimeConfig>` around it and shares that object through `AppState`
and gateway sessions. Ordinary settings remain accessible as
`state.config.daemon.some_setting`; `snapshot()` returns only the immutable YAML
settings for background jobs or serialization.

For a new setting, define its field/default in `config/mod.rs` and read it in the
consumer. Admission settings under `daemon.limits` keep their fields, defaults,
validation, and shared-budget construction together in `config/limits.rs`.
Other daemon-limit validation belongs in `DaemonConfig::validate_runtime_limits`.
When an admission setting controls a shared semaphore, construct it in
`RuntimeLimits::shared_budgets`; `RuntimeConfig` owns the result once per daemon.
Consumers clone the resource's `Arc`, not a new semaphore. Do not add a separate
process static, per-limit daemon initializer, or test-only global setup.

Tests can construct independent `RuntimeConfig` objects with small capacities;
multiple consumers of the same object must still share its allowance. Keep
config/behavior tests and example YAML in sync. Config changes remain
restart-required: editing YAML does not replace live semaphores or invalidate
existing reservations.

### Code changes

Change the module that owns the behavior; avoid duplicate implementations and
forwarding modules. Keep focused tests beside the code and real-driver fixtures
in `tests/real_drivers/`. Keep routes and OpenAPI in sync.

When moving files, update compile-time inclusions, CI/Docker paths, and links.
Rust source files are limited to 1,500 lines.
