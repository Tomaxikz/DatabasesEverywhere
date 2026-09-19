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
| `src/app/api/http/` | Route wiring, application state, and shared HTTP policy/error adapters |
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
- `api` groups HTTP handlers by resource (`instances`, `pools`, `backups`, etc.).
  `api/http/router.rs` wires endpoints and middleware; `api/http/state.rs` owns
  shared request state and mutation-drain coordination. Shared HTTP error adapters
  belong in `api/http/response.rs`, not in another resource's provisioning handler.
- `instances` owns instance metadata and coordination; `placement` owns dedicated
  and shared runtime placement, tenant lifecycle, and migration state.
- `runtime` owns container-engine interaction; `databases` and `protocols` own
  engine-specific operations and wire protocols. `gateway` owns ingress routing.
- `storage`, `backups`, `disk`, `jobs`, and `monitoring` retain their existing
  persistence, backup, quota, scheduling, and measurement responsibilities.

Keep behavior with its owner and expose only the capabilities callers need.
New code should import application state from `api::http::state`; the previous
`api::http::router` exports remain available for library compatibility.

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
