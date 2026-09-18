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

Change the module that owns the behavior; avoid duplicate implementations and
forwarding modules. Keep focused tests beside the code and real-driver fixtures
in `tests/real_drivers/`. Keep routes and OpenAPI in sync.

When moving files, update compile-time inclusions, CI/Docker paths, and links.
Rust source files are limited to 1,500 lines.
