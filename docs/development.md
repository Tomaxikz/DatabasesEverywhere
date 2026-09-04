# Development

## Repository layout

```text
src/
  main.rs                 Process entry point
  app/
    mod.rs                Library module root
    api/
      http/               Routing, request limits, auth policy, errors, tracing
      instances/          Creation, lifecycle, credentials, images, migration
      monitoring/         Resource endpoints, activity, WebSockets, WS tokens
      import_export/      Uploads, inspection, restore, remote imports, recovery
      artifacts/          Artifact access and temporary downloads
      backups.rs          Backup HTTP handlers
      system/             Node information and configuration endpoints
    auth/                 Tokens and scopes
    cli/                  Commands, daemon startup, recovery, background tasks
    config/               Configuration loading and validation
    databases/            Engine-specific provisioning and container setup
    protocols/            Wire parsing and protocol compatibility tests
    gateway/              Connections, routing, TLS, and tenant sessions
    instances/            Instance metadata, state, locks, and reconciliation
    placement/            Shared pools, tenants, placement, and migration state
    jobs/                 Job scheduling and execution support
    monitoring/           Activity storage and engine-level collection
    backups/              Backup catalog and storage drivers
    disk/                 Disk measurement and quota enforcement
    runtime/              Container runtime and socket bridge integration
    storage/              SQLite repositories and encrypted secrets
    compatibility/        Installed database version/capability detection
    shared/               Small cross-cutting utilities
    bins.rs               Embedded helper payload handling
    constants/            Shared constants
    bench/                Node benchmarking commands
```

The two monitoring directories have different roles: `app/monitoring`
collects and stores activity; `app/api/monitoring` exposes it to clients.
Similarly, `app/instances` owns instance state while `app/api/instances`
handles API-driven operations.

Other directories:

- `config/`: example node configuration.
- `deploy/docker/`: Dockerfile and Compose deployment.
- `docs/api/`: API guides and the OpenAPI contract.
- `docs/operations/`: operator setup, quotas, and benchmarks.
- `migrations/`: ordered SQLite schema migrations.
- `helpers/`: helper source, packed payloads, and build instructions.
- `tools/`: Rust workspace tools for helper packing and release builds.
- `tests/`: API contract tests and real-driver integration fixtures.
- `.github/ci/`: shared checks and integration-test runners.
- `.github/workflows/`: CI and release orchestration.

`target/`, `dist/`, `.local/`, local virtual environments, and scratch
scripts are generated or local-only content, not application source.

## Contributing

Change the module that owns the behavior. Keep focused tests beside it and
real-driver fixtures in `tests/real_drivers/`. Avoid forwarding modules and
duplicate implementations. Routes and schemas belong in the router and
[OpenAPI contract](api/openapi.yml).

When moving files, update compile-time inclusions, CI/Docker paths, and links.
Rust source files are limited to 1,500 lines.

## Checks and builds

Run from the repository root on Linux or WSL:

```bash
bash .github/ci/check.sh pre-push
```

This runs formatting, strict Clippy, source-size checks, and workspace tests.
Unit and API contract tests need no running database; ignored integration
tests need external services. See [CI checks](../.github/ci/README.md) for
individual checks and real-driver runners.

A release build is separate from validation:

```bash
cargo build --release --locked
```

The `cargo b` alias runs the workspace's
[release builder](../tools/release-builder/src/main.rs) for cross-release
packaging. It is not a substitute for Linux tests.
