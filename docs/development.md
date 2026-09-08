# Development

## Build and test

Run from the repository root on Linux or WSL with the pinned Rust toolchain:

```bash
bash .github/ci/check.sh pre-push
cargo build --release --locked
```

The first command runs formatting, strict Clippy, source-size checks, and
workspace tests. The second builds `target/release/dbev`; a build alone does
not run tests. External-service tests are opt-in; see [CI checks](../.github/ci/README.md).

For cross-release packaging, `cargo b` runs the workspace's
[release builder](../tools/release-builder/src/main.rs).

## Repository layout

| Path | Contents |
| --- | --- |
| `src/main.rs` | Process entry point |
| `src/app/` | Daemon code, grouped by API, engine, gateway, storage, and runtime |
| `config/`, `deploy/` | Example configuration and deployment files |
| `docs/api/` | Integration guides and [OpenAPI](api/openapi.yml) |
| `migrations/` | SQLite schema migrations |
| `helpers/`, `tools/` | Embedded helpers and build tools |
| `tests/` | Contract tests and real-driver fixtures |
| `.github/` | CI scripts and workflows |

`target/`, `dist/`, `.local/`, and virtual environments are generated/local-only.

## Contributing

Change the module that owns the behavior; avoid duplicate implementations and
forwarding modules. Keep focused tests beside the code and real-driver fixtures
in `tests/real_drivers/`. Keep routes and OpenAPI in sync.

When moving files, update compile-time inclusions, CI/Docker paths, and links.
Rust source files are limited to 1,500 lines.
