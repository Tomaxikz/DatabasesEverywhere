# CI and local checks

DBEV is Linux-only. Run tests on Linux/WSL, not just a Windows cross-build.

```bash
bash .github/ci/check.sh pre-push
```

This runs formatting, strict Clippy, the Rust source-size check, and workspace
tests. To enable it as this clone's pre-push hook:

```bash
chmod +x .githooks/pre-push
git config core.hooksPath .githooks
```

## GitHub Actions

Global lint gates the parallel audit, unit/contract tests, driver tests,
Podman, documentation, CodeQL, and release-architecture builds.
Require the final `CI gate` status in branch rules.

[Release publication](../workflows/release.yml) independently validates the
version, repeats required checks/builds, and publishes only after success.
Release runs are serialized. Configure the `production-release` environment
with reviewers and protected main/version-tag deployment refs.

Binary builds use the reusable [Linux build workflow](../workflows/build-binaries.yml).
Consult the workflows for current matrices, tool versions, and deadlines rather
than duplicating those values here.

## Real database tests

Prerequisites: Linux, Docker, Maven, JDK 21, and OpenSSL.

```bash
bash .github/ci/mysql-driver-matrix.sh mysql mysql:8.4 26.7.0
```

The canonical image/connector cases are in
[mysql-driver-matrix.yml](../workflows/mysql-driver-matrix.yml), shared by CI
and release. They test CLI/JDBC/Hikari, explicit/deferred catalogs, and TLS.
Compilation and bounded runtime execution are separate steps.

## Shared-pool isolation

The weekly/manual [shared isolation workflow](../workflows/shared-pool-isolation.yml)
tests PostgreSQL, MySQL, MariaDB, MongoDB, and ClickHouse independently.
It is not part of ordinary push/release gating.

```bash
bash .github/ci/shared-pool-isolation.sh postgres
bash .github/ci/shared-pool-isolation.sh all
```

Local `all` runs sequentially. Cleanup is restricted to managed test containers.

Without Docker, an official ClickHouse 26.4+ binary can execute the shared
provisioning SQL in an isolated `clickhouse local` process (no listeners or live data):

```bash
DBE_CLICKHOUSE_BINARY=/path/to/clickhouse cargo test --locked --lib \
  databases::clickhouse::integration_tests::shared_sql_executes_and_reapplies_on_clickhouse_local \
  -- --exact --ignored
```

This checks creation, role/profile/quota reapplication, preserved table data and
access-entity cleanup. It does not replace Docker/gateway authentication tests.
For older binaries without local access storage, run `shared_sql_parses_on_clickhouse`
instead with the same test-module prefix. That checks syntax only.

`hosted_console_config_removes_inherited_file_logging` uses the same binary
environment variable to verify ClickHouse's actual config merge for dedicated
and shared engines, without starting a server or touching database data.

## FuseQuota mounts

The FuseQuota mount test runs the embedded helper against disposable data on
Linux. It checks concurrent read/write integrity, quota rejection, deletion
recovery, and updating a healthy mount without restarting its helper:

```bash
cargo test --locked --lib --no-run
sudo /path/to/the/printed-test-binary \
  disk::fuse_quota::tests::mounted_helper_enforces_quota_and_reuses_process \
  --exact --ignored
```

It requires `/dev/fuse` and `fusermount3`; it is excluded from ordinary CI.

## Native project quotas

Run only on a disposable Linux host with passwordless sudo, loop/mount
privileges, the pinned Rust toolchain, `xfsprogs`, `e2fsprogs`, and `quota`:

```bash
bash .github/ci/project-quota-smoke.sh xfs
bash .github/ci/project-quota-smoke.sh ext4
```

The [weekly/manual workflow](../workflows/project-quota-smoke.yml) verifies
real DBEV quota adoption, isolation, accounting, exhaustion, resize, and cleanup.
It temporarily backs up/restores XFS project files. F2FS is optional and also
needs kernel support and `f2fs-tools`; request `f2fs` or `all`.

## Release notes

An empty `release_notes` input uses generated notes. For a local multiline file:

```bash
gh workflow run release.yml --ref main -f version=vX.Y.Z \
  -F release_notes=@CHANGELOG.md
```

The notes file need not be committed.
