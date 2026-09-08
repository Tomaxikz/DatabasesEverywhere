# CI and local checks

Run on Linux/WSL with the pinned Rust toolchain:

```bash
bash .github/ci/check.sh pre-push
```

This runs formatting, strict Clippy, source-size checks, and workspace tests.
Use `lint`, `test`, or `audit` instead of `pre-push` for individual checks.
To enable the pre-push hook:

```bash
chmod +x .githooks/pre-push
git config core.hooksPath .githooks
```

## GitHub Actions

Require the final `CI gate` in branch rules. [CI](../workflows/ci.yml) defines
the check matrix; [release](../workflows/release.yml) independently validates
versions and repeats required checks before publishing. Release runs are serialized.
Protect the `production-release` environment with reviewers and main/version-tag refs.

The [Linux build workflow](../workflows/build-binaries.yml) handles architecture packaging.
Use the workflows as the source for tool versions, matrices, and deadlines.

## Real database tests

Requires Linux, Docker, Maven, JDK 21, and OpenSSL:

```bash
bash .github/ci/mysql-driver-matrix.sh mysql mysql:8.4 26.7.0
```

The [matrix](../workflows/mysql-driver-matrix.yml) is shared by CI and release.
It checks CLI/JDBC/Hikari, explicit/deferred catalogs, and TLS.

## Shared-pool isolation

Gateway checks need no Docker:

```bash
cargo test --locked --lib gateway::
```

For real PostgreSQL, MySQL, MariaDB, MongoDB, and ClickHouse tenants:

```bash
bash .github/ci/shared-pool-isolation.sh postgres
bash .github/ci/shared-pool-isolation.sh all
```

These cover tenant isolation and backup/restore with peer-data preservation.
Local `all` runs sequentially; cleanup targets managed test containers only.
The [workflow](../workflows/shared-pool-isolation.yml) runs weekly/manually,
**not as an ordinary push/release gate**.

For Docker-free provisioning checks with an official ClickHouse 26.4+ binary:

```bash
DBE_CLICKHOUSE_BINARY=/path/to/clickhouse cargo test --locked --lib \
  databases::clickhouse::integration_tests::shared_sql_executes_and_reapplies_on_clickhouse_local \
  -- --exact --ignored
```

This checks SQL execution/reapplication, preserved table data, and access cleanup
in `clickhouse local`, with no listeners or live data. It does not test gateway auth.
Older binaries can use `shared_sql_parses_on_clickhouse` with the same prefix
for syntax only. `hosted_console_config_removes_inherited_file_logging` uses the
same binary variable to test the actual config merge without starting a server.

## FuseQuota mounts

Requires Linux, `/dev/fuse`, and `fusermount3`:

```bash
cargo test --locked --lib --no-run
sudo /path/to/the/printed-test-binary \
  disk::fuse_quota::tests::mounted_helper_enforces_quota_and_reuses_process \
  --exact --ignored
```

Uses disposable data to check append/sync integrity, quota rejection/recovery,
safe helper reuse, and refusal to remount unsafe helpers beneath open files.
Excluded from ordinary CI.

## Native project quotas

Use a disposable Linux host with passwordless sudo, loop/mount privileges,
the pinned Rust toolchain, `xfsprogs`, `e2fsprogs`, and `quota`:

```bash
bash .github/ci/project-quota-smoke.sh xfs
bash .github/ci/project-quota-smoke.sh ext4
```

The [weekly/manual workflow](../workflows/project-quota-smoke.yml) checks
adoption, isolation, accounting, exhaustion, resize, and cleanup, temporarily
backing up/restoring XFS project files. Optional `f2fs` needs kernel support
and `f2fs-tools`; use `all` for every backend.

## Release notes

Empty `release_notes` uses generated notes. To supply a local Markdown file:

```bash
gh workflow run release.yml --ref main -f version=vX.Y.Z \
  -F release_notes=@CHANGELOG.md
```

The version must match Cargo.toml. The notes file need not be committed.
