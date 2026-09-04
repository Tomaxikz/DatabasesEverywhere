# Local CI

DBEV is Linux-only, so the complete test suite must execute under Linux rather
than only being cross-compiled from Windows.

From a WSL2/Linux checkout, run:

```bash
bash .github/ci/check.sh pre-push
```

To make that check automatic for this clone:

```bash
chmod +x .githooks/pre-push
git config core.hooksPath .githooks
```

The hook runs formatting, strict Clippy, and the complete test suite for the
daemon and both tool crates in one locked Cargo workspace. A failed check stops
the push. Git's `--no-verify` option remains available for an intentional
emergency bypass.

GitHub Actions uses `Global lint` as its fast fail gate. After it passes,
dependency auditing, Linux tests, the real MySQL driver matrix, rootless Podman,
documentation, CodeQL, and all three release-architecture builds run in
parallel. The final `CI gate` requires every branch to succeed. The binary
builds have one canonical reusable workflow and use Zig/cargo-zigbuild with a
glibc 2.35 floor, so CI never downloads cross-compilers through Ubuntu mirrors.

The driver matrix runs each official MySQL
8.4/9.7/26.7 and MariaDB 10.11/11.4/11.8/12.3 image/connector combination in
an isolated parallel job. It exercises MariaDB CLI, Connector/J 8.4/9.2/9.7,
MariaDB Connector/J, HikariCP, database-qualified and deferred-catalog
connections, and standard CLIENT_SSL. Each case is compiled before its own
12-minute runtime deadline begins and has a 20-minute total job deadline, so a
stuck external client cannot consume the former one-hour serial matrix timeout.
Configure the `main` branch ruleset to require the single `CI gate` status.

The release workflow independently repeats locked lint/tests, dependency
auditing, real-driver coverage, and binary builds after validating its version.
Those independent jobs run in parallel, but neither GitHub releases nor Docker
images can publish until every validation and build succeeds. Release runs are
serialized so two production publications cannot overlap.

To run one driver case on a Linux host with Docker, Maven, JDK 21, and OpenSSL
installed:

```bash
bash .github/ci/mysql-driver-matrix.sh mysql mysql:8.4 9.7.0
```

The MariaDB CLI runs from an official MariaDB container with host networking:
the tested image for MariaDB cases and `mariadb:11.4` for MySQL cases. CI
therefore does not depend on Ubuntu package mirrors or mutate each ephemeral
runner with `apt-get`.

The complete case list has one canonical definition in
`.github/workflows/mysql-driver-matrix.yml`; CI and release both call that
reusable workflow.

## Shared-pool isolation tests

The real two-tenant isolation suite is intentionally separate from ordinary
push, pull-request, lint, release-build, and release-publication jobs. A weekly
`Shared-pool tenant isolation` workflow runs PostgreSQL, MySQL, MariaDB,
MongoDB, and ClickHouse in independent bounded jobs. The same workflow can be
started manually for all engines or one selected engine.

Run one case on a Linux/WSL2 host with Docker available:

```bash
bash .github/ci/shared-pool-isolation.sh postgres
```

Run all five sequentially, avoiding five database engines competing for local
memory at once:

```bash
bash .github/ci/shared-pool-isolation.sh all
```

Each case uses the production container specification and canonical tenant
lifecycle functions, pulls its version-tagged engine image through DBEV, has a
12-minute execution deadline, and removes only DBEV-managed test containers
whose instance label starts with `shared_it_<protocol>_`.

## Native project-quota smoke tests

Native per-tenant disk enforcement has its own weekly and manually dispatchable
`Native project-quota smoke` workflow. It is intentionally separate from normal
lint, unit, pull-request, release-build, and publication jobs because it needs
root and disposable loopback mounts. XFS and ext4 are required cases. F2FS runs
when both the hosted kernel and installed tools support a project-quota mount;
an unsupported F2FS runner is reported as a notice rather than weakening the
required XFS/ext4 result.

The smoke test calls DBEV's canonical `DiskLimiter` path-quota methods rather
than invoking quota tools as a substitute for application coverage. For each
filesystem it verifies adoption of pre-existing data, independent project IDs
for two tenants, a real `EDQUOT` at tenant A's boundary, kernel-accounted usage,
an in-place limit increase, tenant A clear and permanent ID tombstone, and that
tenant B's writes, limit, accounting, and claim survive tenant A exhaustion and
cleanup. Each filesystem case has a six-minute deadline and the workflow has a
25-minute deadline.

Run it on a disposable Linux host with passwordless `sudo`, loop-device and
mount privileges, Rust 1.95.0, `xfsprogs`, `e2fsprogs`, and `quota` installed:

```bash
bash .github/ci/project-quota-smoke.sh xfs
bash .github/ci/project-quota-smoke.sh ext4
```

Install `f2fs-tools` and use `f2fs` or `all` to request the optional F2FS case.
The runner temporarily backs up and restores `/etc/projects` and `/etc/projid`
for XFS and mounts only images created in a private temporary directory.

## Release notes

GitHub generates release notes automatically when the optional `release_notes`
input is empty. GitHub's web form renders workflow string inputs on one line;
to provide a complete multiline Markdown body without committing a notes file,
use the GitHub CLI:

```bash
gh workflow run release.yml --ref main -f version=vX.Y.Z \
  -F release_notes=@CHANGELOG.md
```

`CHANGELOG.md` may be any local file and does not need to be committed.
