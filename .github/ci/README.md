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

The hook runs formatting, strict Clippy, the explicit Linux-target check, and
the complete test suite for both the daemon workspace and the separately
locked static-helper packer. A failed check stops the push. Git's `--no-verify`
option remains available for an intentional emergency bypass.

GitHub Actions runs `Global lint` first. Only after it passes do dependency
auditing, Linux tests, the real MySQL driver matrix, documentation checks,
CodeQL, and the release build run. The driver matrix runs each official MySQL
8.4/9.7/26.7 and MariaDB 10.11/11.4/11.8/12.3 image/connector combination in
an isolated parallel job. It exercises MariaDB CLI, Connector/J 8.4/9.2/9.7,
MariaDB Connector/J, HikariCP, database-qualified and deferred-catalog
connections, and standard CLIENT_SSL. Each case is compiled before its own
12-minute runtime deadline begins and has a 20-minute total job deadline, so a
stuck external client cannot consume the former one-hour serial matrix timeout.
Configure the `main` branch ruleset to require the single `CI gate` status;
that gate fails when any required stage fails or is skipped.

The release workflow independently repeats the locked lint and test gate and
audits both Cargo lockfiles before it builds publishable artifacts. A release
therefore cannot rely on a separate CI run that is still pending or failed.

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

## Release notes

GitHub generates release notes automatically when the optional `release_notes`
input is empty. GitHub's web form renders workflow string inputs on one line;
to provide a complete multiline Markdown body without committing a notes file,
use the GitHub CLI:

```bash
gh workflow run release.yml --ref main -f version=v0.3.3 \
  -F release_notes=@CHANGELOG.md
```

`CHANGELOG.md` may be any local file and does not need to be committed.
