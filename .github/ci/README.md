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
CodeQL, and the release build run. The driver matrix starts official MySQL
8.4/9.7/26.7 and MariaDB 10.11/11.4/11.8/12.3 containers behind the actual
DBEV gateway and exercises MariaDB CLI, Connector/J 8.4/9.2/9.7, MariaDB Connector/J, HikariCP,
database-qualified and deferred-catalog connections, and standard CLIENT_SSL.
Configure the `main` branch ruleset to require the single `CI gate` status;
that gate fails when any required stage fails or is skipped.

The release workflow independently repeats the locked lint and test gate and
audits both Cargo lockfiles before it builds publishable artifacts. A release
therefore cannot rely on a separate CI run that is still pending or failed.

To run only the driver matrix on a Linux host with Docker, Maven, JDK 21,
OpenSSL, and the MariaDB CLI installed:

```bash
bash .github/ci/mysql-driver-matrix.sh
```

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
