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
the complete test suite. A failed check stops the push. Git's `--no-verify`
option remains available for an intentional emergency bypass.

GitHub Actions runs `Global lint` first. Only after it passes do dependency
auditing, Linux tests, documentation checks, CodeQL, and the release build run.
Configure the `main` branch ruleset to require the single `CI gate` status;
that gate fails when any required stage fails or is skipped.

## Release notes

For a full GitHub release changelog, copy `release-notes/TEMPLATE.md` to a
versioned file such as `release-notes/v0.3.3.md`, edit it, commit it, and enter
that path in the release workflow's `release_notes_file` input. The shorter
`release_notes` input remains available for a one-line release description.
