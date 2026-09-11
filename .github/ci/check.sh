#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != "Linux" ]; then
  echo "The complete DBEV checks must run on Linux; use WSL2 or another Linux host." >&2
  exit 1
fi

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repository_root"

section() {
  printf '\n==> %s\n' "$1"
}

lint() {
  section "Locked Cargo manifests"
  cargo metadata --locked --no-deps --format-version 1 >/dev/null

  section "Unused Rust dependencies"
  cargo machete

  section "Rust source size"
  bash .github/ci/check-source-size.sh

  section "Rust formatting"
  cargo fmt --all -- --check

  section "Strict Clippy"
  cargo clippy --workspace --all-targets --locked -- -D warnings
}

test_all() {
  section "Complete Linux test suite"
  cargo test --workspace --locked
}

test_coverage() {
  section "Instrumented Linux test suite"
  cargo llvm-cov clean --workspace
  cargo llvm-cov --workspace --locked --no-report

  # Stable Rust cannot instrument doctests; keep running them separately.
  section "Workspace documentation tests"
  cargo test --workspace --locked --doc
}

audit_dependencies() {
  section "Workspace dependency audit"
  cargo audit --no-yanked -D warnings
}

case "${1:-pre-push}" in
  lint)
    lint
    ;;
  test)
    test_all
    ;;
  coverage)
    test_coverage
    ;;
  audit)
    audit_dependencies
    ;;
  pre-push)
    lint
    test_all
    ;;
  *)
    echo "usage: .github/ci/check.sh [lint|test|coverage|audit|pre-push]" >&2
    exit 2
    ;;
esac
