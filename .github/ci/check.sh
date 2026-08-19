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

  section "Rust source size"
  bash .github/ci/check-source-size.sh

  section "Rust formatting"
  cargo fmt --all -- --check

  section "Strict Clippy"
  cargo clippy --workspace --all-targets --locked -- -D warnings

  section "Static helper formatting"
  cargo fmt --manifest-path tools/helper-packer/Cargo.toml -- --check

  section "Static helper Clippy"
  cargo clippy --manifest-path tools/helper-packer/Cargo.toml --all-targets --locked -- -D warnings
}

test_all() {
  section "Complete Linux test suite"
  cargo test --workspace --locked

  section "Static helper tests"
  cargo test --manifest-path tools/helper-packer/Cargo.toml --all-targets --locked
}

audit_dependencies() {
  local rsa_tree

  section "Dependency graph policy"
  rsa_tree="$(cargo tree --locked --edges normal -i rsa 2>/dev/null || true)"
  if [ -n "$rsa_tree" ]; then
    echo "RUSTSEC-2023-0071 is ignored only while rsa is absent from the built graph" >&2
    printf '%s\n' "$rsa_tree" >&2
    exit 1
  fi

  section "Root dependency audit"
  cargo audit --no-yanked -D warnings

  section "Static helper dependency audit"
  (
    cd tools/helper-packer
    cargo audit --no-yanked -D warnings
  )
}

case "${1:-pre-push}" in
  lint)
    lint
    ;;
  test)
    test_all
    ;;
  audit)
    audit_dependencies
    ;;
  pre-push)
    lint
    test_all
    ;;
  *)
    echo "usage: .github/ci/check.sh [lint|test|audit|pre-push]" >&2
    exit 2
    ;;
esac
