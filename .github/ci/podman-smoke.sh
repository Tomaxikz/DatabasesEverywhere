#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != "Linux" ]; then
  echo "the Podman compatibility smoke test requires Linux" >&2
  exit 1
fi

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
runtime_dir="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
socket="$runtime_dir/podman/podman.sock"
service_log="$(mktemp -t dbev-podman-service.XXXXXX.log)"
service_pid=""

cleanup() {
  local status
  status="$1"
  if [ -n "$service_pid" ] && kill -0 "$service_pid" 2>/dev/null; then
    kill "$service_pid" 2>/dev/null || true
    wait "$service_pid" 2>/dev/null || true
  fi
  if [ "$status" -ne 0 ]; then
    echo "Podman service log:" >&2
    sed -n '1,240p' "$service_log" >&2 || true
  fi
  rm -f -- "$service_log"
  exit "$status"
}
trap 'cleanup "$?"' EXIT
trap 'exit 130' INT TERM

mkdir -p -- "$runtime_dir/podman"
chmod 0700 "$runtime_dir" "$runtime_dir/podman"
export XDG_RUNTIME_DIR="$runtime_dir"

podman --cgroup-manager=cgroupfs system service --time=0 "unix://$socket" \
  >"$service_log" 2>&1 &
service_pid=$!

ready=false
for ((attempt = 0; attempt < 60; attempt++)); do
  if curl --silent --show-error --fail --unix-socket "$socket" \
    http://localhost/v1.40/_ping >/dev/null 2>&1; then
    ready=true
    break
  fi
  if ! kill -0 "$service_pid" 2>/dev/null; then
    break
  fi
  sleep 0.5
done
if [ "$ready" != true ]; then
  echo "rootless Podman API did not become ready at $socket" >&2
  exit 1
fi

cd "$repository_root"
export DBE_PODMAN_SOCKET="$socket"
export RUST_BACKTRACE=1
timeout 15m cargo test --lib --locked \
  runtime::docker::podman_live_tests::rootless_podman_compatibility_smoke -- \
  --ignored --exact --nocapture
