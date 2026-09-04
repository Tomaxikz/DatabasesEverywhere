#!/usr/bin/env bash
set -euo pipefail

selection="${1:-all}"
case "$selection" in
  all|postgres|mysql|mariadb|mongodb|clickhouse) ;;
  *)
    echo "usage: $0 [all|postgres|mysql|mariadb|mongodb|clickhouse]" >&2
    exit 2
    ;;
esac

for command in cargo docker timeout; do
  command -v "$command" >/dev/null || {
    echo "shared-pool isolation tests require $command" >&2
    exit 1
  }
done
docker info >/dev/null 2>&1 || {
  echo "shared-pool isolation tests require a reachable Docker daemon" >&2
  exit 1
}

case_timeout="${DBE_SHARED_POOL_TEST_TIMEOUT:-12m}"
if ! [[ "$case_timeout" =~ ^[1-9][0-9]*[smh]$ ]]; then
  echo "DBE_SHARED_POOL_TEST_TIMEOUT must be a positive coreutils duration such as 12m" >&2
  exit 2
fi
active_protocol=""
test_catalog=""

cleanup_case() {
  local protocol="$1"
  local container_id instance_id
  while IFS= read -r container_id; do
    [ -n "$container_id" ] || continue
    instance_id="$(
      docker inspect \
        --format '{{ index .Config.Labels "databases-everywhere.instance" }}' \
        "$container_id" 2>/dev/null || true
    )"
    case "$instance_id" in
      "shared_it_${protocol}_"*)
        if ! docker rm --force "$container_id" >/dev/null; then
          echo "warning: could not remove stale test container $container_id" >&2
        fi
        ;;
    esac
  done < <(
    docker ps --all --quiet \
      --filter 'label=databases-everywhere.managed=true' \
      --filter "label=databases-everywhere.protocol=${protocol}"
  )
}

cleanup_active() {
  if [ -n "$active_protocol" ]; then
    cleanup_case "$active_protocol"
  fi
}
trap cleanup_active EXIT

run_case() {
  local protocol="$1"
  local test_name="placement::tenant::integration_tests::${protocol}_shared_pool_enforces_two_tenant_lifecycle_isolation"
  local status

  if [ -z "$test_catalog" ]; then
    test_catalog="$(cargo test --locked --lib -- --list)"
  fi
  if ! grep -Fqx "$test_name: test" <<<"$test_catalog"; then
    echo "shared-pool isolation test is missing from the Rust test catalog: $test_name" >&2
    return 1
  fi

  active_protocol="$protocol"
  cleanup_case "$protocol"
  echo "==> Shared-pool tenant isolation: $protocol"

  set +e
  timeout --signal=TERM --kill-after=30s "$case_timeout" \
    cargo test --locked --lib "$test_name" -- \
      --exact --ignored --nocapture --test-threads=1
  status="$?"
  set -e

  cleanup_case "$protocol"
  active_protocol=""
  if [ "$status" -eq 124 ] || [ "$status" -eq 137 ]; then
    echo "$protocol shared-pool isolation case exceeded its $case_timeout deadline" >&2
  fi
  return "$status"
}

if [ "$selection" = "all" ]; then
  for protocol in postgres mysql mariadb mongodb clickhouse; do
    run_case "$protocol"
  done
else
  run_case "$selection"
fi
