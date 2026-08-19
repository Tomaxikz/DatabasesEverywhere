#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <mysql|mariadb> <container-image> <mysql-connector-version>" >&2
  exit 2
fi

protocol="$1"
image="$2"
connector="$3"
case_timeout="${DBE_DRIVER_CASE_TIMEOUT:-12m}"

case "$protocol" in
  mysql)
    image_prefix='mysql:'
    image_variable='DBE_MYSQL_TEST_IMAGE'
    test_name='databases::mysql::integration_tests::mysql_supported_version_provisions_routes_and_round_trips_dump'
    ;;
  mariadb)
    image_prefix='mariadb:'
    image_variable='DBE_MARIADB_TEST_IMAGE'
    test_name='databases::mariadb::integration_tests::mariadb_supported_version_routes_real_cli_jdbc_tls_and_hikari'
    ;;
  *)
    echo "unsupported database protocol: $protocol" >&2
    exit 2
    ;;
esac

case "$image" in
  "$image_prefix"*) ;;
  *)
    echo "container image '$image' does not match protocol '$protocol'" >&2
    exit 2
    ;;
esac

if ! [[ "$connector" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "invalid MySQL Connector/J version: $connector" >&2
  exit 2
fi
if ! [[ "$case_timeout" =~ ^[1-9][0-9]*[smh]$ ]]; then
  echo "DBE_DRIVER_CASE_TIMEOUT must be a positive coreutils duration such as 12m" >&2
  exit 2
fi

printf '\n==> %s image %s with Connector/J %s, MariaDB Connector/J, HikariCP, and CLI\n' \
  "$protocol" "$image" "$connector"

set +e
env \
  "$image_variable=$image" \
  "DBE_MYSQL_CONNECTOR_VERSION=$connector" \
  DBE_RUN_JDBC_SMOKE=1 \
  timeout --foreground --signal=TERM --kill-after=30s "$case_timeout" \
    cargo test --locked --lib "$test_name" \
      -- --ignored --exact --nocapture --test-threads=1
status="$?"
set -e

if [ "$status" -eq 124 ] || [ "$status" -eq 137 ]; then
  echo "$protocol compatibility case exceeded its $case_timeout deadline: image=$image connector=$connector" >&2
fi
exit "$status"
