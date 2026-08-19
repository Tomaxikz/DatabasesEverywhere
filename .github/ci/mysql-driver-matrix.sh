#!/usr/bin/env bash
set -euo pipefail

cases=(
  'mysql:8.4|8.4.0'
  'mysql:8.4|9.7.0'
  'mysql:9.7|9.2.0'
  'mysql:26.7|9.7.0'
)

mariadb_cases=(
  'mariadb:10.11|8.4.0'
  'mariadb:11.4|9.2.0'
  'mariadb:11.8|9.7.0'
  'mariadb:12.3|9.7.0'
)

for test_case in "${cases[@]}"; do
  image="${test_case%%|*}"
  connector="${test_case##*|}"
  printf '\n==> MySQL image %s with Connector/J %s, MariaDB Connector/J, HikariCP, and CLI\n' \
    "$image" "$connector"
  DBE_MYSQL_TEST_IMAGE="$image" \
  DBE_MYSQL_CONNECTOR_VERSION="$connector" \
  DBE_RUN_JDBC_SMOKE=1 \
    cargo test --locked \
      databases::mysql::integration_tests::mysql_supported_version_provisions_routes_and_round_trips_dump \
      -- --ignored --exact --nocapture --test-threads=1
done

for test_case in "${mariadb_cases[@]}"; do
  image="${test_case%%|*}"
  connector="${test_case##*|}"
  printf '\n==> MariaDB image %s with Connector/J %s, MariaDB Connector/J, HikariCP, and CLI\n' \
    "$image" "$connector"
  DBE_MARIADB_TEST_IMAGE="$image" \
  DBE_MYSQL_CONNECTOR_VERSION="$connector" \
  DBE_RUN_JDBC_SMOKE=1 \
    cargo test --locked \
      databases::mariadb::integration_tests::mariadb_supported_version_routes_real_cli_jdbc_tls_and_hikari \
      -- --ignored --exact --nocapture --test-threads=1
done
