#!/usr/bin/env bash
set -euo pipefail

for variable in \
  DBE_DRIVER_HOST \
  DBE_DRIVER_PORT \
  DBE_DRIVER_TLS_PORT \
  DBE_DRIVER_DATABASE \
  DBE_DRIVER_USERNAME \
  DBE_DRIVER_PASSWORD \
  DBE_MYSQL_CONNECTOR_VERSION
do
  if [ -z "${!variable:-}" ]; then
    echo "${variable} is required" >&2
    exit 2
  fi
done

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
work_dir="$(mktemp -d)"
trap 'rm -rf -- "$work_dir"' EXIT

# Maven downloads the drivers from Maven Central on every run and reports its
# errors on stdout, so send them to stderr, where the caller looks. A download
# can fail for reasons unrelated to the gateway; retry before giving up.
attempts=3
for attempt in $(seq 1 "$attempts"); do
  if mvn --batch-mode --quiet \
    --file "$script_dir/pom.xml" \
    -Dmysql.connector.version="$DBE_MYSQL_CONNECTOR_VERSION" \
    -Dmdep.outputFile="$work_dir/classpath" \
    dependency:build-classpath >&2; then
    break
  fi
  if [ "$attempt" -eq "$attempts" ]; then
    echo "Maven could not resolve the JDBC drivers after $attempts attempts" >&2
    exit 1
  fi
  echo "Maven dependency resolution failed (attempt $attempt of $attempts); retrying" >&2
  sleep $((attempt * 10))
done

classpath="$(<"$work_dir/classpath")"
javac \
  -encoding UTF-8 \
  -classpath "$classpath" \
  -d "$work_dir/classes" \
  "$script_dir/DbevJdbcSmoke.java"

java \
  -classpath "$work_dir/classes:$classpath" \
  DbevJdbcSmoke
