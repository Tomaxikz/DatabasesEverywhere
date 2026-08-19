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

mvn --batch-mode --quiet \
  --file "$script_dir/pom.xml" \
  -Dmysql.connector.version="$DBE_MYSQL_CONNECTOR_VERSION" \
  -Dmdep.outputFile="$work_dir/classpath" \
  dependency:build-classpath

classpath="$(<"$work_dir/classpath")"
javac \
  -encoding UTF-8 \
  -classpath "$classpath" \
  -d "$work_dir/classes" \
  "$script_dir/DbevJdbcSmoke.java"

java \
  -classpath "$work_dir/classes:$classpath" \
  DbevJdbcSmoke
