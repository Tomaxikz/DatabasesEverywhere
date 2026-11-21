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

# Maven downloads the drivers and its dependency plugin from Maven Central unless
# they are already in ~/.m2, and it reports errors on stdout, so send them to
# stderr, where the caller looks. Central can refuse or stall a runner for
# reasons unrelated to the gateway: bound each attempt, and retry through
# Google's mirror of Central before giving up.
cat > "$work_dir/mirror-settings.xml" <<'XML'
<settings>
  <mirrors>
    <mirror>
      <id>google-maven-central</id>
      <mirrorOf>central</mirrorOf>
      <url>https://maven-central.storage-download.googleapis.com/maven2/</url>
    </mirror>
  </mirrors>
</settings>
XML

attempts=3
for attempt in $(seq 1 "$attempts"); do
  settings=()
  if [ "$attempt" -gt 1 ]; then
    settings=(--settings "$work_dir/mirror-settings.xml")
  fi
  # The full plugin coordinate avoids a separate metadata lookup for the
  # "dependency" prefix, which is the request that fails most often.
  if timeout --signal=TERM --kill-after=10s 180s \
    mvn --batch-mode --quiet "${settings[@]}" \
    --file "$script_dir/pom.xml" \
    -Daether.connector.connectTimeout=15000 \
    -Daether.connector.requestTimeout=60000 \
    -Dmysql.connector.version="$DBE_MYSQL_CONNECTOR_VERSION" \
    -Dmdep.outputFile="$work_dir/classpath" \
    org.apache.maven.plugins:maven-dependency-plugin:3.11.0:build-classpath >&2; then
    break
  fi
  if [ "$attempt" -eq "$attempts" ]; then
    echo "Maven could not resolve the JDBC drivers after $attempts attempts" >&2
    exit 1
  fi
  echo "Maven dependency resolution failed (attempt $attempt of $attempts); retrying through the mirror" >&2
  sleep $((attempt * 5))
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
