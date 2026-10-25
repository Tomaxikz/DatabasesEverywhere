#!/usr/bin/env bash
# End-to-end check of the online backups that need no Btrfs/ZFS snapshot,
# against real containers: the MySQL single-transaction dump, ClickHouse
# per-table FREEZE and Qdrant per-collection snapshots.
#
# A throwaway daemon runs with its own node id, paths and ports and with
# disk.mode soft_scanner, so the registry picks the native strategies. Per
# engine: create an instance, seed it, check the online backup refuses what it
# cannot capture, back up online while a writer keeps writing, change the
# data, restore, and compare fingerprints with the state before the backup.
#
#   cargo build --locked
#   sudo bash .github/ci/online-backup-e2e.sh [all|mysql|clickhouse|qdrant|cleanup]
#
# DBEV_BIN overrides the binary. DBEV_E2E_KEEP=1 keeps the daemon, its
# containers and data after a failure; `cleanup` removes them later.
set -euo pipefail
shopt -s inherit_errexit

selection="${1:-all}"
case "$selection" in
  all|mysql|clickhouse|qdrant|cleanup) ;;
  *)
    echo "usage: $0 [all|mysql|clickhouse|qdrant|cleanup]" >&2
    exit 2
    ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: the test daemon manages containers and host paths" >&2
  echo "build first with 'cargo build --locked', then: sudo bash $0 $selection" >&2
  exit 1
fi
for command in docker curl jq openssl ss sha256sum awk seq; do
  command -v "$command" >/dev/null || {
    echo "the online backup e2e test requires $command" >&2
    exit 1
  }
done
docker info >/dev/null 2>&1 || {
  echo "the online backup e2e test requires a reachable Docker daemon" >&2
  exit 1
}

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
binary="${DBEV_BIN:-$repository_root/target/debug/dbev}"
keep="${DBEV_E2E_KEEP:-0}"
node_id=dbev-online-e2e
data_root=/var/lib/dbev-online-e2e
run_root=/run/dbev-online-e2e
config=/run/dbev-online-e2e.yml
pid_file=/run/dbev-online-e2e.pid
api_port=28090
listener_ports=(28090 25434 23307 23308 26380 26381 27028 29000 28123 26334)
api_url="http://127.0.0.1:$api_port"
database=e2edb
username=e2euser
instance_ids=(e2e-mysql e2e-clickhouse e2e-qdrant)
writer_names=(mysql clickhouse qdrant)

stop_daemon() {
  local pid attempt
  [ -f "$pid_file" ] || return 0
  pid="$(cat "$pid_file")"
  # Only signal the process this script started with its config.
  if [ -r "/proc/$pid/cmdline" ] && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -qF -- "$config"; then
    kill -TERM "$pid" 2>/dev/null || true
    for ((attempt = 0; attempt < 60; attempt++)); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.5
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  rm -f -- "$pid_file"
}

test_containers() {
  local id
  docker ps --all --quiet --filter "label=databases-everywhere.node_id=$node_id"
  for id in "${instance_ids[@]}"; do
    docker ps --all --quiet --filter "label=databases-everywhere.backup-instance=$id"
  done
}

remove_leftovers() {
  local container
  while IFS= read -r container; do
    [ -n "$container" ] || continue
    docker rm --force "$container" >/dev/null ||
      echo "warning: could not remove test container $container" >&2
  done < <(test_containers | sort -u)
  rm -rf -- "$data_root" "$run_root" "$config"
}

if [ "$selection" = cleanup ]; then
  stop_daemon
  remove_leftovers
  echo "removed the online backup e2e daemon, its containers and $data_root"
  exit 0
fi

for leftover in "$data_root" "$run_root" "$config" "$pid_file"; do
  if [ -e "$leftover" ]; then
    echo "$leftover is left from an earlier run; remove it with: sudo bash $0 cleanup" >&2
    exit 1
  fi
done
for port in "${listener_ports[@]}"; do
  if [ -n "$(ss -Hltn "sport = :$port")" ]; then
    echo "port $port is already in use; the test daemon needs ports ${listener_ports[*]}" >&2
    exit 1
  fi
done
[ -x "$binary" ] || {
  echo "$binary is missing; build it first with: cargo build --locked" >&2
  exit 1
}

work_root="$(mktemp -d /var/tmp/dbev-online-e2e.XXXXXX)"
daemon_log="$work_root/daemon.log"
auth_header="$work_root/auth.header"
qdrant_header="$work_root/qdrant.header"
response="$work_root/response.json"
password="$(openssl rand -hex 16)"
passed=()
failed=()

finish() {
  local status="$1" name
  trap - EXIT
  for name in "${writer_names[@]}"; do
    touch "$work_root/$name.stop" 2>/dev/null || true
  done
  if [ "$status" -ne 0 ] && [ -f "$daemon_log" ]; then
    echo "--- last daemon log lines ($daemon_log) ---" >&2
    tail -n 60 "$daemon_log" >&2 || true
  fi
  if [ "$status" -ne 0 ] && [ "$keep" = 1 ]; then
    echo "kept the daemon, its containers and $data_root; remove them with: sudo bash $0 cleanup" >&2
    exit "$status"
  fi
  stop_daemon
  remove_leftovers
  rm -f -- "$auth_header" "$qdrant_header"
  if [ "$status" -eq 0 ]; then
    rm -rf -- "$work_root"
  else
    echo "logs kept in $work_root" >&2
  fi
  exit "$status"
}
trap 'finish "$?"' EXIT
trap 'exit 130' INT TERM

umask 077
printf 'Authorization: Bearer %s\n' "$(openssl rand -hex 32)" >"$auth_header"
printf 'api-key: %s\n' "$password" >"$qdrant_header"
cat >"$config" <<EOF
debug: false
uuid: $node_id
token_id: $node_id
token: $(cut -d' ' -f3 "$auth_header")
jwt_signing_key: $(openssl rand -hex 32)
remote: $api_url
postgres: {enabled: false, bind: "127.0.0.1:25434", tls: false}
mariadb: {enabled: false, bind: "127.0.0.1:23307", tls: false}
mysql: {enabled: true, bind: "127.0.0.1:23308", tls: false}
redis: {enabled: false, bind: "127.0.0.1:26380", tls: false}
valkey: {enabled: false, bind: "127.0.0.1:26381", tls: false}
mongodb: {enabled: false, bind: "127.0.0.1:27028", tls: false}
clickhouse: {enabled: true, bind: "127.0.0.1:29000", http_bind: "127.0.0.1:28123", tls: false}
qdrant: {enabled: true, bind: "127.0.0.1:26334", tls: false}
api:
  host: 127.0.0.1
  port: $api_port
security:
  pids_limits:
    clickhouse: 4096
backups:
  enabled: false
  dedicated_mode: offline
  online_timeout_minutes: 30
disk:
  # Not Btrfs/ZFS project quotas, so the native online strategies apply.
  mode: soft_scanner
images:
  postgres: "postgres:18.4"
  redis: "redis:8.8.0"
  valkey: "valkey/valkey:9.1.1"
  mariadb: "mariadb:12.3.2"
  mysql: "${DBEV_E2E_MYSQL_IMAGE:-mysql:8.4}"
  mongodb: "mongo:7.0.37"
  clickhouse: "${DBEV_E2E_CLICKHOUSE_IMAGE:-clickhouse/clickhouse-server:26.4.4.38}"
  qdrant: "${DBEV_E2E_QDRANT_IMAGE:-qdrant/qdrant:v1.18.2}"
paths:
  data: $data_root
  metadata: $data_root/metadata
  volumes: $data_root/volumes
  backups: $data_root/backups
  sockets: $run_root/sockets
  locks: $run_root/locks
  logs: $data_root/logs
  artifacts: $data_root/artifacts
  exports: $data_root/artifacts/exports
  imports: $data_root/artifacts/imports
  fuse: $data_root/fuse
  tmp: $data_root/tmp
EOF
umask 022

# api METHOD PATH [JSON]: prints the HTTP status; the body lands in $response.
api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(--silent --show-error --max-time 3600 -X "$method" -H "@$auth_header"
    -o "$response" -w '%{http_code}')
  if [ -n "$body" ]; then
    args+=(-H 'Content-Type: application/json' --data "$body")
  fi
  curl "${args[@]}" "$api_url$path"
}

# expect_api STATUS METHOD PATH [JSON]
expect_api() {
  local expected="$1" status
  shift
  status="$(api "$@")"
  if [ "$status" != "$expected" ]; then
    echo "  FAIL $1 $2 answered HTTP $status, not $expected: $(head -c 800 "$response")" >&2
    return 1
  fi
}

check() {
  local what="$1" expected="$2" actual="$3"
  if [ "$expected" != "$actual" ]; then
    printf '  FAIL %s\n    expected: %s\n    actual:   %s\n' "$what" "$expected" "$actual" >&2
    return 1
  fi
  echo "  ok   $what"
}

check_changed() {
  local what="$1" before="$2" after="$3"
  if [ "$before" = "$after" ]; then
    echo "  FAIL $what: the change after the backup did not take" >&2
    return 1
  fi
  echo "  ok   $what"
}

start_daemon() {
  local attempt
  echo "==> Starting the test daemon ($binary)"
  # The daemon creates its directories and validates the config at boot.
  "$binary" --config "$config" daemon >"$daemon_log" 2>&1 &
  echo "$!" >"$pid_file"
  for ((attempt = 0; attempt < 240; attempt++)); do
    if [ "$(api GET /api/system 2>/dev/null || true)" = 200 ]; then
      echo "  ok   daemon API on $api_url"
      return 0
    fi
    if ! kill -0 "$(cat "$pid_file")" 2>/dev/null; then
      echo "  FAIL the daemon exited during startup" >&2
      return 1
    fi
    sleep 0.5
  done
  echo "  FAIL the daemon API did not come up within two minutes" >&2
  return 1
}

wait_running() {
  local id="$1" status attempt
  for ((attempt = 0; attempt < 900; attempt++)); do
    expect_api 200 GET "/api/instances/$id/status"
    status="$(jq -r .status "$response")"
    case "$status" in
      running) return 0 ;;
      failed|quarantined|deleting)
        echo "  FAIL $id is $status: $(head -c 800 "$response")" >&2
        return 1
        ;;
    esac
    sleep 1
  done
  echo "  FAIL $id did not reach running within 15 minutes" >&2
  return 1
}

create_instance() {
  local id="$1" protocol="$2" memory="$3" body started=$SECONDS
  body="$(jq -nc --arg id "$id" --arg protocol "$protocol" --arg database "$database" \
    --arg username "$username" --arg password "$password" --argjson memory "$memory" \
    '{instance_id: $id, protocol: $protocol, database: $database, username: $username,
      password: $password, public_host: "127.0.0.1",
      limits: {cpu_cores: 1, memory_mib: $memory, disk_mib: 4096}}')"
  expect_api 202 POST /api/instances "$body"
  wait_running "$id"
  echo "  ok   $id is running ($((SECONDS - started))s, including any image pull)"
}

delete_instance() {
  expect_api 200 DELETE "/api/instances/$1?confirm=true&reason=online%20backup%20e2e"
  echo "  ok   $1 deleted"
}

started_at() {
  docker inspect --format '{{.State.StartedAt}}' "$1"
}

write_once() {
  case "$1" in
    mysql) mysql_write "$2" ;;
    clickhouse) ch_write "$2" ;;
    qdrant) qd_write "$2" ;;
  esac
}

# start_writer ENGINE: writes rows 1, 2, ... until ENGINE.stop exists.
start_writer() {
  local name="$1"
  rm -f -- "$work_root/$name.stop" "$work_root/$name.writes"
  touch "$work_root/$name.writes"
  (
    set +e
    n=0
    while [ ! -e "$work_root/$name.stop" ] && [ "$n" -lt 20000 ]; do
      n=$((n + 1))
      if write_once "$name" "$n" >/dev/null 2>&1; then echo ok; else echo failed; fi >>"$work_root/$name.writes"
      sleep 0.1
    done
  ) &
  writer_pid=$!
}

stop_writer() {
  local name="$1"
  touch "$work_root/$name.stop"
  wait "$writer_pid" || true
  writes_ok="$(grep -c '^ok$' "$work_root/$name.writes" || true)"
  writes_failed="$(grep -c '^failed$' "$work_root/$name.writes" || true)"
}

# online_backup ID CONTAINER RECIPE CONSISTENCY ENGINE
online_backup() {
  local id="$1" container="$2" recipe="$3" consistency="$4" started before
  before="$(started_at "$container")"
  start_writer "$5"
  started=$SECONDS
  expect_api 200 POST "/api/instances/$id/backups?mode=online"
  stop_writer "$5"
  backup_id="$(jq -r .id "$response")"
  echo "  ok   online backup $backup_id: $(jq -r .size_bytes "$response") bytes in $((SECONDS - started))s"
  check "restore recipe" "$recipe" "$(jq -r .restore_recipe "$response")"
  check "recorded consistency" "$consistency" "$(jq -r .consistency "$response")"
  check "the container kept running through the backup" "$before" "$(started_at "$container")"
  check "writes that failed during the backup ($writes_ok succeeded)" 0 "$writes_failed"
  check "backup helper containers left" "" \
    "$(docker ps --all --quiet --filter label=databases-everywhere.backup-helper)"
}

restore_backup() {
  local id="$1" started=$SECONDS
  expect_api 200 POST "/api/instances/$id/backups/$backup_id/restore" \
    '{"confirm":true,"reason":"online backup e2e"}'
  check "restore reported" true "$(jq -r .restored "$response")"
  wait_running "$id"
  echo "  ok   restored in $((SECONDS - started))s"
}

expect_refusal() {
  local id="$1" what="$2"
  expect_api 409 POST "/api/instances/$id/backups?mode=online"
  echo "  ok   $what makes the online backup answer 409: $(jq -r .error "$response")"
}

# --- MySQL: mysqldump --single-transaction, restored through the importer ---

mysql_container=dbe-mysql-e2e-mysql

mysql_sql() {
  docker exec -e MYSQL_PWD="$password" "$mysql_container" \
    mysql --protocol=socket -u"$username" -N -B "$database" -e "$1"
}

mysql_write() {
  mysql_sql "INSERT INTO writes (n) VALUES ($1)"
}

mysql_fingerprint() {
  mysql_sql "SHOW TABLES"
  mysql_sql "SELECT COUNT(*), COALESCE(SUM(CRC32(CONCAT(id, ':', v))), 0) FROM items"
  mysql_sql "SELECT c FROM item_count"
}

test_mysql() {
  local values before
  echo "==> MySQL: consistent dump"
  create_instance e2e-mysql mysql 1024
  mysql_sql "CREATE TABLE items (id INT PRIMARY KEY, v VARCHAR(64)) ENGINE=InnoDB"
  mysql_sql "CREATE TABLE writes (id INT AUTO_INCREMENT PRIMARY KEY, n INT) ENGINE=InnoDB"
  mysql_sql "CREATE VIEW item_count AS SELECT COUNT(*) AS c FROM items"
  values="$(seq 1 2000 | awk '{printf "%s(%d,\047row-%d\047)", (NR > 1 ? "," : ""), $1, $1}')"
  mysql_sql "INSERT INTO items VALUES $values"

  if mysql_sql "CREATE TABLE legacy (id INT) ENGINE=MyISAM" 2>/dev/null; then
    expect_refusal e2e-mysql "a MyISAM table"
    mysql_sql "DROP TABLE legacy"
  else
    echo "  skip MyISAM is disabled on this instance"
  fi

  before="$(mysql_fingerprint)"
  online_backup e2e-mysql "$mysql_container" mysql.logical_dump.import@1 \
    transactional_snapshot mysql

  mysql_sql "DELETE FROM items WHERE id <= 1000"
  mysql_sql "CREATE TABLE after_backup (id INT) ENGINE=InnoDB"
  check_changed "rows deleted and a table added after the backup" "$before" "$(mysql_fingerprint)"
  restore_backup e2e-mysql
  check "tables and rows match the backup" "$before" "$(mysql_fingerprint)"
  delete_instance e2e-mysql
}

# --- ClickHouse: ALTER TABLE ... FREEZE, restored as the data directory ---

clickhouse_container=dbe-clickhouse-e2e-clickhouse

ch_sql() {
  docker exec "$clickhouse_container" \
    clickhouse-client --user "$username" --password "$password" --query "$1"
}

ch_write() {
  ch_sql "INSERT INTO $database.writes VALUES ($1)"
}

ch_ready() {
  local attempt
  for ((attempt = 0; attempt < 120; attempt++)); do
    ch_sql "SELECT 1" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "  FAIL ClickHouse did not answer queries within two minutes" >&2
  return 1
}

ch_fingerprint() {
  ch_sql "SELECT name FROM system.tables WHERE database = '$database' AND NOT startsWith(name, '.inner') ORDER BY name"
  ch_sql "SELECT count(), sum(cityHash64(id, v)) FROM $database.events"
  ch_sql "SELECT sum(c) FROM $database.event_buckets"
  ch_sql "SELECT count() FROM $database.recent_events"
}

test_clickhouse() {
  local batch before data shadows
  echo "==> ClickHouse: per-table FREEZE"
  create_instance e2e-clickhouse clickhouse 2048
  ch_ready
  ch_sql "CREATE TABLE $database.events (id UInt64, v String) ENGINE = MergeTree ORDER BY id"
  ch_sql "CREATE MATERIALIZED VIEW $database.event_buckets ENGINE = SummingMergeTree ORDER BY bucket AS SELECT id % 10 AS bucket, count() AS c FROM $database.events GROUP BY bucket"
  ch_sql "CREATE VIEW $database.recent_events AS SELECT * FROM $database.events WHERE id >= 100000"
  ch_sql "CREATE TABLE $database.writes (n UInt64) ENGINE = MergeTree ORDER BY n"
  for batch in 0 1 2; do
    ch_sql "INSERT INTO $database.events SELECT number + $batch * 50000, toString(number) FROM numbers(50000)"
  done
  echo "  ok   seeded $(ch_sql "SELECT count() FROM system.parts WHERE database = '$database' AND active") active parts"

  ch_sql "CREATE TABLE $database.legacy (n UInt8) ENGINE = TinyLog"
  expect_refusal e2e-clickhouse "a TinyLog table"
  ch_sql "DROP TABLE $database.legacy SYNC"

  before="$(ch_fingerprint)"
  online_backup e2e-clickhouse "$clickhouse_container" clickhouse.frozen_parts.directory@1 \
    per_object clickhouse
  data="$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/clickhouse"}}{{.Source}}{{end}}{{end}}' "$clickhouse_container")"
  [ -d "$data/metadata" ] || {
    echo "  FAIL could not find the ClickHouse data directory on the host ($data)" >&2
    return 1
  }
  shadows="$(find "$data/shadow" -mindepth 1 -maxdepth 1 -name 'dbev_bk_*' 2>/dev/null || true)"
  check "freeze shadow removed from the volume" "" "$shadows"

  ch_sql "TRUNCATE TABLE $database.events"
  ch_sql "DROP VIEW $database.recent_events"
  ch_sql "CREATE TABLE $database.after_backup (n UInt8) ENGINE = MergeTree ORDER BY n"
  check_changed "table truncated, view dropped and a table added after the backup" \
    "$before" "$(ch_fingerprint 2>/dev/null || true)"
  restore_backup e2e-clickhouse
  ch_ready
  check "tables, rows and materialized view match the backup" "$before" "$(ch_fingerprint)"
  delete_instance e2e-clickhouse
}

# --- Qdrant: per-collection snapshots, uploaded back into the running instance ---

qdrant_socket="$run_root/sockets/e2e-qdrant/qdrant-http.sock"

qd() {
  local method="$1" path="$2" body="${3:-}"
  local args=(--silent --show-error --fail-with-body --max-time 300
    --unix-socket "$qdrant_socket" -H "@$qdrant_header" -X "$method")
  if [ -n "$body" ]; then
    args+=(-H 'Content-Type: application/json' --data "$body")
  fi
  curl "${args[@]}" "http://qdrant$path"
}

qd_write() {
  qd PUT "/collections/writes/points?wait=true" "{\"points\":[{\"id\":$1,\"vector\":[1]}]}"
}

qd_ready() {
  local attempt
  for ((attempt = 0; attempt < 60; attempt++)); do
    qd GET /collections >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "  FAIL Qdrant did not answer on $qdrant_socket within a minute" >&2
  return 1
}

qd_points() {
  qd POST "/collections/$1/points/scroll" '{"limit":10000,"with_payload":true,"with_vector":true}' |
    jq -cS '.result.points | sort_by(.id) | map({id, payload, vector})' | sha256sum | cut -d' ' -f1
}

qd_fingerprint() {
  qd GET /collections | jq -c '[.result.collections[].name] | sort'
  qd GET /aliases | jq -c '[.result.aliases[] | [.alias_name, .collection_name]] | sort'
  qd_points docs
  qd_points images
}

qd_seed() {
  local collection="$1" size="$2" count="$3"
  qd PUT "/collections/$collection" "{\"vectors\":{\"size\":$size,\"distance\":\"Dot\"}}" >/dev/null
  if [ "$count" -gt 0 ]; then
    qd PUT "/collections/$collection/points?wait=true" "$(jq -nc --argjson count "$count" \
      '{points: [range(1; $count + 1) | {id: ., vector: [(. % 7), (. % 5), (. % 3), 1],
        payload: {n: ., tag: ("item-" + tostring)}}]}')" >/dev/null
  fi
}

test_qdrant() {
  local before collection left
  echo "==> Qdrant: per-collection snapshots"
  create_instance e2e-qdrant qdrant 1024
  qd_ready
  qd_seed docs 4 300
  qd_seed images 4 50
  qd_seed writes 1 0
  qd POST /collections/aliases \
    '{"actions":[{"create_alias":{"collection_name":"docs","alias_name":"current"}}]}' >/dev/null

  before="$(qd_fingerprint)"
  online_backup e2e-qdrant dbe-qdrant-e2e-qdrant qdrant.collection_snapshots.upload@1 \
    per_object qdrant
  for collection in docs images writes; do
    left="$(qd GET "/collections/$collection/snapshots" | jq '.result | length')"
    check "snapshots left in collection $collection" 0 "$left"
  done

  qd DELETE /collections/images >/dev/null
  qd POST "/collections/docs/points/delete?wait=true" '{"points":[1,2,3]}' >/dev/null
  qd PUT /collections/after_backup '{"vectors":{"size":2,"distance":"Dot"}}' >/dev/null
  qd POST /collections/aliases '{"actions":[{"delete_alias":{"alias_name":"current"}}]}' >/dev/null
  check_changed "collection deleted, points removed and alias dropped after the backup" \
    "$before" "$(qd_fingerprint 2>/dev/null || true)"
  restore_backup e2e-qdrant
  qd_ready
  check "collections, aliases and points match the backup" "$before" "$(qd_fingerprint)"
  delete_instance e2e-qdrant
}

run_engine() {
  local engine="$1" status
  set +e
  (
    set -e
    case "$engine" in
      mysql) test_mysql ;;
      clickhouse) test_clickhouse ;;
      qdrant) test_qdrant ;;
    esac
  )
  status=$?
  set -e
  # A failed case may have left its writer running.
  touch "$work_root/$engine.stop"
  if [ "$status" -eq 0 ]; then
    passed+=("$engine")
  else
    failed+=("$engine")
  fi
}

start_daemon
if [ "$selection" = all ]; then
  for engine in mysql clickhouse qdrant; do
    run_engine "$engine"
  done
else
  run_engine "$selection"
fi

echo
echo "passed: ${passed[*]:-none}"
echo "failed: ${failed[*]:-none}"
[ "${#failed[@]}" -eq 0 ]
