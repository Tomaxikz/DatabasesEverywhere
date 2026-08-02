use super::*;

pub(super) fn qdrant_bridge_start_script() -> String {
    format!(
        r#"{cleanup}
set -eu
{binary} __socket-bridge-supervisor \
  --socket {socket} --tcp 127.0.0.1:6333 \
  -- sh -c 'exec sleep 86400' {marker} >/dev/null 2>&1 &
qdrant_bridge_pid=$!
qdrant_bridge_start=$(qdrant_bridge_process_start_time "$qdrant_bridge_pid")
rm -f -- {pid_temp}
(
  umask 077
  set -C
  printf 'v1 %s %s\n' "$qdrant_bridge_pid" "$qdrant_bridge_start" > {pid_temp}
)
mv -f -- {pid_temp} {pid}
"#,
        cleanup = qdrant_bridge_stop_script(),
        pid = sh_quote(TARGET_BRIDGE_PID),
        pid_temp = sh_quote(&format!("{TARGET_BRIDGE_PID}.new")),
        socket = sh_quote(TARGET_BRIDGE_SOCKET),
        binary = sh_quote(SOCKET_BRIDGE_CONTAINER_PATH),
        marker = sh_quote(TARGET_BRIDGE_MARKER),
    )
}

fn qdrant_bridge_process_helpers_script() -> String {
    format!(
        r#"qdrant_bridge_process_start_time() {{
  qdrant_bridge_stat=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
  qdrant_bridge_stat=${{qdrant_bridge_stat#*) }}
  set -- $qdrant_bridge_stat
  [ "$#" -ge 20 ] || return 1
  qdrant_bridge_start=${{20}}
  case "$qdrant_bridge_start" in
''|*[!0-9]*) return 1 ;;
  esac
  printf '%s\n' "$qdrant_bridge_start"
}}

qdrant_bridge_process_is_owned() {{
  qdrant_bridge_candidate=$1
  qdrant_bridge_expected_start=$2
  case "$qdrant_bridge_candidate" in
''|*[!0-9]*) return 1 ;;
  esac
  [ "$qdrant_bridge_candidate" -gt 1 ] 2>/dev/null || return 1
  qdrant_bridge_actual_start=$(qdrant_bridge_process_start_time "$qdrant_bridge_candidate") ||
return 1
  [ "$qdrant_bridge_actual_start" = "$qdrant_bridge_expected_start" ] || return 1
  qdrant_bridge_actual_cmdline=$(
tr '\000' '\n' < "/proc/$qdrant_bridge_candidate/cmdline" 2>/dev/null
  ) || return 1
  qdrant_bridge_expected_cmdline=$(printf '%s\n' \
{binary} __socket-bridge-supervisor \
--socket {socket} --tcp 127.0.0.1:6333 \
-- sh -c 'exec sleep 86400' {marker})
  qdrant_bridge_legacy_cmdline=$(printf '%s\n' \
{binary} __socket-bridge-supervisor \
--socket {socket} --tcp 127.0.0.1:6333 \
-- sh -c 'exec sleep 86400')
  if [ "$qdrant_bridge_actual_cmdline" != "$qdrant_bridge_expected_cmdline" ] &&
 [ "$qdrant_bridge_actual_cmdline" != "$qdrant_bridge_legacy_cmdline" ]; then
return 1
  fi
  qdrant_bridge_actual_start=$(qdrant_bridge_process_start_time "$qdrant_bridge_candidate") ||
return 1
  [ "$qdrant_bridge_actual_start" = "$qdrant_bridge_expected_start" ]
}}

qdrant_bridge_stop_owned_process() {{
  qdrant_bridge_stop_pid=$1
  qdrant_bridge_stop_start=$2
  qdrant_bridge_process_is_owned "$qdrant_bridge_stop_pid" "$qdrant_bridge_stop_start" ||
return 0
  kill -TERM "$qdrant_bridge_stop_pid" 2>/dev/null || true
  qdrant_bridge_wait=0
  while qdrant_bridge_process_is_owned \
  "$qdrant_bridge_stop_pid" "$qdrant_bridge_stop_start" &&
  [ "$qdrant_bridge_wait" -lt 100 ]; do
sleep 0.05
qdrant_bridge_wait=$((qdrant_bridge_wait + 1))
  done
  if qdrant_bridge_process_is_owned \
  "$qdrant_bridge_stop_pid" "$qdrant_bridge_stop_start"; then
kill -KILL "$qdrant_bridge_stop_pid" 2>/dev/null || true
qdrant_bridge_wait=0
while qdrant_bridge_process_is_owned \
    "$qdrant_bridge_stop_pid" "$qdrant_bridge_stop_start" &&
    [ "$qdrant_bridge_wait" -lt 50 ]; do
  sleep 0.05
  qdrant_bridge_wait=$((qdrant_bridge_wait + 1))
done
  fi
  ! qdrant_bridge_process_is_owned \
"$qdrant_bridge_stop_pid" "$qdrant_bridge_stop_start"
}}
"#,
        binary = sh_quote(SOCKET_BRIDGE_CONTAINER_PATH),
        socket = sh_quote(TARGET_BRIDGE_SOCKET),
        marker = sh_quote(TARGET_BRIDGE_MARKER),
    )
}

pub(super) fn qdrant_bridge_stop_script() -> String {
    format!(
        r#"set -u
{helpers}
qdrant_bridge_cleanup_failed=0
for qdrant_bridge_proc in /proc/[0-9]*; do
  [ -d "$qdrant_bridge_proc" ] || continue
  qdrant_bridge_scan_pid=${{qdrant_bridge_proc#/proc/}}
  qdrant_bridge_scan_start=$(
qdrant_bridge_process_start_time "$qdrant_bridge_scan_pid"
  ) || continue
  if qdrant_bridge_process_is_owned \
  "$qdrant_bridge_scan_pid" "$qdrant_bridge_scan_start"; then
qdrant_bridge_stop_owned_process \
  "$qdrant_bridge_scan_pid" "$qdrant_bridge_scan_start" ||
  qdrant_bridge_cleanup_failed=1
  fi
done
[ "$qdrant_bridge_cleanup_failed" -eq 0 ] || exit 1
rm -f -- {socket} {pid} {pid_temp} {log}
"#,
        helpers = qdrant_bridge_process_helpers_script(),
        pid = sh_quote(TARGET_BRIDGE_PID),
        pid_temp = sh_quote(&format!("{TARGET_BRIDGE_PID}.new")),
        socket = sh_quote(TARGET_BRIDGE_SOCKET),
        log = sh_quote(TARGET_BRIDGE_LOG),
    )
}
