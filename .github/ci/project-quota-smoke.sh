#!/usr/bin/env bash
set -euo pipefail

filesystem="${1:-all}"
engine_protocol="${2:-}"
case "$filesystem" in
  all|xfs|ext4|f2fs) ;;
  *)
    echo "usage: $0 [all|xfs|ext4|f2fs]" >&2
    exit 2
    ;;
esac
case "$engine_protocol" in
  ""|postgres|mysql|mariadb) ;;
  *)
    echo "usage: $0 [all|xfs|ext4|f2fs] [postgres|mysql|mariadb]" >&2
    exit 2
    ;;
esac
if [[ -n "$engine_protocol" && "$filesystem" == all ]]; then
  echo "a real engine quota case must select one filesystem" >&2
  exit 2
fi
if [[ -n "$engine_protocol" && "$filesystem" == f2fs ]]; then
  echo "real engine quota cases currently target the required XFS/ext4 backends" >&2
  exit 2
fi

case_timeout="${DBE_PROJECT_QUOTA_TEST_TIMEOUT:-6m}"
build_timeout="${DBE_PROJECT_QUOTA_BUILD_TIMEOUT:-12m}"
if [[ -n "$engine_protocol" ]]; then
  test_name='placement::tenant::integration_tests::real_shared_engine_project_quota_enforces_tenant_writes'
else
  test_name='disk::project_quota_integration_tests::real_project_quota_enforces_tenant_boundary'
fi

for command in cargo sudo timeout truncate mount umount findmnt find grep; do
  command -v "$command" >/dev/null || {
    echo "project-quota smoke test requires $command" >&2
    exit 1
  }
done
sudo -n true || {
  echo "project-quota smoke test requires passwordless sudo" >&2
  exit 1
}

echo "==> Compiling the ignored native project-quota smoke test"
timeout --kill-after=15s "$build_timeout" \
  cargo test --locked --lib "$test_name" --no-run
test_binary=""
while IFS= read -r -d '' candidate; do
  if "$candidate" --list | grep -F "$test_name" >/dev/null; then
    test_binary="$(pwd -P)/$candidate"
    break
  fi
done < <(find target/debug/deps -maxdepth 1 -type f -name 'databases_everywhere-*' -perm -u+x -print0)
[[ -n "$test_binary" ]] || {
  echo "could not locate the compiled DBEV library test binary" >&2
  exit 1
}

run_case() (
  local fs="$1"
  local temp_root workspace image mount_dir test_root projects_backup projid_backup
  local project_lock_backup
  local projects_existed=0
  local projid_existed=0
  local project_lock_existed=0
  local mounted=0
  local optional=0

  temp_root="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
  workspace="$(mktemp -d "$temp_root/dbev-project-quota-${fs}.XXXXXX")"
  image="$workspace/${fs}.img"
  mount_dir="$workspace/mount"
  test_root="$mount_dir/test-root"
  projects_backup="$workspace/projects.backup"
  projid_backup="$workspace/projid.backup"
  project_lock_backup="$workspace/project-quota-lock.backup"
  mkdir -p "$mount_dir"

  # Invoked by the EXIT trap below; ShellCheck cannot follow this nested callback.
  # shellcheck disable=SC2317
  cleanup_case() {
    local status="$1"
    local cleanup_failed=0
    trap - EXIT
    set +e
    if (( mounted )); then
      sudo umount "$mount_dir" || cleanup_failed=1
    fi
    if [[ "$fs" == xfs ]]; then
      if (( projects_existed )); then
        sudo cp --preserve=mode,ownership,timestamps "$projects_backup" /etc/projects || cleanup_failed=1
      else
        sudo rm -f /etc/projects || cleanup_failed=1
      fi
      if (( projid_existed )); then
        sudo cp --preserve=mode,ownership,timestamps "$projid_backup" /etc/projid || cleanup_failed=1
      else
        sudo rm -f /etc/projid || cleanup_failed=1
      fi
      if (( project_lock_existed )); then
        if sudo rm -f /etc/.dbe-project-quota.lock; then
          sudo cp -a -- "$project_lock_backup" /etc/.dbe-project-quota.lock || cleanup_failed=1
        else
          cleanup_failed=1
        fi
      else
        sudo rm -f /etc/.dbe-project-quota.lock || cleanup_failed=1
      fi
    fi
    if (( cleanup_failed )); then
      echo "project-quota cleanup was incomplete; preserving $workspace for inspection" >&2
    elif [[ "$workspace" == "$temp_root"/dbev-project-quota-"$fs".* ]]; then
      sudo rm -rf -- "$workspace" || cleanup_failed=1
    else
      echo "refusing to remove unexpected temporary path: $workspace" >&2
      cleanup_failed=1
    fi
    if (( status != 0 )); then
      exit "$status"
    fi
    (( cleanup_failed == 0 )) || exit 1
    exit 0
  }
  trap 'cleanup_case "$?"' EXIT

  case "$fs" in
    xfs)
      for command in mkfs.xfs xfs_quota; do
        command -v "$command" >/dev/null || {
          echo "XFS smoke test requires $command" >&2
          return 1
        }
      done
      if [[ -e /etc/projects ]]; then
        sudo cp --preserve=mode,ownership,timestamps /etc/projects "$projects_backup"
        projects_existed=1
      fi
      if [[ -e /etc/projid ]]; then
        sudo cp --preserve=mode,ownership,timestamps /etc/projid "$projid_backup"
        projid_existed=1
      fi
      if [[ -e /etc/.dbe-project-quota.lock || -L /etc/.dbe-project-quota.lock ]]; then
        sudo cp -a -- /etc/.dbe-project-quota.lock "$project_lock_backup"
        project_lock_existed=1
      fi
      sudo touch /etc/projects /etc/projid
      if [[ -n "$engine_protocol" ]]; then
        truncate -s 4G "$image"
      else
        truncate -s 512M "$image"
      fi
      sudo mkfs.xfs -f -q "$image"
      sudo mount -o loop,prjquota "$image" "$mount_dir"
      ;;
    ext4)
      for command in mkfs.ext4 quotaon setquota; do
        command -v "$command" >/dev/null || {
          echo "ext4 smoke test requires $command" >&2
          return 1
        }
      done
      if [[ -n "$engine_protocol" ]]; then
        truncate -s 4G "$image"
      else
        truncate -s 512M "$image"
      fi
      sudo mkfs.ext4 -F -q -O project,quota -E quotatype=prjquota "$image"
      sudo mount -o loop,prjquota "$image" "$mount_dir"
      ;;
    f2fs)
      optional=1
      if ! command -v mkfs.f2fs >/dev/null || \
         ! command -v quotaon >/dev/null || \
         ! command -v setquota >/dev/null; then
        echo "::notice::Skipping optional F2FS quota smoke test: required tools are unavailable"
        return 0
      fi
      truncate -s 512M "$image"
      if ! sudo mkfs.f2fs -f -q -O project_quota,extra_attr,quota "$image"; then
        echo "::notice::Skipping optional F2FS quota smoke test: mkfs lacks project-quota support"
        return 0
      fi
      if ! sudo mount -t f2fs -o loop,prjquota "$image" "$mount_dir"; then
        echo "::notice::Skipping optional F2FS quota smoke test: runner kernel cannot mount it with prjquota"
        return 0
      fi
      ;;
  esac
  mounted=1

  local actual_fs options
  actual_fs="$(findmnt -n -T "$mount_dir" -o FSTYPE)"
  options="$(findmnt -n -T "$mount_dir" -o OPTIONS)"
  if [[ "$actual_fs" != "$fs" ]] || [[ ",$options," != *,prjquota,* && ",$options," != *,pquota,* ]]; then
    if (( optional )); then
      echo "::notice::Skipping optional F2FS quota smoke test: mounted as '$actual_fs' with '$options'"
      return 0
    fi
    echo "$fs loopback mount did not advertise project quotas: fstype=$actual_fs options=$options" >&2
    return 1
  fi

  sudo mkdir "$test_root"
  sudo chmod 0755 "$mount_dir" "$test_root"
  echo "==> Exercising DBEV's canonical project-quota lifecycle on $fs"
  sudo env \
      DBE_PROJECT_QUOTA_TEST_ROOT="$test_root" \
      DBE_PROJECT_QUOTA_TEST_FS="$fs" \
      DBE_PROJECT_QUOTA_ENGINE_PROTOCOL="$engine_protocol" \
    timeout --kill-after=15s "$case_timeout" \
      "$test_binary" --exact --ignored --nocapture --test-threads=1 "$test_name"
)

if [[ "$filesystem" == all ]]; then
  run_case xfs
  run_case ext4
  run_case f2fs
else
  run_case "$filesystem"
fi
