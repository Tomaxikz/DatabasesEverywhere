#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
maximum_lines=1500
failed=0

while IFS= read -r -d '' source_file; do
  line_count="$(wc -l < "$source_file")"
  if ((line_count > maximum_lines)); then
    relative_path="${source_file#"$repository_root"/}"
    printf '%s has %d lines; split it before it exceeds the %d-line limit\n' \
      "$relative_path" "$line_count" "$maximum_lines" >&2
    failed=1
  fi
done < <(find "$repository_root/src" -type f -name '*.rs' -print0)

exit "$failed"
