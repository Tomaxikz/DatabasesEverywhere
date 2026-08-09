#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  echo "release targets must be built on an x86-64 Linux host" >&2
  exit 1
fi

if [ "$#" -ne 2 ]; then
  echo "usage: .github/ci/build-release-target.sh <rust-target> <asset-architecture>" >&2
  exit 2
fi

rust_target="$1"
asset_arch="$2"
helper_target=""
helper_linker=""
helper_uses_zig=false
fusequota_arch=""
fusequota_sha256=""

case "$rust_target:$asset_arch" in
  x86_64-unknown-linux-gnu:x86_64)
    ;;
  aarch64-unknown-linux-gnu:arm64)
    helper_target="aarch64-unknown-linux-musl"
    helper_linker="rust-lld"
    fusequota_arch="aarch64"
    fusequota_sha256="afd429f034458e0f3fe200cf74f91f82813a7395378174ba8985ce988492f740"
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="aarch64-linux-gnu-gcc"
    export CC_aarch64_unknown_linux_gnu="aarch64-linux-gnu-gcc"
    export CXX_aarch64_unknown_linux_gnu="aarch64-linux-gnu-g++"
    export AR_aarch64_unknown_linux_gnu="aarch64-linux-gnu-ar"
    export RANLIB_aarch64_unknown_linux_gnu="aarch64-linux-gnu-ranlib"
    export TARGET_CC_aarch64_unknown_linux_gnu="aarch64-linux-gnu-gcc"
    export TARGET_CXX_aarch64_unknown_linux_gnu="aarch64-linux-gnu-g++"
    ;;
  riscv64gc-unknown-linux-gnu:riscv64)
    helper_target="riscv64gc-unknown-linux-musl"
    helper_uses_zig=true
    fusequota_arch="riscv64"
    fusequota_sha256="ab3b6c84dc905abf8b358f93e5b3eb9d2d8b8d3d0a542971cfa27414c5c34109"
    export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER="riscv64-linux-gnu-gcc"
    export CC_riscv64gc_unknown_linux_gnu="riscv64-linux-gnu-gcc"
    export CXX_riscv64gc_unknown_linux_gnu="riscv64-linux-gnu-g++"
    export AR_riscv64gc_unknown_linux_gnu="riscv64-linux-gnu-ar"
    export RANLIB_riscv64gc_unknown_linux_gnu="riscv64-linux-gnu-ranlib"
    export TARGET_CC_riscv64gc_unknown_linux_gnu="riscv64-linux-gnu-gcc"
    export TARGET_CXX_riscv64gc_unknown_linux_gnu="riscv64-linux-gnu-g++"
    ;;
  *)
    echo "unsupported release target and asset architecture: $rust_target / $asset_arch" >&2
    exit 2
    ;;
esac

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repository_root"
artifact_dir="${DBEV_RELEASE_OUTPUT_DIR:-$repository_root/target/release-artifacts}"
mkdir -p "$artifact_dir"

if [ -n "$helper_target" ]; then
  helper_dir="$repository_root/target/release-helpers/$rust_target"
  fusequota_executable="$helper_dir/fusequota"
  fusequota_payload="$helper_dir/fusequota.zst"
  socket_bridge_executable="$helper_dir/socket-bridge"
  socket_bridge_payload="$helper_dir/socket-bridge.zst"
  mkdir -p "$helper_dir"

  if [ "$helper_uses_zig" = true ]; then
    if ! command -v zig >/dev/null 2>&1; then
      echo "Zig is required to link the static RISC-V socket bridge" >&2
      exit 1
    fi
    helper_linker="$helper_dir/zig-cc-linker"
    printf '%s\n' \
      '#!/usr/bin/env bash' \
      'exec zig cc -target riscv64-linux-musl "$@"' \
      > "$helper_linker"
    chmod 0755 "$helper_linker"
  fi

  curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
    "https://github.com/calagopus/fusequota/releases/download/f939851/fusequota-${fusequota_arch}-linux" \
    --output "$fusequota_executable"
  printf '%s  %s\n' "$fusequota_sha256" "$fusequota_executable" |
    sha256sum --check --strict

  rustc --edition=2024 --target "$helper_target" -D warnings \
    --remap-path-prefix "$repository_root"=/workspace \
    --remap-path-prefix "$(rustc --print sysroot)"=/rust-toolchain \
    -C "linker=$helper_linker" -C opt-level=z -C strip=symbols -C panic=abort \
    "$repository_root/helpers/socket_bridge.rs" \
    -o "$socket_bridge_executable"

  cargo run --quiet --locked \
    --manifest-path "$repository_root/tools/helper-packer/Cargo.toml" \
    --target-dir "$repository_root/target/helper-packer" \
    -- "$fusequota_executable" "$fusequota_payload"
  cargo run --quiet --locked \
    --manifest-path "$repository_root/tools/helper-packer/Cargo.toml" \
    --target-dir "$repository_root/target/helper-packer" \
    -- "$socket_bridge_executable" "$socket_bridge_payload"

  export DBEV_FUSEQUOTA_PAYLOAD="$fusequota_payload"
  export DBEV_SOCKET_BRIDGE_PAYLOAD="$socket_bridge_payload"
fi

export AWS_LC_SYS_CMAKE_BUILDER=0
export CARGO_INCREMENTAL=0

cargo build --release --locked --bin dbev --target "$rust_target"
install -m 0755 \
  "$repository_root/target/$rust_target/release/dbev" \
  "$artifact_dir/dbev-${asset_arch}-linux"

file "$artifact_dir/dbev-${asset_arch}-linux"
