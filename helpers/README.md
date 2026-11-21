# Socket bridge helper

`socket_bridge.rs` is the source for the checked-in, statically linked
`payloads/socket-bridge.zst` executable. The daemon verifies and embeds that
payload at build time, then installs it as a read-only bind mount for TCP-only
database engines. `payloads/fusequota.zst` is the separately maintained,
version-pinned FuseQuota helper. Both payloads are zstd-compressed.

Rebuild it on x86-64 Linux with the repository's pinned Rust toolchain:

```bash
rustup target add x86_64-unknown-linux-musl --toolchain 1.95.0
rustc +1.95.0 --edition=2024 --target x86_64-unknown-linux-musl \
  --remap-path-prefix "$PWD"=/workspace \
  --remap-path-prefix "$(rustc +1.95.0 --print sysroot)"=/rust-toolchain \
  -C linker=rust-lld -C opt-level=z -C strip=symbols -C panic=abort \
  helpers/socket_bridge.rs -o /tmp/dbev-socket-bridge
zstd -19 --force /tmp/dbev-socket-bridge -o helpers/payloads/socket-bridge.zst
```

The helper proxies every bridge connection on one edge-triggered epoll thread
with fixed per-direction buffers. Its unit tests run without Cargo:

```bash
rustc +1.95.0 --edition=2024 -D warnings --test helpers/socket_bridge.rs \
  -o /tmp/dbev-socket-bridge-tests && /tmp/dbev-socket-bridge-tests
```

On a development host without the `zstd` CLI, the checked-in packer produces
the same zstd payload format:

```bash
cargo run --quiet --locked --package dbev-helper-packer -- \
  /tmp/dbev-socket-bridge helpers/payloads/socket-bridge.zst
```

The `.version` files are the canonical helper versions consumed by both the
build script and cross-release tooling. Update the applicable version file and
the source, compressed-payload, and executable SHA-256 values in `build.rs` in
the same reviewed change. Never download or replace an executable at daemon
runtime.
