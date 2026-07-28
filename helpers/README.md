# Socket bridge helper

`socket_bridge.rs` is the source for the checked-in, statically linked
`bins/socket-bridge` payload. The daemon verifies and embeds that payload at
build time, then installs it as a read-only bind mount for TCP-only database
engines.

Rebuild it on x86-64 Linux with the repository's pinned Rust toolchain:

```bash
rustup target add x86_64-unknown-linux-musl --toolchain 1.95.0
rustc +1.95.0 --edition=2024 --target x86_64-unknown-linux-musl \
  --remap-path-prefix "$PWD"=/workspace \
  --remap-path-prefix "$(rustc +1.95.0 --print sysroot)"=/rust-toolchain \
  -C linker=rust-lld -C opt-level=z -C strip=symbols -C panic=abort \
  helpers/socket_bridge.rs -o /tmp/dbev-socket-bridge
zstd -19 --force /tmp/dbev-socket-bridge -o bins/socket-bridge
```

On a development host without the `zstd` CLI, the checked-in packer produces
the same zstd payload format:

```bash
cargo run --quiet --manifest-path tools/helper-packer/Cargo.toml -- \
  /tmp/dbev-socket-bridge bins/socket-bridge
```

Update the pinned version and the source, compressed-payload, and executable
SHA-256 values in `build.rs` in the same reviewed change. Never download or
replace this executable at daemon runtime.
