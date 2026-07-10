# Socket bridge helper

`socket_bridge.rs` is the source for the checked-in, statically linked
`bins/socket-bridge` payload. The daemon verifies and embeds that payload at
build time, then installs it as a read-only bind mount for TCP-only database
engines.

Rebuild it on x86-64 Linux with the repository's pinned Rust toolchain:

```bash
rustup target add x86_64-unknown-linux-musl --toolchain 1.95.0
rustc +1.95.0 --edition=2024 --target x86_64-unknown-linux-musl \
  -C opt-level=z -C strip=symbols -C panic=abort \
  helpers/socket_bridge.rs -o /tmp/dbev-socket-bridge
zstd -19 --force /tmp/dbev-socket-bridge -o bins/socket-bridge
```

Update the pinned version and both SHA-256 values in `build.rs` in the same
reviewed change. Never download or replace this executable at daemon runtime.
