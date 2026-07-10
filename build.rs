use sha2::{Digest, Sha256};
use std::path::Path;

const FUSEQUOTA_VERSION: &str = "795d0fe";
const FUSEQUOTA_COMPRESSED_SHA256: &str =
    "e1c23625877c4394f2542e7e9b763ff4f9228038d6c497e778b67234ea67d4fa";
const FUSEQUOTA_EXECUTABLE_SHA256: &str =
    "102ba39c6157469cfc2dd635f5186754a301eb09dd8904b15268d2ba1215943a";
const SOCKET_BRIDGE_VERSION: &str = "3";
const SOCKET_BRIDGE_COMPRESSED_SHA256: &str =
    "3d586358008efa67392582ecb5179fdf15d7e73c95646602487513b8ec28d4bb";
const SOCKET_BRIDGE_EXECUTABLE_SHA256: &str =
    "8d40d567dc976d883bd4ca50440fcf2340a9ad3ecdade32285f4dffff8e8231a";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=bins/fusequota");
    println!("cargo:rerun-if-changed=bins/fusequota.version");
    println!("cargo:rerun-if-changed=bins/socket-bridge");
    println!("cargo:rerun-if-changed=bins/socket-bridge.version");
    println!("cargo:rerun-if-changed=helpers/socket_bridge.rs");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_os == "linux" && target_arch == "x86_64" {
        verify_checked_in_fusequota();
        verify_checked_in_socket_bridge();
        println!("cargo:rustc-env=FUSEQUOTA_VERSION={FUSEQUOTA_VERSION}");
        println!("cargo:rustc-env=FUSEQUOTA_SHA256={FUSEQUOTA_EXECUTABLE_SHA256}");
        println!("cargo:rustc-env=SOCKET_BRIDGE_VERSION={SOCKET_BRIDGE_VERSION}");
        println!("cargo:rustc-env=SOCKET_BRIDGE_SHA256={SOCKET_BRIDGE_EXECUTABLE_SHA256}");
    } else {
        // The checked-in helper is an x86-64 Linux executable. Other targets
        // must configure disk.fuse_quota_binary explicitly instead of silently
        // downloading or attempting to execute a binary for the wrong target.
        println!("cargo:rustc-env=FUSEQUOTA_VERSION=");
        println!("cargo:rustc-env=FUSEQUOTA_SHA256=");
        println!("cargo:rustc-env=SOCKET_BRIDGE_VERSION=");
        println!("cargo:rustc-env=SOCKET_BRIDGE_SHA256=");
    }
}

fn verify_checked_in_socket_bridge() {
    let version = std::fs::read_to_string("bins/socket-bridge.version")
        .expect("missing checked-in bins/socket-bridge.version");
    assert_eq!(
        version.trim(),
        SOCKET_BRIDGE_VERSION,
        "checked-in socket bridge version does not match the pinned build version"
    );

    let compressed = std::fs::read(Path::new("bins/socket-bridge"))
        .expect("missing checked-in compressed bins/socket-bridge");
    assert_digest(
        "compressed socket bridge",
        &compressed,
        SOCKET_BRIDGE_COMPRESSED_SHA256,
    );
    let executable = zstd::decode_all(compressed.as_slice())
        .expect("checked-in socket bridge is not valid zstd");
    assert_digest(
        "decompressed socket bridge executable",
        &executable,
        SOCKET_BRIDGE_EXECUTABLE_SHA256,
    );
}

fn verify_checked_in_fusequota() {
    let version = std::fs::read_to_string("bins/fusequota.version")
        .expect("missing checked-in bins/fusequota.version");
    assert_eq!(
        version.trim(),
        FUSEQUOTA_VERSION,
        "checked-in fusequota version does not match the pinned build version"
    );

    let compressed = std::fs::read(Path::new("bins/fusequota"))
        .expect("missing checked-in compressed bins/fusequota");
    assert_digest(
        "compressed fusequota",
        &compressed,
        FUSEQUOTA_COMPRESSED_SHA256,
    );
    let executable =
        zstd::decode_all(compressed.as_slice()).expect("checked-in fusequota is not valid zstd");
    assert_digest(
        "decompressed fusequota executable",
        &executable,
        FUSEQUOTA_EXECUTABLE_SHA256,
    );
}

fn assert_digest(label: &str, bytes: &[u8], expected: &str) {
    let actual = format!("{:x}", Sha256::digest(bytes));
    assert_eq!(actual, expected, "{label} SHA-256 mismatch");
}
