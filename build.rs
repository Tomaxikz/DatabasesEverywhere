use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const FUSEQUOTA_VERSION: &str = "795d0fe";
const FUSEQUOTA_X86_64_COMPRESSED_SHA256: &str =
    "e1c23625877c4394f2542e7e9b763ff4f9228038d6c497e778b67234ea67d4fa";
const FUSEQUOTA_X86_64_EXECUTABLE_SHA256: &str =
    "102ba39c6157469cfc2dd635f5186754a301eb09dd8904b15268d2ba1215943a";
const FUSEQUOTA_AARCH64_EXECUTABLE_SHA256: &str =
    "fbaf45180b04d6eb8b451ba23eac2dbb62334ee25b5aba203868671b46a5434c";
const FUSEQUOTA_RISCV64_EXECUTABLE_SHA256: &str =
    "66fda6a162918d1ee7727a564cc4aa7debec2ea8e077f9d4f6a88456592767f4";
const SOCKET_BRIDGE_VERSION: &str = "5";
// Pin the reviewed source and both artifact forms. Rust/LLD output is not
// guaranteed to be byte-identical when the compiler host OS changes.
const SOCKET_BRIDGE_SOURCE_SHA256: &str =
    "34a06686c9a42d6f55f280d6f2bd24002152b51867cf0655d126b7e6997cfb19";
const SOCKET_BRIDGE_COMPRESSED_SHA256: &str =
    "3e8f16c994ad8f96ecfe2b4509db2ecac4e40b7368ceb2ff5388e7f5634a4aea";
const SOCKET_BRIDGE_EXECUTABLE_SHA256: &str =
    "be614294f1b7d8e91217c0aaeb8503d4d969fb3868981b224e2d4f621ccc820f";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=bins/fusequota");
    println!("cargo:rerun-if-changed=bins/fusequota.version");
    println!("cargo:rerun-if-changed=bins/socket-bridge");
    println!("cargo:rerun-if-changed=bins/socket-bridge.version");
    println!("cargo:rerun-if-changed=helpers/socket_bridge.rs");
    println!("cargo:rerun-if-env-changed=DBEV_FUSEQUOTA_PAYLOAD");
    println!("cargo:rerun-if-env-changed=DBEV_SOCKET_BRIDGE_PAYLOAD");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_os == "linux" && target_arch == "x86_64" {
        let fusequota = verify_checked_in_fusequota();
        let socket_bridge = verify_checked_in_socket_bridge();
        configure_helpers(
            &fusequota,
            FUSEQUOTA_X86_64_EXECUTABLE_SHA256,
            &socket_bridge,
            SOCKET_BRIDGE_EXECUTABLE_SHA256,
        );
    } else if target_os == "linux" && matches!(target_arch.as_str(), "aarch64" | "riscv64") {
        verify_socket_bridge_source();
        let fusequota_sha256 = fusequota_sha256(&target_arch);
        let (fusequota, _) = verify_external_payload(
            "FuseQuota",
            "DBEV_FUSEQUOTA_PAYLOAD",
            Some(fusequota_sha256),
        );
        let (socket_bridge, socket_bridge_sha256) =
            verify_external_payload("socket bridge", "DBEV_SOCKET_BRIDGE_PAYLOAD", None);
        configure_helpers(
            &fusequota,
            fusequota_sha256,
            &socket_bridge,
            &socket_bridge_sha256,
        );
    } else {
        // The daemon is Linux-only. Keep unsupported development targets
        // buildable without embedding an executable for the wrong platform.
        println!("cargo:rustc-env=FUSEQUOTA_PAYLOAD_PATH=");
        println!("cargo:rustc-env=FUSEQUOTA_VERSION=");
        println!("cargo:rustc-env=FUSEQUOTA_SHA256=");
        println!("cargo:rustc-env=SOCKET_BRIDGE_PAYLOAD_PATH=");
        println!("cargo:rustc-env=SOCKET_BRIDGE_VERSION=");
        println!("cargo:rustc-env=SOCKET_BRIDGE_SHA256=");
    }
}

fn configure_helpers(
    fusequota: &Path,
    fusequota_sha256: &str,
    socket_bridge: &Path,
    socket_bridge_sha256: &str,
) {
    println!(
        "cargo:rustc-env=FUSEQUOTA_PAYLOAD_PATH={}",
        printable_path(fusequota)
    );
    println!("cargo:rustc-env=FUSEQUOTA_VERSION={FUSEQUOTA_VERSION}");
    println!("cargo:rustc-env=FUSEQUOTA_SHA256={fusequota_sha256}");
    println!(
        "cargo:rustc-env=SOCKET_BRIDGE_PAYLOAD_PATH={}",
        printable_path(socket_bridge)
    );
    println!("cargo:rustc-env=SOCKET_BRIDGE_VERSION={SOCKET_BRIDGE_VERSION}");
    println!("cargo:rustc-env=SOCKET_BRIDGE_SHA256={socket_bridge_sha256}");
}

fn fusequota_sha256(target_arch: &str) -> &'static str {
    match target_arch {
        "aarch64" => FUSEQUOTA_AARCH64_EXECUTABLE_SHA256,
        "riscv64" => FUSEQUOTA_RISCV64_EXECUTABLE_SHA256,
        _ => panic!("unsupported cross-release architecture {target_arch}"),
    }
}

fn verify_external_payload(
    label: &str,
    variable: &str,
    expected_sha256: Option<&str>,
) -> (PathBuf, String) {
    let path = std::env::var_os(variable)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!("{variable} is required when building a Linux ARM64 or RISC-V release")
        });
    let path = canonical_payload_path(&path, label);
    println!("cargo:rerun-if-changed={}", printable_path(&path));
    let compressed = std::fs::read(&path)
        .unwrap_or_else(|error| panic!("failed to read {label} payload: {error}"));
    let executable = zstd::decode_all(compressed.as_slice())
        .unwrap_or_else(|error| panic!("{label} payload is not valid zstd: {error}"));
    let actual_sha256 = format!("{:x}", Sha256::digest(&executable));
    if let Some(expected_sha256) = expected_sha256 {
        assert_eq!(
            actual_sha256, expected_sha256,
            "decompressed {label} executable SHA-256 mismatch"
        );
    }
    (path, actual_sha256)
}

fn printable_path(path: &Path) -> &str {
    let value = path
        .to_str()
        .unwrap_or_else(|| panic!("helper path is not valid UTF-8: {}", path.display()));
    assert!(
        !value.contains(['\r', '\n']),
        "helper path must not contain CR or LF characters"
    );
    value
}

fn canonical_payload_path(path: &Path, label: &str) -> PathBuf {
    let path = std::fs::canonicalize(path)
        .unwrap_or_else(|error| panic!("failed to resolve {label} payload path: {error}"));
    let metadata = std::fs::metadata(&path)
        .unwrap_or_else(|error| panic!("failed to inspect {label} payload: {error}"));
    assert!(metadata.is_file(), "{label} payload must be a regular file");
    path
}

fn verify_socket_bridge_source() {
    let source = std::fs::read("helpers/socket_bridge.rs")
        .expect("missing checked-in helpers/socket_bridge.rs");
    assert_digest("socket bridge source", &source, SOCKET_BRIDGE_SOURCE_SHA256);
}

fn verify_checked_in_socket_bridge() -> PathBuf {
    let version = std::fs::read_to_string("bins/socket-bridge.version")
        .expect("missing checked-in bins/socket-bridge.version");
    assert_eq!(
        version.trim(),
        SOCKET_BRIDGE_VERSION,
        "checked-in socket bridge version does not match the pinned build version"
    );

    verify_socket_bridge_source();

    let path = canonical_payload_path(Path::new("bins/socket-bridge"), "socket bridge");
    let compressed =
        std::fs::read(&path).expect("missing checked-in compressed bins/socket-bridge");
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
    path
}

fn verify_checked_in_fusequota() -> PathBuf {
    let version = std::fs::read_to_string("bins/fusequota.version")
        .expect("missing checked-in bins/fusequota.version");
    assert_eq!(
        version.trim(),
        FUSEQUOTA_VERSION,
        "checked-in fusequota version does not match the pinned build version"
    );

    let path = canonical_payload_path(Path::new("bins/fusequota"), "FuseQuota");
    let compressed = std::fs::read(&path).expect("missing checked-in compressed bins/fusequota");
    assert_digest(
        "compressed fusequota",
        &compressed,
        FUSEQUOTA_X86_64_COMPRESSED_SHA256,
    );
    let executable =
        zstd::decode_all(compressed.as_slice()).expect("checked-in fusequota is not valid zstd");
    assert_digest(
        "decompressed fusequota executable",
        &executable,
        FUSEQUOTA_X86_64_EXECUTABLE_SHA256,
    );
    path
}

fn assert_digest(label: &str, bytes: &[u8], expected: &str) {
    let actual = format!("{:x}", Sha256::digest(bytes));
    assert_eq!(actual, expected, "{label} SHA-256 mismatch");
}
