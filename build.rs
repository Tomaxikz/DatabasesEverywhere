use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const FUSEQUOTA_X86_64_COMPRESSED_SHA256: &str =
    "1c03574bd8b4471f79a11c745e7d9ba360a8f8bb76aeb499c0f4184ea6c32939";
const FUSEQUOTA_X86_64_EXECUTABLE_SHA256: &str =
    "b339e7d89fccc97c85e8575df61b55564f77091da822b421f23f07631d189992";
const FUSEQUOTA_AARCH64_EXECUTABLE_SHA256: &str =
    "e5a8702c91c43e10377bfaadb856f0d8c8e6d7eb4e8f54a0fbde7a3066f8554a";
const FUSEQUOTA_RISCV64_EXECUTABLE_SHA256: &str =
    "574c6fbfbda83ee04cd4b870d3dd0e405d185c7f68524c0a81edfeb287b020b2";
// Pin the reviewed source and both artifact forms. Rust/LLD output is not
// guaranteed to be byte-identical when the compiler host OS changes.
const SOCKET_BRIDGE_SOURCE_SHA256: &str =
    "1c57ef410182639fa314e2a06e1efb2496fde7214ec4d9296d68f5abae092d62";
const SOCKET_BRIDGE_COMPRESSED_SHA256: &str =
    "cd351642cfa603eae85925d2180345024fcd2ae406da0e40c0765ec90aa3e093";
const SOCKET_BRIDGE_EXECUTABLE_SHA256: &str =
    "0432a7ed8d5498645643dc2eee1b0e435097a1748619cf811cb8b2e6e1c154c8";

const FUSEQUOTA_PAYLOAD: &str = "helpers/payloads/fusequota.zst";
const FUSEQUOTA_VERSION_FILE: &str = "helpers/payloads/fusequota.version";
const SOCKET_BRIDGE_PAYLOAD: &str = "helpers/payloads/socket-bridge.zst";
const SOCKET_BRIDGE_SOURCE: &str = "helpers/socket_bridge.rs";
const SOCKET_BRIDGE_VERSION_FILE: &str = "helpers/payloads/socket-bridge.version";

fn main() -> Result<(), String> {
    println!("cargo:rerun-if-changed=build.rs");
    for path in [
        FUSEQUOTA_PAYLOAD,
        FUSEQUOTA_VERSION_FILE,
        SOCKET_BRIDGE_PAYLOAD,
        SOCKET_BRIDGE_SOURCE,
        SOCKET_BRIDGE_VERSION_FILE,
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-env-changed=DBEV_FUSEQUOTA_PAYLOAD");
    println!("cargo:rerun-if-env-changed=DBEV_SOCKET_BRIDGE_PAYLOAD");

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_os == "linux" && target_arch == "x86_64" {
        let fusequota = verify_checked_in_fusequota()?;
        let socket_bridge = verify_checked_in_socket_bridge()?;
        configure_helpers(
            &fusequota,
            FUSEQUOTA_X86_64_EXECUTABLE_SHA256,
            &socket_bridge,
            SOCKET_BRIDGE_EXECUTABLE_SHA256,
        )?;
    } else if target_os == "linux" && matches!(target_arch.as_str(), "aarch64" | "riscv64") {
        verify_socket_bridge_source()?;
        let fusequota_sha256 = fusequota_sha256(&target_arch)?;
        let (fusequota, _) = verify_external_payload(
            "FuseQuota",
            "DBEV_FUSEQUOTA_PAYLOAD",
            Some(fusequota_sha256),
        )?;
        let (socket_bridge, socket_bridge_sha256) =
            verify_external_payload("socket bridge", "DBEV_SOCKET_BRIDGE_PAYLOAD", None)?;
        configure_helpers(
            &fusequota,
            fusequota_sha256,
            &socket_bridge,
            &socket_bridge_sha256,
        )?;
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
    Ok(())
}

fn configure_helpers(
    fusequota: &Path,
    fusequota_sha256: &str,
    socket_bridge: &Path,
    socket_bridge_sha256: &str,
) -> Result<(), String> {
    let fusequota_version = read_helper_version(FUSEQUOTA_VERSION_FILE, "FuseQuota")?;
    let socket_bridge_version = read_helper_version(SOCKET_BRIDGE_VERSION_FILE, "socket bridge")?;
    println!(
        "cargo:rustc-env=FUSEQUOTA_PAYLOAD_PATH={}",
        printable_path(fusequota)?
    );
    println!("cargo:rustc-env=FUSEQUOTA_VERSION={fusequota_version}");
    println!("cargo:rustc-env=FUSEQUOTA_SHA256={fusequota_sha256}");
    println!(
        "cargo:rustc-env=SOCKET_BRIDGE_PAYLOAD_PATH={}",
        printable_path(socket_bridge)?
    );
    println!("cargo:rustc-env=SOCKET_BRIDGE_VERSION={socket_bridge_version}");
    println!("cargo:rustc-env=SOCKET_BRIDGE_SHA256={socket_bridge_sha256}");
    Ok(())
}

fn read_helper_version(path: &str, label: &str) -> Result<String, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|error| format!("missing checked-in {path}: {error}"))?;
    let version = contents.trim();
    if version.is_empty()
        || version.len() > 64
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(format!("{label} version in {path} is invalid"));
    }
    Ok(version.to_owned())
}

fn fusequota_sha256(target_arch: &str) -> Result<&'static str, String> {
    match target_arch {
        "aarch64" => Ok(FUSEQUOTA_AARCH64_EXECUTABLE_SHA256),
        "riscv64" => Ok(FUSEQUOTA_RISCV64_EXECUTABLE_SHA256),
        _ => Err(format!(
            "unsupported cross-release architecture {target_arch}"
        )),
    }
}

fn verify_external_payload(
    label: &str,
    variable: &str,
    expected_sha256: Option<&str>,
) -> Result<(PathBuf, String), String> {
    let path = std::env::var_os(variable)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| {
            format!("{variable} is required when building a Linux ARM64 or RISC-V release")
        })?;
    let path = canonical_payload_path(&path, label)?;
    println!("cargo:rerun-if-changed={}", printable_path(&path)?);
    let compressed =
        std::fs::read(&path).map_err(|error| format!("failed to read {label} payload: {error}"))?;
    let executable = zstd::decode_all(compressed.as_slice())
        .map_err(|error| format!("{label} payload is not valid zstd: {error}"))?;
    let actual_sha256 = sha256_hex(&executable);
    if expected_sha256.is_some_and(|expected| expected != actual_sha256) {
        return Err(format!("decompressed {label} executable SHA-256 mismatch"));
    }
    Ok((path, actual_sha256))
}

fn printable_path(path: &Path) -> Result<&str, String> {
    let value = path
        .to_str()
        .ok_or_else(|| format!("helper path is not valid UTF-8: {}", path.display()))?;
    if value.contains(['\r', '\n']) {
        return Err("helper path must not contain CR or LF characters".into());
    }
    Ok(value)
}

fn canonical_payload_path(path: &Path, label: &str) -> Result<PathBuf, String> {
    let path = std::fs::canonicalize(path)
        .map_err(|error| format!("failed to resolve {label} payload path: {error}"))?;
    let metadata = std::fs::metadata(&path)
        .map_err(|error| format!("failed to inspect {label} payload: {error}"))?;
    if !metadata.is_file() {
        return Err(format!("{label} payload must be a regular file"));
    }
    Ok(path)
}

fn verify_socket_bridge_source() -> Result<(), String> {
    let source = std::fs::read(SOCKET_BRIDGE_SOURCE)
        .map_err(|error| format!("missing checked-in {SOCKET_BRIDGE_SOURCE}: {error}"))?;
    verify_digest("socket bridge source", &source, SOCKET_BRIDGE_SOURCE_SHA256)
}

fn verify_checked_in_socket_bridge() -> Result<PathBuf, String> {
    verify_socket_bridge_source()?;

    let path = canonical_payload_path(Path::new(SOCKET_BRIDGE_PAYLOAD), "socket bridge")?;
    let compressed = std::fs::read(&path)
        .map_err(|error| format!("missing checked-in {SOCKET_BRIDGE_PAYLOAD}: {error}"))?;
    verify_digest(
        "compressed socket bridge",
        &compressed,
        SOCKET_BRIDGE_COMPRESSED_SHA256,
    )?;
    let executable = zstd::decode_all(compressed.as_slice())
        .map_err(|error| format!("checked-in socket bridge is not valid zstd: {error}"))?;
    verify_digest(
        "decompressed socket bridge executable",
        &executable,
        SOCKET_BRIDGE_EXECUTABLE_SHA256,
    )?;
    Ok(path)
}

fn verify_checked_in_fusequota() -> Result<PathBuf, String> {
    let path = canonical_payload_path(Path::new(FUSEQUOTA_PAYLOAD), "FuseQuota")?;
    let compressed = std::fs::read(&path)
        .map_err(|error| format!("missing checked-in {FUSEQUOTA_PAYLOAD}: {error}"))?;
    verify_digest(
        "compressed fusequota",
        &compressed,
        FUSEQUOTA_X86_64_COMPRESSED_SHA256,
    )?;
    let executable = zstd::decode_all(compressed.as_slice())
        .map_err(|error| format!("checked-in fusequota is not valid zstd: {error}"))?;
    verify_digest(
        "decompressed fusequota executable",
        &executable,
        FUSEQUOTA_X86_64_EXECUTABLE_SHA256,
    )?;
    Ok(path)
}

fn verify_digest(label: &str, bytes: &[u8], expected: &str) -> Result<(), String> {
    let actual = sha256_hex(bytes);
    if actual != expected {
        return Err(format!(
            "{label} SHA-256 mismatch: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    // The build script runs before the application's shared helpers exist.
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
