use serde::Deserialize;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

const DEFAULT_FUSEQUOTA_RELEASE: &str = "795d0fe";

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=FUSEQUOTA_RELEASE");

    let bin_dir = Path::new("bins");
    std::fs::create_dir_all(bin_dir).ok();

    let bin_path = bin_dir.join("fusequota");
    let version_path = bin_dir.join("fusequota.version");
    let existing_version = std::fs::read_to_string(&version_path)
        .map(|version| version.trim().to_string())
        .unwrap_or_default();
    let requested_release = std::env::var("FUSEQUOTA_RELEASE")
        .unwrap_or_else(|_| DEFAULT_FUSEQUOTA_RELEASE.to_string());
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let version_matches = !existing_version.is_empty()
        && (requested_release == existing_version || requested_release == "latest");

    let mut final_version = existing_version.clone();
    if target_os == "linux"
        && (!bin_path.exists() || !version_matches || requested_release == "latest")
        && let Some((tag, url)) = fetch_release_metadata(&requested_release)
        && let Ok(binary) = download_asset(&url)
        && let Ok(compressed) = zstd::encode_all(binary.as_slice(), 19)
    {
        let mut file = File::create(&bin_path).expect("failed to create bins/fusequota");
        file.write_all(&compressed)
            .expect("failed to write bins/fusequota");
        std::fs::write(&version_path, &tag).ok();
        final_version = tag;
    }

    if !bin_path.exists() {
        File::create(&bin_path).ok();
    }

    println!("cargo:rustc-env=FUSEQUOTA_VERSION={final_version}");
}

fn fetch_release_metadata(requested_release: &str) -> Option<(String, String)> {
    let arch = release_arch()?;
    let url = if requested_release == "latest" {
        "https://api.github.com/repos/calagopus/fusequota/releases/latest".to_string()
    } else {
        format!(
            "https://api.github.com/repos/calagopus/fusequota/releases/tags/{requested_release}"
        )
    };
    let mut response = ureq::get(&url)
        .header("User-Agent", "databases-everywhere-build")
        .call()
        .ok()?;
    let release: GithubRelease = serde_json::from_reader(response.body_mut().as_reader()).ok()?;
    let expected_name = format!("fusequota-{arch}-linux");
    let asset = release
        .assets
        .into_iter()
        .find(|asset| asset.name == expected_name)?;
    Some((release.tag_name, asset.browser_download_url))
}

fn download_asset(url: &str) -> Result<Vec<u8>, std::io::Error> {
    let mut response = ureq::get(url)
        .header("User-Agent", "databases-everywhere-build")
        .call()
        .map_err(std::io::Error::other)?;
    let mut body = Vec::new();
    response.body_mut().as_reader().read_to_end(&mut body)?;
    Ok(body)
}

fn release_arch() -> Option<&'static str> {
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").ok()?;
    match arch.as_str() {
        "x86_64" => Some("x86_64"),
        "aarch64" => Some("aarch64"),
        "riscv64" => Some("riscv64"),
        "powerpc64"
            if std::env::var("CARGO_CFG_TARGET_ENDIAN").ok().as_deref() == Some("little") =>
        {
            Some("ppc64le")
        }
        _ => None,
    }
}
