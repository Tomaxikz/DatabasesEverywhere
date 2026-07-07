use std::{
    io::{Error, ErrorKind},
    path::PathBuf,
};

use tokio::io::AsyncWriteExt;

pub const FUSEQUOTA_VERSION: &str = env!("FUSEQUOTA_VERSION");
static FUSEQUOTA_BIN: &[u8] = include_bytes!("../bins/fusequota");
static BIN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub fn embedded_fusequota_available() -> bool {
    !FUSEQUOTA_BIN.is_empty() && !FUSEQUOTA_VERSION.trim().is_empty()
}

pub async fn get_fusequota_bin_path() -> Result<PathBuf, Error> {
    if !embedded_fusequota_available() {
        return Err(Error::new(
            ErrorKind::NotFound,
            "embedded fusequota binary is not available in this build",
        ));
    }

    let bin_path = std::env::temp_dir().join(format!(
        "databases-everywhere-fusequota-{}",
        FUSEQUOTA_VERSION
    ));
    if tokio::fs::metadata(&bin_path).await.is_ok() {
        return Ok(bin_path);
    }

    let _lock = BIN_LOCK.lock().await;
    if tokio::fs::metadata(&bin_path).await.is_ok() {
        return Ok(bin_path);
    }

    let tmp_path = bin_path.with_extension("tmp");
    let decompressed =
        tokio::task::spawn_blocking(|| zstd::decode_all(FUSEQUOTA_BIN).map_err(Error::other))
            .await
            .map_err(Error::other)??;

    let mut file = tokio::fs::File::create(&tmp_path).await?;
    file.write_all(&decompressed).await?;
    file.flush().await?;
    drop(file);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755)).await?;
    }

    tokio::fs::rename(&tmp_path, &bin_path).await?;
    Ok(bin_path)
}
