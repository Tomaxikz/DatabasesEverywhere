//! Bounded reads of the PEM files tether is configured with.

use std::{
    fs::{self, File},
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use anyhow::{Context, bail};

/// Certificates, chains and keys are a few KiB; anything bigger is not one.
const MAX_PEM_BYTES: u64 = 1024 * 1024;

/// Reads a regular file of at most 1 MiB. The type is checked through symlinks before the
/// file is opened and the open does not block, so a FIFO or device in that place is
/// refused instead of hanging startup.
pub(super) async fn read(what: &'static str, path: &str) -> anyhow::Result<Vec<u8>> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || read_bounded(Path::new(&path)))
        .await
        .context("PEM reader panicked")?
        .with_context(|| format!("tether {what}"))
}

fn read_bounded(path: &Path) -> anyhow::Result<Vec<u8>> {
    let shown = path.display();
    let metadata = fs::metadata(path).with_context(|| format!("cannot stat {shown}"))?;
    if !metadata.is_file() {
        bail!("{shown} is not a regular file");
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("cannot open {shown}"))?;
    read_open(file, shown)
}

fn read_open(file: File, shown: std::path::Display<'_>) -> anyhow::Result<Vec<u8>> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("{shown} is not a regular file");
    }
    if metadata.len() > MAX_PEM_BYTES {
        bail!("{shown} is larger than {MAX_PEM_BYTES} bytes");
    }
    let mut bytes = Vec::new();
    file.take(MAX_PEM_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {shown}"))?;
    if bytes.len() as u64 > MAX_PEM_BYTES {
        bail!("{shown} is larger than {MAX_PEM_BYTES} bytes");
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_regular_files_and_refuses_everything_else() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let ok = dir.path().join("ok.pem");
        fs::write(&ok, b"pem")?;
        assert_eq!(read("ca", ok.to_str().unwrap_or_default()).await?, b"pem");

        let link = dir.path().join("link.pem");
        std::os::unix::fs::symlink(&ok, &link)?;
        assert_eq!(read("ca", link.to_str().unwrap_or_default()).await?, b"pem");

        let big = dir.path().join("big.pem");
        fs::write(&big, vec![b'x'; MAX_PEM_BYTES as usize + 1])?;
        let fifo = dir.path().join("fifo.pem");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()?
                .success()
        );
        for refused in [
            big,
            fifo,
            dir.path().to_path_buf(),
            dir.path().join("missing.pem"),
        ] {
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                read("key", refused.to_str().unwrap_or_default()),
            )
            .await
            .expect("must not block");
            let error = format!("{:#}", result.expect_err("refused"));
            assert!(error.contains("tether key"), "{error}");
        }
        Ok(())
    }
}
