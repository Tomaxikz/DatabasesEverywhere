use super::*;

pub(super) struct DownloadStream {
    pub(super) inner: ReaderStream<File>,
    pub(super) _permit: ArtifactDownloadPermit,
    pub(super) cleanup: Option<PathBuf>,
    pub(super) _backup: Option<crate::instance::backup::MaterializedBackup>,
}

#[derive(Debug)]
pub(super) struct DownloadableArtifact {
    pub(super) path: PathBuf,
    pub(super) one_use: bool,
}

impl Stream for DownloadStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_next(context)
    }
}

impl Drop for DownloadStream {
    fn drop(&mut self) {
        let Some(path) = self.cleanup.take() else {
            return;
        };
        if let Err(error) = one_use::remove_download_spool_sync(&path) {
            tracing::warn!(
                path = %path.display(),
                %error,
                "failed to remove temporary download spool"
            );
        }
    }
}
