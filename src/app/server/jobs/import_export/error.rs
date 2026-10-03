#[derive(Debug, thiserror::Error)]
pub enum ImportExportError {
    #[error("io failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("task failed: {0}")]
    Join(String),
    #[error("invalid archive: {0}")]
    InvalidArchive(String),
}

#[derive(Debug, thiserror::Error)]
pub enum JobParseError {
    #[error("unknown import/export action {0}")]
    UnknownAction(String),
    #[error("unknown import/export status {0}")]
    UnknownStatus(String),
}
