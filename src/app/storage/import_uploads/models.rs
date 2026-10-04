use super::ImportUploadParseError;
use crate::databases::protocol::Protocol;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportUploadState {
    Uploading,
    Uploaded,
    Processing,
    Ready,
    Failed,
    Importing,
    Consumed,
    Deleting,
}

impl ImportUploadState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Uploading => "uploading",
            Self::Uploaded => "uploaded",
            Self::Processing => "processing",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Importing => "importing",
            Self::Consumed => "consumed",
            Self::Deleting => "deleting",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ImportUploadParseError> {
        match value {
            "uploading" => Ok(Self::Uploading),
            "uploaded" => Ok(Self::Uploaded),
            "processing" => Ok(Self::Processing),
            "ready" => Ok(Self::Ready),
            "failed" => Ok(Self::Failed),
            "importing" => Ok(Self::Importing),
            "consumed" => Ok(Self::Consumed),
            "deleting" => Ok(Self::Deleting),
            _ => Err(ImportUploadParseError::State(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportUploadArchiveFormat {
    Plain,
    Gzip,
    Bzip2,
    Tar,
    TarGzip,
    Zip,
}

impl ImportUploadArchiveFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Gzip => "gzip",
            Self::Bzip2 => "bzip2",
            Self::Tar => "tar",
            Self::TarGzip => "tar.gz",
            Self::Zip => "zip",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ImportUploadParseError> {
        match value {
            "plain" => Ok(Self::Plain),
            "gzip" => Ok(Self::Gzip),
            "bzip2" => Ok(Self::Bzip2),
            "tar" => Ok(Self::Tar),
            "tar.gz" => Ok(Self::TarGzip),
            "zip" => Ok(Self::Zip),
            _ => Err(ImportUploadParseError::ArchiveFormat(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportUpload {
    pub upload_id: String,
    pub instance_id: String,
    pub original_filename: String,
    pub stored_filename: String,
    pub protocol: Protocol,
    pub archive_format: Option<ImportUploadArchiveFormat>,
    pub state: ImportUploadState,
    pub size_bytes: u64,
    pub sha256: Option<String>,
    pub catalog_json: Option<String>,
    pub last_error: Option<String>,
    pub claimed_job_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewImportUpload {
    pub upload_id: String,
    pub instance_id: String,
    pub original_filename: String,
    pub stored_filename: String,
    pub protocol: Protocol,
    pub archive_format: Option<ImportUploadArchiveFormat>,
    pub size_bytes: u64,
    pub created_at: String,
    pub expires_at: String,
}

impl NewImportUpload {
    pub(super) fn into_upload(self) -> ImportUpload {
        ImportUpload {
            upload_id: self.upload_id,
            instance_id: self.instance_id,
            original_filename: self.original_filename,
            stored_filename: self.stored_filename,
            protocol: self.protocol,
            archive_format: self.archive_format,
            state: ImportUploadState::Uploading,
            size_bytes: self.size_bytes,
            sha256: None,
            catalog_json: None,
            last_error: None,
            claimed_job_id: None,
            updated_at: self.created_at.clone(),
            created_at: self.created_at,
            expires_at: self.expires_at,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportUploadUsage {
    pub active_count: u64,
    pub active_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportUploadAdmission {
    Admitted(Box<ImportUpload>),
    InstanceCountExceeded {
        active_count: u64,
        limit: u64,
    },
    TotalBytesExceeded {
        active_bytes: u64,
        requested_bytes: u64,
        limit: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptedImportDisposition {
    Ready,
    Failed,
}
