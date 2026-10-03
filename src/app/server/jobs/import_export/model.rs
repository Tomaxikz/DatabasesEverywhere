use super::*;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ImportExportJob {
    pub job_id: String,
    pub instance_id: String,
    pub action: ImportExportAction,
    pub status: ImportExportStatus,
    pub artifact_path: Option<String>,
    #[serde(skip)]
    pub replay_options: Option<String>,
    pub error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ImportExportAction {
    Import,
    Export,
}

impl ImportExportAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Export => "export",
        }
    }

    pub fn parse(value: &str) -> Result<Self, JobParseError> {
        match value {
            "import" => Ok(Self::Import),
            "export" => Ok(Self::Export),
            value => Err(JobParseError::UnknownAction(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ImportExportStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
}

impl ImportExportStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    pub fn parse(value: &str) -> Result<Self, JobParseError> {
        match value {
            "queued" => Ok(Self::Queued),
            "running" => Ok(Self::Running),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            value => Err(JobParseError::UnknownStatus(value.to_string())),
        }
    }

    pub(super) fn is_completed(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed)
    }
}
