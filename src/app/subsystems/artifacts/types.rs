use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DownloadKind {
    Artifact,
    Backup,
}

impl DownloadKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Artifact => "artifact",
            Self::Backup => "backup",
        }
    }

    pub(super) fn download_path(self, instance_id: &str, artifact_id: &str, token: &str) -> String {
        match self {
            Self::Artifact => format!(
                "/api/instances/{instance_id}/artifacts/{artifact_id}/download?token={token}"
            ),
            Self::Backup => {
                format!("/api/instances/{instance_id}/backups/{artifact_id}/download?token={token}")
            }
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ArtifactInfo {
    pub id: String,
    pub instance_id: String,
    pub size_bytes: u64,
    pub modified_at: String,
    pub sha256: String,
}

#[derive(Debug, Serialize)]
pub struct RetentionResponse {
    pub deleted: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DeleteArtifactResponse {
    pub id: String,
    pub deleted: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateDownloadRequest {
    #[serde(default)]
    pub expires_in_seconds: Option<i64>,
    #[serde(default)]
    pub single_use: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct DownloadUrlResponse {
    pub url: String,
    pub expires_at_unix: i64,
    pub single_use: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadQuery {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DownloadClaims {
    pub(super) iss: String,
    pub(super) aud: String,
    pub(super) sub: String,
    pub(super) purpose: String,
    pub(super) kind: String,
    pub(super) artifact: String,
    pub(super) instance_id: String,
    pub(super) single_use: bool,
    pub(super) iat: i64,
    pub(super) nbf: i64,
    pub(super) exp: i64,
    pub(super) jti: String,
}
