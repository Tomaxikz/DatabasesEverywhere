use std::{
    collections::HashMap,
    io::Read,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use axum::{
    Json,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, Uri, header},
    response::{IntoResponse, Response},
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{fs::File, sync::Mutex};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::api::{
    handlers::{ApiError, ApiResult, authorize_scope},
    routes::AppState,
};
use crate::{
    auth::scopes,
    constants::jwt::{AUDIENCE, ISSUER},
    jobs::import_export::{ImportExportAction, ImportExportStatus},
    shared::files::{is_safe_flat_file_name, safe_header_filename},
};

const DOWNLOAD_PURPOSE: &str = "artifact_download";
const DEFAULT_DOWNLOAD_TTL_SECONDS: i64 = 120;
const MAX_DOWNLOAD_TTL_SECONDS: i64 = 900;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownloadKind {
    Artifact,
    Backup,
}

impl DownloadKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Artifact => "artifact",
            Self::Backup => "backup",
        }
    }

    fn signed_path(self, token: &str) -> String {
        match self {
            Self::Artifact => format!("/api/artifacts/download-signed?token={token}"),
            Self::Backup => format!("/api/backups/download-signed?token={token}"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ArtifactInfo {
    pub name: String,
    pub path: String,
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
    pub name: String,
    pub deleted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ArtifactDownloadTickets {
    consumed: Arc<Mutex<HashMap<String, i64>>>,
}

impl ArtifactDownloadTickets {
    pub async fn consume(&self, jti: &str, exp: i64) -> bool {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut consumed = self.consumed.lock().await;
        consumed.retain(|_, expires_at| *expires_at >= now);
        if consumed.contains_key(jti) {
            return false;
        }
        consumed.insert(jti.to_string(), exp);
        true
    }
}

#[derive(Debug, Deserialize)]
pub struct IssueDownloadTokenRequest {
    pub instance_id: String,
    #[serde(default)]
    pub expires_in_seconds: Option<i64>,
    #[serde(default)]
    pub single_use: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct IssueDownloadTokenResponse {
    pub token_type: &'static str,
    pub token: String,
    pub url: String,
    pub download_path: String,
    pub expires_at_unix: i64,
    pub single_use: bool,
}

#[derive(Debug, Deserialize)]
pub struct SignedDownloadQuery {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DownloadClaims {
    iss: String,
    aud: String,
    sub: String,
    purpose: String,
    kind: String,
    artifact: String,
    instance_id: String,
    single_use: bool,
    iat: i64,
    nbf: i64,
    exp: i64,
    jti: String,
}

pub async fn list_artifacts(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<Vec<ArtifactInfo>> {
    authorize_scope(&state, &headers, &uri, scopes::ARTIFACTS_READ)?;
    Ok(Json(read_artifacts(&state).await?))
}

pub async fn delete_artifact(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<DeleteArtifactResponse> {
    authorize_scope(&state, &headers, &uri, scopes::ARTIFACTS_WRITE)?;
    let path = artifact_path(&state, &name)?;
    match tokio::fs::remove_file(&path).await {
        Ok(()) => {
            tracing::info!(event = "audit artifact_deleted", artifact = %name);
            Ok(Json(DeleteArtifactResponse {
                name,
                deleted: true,
            }))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(ApiError::NotFound),
        Err(error) => Err(ApiError::Runtime(format!(
            "failed to delete artifact: {error}"
        ))),
    }
}

pub async fn apply_retention(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<RetentionResponse> {
    authorize_scope(&state, &headers, &uri, scopes::ARTIFACTS_WRITE)?;
    let mut artifacts = read_artifacts(&state).await?;
    artifacts.sort_by(|left, right| right.modified_at.cmp(&left.modified_at));
    let cutoff = OffsetDateTime::now_utc()
        - time::Duration::days(state.config.artifacts.retention_max_age_days as i64);
    let keep_latest = state.config.artifacts.retention_keep_latest;
    let mut deleted = Vec::new();

    for (index, artifact) in artifacts.into_iter().enumerate() {
        let modified = OffsetDateTime::parse(&artifact.modified_at, &Rfc3339)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        if index < keep_latest && modified >= cutoff {
            continue;
        }
        let path = artifact_path(&state, &artifact.name)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => deleted.push(artifact.name),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ApiError::Runtime(format!(
                    "failed to delete artifact {}: {error}",
                    artifact.name
                )));
            }
        }
    }

    tracing::info!(event = "audit artifact_retention_applied", deleted = ?deleted);
    Ok(Json(RetentionResponse { deleted }))
}

pub async fn issue_artifact_download_token(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    uri: Uri,
    Json(request): Json<IssueDownloadTokenRequest>,
) -> ApiResult<IssueDownloadTokenResponse> {
    authorize_scope(&state, &headers, &uri, scopes::ARTIFACTS_READ)?;
    issue_download_token(&state, &headers, &name, request, DownloadKind::Artifact).await
}

pub async fn issue_backup_download_token(
    State(state): State<AppState>,
    Path(name): Path<String>,
    headers: HeaderMap,
    uri: Uri,
    Json(request): Json<IssueDownloadTokenRequest>,
) -> ApiResult<IssueDownloadTokenResponse> {
    authorize_scope(&state, &headers, &uri, scopes::BACKUPS_READ)?;
    issue_download_token(&state, &headers, &name, request, DownloadKind::Backup).await
}

pub(crate) async fn issue_artifact_download_ticket(
    state: &AppState,
    headers: &HeaderMap,
    name: &str,
    instance_id: &str,
    expires_in_seconds: Option<i64>,
    single_use: bool,
) -> Result<IssueDownloadTokenResponse, ApiError> {
    issue_download_token(
        state,
        headers,
        name,
        IssueDownloadTokenRequest {
            instance_id: instance_id.to_string(),
            expires_in_seconds,
            single_use: Some(single_use),
        },
        DownloadKind::Artifact,
    )
    .await
    .map(|Json(response)| response)
}

pub async fn signed_artifact_download(
    State(state): State<AppState>,
    Query(query): Query<SignedDownloadQuery>,
) -> Result<Response, ApiError> {
    signed_download(&state, &query.token, DownloadKind::Artifact).await
}

pub async fn signed_backup_download(
    State(state): State<AppState>,
    Query(query): Query<SignedDownloadQuery>,
) -> Result<Response, ApiError> {
    signed_download(&state, &query.token, DownloadKind::Backup).await
}

async fn issue_download_token(
    state: &AppState,
    headers: &HeaderMap,
    name: &str,
    request: IssueDownloadTokenRequest,
    kind: DownloadKind,
) -> ApiResult<IssueDownloadTokenResponse> {
    validate_artifact_name(name)?;
    let instance_id = request.instance_id.trim();
    if instance_id.is_empty() {
        return Err(ApiError::BadRequest(
            "instance_id must not be empty".to_string(),
        ));
    }
    let ttl_seconds = request
        .expires_in_seconds
        .unwrap_or(DEFAULT_DOWNLOAD_TTL_SECONDS);
    if !(1..=MAX_DOWNLOAD_TTL_SECONDS).contains(&ttl_seconds) {
        return Err(ApiError::BadRequest(format!(
            "expires_in_seconds must be between 1 and {MAX_DOWNLOAD_TTL_SECONDS}"
        )));
    }
    let single_use = request.single_use.unwrap_or(true);
    match kind {
        DownloadKind::Artifact => {
            verified_artifact_path(state, name).await?;
            ensure_artifact_belongs_to_instance(state, name, instance_id).await?;
        }
        DownloadKind::Backup => {
            crate::api::backups::verified_backup_path_for_instance(state, name, instance_id)
                .await?;
        }
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let exp = now + ttl_seconds;
    let claims = DownloadClaims {
        iss: ISSUER.to_string(),
        aud: AUDIENCE.to_string(),
        sub: "panel".to_string(),
        purpose: DOWNLOAD_PURPOSE.to_string(),
        kind: kind.as_str().to_string(),
        artifact: name.to_string(),
        instance_id: instance_id.to_string(),
        single_use,
        iat: now,
        nbf: now,
        exp,
        jti: Uuid::new_v4().to_string(),
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(state.config.websocket_jwt_secret()),
    )
    .map_err(|error| ApiError::Runtime(format!("failed to issue download token: {error}")))?;
    let path_url = kind.signed_path(&token);
    let url = absolute_url(headers, &path_url);

    tracing::info!(
        event = "audit artifact_download_token_issued",
        artifact = %name,
        instance_id,
        expires_at_unix = exp,
        single_use,
    );

    Ok(Json(IssueDownloadTokenResponse {
        token_type: "Bearer",
        token,
        url,
        download_path: path_url,
        expires_at_unix: exp,
        single_use,
    }))
}

async fn signed_download(
    state: &AppState,
    token: &str,
    kind: DownloadKind,
) -> Result<Response, ApiError> {
    let claims = validate_download_token(state, token)?;
    if claims.kind != kind.as_str() {
        return Err(ApiError::Unauthorized);
    }
    if claims.single_use
        && !state
            .artifact_downloads
            .consume(&claims.jti, claims.exp)
            .await
    {
        return Err(ApiError::Unauthorized);
    }
    let path = match kind {
        DownloadKind::Artifact => {
            let path = verified_artifact_path(state, &claims.artifact).await?;
            ensure_artifact_belongs_to_instance(state, &claims.artifact, &claims.instance_id)
                .await?;
            path
        }
        DownloadKind::Backup => {
            crate::api::backups::verified_backup_path_for_instance(
                state,
                &claims.artifact,
                &claims.instance_id,
            )
            .await?
        }
    };
    let file = File::open(&path)
        .await
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => ApiError::NotFound,
            _ => ApiError::Runtime(format!("failed to open artifact: {error}")),
        })?;
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);
    tracing::info!(
        event = "audit artifact_downloaded_signed",
        artifact = %claims.artifact,
        instance_id = %claims.instance_id,
        jti = %claims.jti,
    );
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!(
                    "attachment; filename=\"{}\"",
                    safe_header_filename(&claims.artifact)
                ),
            ),
            (header::CACHE_CONTROL, "private, no-store".to_string()),
        ],
        body,
    )
        .into_response())
}

fn validate_download_token(state: &AppState, token: &str) -> Result<DownloadClaims, ApiError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[AUDIENCE]);
    validation.set_issuer(&[ISSUER]);
    validation.validate_nbf = true;
    let claims = decode::<DownloadClaims>(
        token,
        &DecodingKey::from_secret(state.config.websocket_jwt_secret()),
        &validation,
    )
    .map_err(|_| ApiError::Unauthorized)?
    .claims;
    if claims.purpose != DOWNLOAD_PURPOSE {
        return Err(ApiError::Unauthorized);
    }
    validate_artifact_name(&claims.artifact)?;
    if claims.instance_id.trim().is_empty() {
        return Err(ApiError::Unauthorized);
    }
    Ok(claims)
}

pub(crate) async fn read_artifacts(state: &AppState) -> Result<Vec<ArtifactInfo>, ApiError> {
    let export_root = export_root(state);
    let mut entries = match tokio::fs::read_dir(&export_root).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(ApiError::Runtime(format!(
                "failed to read artifacts: {error}"
            )));
        }
    };

    let mut artifacts = Vec::new();
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to read artifact entry: {error}")))?
    {
        let metadata = entry
            .metadata()
            .await
            .map_err(|error| ApiError::Runtime(format!("failed to stat artifact: {error}")))?;
        if !metadata.is_file() {
            continue;
        }
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| ApiError::Runtime("invalid artifact name".to_string()))?
            .to_string();
        artifacts.push(ArtifactInfo {
            name,
            path: path.display().to_string(),
            size_bytes: metadata.len(),
            modified_at: system_time_rfc3339(metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH)),
            sha256: sha256_file(path).await?,
        });
    }
    artifacts.sort_by(|left, right| right.modified_at.cmp(&left.modified_at));
    Ok(artifacts)
}

pub(crate) fn artifact_path(state: &AppState, name: &str) -> Result<PathBuf, ApiError> {
    validate_artifact_name(name)?;
    Ok(export_root(state).join(name))
}

pub(crate) fn export_root(state: &AppState) -> PathBuf {
    PathBuf::from(state.config.paths.exports_root())
}

fn validate_artifact_name(name: &str) -> Result<(), ApiError> {
    if !is_safe_flat_file_name(name) {
        return Err(ApiError::BadRequest("invalid artifact name".to_string()));
    }
    Ok(())
}

async fn verified_artifact_path(state: &AppState, name: &str) -> Result<PathBuf, ApiError> {
    validate_artifact_name(name)?;
    let root = export_root(state);
    tokio::fs::create_dir_all(&root)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to create artifact root: {error}")))?;
    let root = tokio::fs::canonicalize(&root)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to resolve artifact root: {error}")))?;
    let path = root.join(name);
    let metadata =
        tokio::fs::symlink_metadata(&path)
            .await
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::NotFound => ApiError::NotFound,
                _ => ApiError::Runtime(format!("failed to inspect artifact: {error}")),
            })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ApiError::BadRequest(
            "artifact is not a regular file".to_string(),
        ));
    }
    let canonical = tokio::fs::canonicalize(&path)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to resolve artifact: {error}")))?;
    if !canonical.starts_with(&root) {
        return Err(ApiError::BadRequest(
            "artifact resolves outside artifact root".to_string(),
        ));
    }
    Ok(canonical)
}

async fn ensure_artifact_belongs_to_instance(
    state: &AppState,
    name: &str,
    instance_id: &str,
) -> Result<(), ApiError> {
    state
        .instances
        .get(instance_id)
        .await
        .ok_or(ApiError::NotFound)?;
    let jobs = state
        .import_export_jobs
        .list(Some(instance_id), Some(ImportExportStatus::Succeeded), 500)
        .await;
    let belongs = jobs.into_iter().any(|job| {
        job.action == ImportExportAction::Export
            && job
                .artifact_path
                .as_deref()
                .and_then(|path| FsPath::new(path).file_name())
                .and_then(|name| name.to_str())
                .is_some_and(|artifact| artifact == name)
    });
    if belongs {
        Ok(())
    } else {
        Err(ApiError::Forbidden(
            "artifact is not associated with the requested instance".to_string(),
        ))
    }
}

fn absolute_url(headers: &HeaderMap, path: &str) -> String {
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("127.0.0.1");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .filter(|value| matches!(*value, "http" | "https"))
        .unwrap_or("https");
    format!("{scheme}://{host}{path}")
}

pub(crate) async fn sha256_file(path: PathBuf) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || {
        let mut file = std::fs::File::open(path)?;
        let mut buffer = [0_u8; 64 * 1024];
        let mut hasher = Sha256::new();
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok::<_, std::io::Error>(format!("{:x}", hasher.finalize()))
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to hash artifact: {error}")))?
    .map_err(|error| ApiError::Runtime(format!("failed to hash artifact: {error}")))
}

pub(crate) fn system_time_rfc3339(time: SystemTime) -> String {
    OffsetDateTime::from(time)
        .format(&Rfc3339)
        .expect("Rfc3339 formatting works")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::http::{HeaderMap, HeaderValue};

    use super::*;
    use crate::{
        auth::api_token::ApiToken,
        config::{Config, PathConfig},
        instances::{
            manager::InstanceManager,
            metadata::{
                DatabaseIdentity, InstanceMetadata, InstanceStatus, PublicEndpoint, RuntimeKind,
                RuntimeMetadata,
            },
            state::InstanceStore,
        },
        jobs::import_export::{ImportExportAction, ImportExportJob, ImportExportJobs},
        runtime::docker::DockerRuntime,
        shared::{backend::BackendEndpoint, limits::InstanceLimits, protocol::Protocol},
        storage::{repositories::InstanceRepository, sqlite},
    };

    #[test]
    fn artifact_names_reject_path_traversal_and_controls() {
        for name in [
            "../x.sql",
            "nested/x.sql",
            "nested\\x.sql",
            "..x.sql",
            "",
            ".",
        ] {
            assert!(validate_artifact_name(name).is_err(), "{name}");
        }
        assert!(validate_artifact_name("inst_1.postgres.sql.gz").is_ok());
    }

    #[tokio::test]
    async fn signed_download_ticket_is_single_use() {
        let state = test_state().await;
        let artifact_name = "inst_abc.postgres.sql.gz";
        let artifact = export_root(&state).join(artifact_name);
        tokio::fs::create_dir_all(artifact.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&artifact, b"dump").await.unwrap();
        state.instances.upsert(sample_metadata("inst_abc")).await;
        state
            .import_export_jobs
            .insert(sample_export_job("inst_abc", &artifact))
            .await;

        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("dbe.example.com:8090"));
        let token = issue_download_token(
            &state,
            &headers,
            artifact_name,
            IssueDownloadTokenRequest {
                instance_id: "inst_abc".to_string(),
                expires_in_seconds: Some(60),
                single_use: Some(true),
            },
            DownloadKind::Artifact,
        )
        .await
        .unwrap()
        .0
        .token;

        signed_download(&state, &token, DownloadKind::Artifact)
            .await
            .unwrap();
        let error = signed_download(&state, &token, DownloadKind::Artifact)
            .await
            .unwrap_err();
        assert!(matches!(error, ApiError::Unauthorized));
    }

    #[tokio::test]
    async fn artifact_must_belong_to_requested_instance() {
        let state = test_state().await;
        let artifact_name = "inst_abc.postgres.sql.gz";
        let artifact = export_root(&state).join(artifact_name);
        tokio::fs::create_dir_all(artifact.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&artifact, b"dump").await.unwrap();
        state.instances.upsert(sample_metadata("inst_other")).await;
        state
            .import_export_jobs
            .insert(sample_export_job("inst_other", &artifact))
            .await;

        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("dbe.example.com:8090"));
        let error = issue_download_token(
            &state,
            &headers,
            artifact_name,
            IssueDownloadTokenRequest {
                instance_id: "inst_abc".to_string(),
                expires_in_seconds: Some(60),
                single_use: Some(true),
            },
            DownloadKind::Artifact,
        )
        .await
        .unwrap_err();

        assert!(matches!(error, ApiError::NotFound));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn verified_artifact_path_rejects_symlinks() {
        let state = test_state().await;
        let artifact = export_root(&state).join("link.sql");
        tokio::fs::create_dir_all(artifact.parent().unwrap())
            .await
            .unwrap();
        std::os::unix::fs::symlink("/etc/passwd", &artifact).unwrap();

        let error = verified_artifact_path(&state, "link.sql")
            .await
            .unwrap_err();
        assert!(matches!(error, ApiError::BadRequest(_)));
    }

    async fn test_state() -> AppState {
        let dir = tempfile::tempdir().unwrap().keep();
        let pool = sqlite::connect(&dir).await.unwrap();
        let store = InstanceStore::default();
        let manager = InstanceManager::new(store.clone(), InstanceRepository::new(pool));
        AppState {
            config: Arc::new(Config {
                uuid: "node".to_string(),
                token_id: "token-id".to_string(),
                token: "secret".to_string(),
                remote: "https://panel.example.com".to_string(),
                paths: PathConfig {
                    artifacts: dir.join("artifacts").display().to_string(),
                    ..Default::default()
                },
                ..Default::default()
            }),
            config_path: dir.join("config.yml"),
            api_token: ApiToken::new("secret"),
            instances: store,
            manager,
            docker: DockerRuntime::new(&Default::default(), false).unwrap(),
            import_export_jobs: ImportExportJobs::default(),
            api_rate_limiter: crate::api::security::ApiRateLimiter::default(),
            install_progress: crate::api::progress::InstallProgressStore::default(),
            artifact_downloads: ArtifactDownloadTickets::default(),
        }
    }

    fn sample_metadata(instance_id: &str) -> InstanceMetadata {
        InstanceMetadata {
            schema_version: 1,
            instance_id: instance_id.to_string(),
            protocol: Protocol::Postgres,
            status: InstanceStatus::Running,
            public: PublicEndpoint {
                host: "db.example.com".to_string(),
                port: 5434,
            },
            backend: BackendEndpoint::DockerTcp {
                host: "172.30.0.2".to_string(),
                port: 5432,
            },
            runtime: RuntimeMetadata {
                kind: RuntimeKind::Docker,
                container_name: format!("dbe-postgres-{instance_id}"),
                network: "databases-everywhere".to_string(),
            },
            database: DatabaseIdentity {
                name: "db".to_string(),
                username: "user".to_string(),
            },
            route_key_sha256: None,
            mariadb_native_password_sha1_stage2: None,
            mariadb_root_password: None,
            limits: InstanceLimits::default(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    fn sample_export_job(instance_id: &str, artifact: &FsPath) -> ImportExportJob {
        ImportExportJob {
            job_id: Uuid::new_v4().to_string(),
            instance_id: instance_id.to_string(),
            action: ImportExportAction::Export,
            status: ImportExportStatus::Succeeded,
            artifact_path: Some(artifact.display().to_string()),
            error: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:01Z".to_string(),
        }
    }
}
