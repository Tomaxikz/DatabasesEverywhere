use std::{
    collections::HashMap,
    io::Read,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, Uri, header},
    response::{IntoResponse, Response},
};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, decode, encode};
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
    shared::{
        files::{is_safe_flat_file_name, safe_header_filename},
        ids::validate_instance_id,
    },
};

const DOWNLOAD_PURPOSE: &str = "artifact_download";
const DEFAULT_DOWNLOAD_TTL_SECONDS: i64 = 120;
const MAX_DOWNLOAD_TTL_SECONDS: i64 = 900;
const MAX_CONSUMED_DOWNLOAD_TICKETS: usize = 16_384;

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

    fn download_path(self, instance_id: &str, artifact_id: &str, token: &str) -> String {
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

#[derive(Debug, Clone, Default)]
pub struct ArtifactDownloadTickets {
    consumed: Arc<Mutex<HashMap<String, i64>>>,
}

impl ArtifactDownloadTickets {
    pub async fn consume(&self, jti: &str, exp: i64) -> bool {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut consumed = self.consumed.lock().await;
        consumed.retain(|_, expires_at| *expires_at > now);
        if consumed.contains_key(jti) {
            return false;
        }
        if consumed.len() >= MAX_CONSUMED_DOWNLOAD_TICKETS {
            tracing::warn!("audit artifact_download_ticket_capacity_reached");
            return false;
        }
        consumed.insert(jti.to_string(), exp);
        true
    }
}

#[derive(Debug, Deserialize)]
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
pub struct DownloadQuery {
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

pub async fn list_instance_artifacts(
    State(state): State<AppState>,
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<Vec<ArtifactInfo>> {
    authorize_scope(&state, &headers, &uri, scopes::ARTIFACTS_READ)?;
    ensure_instance_exists(&state, &instance_id).await?;
    Ok(Json(read_instance_artifacts(&state, &instance_id).await?))
}

pub async fn delete_artifact(
    State(state): State<AppState>,
    Path((instance_id, artifact_id)): Path<(String, String)>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<DeleteArtifactResponse> {
    authorize_scope(&state, &headers, &uri, scopes::ARTIFACTS_WRITE)?;
    ensure_instance_exists(&state, &instance_id).await?;
    let path = verified_artifact_path_for_instance(&state, &artifact_id, &instance_id).await?;
    match tokio::fs::remove_file(&path).await {
        Ok(()) => {
            remove_checksum_sidecar(&path).await;
            tracing::info!(event = "audit artifact_deleted", instance_id, artifact_id);
            Ok(Json(DeleteArtifactResponse {
                id: artifact_id,
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
    Path(instance_id): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<RetentionResponse> {
    authorize_scope(&state, &headers, &uri, scopes::ARTIFACTS_WRITE)?;
    ensure_instance_exists(&state, &instance_id).await?;
    let mut artifacts = read_instance_artifacts(&state, &instance_id).await?;
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
        let path = verified_artifact_path_for_instance(&state, &artifact.id, &instance_id).await?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {
                remove_checksum_sidecar(&path).await;
                deleted.push(artifact.id);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ApiError::Runtime(format!(
                    "failed to delete artifact {}: {error}",
                    artifact.id
                )));
            }
        }
    }

    tracing::info!(event = "audit artifact_retention_applied", deleted = ?deleted);
    Ok(Json(RetentionResponse { deleted }))
}

pub async fn create_artifact_download(
    State(state): State<AppState>,
    Path((instance_id, artifact_id)): Path<(String, String)>,
    headers: HeaderMap,
    uri: Uri,
    Json(request): Json<CreateDownloadRequest>,
) -> ApiResult<DownloadUrlResponse> {
    authorize_scope(&state, &headers, &uri, scopes::ARTIFACTS_READ)?;
    create_download_url(
        &state,
        &headers,
        &artifact_id,
        &instance_id,
        request,
        DownloadKind::Artifact,
    )
    .await
}

pub async fn create_backup_download(
    State(state): State<AppState>,
    Path((instance_id, backup_id)): Path<(String, String)>,
    headers: HeaderMap,
    uri: Uri,
    Json(request): Json<CreateDownloadRequest>,
) -> ApiResult<DownloadUrlResponse> {
    authorize_scope(&state, &headers, &uri, scopes::BACKUPS_READ)?;
    create_download_url(
        &state,
        &headers,
        &backup_id,
        &instance_id,
        request,
        DownloadKind::Backup,
    )
    .await
}

pub(crate) async fn create_artifact_download_url(
    state: &AppState,
    headers: &HeaderMap,
    name: &str,
    instance_id: &str,
    expires_in_seconds: Option<i64>,
    single_use: bool,
) -> Result<DownloadUrlResponse, ApiError> {
    create_download_url(
        state,
        headers,
        name,
        instance_id,
        CreateDownloadRequest {
            expires_in_seconds,
            single_use: Some(single_use),
        },
        DownloadKind::Artifact,
    )
    .await
    .map(|Json(response)| response)
}

pub async fn download_artifact(
    State(state): State<AppState>,
    Path((instance_id, artifact_id)): Path<(String, String)>,
    Query(query): Query<DownloadQuery>,
) -> Result<Response, ApiError> {
    download(
        &state,
        &query.token,
        &instance_id,
        &artifact_id,
        DownloadKind::Artifact,
    )
    .await
}

pub async fn download_backup(
    State(state): State<AppState>,
    Path((instance_id, backup_id)): Path<(String, String)>,
    Query(query): Query<DownloadQuery>,
) -> Result<Response, ApiError> {
    download(
        &state,
        &query.token,
        &instance_id,
        &backup_id,
        DownloadKind::Backup,
    )
    .await
}

async fn create_download_url(
    state: &AppState,
    _headers: &HeaderMap,
    name: &str,
    instance_id: &str,
    request: CreateDownloadRequest,
    kind: DownloadKind,
) -> ApiResult<DownloadUrlResponse> {
    validate_artifact_name(name)?;
    validate_instance_id(instance_id).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    ensure_instance_exists(state, instance_id).await?;
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
            verified_artifact_path_for_instance(state, name, instance_id).await?;
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
    let path_url = kind.download_path(instance_id, name, &token);
    // Keep the credential-bearing URL origin-relative. Building an absolute URL
    // from Host or X-Forwarded-* would let an untrusted proxy/client poison it.
    let url = path_url.clone();

    tracing::info!(
        event = "audit artifact_download_url_created",
        artifact = %name,
        instance_id,
        expires_at_unix = exp,
        single_use,
    );

    Ok(Json(DownloadUrlResponse {
        url,
        expires_at_unix: exp,
        single_use,
    }))
}

async fn download(
    state: &AppState,
    token: &str,
    instance_id: &str,
    artifact_id: &str,
    kind: DownloadKind,
) -> Result<Response, ApiError> {
    let claims = validate_download_token(state, token)?;
    if claims.kind != kind.as_str()
        || claims.instance_id != instance_id
        || claims.artifact != artifact_id
    {
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
            verified_artifact_path_for_instance(state, &claims.artifact, &claims.instance_id)
                .await?
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
        event = "audit artifact_downloaded",
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
    let claims = decode::<DownloadClaims>(
        token,
        &DecodingKey::from_secret(state.config.websocket_jwt_secret()),
        &crate::auth::jwt::strict_hs256_validation(),
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

async fn ensure_instance_exists(state: &AppState, instance_id: &str) -> Result<(), ApiError> {
    validate_instance_id(instance_id).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    state
        .instances
        .get(instance_id)
        .await
        .map(|_| ())
        .ok_or(ApiError::NotFound)
}

pub(crate) async fn read_instance_artifacts(
    state: &AppState,
    instance_id: &str,
) -> Result<Vec<ArtifactInfo>, ApiError> {
    validate_instance_id(instance_id).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let instance_root = instance_export_root(state, instance_id);
    match tokio::fs::symlink_metadata(&instance_root).await {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(ApiError::Runtime(
                "instance artifact root must be a real directory".to_string(),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(ApiError::Runtime(format!(
                "failed to inspect instance artifact root: {error}"
            )));
        }
    }
    let mut entries = match tokio::fs::read_dir(&instance_root).await {
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
        let metadata = tokio::fs::symlink_metadata(entry.path())
            .await
            .map_err(|error| ApiError::Runtime(format!("failed to stat artifact: {error}")))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            continue;
        }
        let path = entry.path();
        if is_checksum_sidecar(&path) {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| ApiError::Runtime("invalid artifact name".to_string()))?
            .to_string();
        artifacts.push(ArtifactInfo {
            id: name,
            instance_id: instance_id.to_string(),
            size_bytes: metadata.len(),
            modified_at: system_time_rfc3339(metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH)),
            sha256: sha256_file(path).await?,
        });
    }
    artifacts.sort_by(|left, right| right.modified_at.cmp(&left.modified_at));
    Ok(artifacts)
}

pub(crate) fn export_root(state: &AppState) -> PathBuf {
    PathBuf::from(state.config.paths.exports_root())
}

pub(crate) fn instance_export_root(state: &AppState, instance_id: &str) -> PathBuf {
    export_root(state).join(instance_id)
}

fn validate_artifact_name(name: &str) -> Result<(), ApiError> {
    if !is_safe_flat_file_name(name) {
        return Err(ApiError::BadRequest("invalid artifact name".to_string()));
    }
    Ok(())
}

pub(crate) async fn verified_artifact_path_for_instance(
    state: &AppState,
    name: &str,
    instance_id: &str,
) -> Result<PathBuf, ApiError> {
    validate_instance_id(instance_id).map_err(|error| ApiError::BadRequest(error.to_string()))?;
    validate_artifact_name(name)?;
    let root = instance_export_root(state, instance_id);
    let root_metadata =
        tokio::fs::symlink_metadata(&root)
            .await
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::NotFound => ApiError::NotFound,
                _ => ApiError::Runtime(format!("failed to inspect artifact root: {error}")),
            })?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(ApiError::Runtime(
            "instance artifact root must be a real directory".to_string(),
        ));
    }
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

pub(crate) async fn sha256_file(path: PathBuf) -> Result<String, ApiError> {
    let metadata = tokio::fs::metadata(&path)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to stat artifact: {error}")))?;
    if let Some(hash) = cached_sha256(&path, &metadata).await? {
        return Ok(hash);
    }

    let hash = tokio::task::spawn_blocking({
        let path = path.clone();
        move || {
            let mut file = std::fs::File::open(&path)?;
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
        }
    })
    .await
    .map_err(|error| ApiError::Runtime(format!("failed to hash artifact: {error}")))?
    .map_err(|error| ApiError::Runtime(format!("failed to hash artifact: {error}")))?;
    write_checksum_sidecar(&path, &metadata, &hash).await;
    Ok(hash)
}

fn checksum_sidecar_path(path: &FsPath) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    Some(path.with_file_name(format!("{name}.sha256")))
}

pub(crate) fn is_checksum_sidecar(path: &FsPath) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".sha256"))
}

async fn cached_sha256(
    path: &FsPath,
    metadata: &std::fs::Metadata,
) -> Result<Option<String>, ApiError> {
    let Some(sidecar) = checksum_sidecar_path(path) else {
        return Ok(None);
    };
    let content = match tokio::fs::read_to_string(sidecar).await {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            tracing::debug!(%error, path = %path.display(), "failed to read checksum sidecar");
            return Ok(None);
        }
    };
    let mut hash = None;
    let mut size = None;
    let mut modified_nanos = None;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("sha256 ") {
            hash = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("size ") {
            size = value.trim().parse::<u64>().ok();
        } else if let Some(value) = line.strip_prefix("modified_unix_nanos ") {
            modified_nanos = value.trim().parse::<u128>().ok();
        }
    }
    let Some(hash) = hash.filter(|hash| is_sha256_hex(hash)) else {
        return Ok(None);
    };
    if size == Some(metadata.len())
        && modified_nanos
            == Some(system_time_unix_nanos(
                metadata.modified().unwrap_or(UNIX_EPOCH),
            ))
    {
        Ok(Some(hash))
    } else {
        Ok(None)
    }
}

async fn write_checksum_sidecar(path: &FsPath, metadata: &std::fs::Metadata, hash: &str) {
    let Some(sidecar) = checksum_sidecar_path(path) else {
        return;
    };
    let modified = system_time_unix_nanos(metadata.modified().unwrap_or(UNIX_EPOCH));
    let content = format!(
        "sha256 {hash}\nsize {}\nmodified_unix_nanos {modified}\n",
        metadata.len()
    );
    if let Err(error) = tokio::task::spawn_blocking(move || {
        crate::shared::files::atomic_write_private(&sidecar, content.as_bytes())
    })
    .await
    .map_err(std::io::Error::other)
    .and_then(|result| result)
    {
        tracing::debug!(%error, path = %path.display(), "failed to write checksum sidecar");
    }
}

pub(crate) async fn remove_checksum_sidecar(path: &FsPath) {
    if let Some(sidecar) = checksum_sidecar_path(path) {
        match tokio::fs::remove_file(sidecar).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::debug!(%error, path = %path.display(), "failed to delete checksum sidecar")
            }
        }
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn system_time_unix_nanos(time: SystemTime) -> u128 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
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
        jobs::import_export::ImportExportJobs,
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
    async fn temporary_download_url_is_single_use_and_path_scoped() {
        let state = test_state().await;
        let artifact_name = "inst_abc.postgres.sql.gz";
        let artifact = instance_export_root(&state, "inst_abc").join(artifact_name);
        tokio::fs::create_dir_all(artifact.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&artifact, b"dump").await.unwrap();
        state.instances.upsert(sample_metadata("inst_abc")).await;

        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("dbe.example.com:8090"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("http"));
        let ticket = create_download_url(
            &state,
            &headers,
            artifact_name,
            "inst_abc",
            CreateDownloadRequest {
                expires_in_seconds: Some(60),
                single_use: Some(true),
            },
            DownloadKind::Artifact,
        )
        .await
        .unwrap()
        .0;
        let public_ticket = serde_json::to_value(&ticket).unwrap();
        let fields = public_ticket.as_object().unwrap();
        assert_eq!(fields.len(), 3);
        assert!(fields.contains_key("url"));
        assert!(fields.contains_key("expires_at_unix"));
        assert!(fields.contains_key("single_use"));
        assert!(ticket.url.starts_with(&format!(
            "/api/instances/inst_abc/artifacts/{artifact_name}/download?token="
        )));
        assert!(!ticket.url.contains("dbe.example.com"));
        let token = ticket
            .url
            .split_once("token=")
            .expect("signed URL contains token")
            .1
            .to_string();

        let mismatch = download(
            &state,
            &token,
            "inst_other",
            artifact_name,
            DownloadKind::Artifact,
        )
        .await
        .unwrap_err();
        assert!(matches!(mismatch, ApiError::Unauthorized));

        download(
            &state,
            &token,
            "inst_abc",
            artifact_name,
            DownloadKind::Artifact,
        )
        .await
        .unwrap();
        let error = download(
            &state,
            &token,
            "inst_abc",
            artifact_name,
            DownloadKind::Artifact,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ApiError::Unauthorized));
    }

    #[tokio::test]
    async fn temporary_download_url_rejects_expired_token_without_leeway() {
        let state = test_state().await;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = DownloadClaims {
            iss: ISSUER.to_string(),
            aud: AUDIENCE.to_string(),
            sub: "panel".to_string(),
            purpose: DOWNLOAD_PURPOSE.to_string(),
            kind: DownloadKind::Artifact.as_str().to_string(),
            artifact: "inst_abc.postgres.sql.gz".to_string(),
            instance_id: "inst_abc".to_string(),
            single_use: true,
            iat: now - 10,
            nbf: now - 10,
            exp: now - 1,
            jti: Uuid::new_v4().to_string(),
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(state.config.websocket_jwt_secret()),
        )
        .unwrap();

        let error = validate_download_token(&state, &token).unwrap_err();

        assert!(matches!(error, ApiError::Unauthorized));
    }

    #[tokio::test]
    async fn artifact_must_belong_to_requested_instance() {
        let state = test_state().await;
        let artifact_name = "inst_abc.postgres.sql.gz";
        let artifact = instance_export_root(&state, "inst_other").join(artifact_name);
        tokio::fs::create_dir_all(artifact.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&artifact, b"dump").await.unwrap();
        state.instances.upsert(sample_metadata("inst_abc")).await;
        state.instances.upsert(sample_metadata("inst_other")).await;

        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("dbe.example.com:8090"));
        let error = create_download_url(
            &state,
            &headers,
            artifact_name,
            "inst_abc",
            CreateDownloadRequest {
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
        let artifact = instance_export_root(&state, "inst_abc").join("link.sql");
        tokio::fs::create_dir_all(artifact.parent().unwrap())
            .await
            .unwrap();
        std::os::unix::fs::symlink("/etc/passwd", &artifact).unwrap();

        let error = verified_artifact_path_for_instance(&state, "link.sql", "inst_abc")
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
                jwt_signing_key: "test-jwt-signing-key-at-least-32-bytes".to_string(),
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
            instance_locks: crate::instances::locks::InstanceLocks::default(),
            docker: DockerRuntime::new(&Default::default(), false).unwrap(),
            import_export_jobs: ImportExportJobs::default(),
            api_rate_limiter: crate::api::security::ApiRateLimiter::default(),
            install_progress: crate::api::progress::InstallProgressStore::default(),
            artifact_downloads: ArtifactDownloadTickets::default(),
            resource_cache: crate::api::resources::ResourceCache::default(),
            instance_runtime_cache: crate::api::instances::InstanceRuntimeInfoCache::default(),
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
            mongodb_root_password: None,
            limits: InstanceLimits::default(),
            image: None,
            database_version: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }
}
