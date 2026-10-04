use super::files::{downloadable_artifact_path, require_instance, validate_artifact_name};
use super::stream::DownloadStream;
use super::types::DownloadUrlResponse;
use super::types::{CreateDownloadRequest, DownloadClaims, DownloadKind};
use super::{
    DEFAULT_DOWNLOAD_TTL_SECONDS, DOWNLOAD_PURPOSE, DOWNLOAD_STREAM_BUFFER_BYTES,
    MAX_DOWNLOAD_TTL_SECONDS,
};
use crate::io::files::safe_header_filename;
use crate::routes::http::response::{ApiError, ApiResponse, ApiResult};
use crate::routes::http::router::AppState;
use crate::utils::constants::jwt::{AUDIENCE, ISSUER};
use crate::utils::time::now_unix;
use axum::body::Body;
use axum::http::header;
use axum::response::IntoResponse;
use axum::response::Response;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, decode, encode};
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::fs::File;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

pub(super) async fn create_download_url(
    state: &AppState,
    name: &str,
    instance_id: &str,
    request: CreateDownloadRequest,
    kind: DownloadKind,
) -> ApiResult<DownloadUrlResponse> {
    validate_artifact_name(name)?;
    require_instance(state, instance_id).await?;
    let ttl_seconds = request
        .expires_in_seconds
        .unwrap_or(DEFAULT_DOWNLOAD_TTL_SECONDS);
    if !(1..=MAX_DOWNLOAD_TTL_SECONDS).contains(&ttl_seconds) {
        return Err(ApiError::BadRequest(format!(
            "expires_in_seconds must be between 1 and {MAX_DOWNLOAD_TTL_SECONDS}"
        )));
    }
    let one_use = match kind {
        DownloadKind::Artifact => {
            downloadable_artifact_path(state, name, instance_id)
                .await?
                .one_use
        }
        DownloadKind::Backup => {
            crate::subsystems::backups::require_backup(state, instance_id, name).await?;
            false
        }
    };
    let single_use = request.single_use.unwrap_or(true) || one_use;

    let now = now_unix();
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
    // Keep the credential-bearing URL origin-relative. Building an absolute URL
    // from Host or X-Forwarded-* would let an untrusted proxy/client poison it.
    let url = kind.download_path(instance_id, name, &token);

    tracing::info!(
        event = "audit artifact_download_url_created",
        artifact = %name,
        instance_id,
        expires_at_unix = exp,
        single_use,
    );

    Ok(ApiResponse::ok(DownloadUrlResponse {
        url,
        expires_at_unix: exp,
        single_use,
    }))
}

pub(super) async fn download(
    state: &AppState,
    token: &str,
    instance_id: &str,
    artifact_id: &str,
    kind: DownloadKind,
    peer: Option<SocketAddr>,
) -> Result<Response, ApiError> {
    let claims = validate_download_token(state, token)?;
    if !claims.matches_request(kind, instance_id, artifact_id) {
        return Err(ApiError::Unauthorized);
    }
    let permit = state.artifact_downloads.admit_download(peer)?;
    if claims.single_use {
        let first_use = state
            .artifact_downloads
            .consume(&claims.jti, claims.exp)
            .await;
        if !first_use {
            return Err(ApiError::Unauthorized);
        }
    }
    let DownloadSource {
        path,
        cleanup,
        backup,
    } = resolve_download_source(state, &claims, kind).await?;
    let file = match File::open(&path).await {
        Ok(file) => file,
        Err(error) => {
            if let Some(path) = cleanup.as_ref() {
                let _ = tokio::fs::remove_file(path).await;
            }
            return Err(match error.kind() {
                std::io::ErrorKind::NotFound => ApiError::NotFound,
                _ => ApiError::Runtime(format!("failed to open artifact: {error}")),
            });
        }
    };
    let stream = DownloadStream {
        inner: ReaderStream::with_capacity(file, DOWNLOAD_STREAM_BUFFER_BYTES),
        _permit: permit,
        cleanup,
        _backup: backup,
    };
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

pub(super) struct DownloadSource {
    pub(super) path: PathBuf,
    pub(super) cleanup: Option<PathBuf>,
    pub(super) backup: Option<crate::server::backup::MaterializedBackup>,
}

pub(super) async fn resolve_download_source(
    state: &AppState,
    claims: &DownloadClaims,
    kind: DownloadKind,
) -> Result<DownloadSource, ApiError> {
    match kind {
        DownloadKind::Artifact => {
            let artifact =
                downloadable_artifact_path(state, &claims.artifact, &claims.instance_id).await?;
            let cleanup = artifact.one_use.then(|| artifact.path.clone());
            Ok(DownloadSource {
                path: artifact.path,
                cleanup,
                backup: None,
            })
        }
        DownloadKind::Backup => {
            let backup = crate::subsystems::backups::prepare_backup_download(
                state,
                &claims.instance_id,
                &claims.artifact,
            )
            .await?;
            Ok(DownloadSource {
                path: backup.path.clone(),
                cleanup: None,
                backup: Some(backup),
            })
        }
    }
}

impl DownloadClaims {
    pub(super) fn matches_request(
        &self,
        kind: DownloadKind,
        instance_id: &str,
        artifact_id: &str,
    ) -> bool {
        self.kind == kind.as_str()
            && self.instance_id == instance_id
            && self.artifact == artifact_id
    }
}

pub(super) fn validate_download_token(
    state: &AppState,
    token: &str,
) -> Result<DownloadClaims, ApiError> {
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
