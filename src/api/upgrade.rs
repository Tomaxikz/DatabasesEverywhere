use std::{collections::HashMap, os::unix::fs::PermissionsExt, path::PathBuf, time::Duration};

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Uri},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::{
    api::{
        handlers::{ApiError, ApiResult, authorize_scope},
        routes::AppState,
    },
    auth::scopes,
};

const MAX_UPGRADE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct UpgradeRequest {
    pub url: String,
    pub sha256: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    pub restart_command: String,
    #[serde(default)]
    pub restart_command_args: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct UpgradeResponse {
    pub accepted: bool,
    pub restart_command: String,
}

pub async fn self_upgrade(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    Json(request): Json<UpgradeRequest>,
) -> ApiResult<UpgradeResponse> {
    authorize_scope(&state, &headers, &uri, scopes::UPGRADES_ADMIN)?;
    if !state.config.security.self_upgrade_enabled {
        return Err(ApiError::BadRequest(
            "self-upgrade is disabled by security.self_upgrade_enabled".to_string(),
        ));
    }
    validate_request(&request)?;

    let current_exe = std::env::current_exe()
        .map_err(|error| ApiError::Runtime(format!("failed to resolve current binary: {error}")))?;
    let tmp_path = upgrade_temp_path(&current_exe)?;
    download_and_verify(&request, &tmp_path).await?;

    let restart_command = request.restart_command.clone();
    let restart_command_args = request.restart_command_args.clone();
    let response_command = command_display(&restart_command, &restart_command_args);
    tokio::spawn(async move {
        if let Err(error) =
            replace_binary_and_restart(tmp_path, current_exe, restart_command, restart_command_args)
                .await
        {
            tracing::error!(%error, "self-upgrade failed after download");
        }
    });

    tracing::info!(
        event = "audit self_upgrade_accepted",
        url = %request.url,
        restart = %response_command,
        "self-upgrade accepted"
    );

    Ok(Json(UpgradeResponse {
        accepted: true,
        restart_command: response_command,
    }))
}

fn validate_request(request: &UpgradeRequest) -> Result<(), ApiError> {
    let url = request.url.trim();
    if !url.starts_with("https://") {
        return Err(ApiError::BadRequest(
            "upgrade url must use https".to_string(),
        ));
    }
    if request.sha256.len() != 64 || !request.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest(
            "sha256 must be a 64 character hex digest".to_string(),
        ));
    }
    if request.restart_command.trim().is_empty()
        || request.restart_command.contains('/')
        || request.restart_command.contains('\0')
    {
        return Err(ApiError::BadRequest(
            "restart_command must be a command name, not a path".to_string(),
        ));
    }
    if request
        .restart_command_args
        .iter()
        .any(|arg| arg.contains('\0'))
    {
        return Err(ApiError::BadRequest(
            "restart_command_args must not contain NUL bytes".to_string(),
        ));
    }
    Ok(())
}

fn upgrade_temp_path(current_exe: &std::path::Path) -> Result<PathBuf, ApiError> {
    let parent = current_exe
        .parent()
        .ok_or_else(|| ApiError::Runtime("current binary has no parent directory".to_string()))?;
    let file_name = current_exe
        .file_name()
        .ok_or_else(|| ApiError::Runtime("current binary has no file name".to_string()))?
        .to_string_lossy();
    Ok(parent.join(format!(".{file_name}.upgrade")))
}

async fn download_and_verify(request: &UpgradeRequest, tmp_path: &PathBuf) -> Result<(), ApiError> {
    let mut headers = HeaderMap::new();
    for (key, value) in &request.headers {
        let key = HeaderName::from_bytes(key.as_bytes())
            .map_err(|error| ApiError::BadRequest(format!("invalid header name: {error}")))?;
        let value = HeaderValue::from_str(value)
            .map_err(|error| ApiError::BadRequest(format!("invalid header value: {error}")))?;
        headers.insert(key, value);
    }

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|error| ApiError::Runtime(format!("failed to build http client: {error}")))?;
    let mut response = client
        .get(request.url.trim())
        .headers(headers)
        .send()
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to download upgrade: {error}")))?;
    if !response.status().is_success() {
        return Err(ApiError::BadRequest(format!(
            "upgrade download returned HTTP {}",
            response.status()
        )));
    }

    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .read(true)
        .open(tmp_path)
        .await
        .map_err(|error| {
            ApiError::Runtime(format!(
                "failed to create upgrade file {}: {error}",
                tmp_path.display()
            ))
        })?;

    let mut written = 0_u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to read upgrade chunk: {error}")))?
    {
        written += chunk.len() as u64;
        if written > MAX_UPGRADE_BYTES {
            let _ = tokio::fs::remove_file(tmp_path).await;
            return Err(ApiError::BadRequest(
                "upgrade binary exceeds maximum allowed size".to_string(),
            ));
        }
        file.write_all(&chunk)
            .await
            .map_err(|error| ApiError::Runtime(format!("failed to write upgrade: {error}")))?;
    }
    file.flush()
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to flush upgrade: {error}")))?;
    file.seek(std::io::SeekFrom::Start(0))
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to rewind upgrade: {error}")))?;

    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let bytes = file
            .read(&mut buffer)
            .await
            .map_err(|error| ApiError::Runtime(format!("failed to verify upgrade: {error}")))?;
        if bytes == 0 {
            break;
        }
        hasher.update(&buffer[..bytes]);
    }
    let actual = format!("{:x}", hasher.finalize());
    if !actual.eq_ignore_ascii_case(&request.sha256) {
        let _ = tokio::fs::remove_file(tmp_path).await;
        return Err(ApiError::Conflict(
            "downloaded upgrade sha256 does not match".to_string(),
        ));
    }
    drop(file);
    let mut permissions = tokio::fs::metadata(tmp_path)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to read upgrade metadata: {error}")))?
        .permissions();
    permissions.set_mode(0o755);
    tokio::fs::set_permissions(tmp_path, permissions)
        .await
        .map_err(|error| ApiError::Runtime(format!("failed to chmod upgrade: {error}")))?;
    Ok(())
}

async fn replace_binary_and_restart(
    tmp_path: PathBuf,
    current_exe: PathBuf,
    restart_command: String,
    restart_command_args: Vec<String>,
) -> Result<(), anyhow::Error> {
    tokio::time::sleep(Duration::from_secs(1)).await;
    tokio::fs::rename(&tmp_path, &current_exe).await?;
    std::process::Command::new(&restart_command)
        .args(&restart_command_args)
        .spawn()?;
    Ok(())
}

fn command_display(command: &str, args: &[String]) -> String {
    std::iter::once(command)
        .chain(args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}
