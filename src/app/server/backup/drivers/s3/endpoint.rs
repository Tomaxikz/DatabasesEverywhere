use reqwest::Url;

use super::{S3Credentials, S3Endpoint, signing::aws_uri_encode};
use crate::{config::BackupS3Config, server::backup::BackupStoreError};

impl S3Endpoint {
    pub(super) fn new(config: &BackupS3Config) -> Result<Self, BackupStoreError> {
        let custom_endpoint = config.endpoint.trim();
        let region = config.region.trim();
        let bucket = config.bucket.trim();
        let mut base = if !custom_endpoint.is_empty() {
            Url::parse(custom_endpoint)
        } else if config.path_style {
            Url::parse(&format!("https://s3.{region}.amazonaws.com/"))
        } else {
            Url::parse(&format!("https://{bucket}.s3.{region}.amazonaws.com/"))
        }
        .map_err(|error| BackupStoreError::InvalidConfiguration(error.to_string()))?;
        if !config.path_style && !custom_endpoint.is_empty() {
            let host = base.host_str().ok_or_else(|| {
                BackupStoreError::InvalidConfiguration("S3 endpoint has no host".to_string())
            })?;
            let virtual_host = format!("{bucket}.{host}");
            base.set_host(Some(&virtual_host)).map_err(|_| {
                BackupStoreError::InvalidConfiguration(
                    "failed to construct virtual-hosted S3 endpoint".to_string(),
                )
            })?;
        }
        let host = base.host().ok_or_else(|| {
            BackupStoreError::InvalidConfiguration("S3 endpoint has no host".to_string())
        })?;
        let authority = match base.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        let base_path = base.path().trim_end_matches('/').to_string();
        base.set_query(None);
        base.set_fragment(None);
        Ok(Self {
            base,
            authority,
            base_path,
            bucket_in_path: config.path_style,
        })
    }

    pub(super) fn url(
        &self,
        bucket: &str,
        key: &str,
        canonical_query: &str,
    ) -> Result<(Url, String), BackupStoreError> {
        let mut canonical_uri = self.base_path.clone();
        if self.bucket_in_path {
            canonical_uri.push('/');
            canonical_uri.push_str(&aws_uri_encode(bucket.as_bytes(), false));
        }
        if !key.is_empty() {
            canonical_uri.push('/');
            canonical_uri.push_str(&aws_uri_encode(key.as_bytes(), true));
        } else if canonical_uri.is_empty() {
            canonical_uri.push('/');
        }
        if !canonical_uri.starts_with('/') {
            canonical_uri.insert(0, '/');
        }
        let mut url = format!(
            "{}://{}{}",
            self.base.scheme(),
            self.authority,
            canonical_uri
        );
        if !canonical_query.is_empty() {
            url.push('?');
            url.push_str(canonical_query);
        }
        let url = Url::parse(&url)
            .map_err(|error| BackupStoreError::InvalidConfiguration(error.to_string()))?;
        Ok((url, canonical_uri))
    }
}

pub(super) fn credentials(config: &BackupS3Config) -> Result<S3Credentials, BackupStoreError> {
    let configured_or_env = |configured: &str, variable: &str| {
        let value = if configured.is_empty() {
            std::env::var(variable).unwrap_or_default()
        } else {
            configured.to_string()
        };
        value.trim().to_string()
    };
    let access_key_id = configured_or_env(config.access_key_id.trim(), "AWS_ACCESS_KEY_ID");
    let secret_access_key = configured_or_env(
        config.secret_access_key.expose().trim(),
        "AWS_SECRET_ACCESS_KEY",
    );
    if access_key_id.is_empty() || secret_access_key.is_empty() {
        return Err(BackupStoreError::InvalidConfiguration(
            "S3 requires access_key_id/secret_access_key or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY"
                .to_string(),
        ));
    }
    let configured_token = config.session_token.expose().trim();
    let session_token = if configured_token.is_empty() {
        std::env::var("AWS_SESSION_TOKEN").ok()
    } else {
        Some(configured_token.to_string())
    }
    .map(|token| token.trim().to_string())
    .filter(|token| !token.is_empty());
    Ok(S3Credentials {
        access_key_id,
        secret_access_key,
        session_token,
    })
}
