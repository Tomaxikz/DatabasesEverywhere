//! Mapping of [`BackupS3Config`] onto `object_store`, the HTTP client both
//! share, and the signed S3 calls `object_store` has no API for.

use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use object_store::{
    BackoffConfig, ClientOptions, RetryConfig,
    aws::{AmazonS3, AmazonS3Builder, AwsAuthorizer, AwsCredential},
    client::{
        HttpClient, HttpConnector, HttpError, HttpErrorKind, HttpRequest, HttpRequestBody,
        HttpResponse, HttpResponseBody, HttpService,
    },
};
use reqwest::{Method, StatusCode, Url};

use super::{
    MAX_CONNECT_TIMEOUT_SECONDS, MAX_RESPONSE_BYTES, MAX_RETRY_BACKOFF_EXPONENT,
    RETRY_BASE_DELAY_MILLIS,
};
use crate::{config::BackupS3Config, server::backup::BackupStoreError};

#[derive(Clone)]
pub(super) struct S3Credentials {
    pub(super) access_key_id: String,
    pub(super) secret_access_key: String,
    pub(super) session_token: Option<String>,
}

impl S3Credentials {
    fn aws(&self) -> AwsCredential {
        AwsCredential {
            key_id: self.access_key_id.clone(),
            secret_key: self.secret_access_key.clone(),
            token: self.session_token.clone(),
        }
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

/// The service endpoint: the custom endpoint, with the bucket prepended to
/// its host for virtual-hosted style, or AWS's regional endpoint. Its string
/// form is part of the storage identity, so it must stay stable.
pub(super) fn endpoint_base(config: &BackupS3Config) -> Result<Url, BackupStoreError> {
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
    let host = base
        .host_str()
        .ok_or_else(|| BackupStoreError::InvalidConfiguration("S3 endpoint has no host".into()))?
        .to_string();
    if !config.path_style && !custom_endpoint.is_empty() {
        base.set_host(Some(&format!("{bucket}.{host}")))
            .map_err(|_| {
                BackupStoreError::InvalidConfiguration(
                    "failed to construct virtual-hosted S3 endpoint".to_string(),
                )
            })?;
    }
    base.set_query(None);
    base.set_fragment(None);
    Ok(base)
}

/// URL of the bucket itself, to which `object_store` appends object keys.
pub(super) fn bucket_endpoint(base: &Url, config: &BackupS3Config) -> String {
    let mut endpoint = base.as_str().trim_end_matches('/').to_string();
    if config.path_style {
        endpoint.push('/');
        endpoint.push_str(config.bucket.trim());
    }
    endpoint
}

pub(super) fn http_client(config: &BackupS3Config) -> Result<HttpClient, BackupStoreError> {
    let timeout = Duration::from_secs(config.request_timeout_seconds);
    let client = reqwest::Client::builder()
        .tls_certs_only(crate::utils::tls::mozilla_root_certificates())
        .https_only(!config.allow_http)
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(
            timeout.as_secs().min(MAX_CONNECT_TIMEOUT_SECONDS),
        ))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| BackupStoreError::InvalidConfiguration(error.to_string()))?;
    Ok(HttpClient::new(BoundedService(client)))
}

pub(super) fn amazon_s3(
    config: &BackupS3Config,
    credentials: &S3Credentials,
    bucket_endpoint: &str,
    http: HttpClient,
) -> Result<AmazonS3, BackupStoreError> {
    let timeout = Duration::from_secs(config.request_timeout_seconds);
    let attempts = u32::try_from(config.max_retries.saturating_add(1)).unwrap_or(u32::MAX);
    let mut builder = AmazonS3Builder::new()
        .with_bucket_name(config.bucket.trim())
        .with_region(config.region.trim())
        // The endpoint already names the bucket in either addressing style.
        .with_endpoint(bucket_endpoint)
        .with_virtual_hosted_style_request(true)
        .with_access_key_id(&credentials.access_key_id)
        .with_secret_access_key(&credentials.secret_access_key)
        .with_allow_http(config.allow_http)
        // Single-object DELETE is the one every S3-compatible store supports.
        .with_disable_bulk_delete(true)
        .with_retry(retry_config(
            config.max_retries,
            timeout.saturating_mul(attempts),
        ))
        .with_http_connector(FixedConnector(http));
    if let Some(token) = &credentials.session_token {
        builder = builder.with_token(token);
    }
    builder
        .build()
        .map_err(|error| BackupStoreError::InvalidConfiguration(error.to_string()))
}

fn retry_config(max_retries: usize, retry_timeout: Duration) -> RetryConfig {
    RetryConfig {
        backoff: BackoffConfig {
            init_backoff: Duration::from_millis(RETRY_BASE_DELAY_MILLIS),
            max_backoff: Duration::from_millis(
                RETRY_BASE_DELAY_MILLIS << MAX_RETRY_BACKOFF_EXPONENT,
            ),
            base: 2.0,
        },
        max_retries,
        retry_timeout,
    }
}

pub(super) fn remote_error(operation: &str, error: object_store::Error) -> BackupStoreError {
    BackupStoreError::Remote(format!("S3 {operation} failed: {error}"))
}

/// Hands `object_store` the preconfigured client instead of letting it build
/// one from [`ClientOptions`], so TLS roots and timeouts stay ours.
#[derive(Debug)]
struct FixedConnector(HttpClient);

impl HttpConnector for FixedConnector {
    fn connect(&self, _options: &ClientOptions) -> object_store::Result<HttpClient> {
        Ok(self.0.clone())
    }
}

/// Caps every response body except a successful object download at
/// [`MAX_RESPONSE_BYTES`], so a hostile endpoint cannot make the daemon
/// buffer an unbounded listing or error document.
#[derive(Debug)]
struct BoundedService(reqwest::Client);

#[async_trait::async_trait]
impl HttpService for BoundedService {
    async fn call(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let object_get = request.method() == Method::GET && request.uri().query().is_none();
        let response = self.0.call(request).await?;
        if object_get && response.status().is_success() {
            return Ok(response);
        }
        let (parts, body) = response.into_parts();
        let body = HttpResponseBody::new(BoundedBody {
            inner: body,
            remaining: MAX_RESPONSE_BYTES,
        });
        Ok(HttpResponse::from_parts(parts, body))
    }
}

struct BoundedBody {
    inner: HttpResponseBody,
    remaining: u64,
}

impl Body for BoundedBody {
    type Data = Bytes;
    type Error = HttpError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, HttpError>>> {
        let frame = match Pin::new(&mut self.inner).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => frame,
            other => return other,
        };
        let length = frame.data_ref().map_or(0, |data| data.len() as u64);
        match self.remaining.checked_sub(length) {
            Some(remaining) => {
                self.remaining = remaining;
                Poll::Ready(Some(Ok(frame)))
            }
            None => Poll::Ready(Some(Err(HttpError::new(
                HttpErrorKind::Decode,
                std::io::Error::other("S3 response exceeded its safety limit"),
            )))),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Signed bucket-level requests for multipart upload discovery.
pub(super) struct UploadAdmin {
    http: HttpClient,
    credential: AwsCredential,
    region: String,
    bucket_endpoint: String,
    max_retries: usize,
}

impl UploadAdmin {
    pub(super) fn new(
        config: &BackupS3Config,
        credentials: &S3Credentials,
        bucket_endpoint: &str,
        http: HttpClient,
    ) -> Self {
        Self {
            http,
            credential: credentials.aws(),
            region: config.region.trim().to_string(),
            bucket_endpoint: bucket_endpoint.to_string(),
            max_retries: config.max_retries,
        }
    }

    /// Sends a signed request for `key` (or the bucket when empty), retrying
    /// throttling, server errors and transport failures. Returns the status
    /// and the bounded body.
    pub(super) async fn send(
        &self,
        method: Method,
        key: &str,
        query: &[(&str, &str)],
        operation: &str,
    ) -> Result<(StatusCode, Bytes), BackupStoreError> {
        let url = self.url(key, query)?;
        let mut attempt = 0;
        loop {
            let retry = attempt < self.max_retries;
            match self.send_once(method.clone(), &url).await {
                Ok(response) if retry && retryable_status(response.status()) => {}
                Ok(response) => {
                    let status = response.status();
                    let body = response.into_body().bytes().await.map_err(|error| {
                        BackupStoreError::Remote(format!(
                            "failed to read S3 {operation} response: {error}"
                        ))
                    })?;
                    return Ok((status, body));
                }
                Err(error) if retry && retryable_error(&error) => {}
                Err(error) => {
                    return Err(BackupStoreError::Remote(format!(
                        "S3 {operation} request failed: {error}"
                    )));
                }
            }
            let factor = 1_u64 << attempt.min(MAX_RETRY_BACKOFF_EXPONENT as usize);
            tokio::time::sleep(Duration::from_millis(RETRY_BASE_DELAY_MILLIS * factor)).await;
            attempt += 1;
        }
    }

    async fn send_once(&self, method: Method, url: &Url) -> Result<HttpResponse, HttpError> {
        let mut request = HttpRequest::new(HttpRequestBody::empty());
        *request.method_mut() = method;
        *request.uri_mut() = url
            .as_str()
            .parse()
            .map_err(|error| HttpError::new(HttpErrorKind::Request, error))?;
        AwsAuthorizer::new(&self.credential, "s3", &self.region)
            .try_authorize(&mut request, None)
            .map_err(|error| HttpError::new(HttpErrorKind::Unknown, error))?;
        self.http.execute(request).await
    }

    pub(super) fn url(&self, key: &str, query: &[(&str, &str)]) -> Result<Url, BackupStoreError> {
        let mut url = self.bucket_endpoint.clone();
        if !key.is_empty() {
            url.push('/');
            url.push_str(&crate::utils::percent::encode_path(key.as_bytes()));
        }
        let mut url = Url::parse(&url)
            .map_err(|error| BackupStoreError::InvalidConfiguration(error.to_string()))?;
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        Ok(url)
    }
}

fn retryable_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn retryable_error(error: &HttpError) -> bool {
    matches!(
        error.kind(),
        HttpErrorKind::Connect
            | HttpErrorKind::Request
            | HttpErrorKind::Timeout
            | HttpErrorKind::Interrupted
    )
}
