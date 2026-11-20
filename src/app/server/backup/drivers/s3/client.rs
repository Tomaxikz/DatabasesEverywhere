use std::time::{Duration, SystemTime};

use aws_credential_types::Credentials;
use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode, header};
use reqwest::{Response, Url};
use serde::Deserialize;
use tokio::time::Instant;

use super::{
    MAX_CONNECT_TIMEOUT_SECONDS, MAX_RESPONSE_BYTES, MAX_RETRY_BACKOFF_EXPONENT,
    RETRY_BASE_DELAY_MILLIS,
    objects::object_path,
    signing::{ReplayBody, sign_request},
};
use crate::{
    config::BackupS3Config,
    server::backup::BackupStoreError,
    utils::percent::{encode_path, encode_unreserved},
};

pub(super) fn credentials(config: &BackupS3Config) -> Result<Credentials, BackupStoreError> {
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
    // These values are interpolated into HTTP headers by the signer.
    for value in [access_key_id.as_str(), config.region.trim()]
        .into_iter()
        .chain(session_token.as_deref())
    {
        if !value.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
            return Err(BackupStoreError::InvalidConfiguration(
                "S3 signing header contains an invalid character".into(),
            ));
        }
    }
    Ok(Credentials::new(
        access_key_id,
        secret_access_key,
        session_token,
        None,
        "dbev",
    ))
}

/// Service endpoint; its string form is part of the storage identity and must stay stable.
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

pub(super) fn bucket_endpoint(base: &Url, config: &BackupS3Config) -> String {
    let mut endpoint = base.as_str().trim_end_matches('/').to_string();
    if config.path_style {
        endpoint.push('/');
        endpoint.push_str(config.bucket.trim());
    }
    endpoint
}

pub(super) struct S3Client {
    http: reqwest::Client,
    pub(super) credentials: Credentials,
    region: String,
    bucket_endpoint: String,
    max_retries: usize,
    pub(super) signing_time: fn() -> SystemTime,
    timeout: Duration,
}

pub(super) struct RetryBudget {
    remaining: usize,
    deadline: Option<Instant>,
    delay_ms: u64,
}

impl RetryBudget {
    pub(super) async fn retry(&mut self) -> bool {
        let delay = Duration::from_millis(self.delay_ms);
        if self.remaining == 0
            || self
                .deadline
                .is_some_and(|end| Instant::now() + delay >= end)
        {
            return false;
        }
        self.remaining -= 1;
        let doubled = self.delay_ms * 2;
        // Object operations use decorrelated jitter. Multipart discovery and confirmation
        // retain their deterministic backoff and per-request timeout.
        self.delay_ms = if self.deadline.is_some() {
            let mut random = [0; 4];
            let _ = aws_lc_rs::rand::fill(&mut random);
            RETRY_BASE_DELAY_MILLIS
                + u32::from_ne_bytes(random) as u64 % (doubled - RETRY_BASE_DELAY_MILLIS)
        } else {
            doubled
        }
        .min(RETRY_BASE_DELAY_MILLIS << MAX_RETRY_BACKOFF_EXPONENT);
        tokio::time::sleep(delay).await;
        true
    }
}

impl S3Client {
    pub(super) fn new(
        config: &BackupS3Config,
        credentials: Credentials,
        bucket_endpoint: String,
    ) -> Result<Self, BackupStoreError> {
        Self::with_builder(
            config,
            credentials,
            bucket_endpoint,
            crate::utils::tls::http_client_builder(),
        )
    }

    pub(super) fn with_builder(
        config: &BackupS3Config,
        credentials: Credentials,
        bucket_endpoint: String,
        builder: reqwest::ClientBuilder,
    ) -> Result<Self, BackupStoreError> {
        let timeout = Duration::from_secs(config.request_timeout_seconds);
        // reqwest retries remote HTTP/2 REFUSED_STREAM and graceful GOAWAY (NO_ERROR).
        // The application retry budget covers all other retries.
        let http = builder
            .tls_certs_only(crate::utils::tls::mozilla_root_certificates())
            .https_only(!config.allow_http)
            .timeout(timeout)
            .connect_timeout(timeout.min(Duration::from_secs(MAX_CONNECT_TIMEOUT_SECONDS)))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| BackupStoreError::InvalidConfiguration(error.to_string()))?;
        Ok(Self {
            http,
            signing_time: SystemTime::now,
            credentials,
            bucket_endpoint,
            region: config.region.trim().into(),
            timeout,
            max_retries: config.max_retries,
        })
    }

    pub(super) fn budget(&self) -> RetryBudget {
        let attempts = u32::try_from(self.max_retries.saturating_add(1)).unwrap_or(u32::MAX);
        RetryBudget {
            remaining: self.max_retries,
            deadline: Instant::now().checked_add(self.timeout.saturating_mul(attempts)),
            delay_ms: RETRY_BASE_DELAY_MILLIS,
        }
    }

    pub(super) fn url(&self, key: &str, query: &[(&str, &str)]) -> Result<Url, BackupStoreError> {
        let mut url = self.bucket_endpoint.clone();
        if !key.is_empty() {
            object_path(key)?;
            url.push('/');
            url.push_str(&encode_path(key.as_bytes()));
        }
        for (index, (name, value)) in query.iter().enumerate() {
            url.push(if index == 0 { '?' } else { '&' });
            url.push_str(&encode_unreserved(name.as_bytes()));
            url.push('=');
            url.push_str(&encode_unreserved(value.as_bytes()));
        }
        Url::parse(&url).map_err(|e| BackupStoreError::InvalidConfiguration(e.to_string()))
    }

    pub(super) fn request(
        &self,
        method: Method,
        key: &str,
        query: &[(&str, &str)],
        body: Bytes,
    ) -> Result<Request<ReplayBody>, BackupStoreError> {
        let mut builder = Request::builder().uri(self.url(key, query)?.as_str());
        if method == Method::PUT || method == Method::POST {
            builder = builder.header(header::CONTENT_LENGTH, body.len());
        }
        builder
            .method(method)
            .body(ReplayBody::new(body))
            .map_err(|e| BackupStoreError::InvalidConfiguration(e.to_string()))
    }

    pub(super) async fn execute(
        &self,
        request: &Request<ReplayBody>,
        budget: &mut RetryBudget,
        operation: &str,
    ) -> Result<Response, BackupStoreError> {
        loop {
            let signed = sign_request(
                request.clone(),
                &self.credentials,
                &self.region,
                (self.signing_time)(),
            )?;
            match self.http.execute(signed).await {
                Ok(response) => {
                    let status = response.status();
                    if !(status == StatusCode::TOO_MANY_REQUESTS
                        || status.is_server_error()
                        || (budget.deadline.is_some() && status == StatusCode::REQUEST_TIMEOUT))
                        || !budget.retry().await
                    {
                        return Ok(response);
                    }
                }
                Err(error) => {
                    if !retryable_transport(&error, request.method()) || !budget.retry().await {
                        return Err(BackupStoreError::Remote(format!(
                            "S3 {operation} request failed: {}",
                            error.without_url()
                        )));
                    }
                }
            }
        }
    }

    pub(super) async fn control(
        &self,
        request: &Request<ReplayBody>,
        budget: &mut RetryBudget,
        operation: &str,
    ) -> Result<ControlResponse, BackupStoreError> {
        let response = self.execute(request, budget, operation).await?;
        ControlResponse::read(response, operation).await
    }

    pub(super) async fn send(
        &self,
        method: Method,
        key: &str,
        query: &[(&str, &str)],
        body: Bytes,
        operation: &str,
    ) -> Result<ControlResponse, BackupStoreError> {
        let request = self.request(method, key, query, body)?;
        self.control(&request, &mut self.budget(), operation).await
    }

    pub(super) async fn discovery_get(
        &self,
        key: &str,
        query: &[(&str, &str)],
        operation: &str,
    ) -> Result<ControlResponse, BackupStoreError> {
        let request = self.request(Method::GET, key, query, Bytes::new())?;
        let mut budget = self.budget();
        budget.deadline = None;
        self.control(&request, &mut budget, operation).await
    }
}

/// Closed or incomplete requests can be retried on all operations. For a timeout
/// or interrupted connection, retain the single DELETE attempt used by the old driver.
fn retryable_transport(error: &reqwest::Error, method: &Method) -> bool {
    use std::{error::Error, io::ErrorKind};
    let replay = method != Method::DELETE;
    if error.is_timeout() {
        return replay;
    }
    if error.is_connect() {
        return true;
    }
    let mut source = error.source();
    while let Some(cause) = source {
        if let Some(http) = cause.downcast_ref::<hyper::Error>() {
            if http.is_closed() || http.is_incomplete_message() || http.is_body_write_aborted() {
                return true;
            }
            if http.is_timeout() {
                return replay;
            }
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>()
            && matches!(
                io.kind(),
                ErrorKind::TimedOut
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::ConnectionReset
                    | ErrorKind::BrokenPipe
                    | ErrorKind::UnexpectedEof
            )
        {
            return replay;
        }
        source = cause.source();
    }
    false
}

pub(super) struct ControlResponse {
    pub(super) status: StatusCode,
    headers: HeaderMap,
    pub(super) body: Vec<u8>,
}

impl ControlResponse {
    pub(super) async fn read(
        mut response: Response,
        operation: &str,
    ) -> Result<Self, BackupStoreError> {
        let too_large = || {
            BackupStoreError::Corrupt(format!("S3 {operation} response exceeded its safety limit"))
        };
        if response
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE_BYTES)
        {
            return Err(too_large());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| {
            BackupStoreError::Remote(format!(
                "failed to read S3 {operation} response: {}",
                e.without_url()
            ))
        })? {
            if chunk.len() > MAX_RESPONSE_BYTES as usize - body.len() {
                return Err(too_large());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Self {
            status: response.status(),
            headers: std::mem::take(response.headers_mut()),
            body,
        })
    }

    pub(super) fn etag(&self, operation: &str) -> Result<&str, BackupStoreError> {
        self.headers
            .get(header::ETAG)
            .and_then(|h| h.to_str().ok())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                BackupStoreError::Corrupt(format!("S3 {operation} response has no valid ETag"))
            })
    }

    pub(super) fn success(self, operation: &str) -> Result<Self, BackupStoreError> {
        if self.status.is_success() {
            Ok(self)
        } else {
            Err(self.error(operation))
        }
    }

    pub(super) fn error_code(&self) -> Option<&'static str> {
        #[derive(Deserialize)]
        enum ErrorDocument {
            Error {
                #[serde(rename = "Code")]
                code: String,
            },
        }

        quick_xml::de::from_reader::<_, ErrorDocument>(self.body.as_slice())
            .ok()
            .and_then(|ErrorDocument::Error { code }| known_code(&code))
    }

    pub(super) fn error(&self, operation: &str) -> BackupStoreError {
        service_error(operation, self.status, self.error_code())
    }
}

pub(super) fn known_code(code: &str) -> Option<&'static str> {
    [
        "AccessDenied",
        "EntityTooSmall",
        "InternalError",
        "InvalidAccessKeyId",
        "InvalidPart",
        "InvalidPartOrder",
        "NoSuchBucket",
        "NoSuchKey",
        "NoSuchUpload",
        "RequestTimeout",
        "SignatureDoesNotMatch",
        "SlowDown",
    ]
    .into_iter()
    .find(|known| *known == code)
}

pub(super) fn service_error(
    operation: &str,
    status: StatusCode,
    code: Option<&'static str>,
) -> BackupStoreError {
    let mut message = format!("S3 {operation} returned HTTP {status}");
    if let Some(code) = code {
        message.push_str(&format!(" ({code})"));
    }
    BackupStoreError::Remote(message)
}
