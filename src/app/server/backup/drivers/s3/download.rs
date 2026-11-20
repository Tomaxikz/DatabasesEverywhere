//! A download shares one retry budget across the initial GET and every range request.
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use reqwest::Response;

use super::{
    S3Client,
    client::{ControlResponse, RetryBudget},
    signing::ReplayBody,
};
use crate::server::backup::BackupStoreError;

pub(super) struct Download<'a> {
    client: &'a S3Client,
    request: Request<ReplayBody>,
    budget: RetryBudget,
    response: Response,
    etag: Option<HeaderValue>,
    pub(super) size: u64,
    delivered: u64,
    overlap: u64,
}

impl<'a> Download<'a> {
    pub(super) async fn open(client: &'a S3Client, key: &str) -> Result<Self, BackupStoreError> {
        let request = client.request(Method::GET, key, &[], Bytes::new())?;
        let mut budget = client.budget();
        let response = client
            .execute(&request, &mut budget, "download object")
            .await?;
        if response.status() != StatusCode::OK {
            let response = ControlResponse::read(response, "download object").await?;
            if response.status == StatusCode::NOT_FOUND {
                return Err(BackupStoreError::NotFound);
            }
            return Err(response.error("download object"));
        }
        let size = length(&response)?.ok_or_else(|| invalid("missing Content-Length"))?;
        let etag = strong_etag(response.headers()).cloned();
        Ok(Self {
            client,
            request,
            budget,
            response,
            etag,
            size,
            delivered: 0,
            overlap: 0,
        })
    }

    pub(super) async fn chunk(&mut self) -> Result<Option<Bytes>, BackupStoreError> {
        loop {
            let error = match self.response.chunk().await {
                Ok(Some(bytes)) => {
                    let skip = self.overlap.min(bytes.len() as u64);
                    self.overlap -= skip;
                    let chunk = bytes.slice(skip as usize..);
                    if chunk.is_empty() {
                        continue;
                    }
                    if chunk.len() as u64 > self.size - self.delivered {
                        return Err(invalid("body exceeds its advertised length"));
                    }
                    self.delivered += chunk.len() as u64;
                    return Ok(Some(chunk));
                }
                Ok(None) if self.delivered == self.size => return Ok(None),
                Ok(None) => invalid("body ended before its advertised length"),
                Err(e) => BackupStoreError::Remote(format!(
                    "failed to read S3 object: {}",
                    e.without_url()
                )),
            };
            let Some(etag) = self.etag.clone() else {
                return Err(error);
            };
            if self.delivered >= self.size || !self.budget.retry().await {
                return Err(error);
            }
            self.resume(etag).await?;
        }
    }

    async fn resume(&mut self, etag: HeaderValue) -> Result<(), BackupStoreError> {
        let range = format!("bytes={}-{}", self.delivered, self.size - 1);
        self.request
            .headers_mut()
            .insert(header::RANGE, range.parse().expect("numeric range"));
        self.request.headers_mut().insert(header::IF_MATCH, etag);
        let response = self
            .client
            .execute(&self.request, &mut self.budget, "resume download")
            .await?;
        if !response.status().is_success() {
            return Err(ControlResponse::read(response, "resume download")
                .await?
                .error("resume download"));
        }
        if response.status() != StatusCode::PARTIAL_CONTENT
            || strong_etag(response.headers()) != self.etag.as_ref()
        {
            return Err(invalid(
                "resumed GET requires HTTP 206 and the original ETag",
            ));
        }
        let (start, end, total) = response
            .headers()
            .get(header::CONTENT_RANGE)
            .and_then(|h| h.to_str().ok())
            .and_then(parse_range)
            .ok_or_else(|| invalid("invalid Content-Range"))?;
        if start > self.delivered
            || total != self.size
            || end != total - 1
            || length(&response)?.is_some_and(|n| n != total - start)
        {
            return Err(invalid("Content-Range does not cover the remaining object"));
        }
        self.overlap = self.delivered - start;
        self.response = response;
        Ok(())
    }
}

fn strong_etag(headers: &HeaderMap) -> Option<&HeaderValue> {
    let mut values = headers.get_all(header::ETAG).iter();
    let tag = values.next()?;
    let opaque = tag.as_bytes().strip_prefix(b"\"")?.strip_suffix(b"\"")?;
    // RFC 9110 etagc permits "!", bytes from "#" through "~", and obs-text.
    (values.next().is_none()
        && opaque
            .iter()
            .all(|b| matches!(b, 0x21 | 0x23..=0x7e | 0x80..=0xff)))
    .then_some(tag)
}

fn length(response: &Response) -> Result<Option<u64>, BackupStoreError> {
    response
        .headers()
        .get(header::CONTENT_LENGTH)
        .map(|v| {
            v.to_str()
                .ok()
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| invalid("invalid Content-Length"))
        })
        .transpose()
}

fn parse_range(value: &str) -> Option<(u64, u64, u64)> {
    let (range, size) = value.strip_prefix("bytes ")?.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    Some((start.parse().ok()?, end.parse().ok()?, size.parse().ok()?))
}

fn invalid(message: &str) -> BackupStoreError {
    BackupStoreError::Corrupt(format!("S3 download: {message}"))
}
