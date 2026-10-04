use reqwest::{Method, header};
use sha2::Digest;
use sha2::Sha256;

use super::S3BackupDriver;
use crate::{server::backup::BackupStoreError, utils::hex::encode_lower};

impl S3BackupDriver {
    pub(super) fn signed_request(
        &self,
        method: Method,
        key: &str,
        query: &[(String, String)],
        payload_hash: &str,
    ) -> Result<reqwest::RequestBuilder, BackupStoreError> {
        let now = time::OffsetDateTime::now_utc();
        let date = format!(
            "{:04}{:02}{:02}",
            now.year(),
            u8::from(now.month()),
            now.day()
        );
        let timestamp = format!(
            "{date}T{:02}{:02}{:02}Z",
            now.hour(),
            now.minute(),
            now.second()
        );
        let canonical_query = canonical_query(query);
        let (url, canonical_uri) = self
            .endpoint
            .url(&self.config.bucket, key, &canonical_query)?;
        let mut canonical_headers = format!(
            "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
            self.endpoint.authority, payload_hash, timestamp
        );
        let mut signed_headers = "host;x-amz-content-sha256;x-amz-date".to_string();
        if let Some(token) = self.credentials.session_token.as_deref() {
            canonical_headers.push_str(&format!("x-amz-security-token:{}\n", token.trim()));
            signed_headers.push_str(";x-amz-security-token");
        }
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method.as_str(),
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_hash
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.config.region.trim());
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            timestamp,
            scope,
            hex_sha256(canonical_request.as_bytes())
        );
        let signing_key = signing_key(
            &self.credentials.secret_access_key,
            &date,
            self.config.region.trim(),
        );
        let signature = encode_lower(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{},SignedHeaders={},Signature={}",
            self.credentials.access_key_id, scope, signed_headers, signature
        );
        let mut request = self
            .client
            .request(method, url)
            .header(header::HOST, &self.endpoint.authority)
            .header("x-amz-content-sha256", payload_hash)
            .header("x-amz-date", timestamp)
            .header(header::AUTHORIZATION, authorization);
        if let Some(token) = self.credentials.session_token.as_deref() {
            request = request.header("x-amz-security-token", token);
        }
        Ok(request)
    }
}

pub(super) fn canonical_query(query: &[(String, String)]) -> String {
    let mut encoded = query
        .iter()
        .map(|(name, value)| {
            (
                aws_uri_encode(name.as_bytes(), false),
                aws_uri_encode(value.as_bytes(), false),
            )
        })
        .collect::<Vec<_>>();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

pub(super) fn aws_uri_encode(bytes: &[u8], preserve_slashes: bool) -> String {
    let mut encoded = String::with_capacity(bytes.len());
    for &byte in bytes {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (preserve_slashes && byte == b'/')
        {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    encoded
}

fn signing_key(secret: &str, date: &str, region: &str) -> [u8; 32] {
    let date_key = hmac_sha256(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, b"s3");
    hmac_sha256(&service_key, b"aws4_request")
}

pub(super) fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_BYTES: usize = 64;
    let mut normalized = [0_u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; BLOCK_BYTES];
    for index in 0..BLOCK_BYTES {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

pub(super) fn hex_sha256(bytes: &[u8]) -> String {
    encode_lower(&Sha256::digest(bytes))
}
