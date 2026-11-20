use std::time::SystemTime;

use aws_credential_types::Credentials;
use aws_sigv4::{
    http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
        UriPathNormalizationMode, sign,
    },
    sign::v4,
};
use bytes::Bytes;
use http::{Request, header};
use sha2::{Digest, Sha256};

use crate::server::backup::BackupStoreError;

// The immutable bytes and their digest travel together through every application retry.
#[derive(Clone)]
pub(super) struct ReplayBody {
    bytes: Bytes,
    sha256: String,
}

impl ReplayBody {
    pub(super) fn new(bytes: Bytes) -> Self {
        let sha256 = hex::encode(Sha256::digest(&bytes));
        Self { bytes, sha256 }
    }
}

pub(super) fn sign_request(
    request: Request<ReplayBody>,
    credentials: &Credentials,
    region: &str,
    time: SystemTime,
) -> Result<reqwest::Request, BackupStoreError> {
    let identity = credentials.clone().into();
    let mut settings = SigningSettings::default();
    settings.percent_encoding_mode = PercentEncodingMode::Single;
    settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name("s3")
        .time(time)
        .settings(settings)
        .build()
        .map_err(signing_error)?
        .into();
    let (parts, body) = request.into_parts();
    let mut request = Request::from_parts(parts, body.bytes);
    let headers = request
        .headers()
        .iter()
        .map(|(name, value)| Ok((name.as_str(), value.to_str().map_err(signing_error)?)))
        .collect::<Result<Vec<_>, BackupStoreError>>()?;
    let signable = SignableRequest::new(
        request.method().as_str(),
        request.uri().to_string(),
        headers.into_iter(),
        SignableBody::Precomputed(body.sha256),
    )
    .map_err(signing_error)?;
    let (instructions, _) = sign(signable, &params).map_err(signing_error)?.into_parts();
    instructions.apply_to_request_http1x(&mut request);
    if let Some(auth) = request.headers_mut().get_mut(header::AUTHORIZATION) {
        auth.set_sensitive(true);
    }
    reqwest::Request::try_from(request).map_err(signing_error)
}

fn signing_error(_: impl std::fmt::Display) -> BackupStoreError {
    BackupStoreError::Remote("failed to sign S3 request".into())
}
