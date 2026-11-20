use bytes::Bytes;
use http::{Method, StatusCode, header};
use serde::{Deserialize, Serialize};

use super::{
    S3Client,
    client::{known_code, service_error},
};
use crate::server::backup::BackupStoreError;

#[derive(Deserialize)]
enum Initiation {
    InitiateMultipartUploadResult {
        #[serde(rename = "UploadId")]
        upload_id: String,
    },
}

#[derive(Deserialize)]
enum Completion {
    CompleteMultipartUploadResult {
        #[serde(rename = "ETag")]
        etag: String,
    },
    Error {
        #[serde(rename = "Code")]
        code: String,
    },
}

#[derive(Serialize)]
pub(super) struct Part {
    #[serde(rename = "PartNumber")]
    number: u64,
    #[serde(rename = "ETag")]
    etag: String,
}

#[derive(Serialize)]
struct CompleteMultipartUpload {
    #[serde(rename = "Part")]
    parts: Vec<Part>,
}

impl S3Client {
    pub(super) async fn create_multipart(&self, key: &str) -> Result<String, BackupStoreError> {
        let operation = "initiate multipart upload";
        let response = self
            .send(
                Method::POST,
                key,
                &[("uploads", "")],
                Bytes::new(),
                operation,
            )
            .await?
            .success(operation)?;
        let Initiation::InitiateMultipartUploadResult { upload_id } =
            quick_xml::de::from_reader(response.body.as_slice())
                .map_err(|_| BackupStoreError::Corrupt("invalid S3 multipart initiation".into()))?;
        if upload_id.is_empty() {
            return Err(BackupStoreError::Corrupt(
                "S3 returned an empty upload ID".into(),
            ));
        }
        Ok(upload_id)
    }

    pub(super) async fn put_part(
        &self,
        key: &str,
        upload_id: &str,
        number: u64,
        body: Bytes,
    ) -> Result<Part, BackupStoreError> {
        let operation = "upload multipart part";
        let part_number = number.to_string();
        let response = self
            .send(
                Method::PUT,
                key,
                &[("partNumber", &part_number), ("uploadId", upload_id)],
                body,
                operation,
            )
            .await?
            .success(operation)?;
        Ok(Part {
            number,
            etag: response.etag(operation)?.to_owned(),
        })
    }

    pub(super) async fn complete_multipart(
        &self,
        key: &str,
        upload_id: &str,
        parts: Vec<Part>,
    ) -> Result<(), BackupStoreError> {
        let operation = "complete multipart upload";
        let xml = quick_xml::se::to_string(&CompleteMultipartUpload { parts })
            .map_err(|_| BackupStoreError::Runtime("failed to serialize S3 completion".into()))?;
        let mut request =
            self.request(Method::POST, key, &[("uploadId", upload_id)], xml.into())?;
        request.headers_mut().insert(
            header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/xml"),
        );
        let mut budget = self.budget();
        loop {
            let response = self
                .control(&request, &mut budget, operation)
                .await?
                .success(operation)?;
            let result = quick_xml::de::from_reader(response.body.as_slice())
                .map_err(|_| BackupStoreError::Corrupt("invalid S3 completion response".into()))?;
            match result {
                Completion::CompleteMultipartUploadResult { etag } if !etag.is_empty() => {
                    return Ok(());
                }
                Completion::CompleteMultipartUploadResult { .. } => {
                    return Err(BackupStoreError::Corrupt("empty S3 completion ETag".into()));
                }
                Completion::Error { code } => {
                    let code = known_code(&code);
                    if !matches!(code, Some("InternalError" | "SlowDown")) || !budget.retry().await
                    {
                        return Err(service_error(operation, response.status, code));
                    }
                }
            }
        }
    }

    /// A missing upload is confirmed separately by ListParts during purge.
    pub(super) async fn abort_multipart(
        &self,
        key: &str,
        upload_id: &str,
    ) -> Result<(), BackupStoreError> {
        let operation = "abort multipart upload";
        let response = self
            .send(
                Method::DELETE,
                key,
                &[("uploadId", upload_id)],
                Bytes::new(),
                operation,
            )
            .await?;
        if response.status == StatusCode::NOT_FOUND {
            return Ok(());
        }
        response.success(operation).map(drop)
    }
}
