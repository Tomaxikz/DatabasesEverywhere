use super::*;

impl S3BackupDriver {
    pub(super) async fn get_bytes(
        &self,
        key: &str,
        max_bytes: u64,
    ) -> Result<Vec<u8>, BackupStoreError> {
        for attempt in 0..=self.config.max_retries {
            let response = self
                .signed_request(Method::GET, key, &[], EMPTY_SHA256)?
                .send()
                .await;
            let response = match response {
                Ok(response) if response.status() == StatusCode::NOT_FOUND => {
                    return Err(BackupStoreError::NotFound);
                }
                Ok(response) if response.status().is_success() => response,
                Ok(response)
                    if retryable_status(response.status()) && attempt < self.config.max_retries =>
                {
                    retry_delay(attempt).await;
                    continue;
                }
                Ok(response) => return Err(s3_status_error("download object", &response)),
                Err(error) if attempt < self.config.max_retries && retryable_error(&error) => {
                    retry_delay(attempt).await;
                    continue;
                }
                Err(error) => {
                    return Err(BackupStoreError::Remote(format!(
                        "S3 download request failed: {error}"
                    )));
                }
            };
            return response_bytes_bounded(response, max_bytes, "object download")
                .await
                .map(|bytes| bytes.to_vec());
        }
        Err(BackupStoreError::Remote(
            "S3 download exhausted its retry budget".to_string(),
        ))
    }

    pub(super) async fn download_file(
        &self,
        key: &str,
        destination: &Path,
        manifest: &StoredBackup,
    ) -> Result<(), BackupStoreError> {
        let response = self.get_with_retry(key, "download backup archive").await?;
        if response
            .content_length()
            .is_some_and(|length| length != manifest.size_bytes)
        {
            return Err(BackupStoreError::Corrupt(
                "S3 backup size does not match its metadata".to_string(),
            ));
        }

        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options
            .open(destination)
            .await
            .map_err(|source| io_error("create materialized S3 backup", source))?;
        let mut stream = response.bytes_stream();
        let mut written = 0_u64;
        let result = async {
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|error| {
                    BackupStoreError::Remote(format!("failed while reading S3 backup: {error}"))
                })?;
                written = written.saturating_add(chunk.len() as u64);
                if written > manifest.size_bytes {
                    return Err(BackupStoreError::Corrupt(
                        "S3 backup exceeds the size recorded in its metadata".to_string(),
                    ));
                }
                file.write_all(&chunk)
                    .await
                    .map_err(|source| io_error("write materialized S3 backup", source))?;
            }
            file.flush()
                .await
                .map_err(|source| io_error("flush materialized S3 backup", source))?;
            file.sync_all()
                .await
                .map_err(|source| io_error("sync materialized S3 backup", source))?;
            if written != manifest.size_bytes {
                return Err(BackupStoreError::Corrupt(
                    "S3 backup ended before its recorded size".to_string(),
                ));
            }
            manifest.verify_archive(destination, "S3 backup").await
        }
        .await;
        if result.is_err() {
            drop(file);
            remove_file_if_exists(destination).await;
        }
        result
    }

    async fn get_with_retry(
        &self,
        key: &str,
        operation: &str,
    ) -> Result<reqwest::Response, BackupStoreError> {
        for attempt in 0..=self.config.max_retries {
            match self
                .signed_request(Method::GET, key, &[], EMPTY_SHA256)?
                .send()
                .await
            {
                Ok(response) if response.status() == StatusCode::NOT_FOUND => {
                    return Err(BackupStoreError::NotFound);
                }
                Ok(response) if response.status().is_success() => return Ok(response),
                Ok(response)
                    if retryable_status(response.status()) && attempt < self.config.max_retries =>
                {
                    retry_delay(attempt).await;
                }
                Ok(response) => return Err(s3_status_error(operation, &response)),
                Err(error) if attempt < self.config.max_retries && retryable_error(&error) => {
                    retry_delay(attempt).await;
                }
                Err(error) => {
                    return Err(BackupStoreError::Remote(format!(
                        "S3 {operation} request failed: {error}"
                    )));
                }
            }
        }
        Err(BackupStoreError::Remote(format!(
            "S3 {operation} exhausted its retry budget"
        )))
    }
}

pub(super) async fn response_bytes_bounded(
    mut response: reqwest::Response,
    max_bytes: u64,
    operation: &str,
) -> Result<Bytes, BackupStoreError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes)
    {
        return Err(BackupStoreError::Corrupt(format!(
            "S3 {operation} response exceeded its safety limit"
        )));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        BackupStoreError::Remote(format!("failed to read S3 {operation} response: {error}"))
    })? {
        append_bounded_chunk(&mut bytes, &chunk, max_bytes, operation)?;
    }
    Ok(Bytes::from(bytes))
}

pub(super) fn append_bounded_chunk(
    bytes: &mut Vec<u8>,
    chunk: &[u8],
    max_bytes: u64,
    operation: &str,
) -> Result<(), BackupStoreError> {
    let prospective_size = u64::try_from(bytes.len())
        .unwrap_or(u64::MAX)
        .saturating_add(chunk.len() as u64);
    if prospective_size > max_bytes {
        return Err(BackupStoreError::Corrupt(format!(
            "S3 {operation} response exceeded its safety limit"
        )));
    }
    bytes.extend_from_slice(chunk);
    Ok(())
}
