use crate::{routes::http::router::AppState, utils::time::now_rfc3339};

use super::{records::load_upload, storage::remove_upload_file};

pub(in super::super) async fn finish_upload_import_job(
    state: &AppState,
    instance_id: &str,
    upload_id: &str,
    job_id: &str,
    succeeded: bool,
    failure: Option<&str>,
) {
    let now = now_rfc3339();
    if succeeded {
        consume_and_delete_upload(state, instance_id, upload_id, job_id, &now).await;
    } else {
        release_failed_upload_claim(state, instance_id, upload_id, job_id, failure, &now).await;
    }
}

pub(super) async fn release_failed_upload_claim(
    state: &AppState,
    instance_id: &str,
    upload_id: &str,
    job_id: &str,
    failure: Option<&str>,
    now: &str,
) {
    match state
        .import_uploads
        .repo()
        .release_failed_claim(
            instance_id,
            upload_id,
            job_id,
            failure.unwrap_or("import job failed"),
            now,
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => tracing::error!(
            instance_id,
            upload_id,
            job_id,
            "failed import could not release its upload claim"
        ),
        Err(error) => {
            tracing::error!(instance_id, upload_id, job_id, %error, "failed to persist import upload release")
        }
    }
}

pub(super) async fn consume_and_delete_upload(
    state: &AppState,
    instance_id: &str,
    upload_id: &str,
    job_id: &str,
    now: &str,
) {
    match state
        .import_uploads
        .repo()
        .mark_consumed(instance_id, upload_id, job_id, now)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::error!(
                instance_id,
                upload_id,
                job_id,
                "successful import could not mark its upload consumed"
            );
            return;
        }
        Err(error) => {
            tracing::error!(instance_id, upload_id, job_id, %error, "successful import could not persist upload consumption");
            return;
        }
    }
    let upload = match load_upload(state, instance_id, upload_id).await {
        Ok(upload) => upload,
        Err(error) => {
            tracing::error!(instance_id, upload_id, job_id, %error, "consumed upload could not be loaded for cleanup");
            return;
        }
    };
    match state
        .import_uploads
        .repo()
        .claim_for_deletion(instance_id, upload_id, &now_rfc3339())
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::error!(
                instance_id,
                upload_id,
                job_id,
                "consumed upload could not enter cleanup state"
            );
            return;
        }
        Err(error) => {
            tracing::error!(instance_id, upload_id, job_id, %error, "consumed upload cleanup claim failed");
            return;
        }
    }
    if let Err(error) = remove_upload_file(state, &upload).await {
        tracing::error!(instance_id, upload_id, job_id, %error, "consumed upload cleanup will be retried");
        return;
    }
    if let Err(error) = state
        .import_uploads
        .repo()
        .finalize_delete(instance_id, upload_id)
        .await
    {
        tracing::error!(instance_id, upload_id, job_id, %error, "consumed upload row cleanup will be retried");
    }
}
