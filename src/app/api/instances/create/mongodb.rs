use std::time::Duration;

use secrecy::SecretString;
use tokio::time::sleep;

use super::{fail_bad_request, fail_runtime};
use crate::{
    api::http::{response::ApiError, router::AppState},
    databases,
    shared::{protocol::Protocol, shell::sh_quote},
};

pub(crate) async fn provision_tenant(
    state: &AppState,
    instance_id: &str,
    database: &str,
    username: &str,
    password: &str,
    root_password: &str,
) -> Result<(), ApiError> {
    bootstrap_root(state, instance_id, root_password).await?;

    let tenant_script = databases::mongodb::provision::create_tenant_script(database, username)
        .map_err(|error| fail_bad_request(state, instance_id, error))?;
    let tenant_script = databases::mongodb::provision::admin_script(&tenant_script);
    let command = format!("mongosh --quiet --nodb --eval {}", sh_quote(&tenant_script));
    let tenant_password = SecretString::from(password.to_string());
    let root_password = SecretString::from(root_password.to_string());
    state
        .docker
        .exec_shell_with_secrets(
            Protocol::Mongodb,
            instance_id,
            &command,
            &[
                ("DBE_TENANT_PASSWORD", &tenant_password),
                ("DBE_ADMIN_PASSWORD", &root_password),
            ],
        )
        .await
        .map_err(|error| fail_runtime(state, instance_id, error))?;
    Ok(())
}

pub(crate) async fn bootstrap_root(
    state: &AppState,
    instance_id: &str,
    root_password: &str,
) -> Result<(), ApiError> {
    wait_for_localhost(state, instance_id).await?;
    let script = databases::mongodb::provision::create_root_user_script(
        databases::mongodb::docker::INTERNAL_ROOT_USERNAME,
    )
    .map_err(|error| fail_bad_request(state, instance_id, error))?;
    let command = format!(
        "mongosh --quiet mongodb://127.0.0.1/admin?directConnection=true --eval {}",
        sh_quote(&script)
    );
    let root_password = SecretString::from(root_password.to_string());
    state
        .docker
        .exec_shell_with_secrets(
            Protocol::Mongodb,
            instance_id,
            &command,
            &[("DBE_MONGO_ROOT_PASSWORD", &root_password)],
        )
        .await
        .map_err(|error| fail_runtime(state, instance_id, error))?;
    Ok(())
}

async fn wait_for_localhost(state: &AppState, instance_id: &str) -> Result<(), ApiError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut last_error = String::new();
    while tokio::time::Instant::now() < deadline {
        match state
            .docker
            .exec(
                Protocol::Mongodb,
                instance_id,
                vec![
                    "mongosh".to_string(),
                    "--quiet".to_string(),
                    "mongodb://127.0.0.1/admin?directConnection=true".to_string(),
                    "--eval".to_string(),
                    "db.adminCommand({ ping: 1 }).ok".to_string(),
                ],
            )
            .await
        {
            Ok(_) => return Ok(()),
            Err(error) => {
                last_error = error.to_string();
                sleep(Duration::from_secs(1)).await;
            }
        }
    }
    let message = format!("mongodb localhost bootstrap did not become ready: {last_error}");
    state
        .install_progress
        .fail_internal(instance_id, "mongodb bootstrap", &message);
    Err(ApiError::Runtime(message))
}
