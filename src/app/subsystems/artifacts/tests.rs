use super::download::{create_download_url, download, validate_download_token};
use super::files::{read_instance_artifacts, validate_artifact_name};
use super::types::{CreateDownloadRequest, DownloadClaims, DownloadKind};
use super::*;
use crate::routes::http::response::ApiError;
use crate::routes::http::router::AppState;
use crate::utils::constants::jwt::AUDIENCE;
use crate::utils::constants::jwt::ISSUER;
use crate::utils::time::now_unix;
use crate::{
    auth::api_token::ApiToken,
    config::{Config, PathConfig},
    databases::protocol::Protocol,
    server::{
        manager::InstanceManager, metadata::InstanceMetadata, state::InstanceStore, test_support,
    },
    storage::{repositories::InstanceRepository, sqlite},
    subsystems::test_support as api_test_support,
    utils::backend::BackendEndpoint,
};
use jsonwebtoken::Algorithm;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use jsonwebtoken::encode;
use std::net::SocketAddr;

#[test]
fn artifact_names_reject_path_traversal_and_controls() {
    for name in [
        "../x.sql",
        "nested/x.sql",
        "nested\\x.sql",
        "..x.sql",
        "",
        ".",
    ] {
        assert!(validate_artifact_name(name).is_err(), "{name}");
    }
    assert!(validate_artifact_name("inst_1.postgres.sql.gz").is_ok());
}

#[test]
fn download_admission_normalizes_peers_and_releases_capacity() -> anyhow::Result<()> {
    let tickets = ArtifactDownloadTickets::default();
    let peer = Some("192.0.2.10:5000".parse()?);
    let mapped = Some("[::ffff:192.0.2.10]:5000".parse()?);
    let permits = (0..MAX_ACTIVE_DOWNLOADS_PER_PEER)
        .map(|_| {
            tickets
                .admit_download(peer)
                .expect("admit download should succeed")
        })
        .collect::<Vec<_>>();

    assert!(matches!(
        tickets.admit_download(mapped),
        Err(ApiError::RateLimited)
    ));
    assert!(
        tickets
            .admit_download(Some("192.0.2.11:5000".parse()?))
            .is_ok()
    );
    drop(permits);
    assert!(tickets.admit_download(mapped).is_ok());

    Ok(())
}

#[test]
fn download_streams_are_bounded_node_wide() -> anyhow::Result<()> {
    let tickets = ArtifactDownloadTickets::default();
    let permits = (0..MAX_ACTIVE_DOWNLOADS)
        .map(|index| {
            let third = u8::try_from(index / 256).expect("try from should succeed");
            let fourth = u8::try_from(index % 256).expect("try from should succeed");
            tickets
                .admit_download(Some(SocketAddr::from(([198, 18, third, fourth], 5000))))
                .expect("admit download should succeed")
        })
        .collect::<Vec<_>>();

    assert!(matches!(
        tickets.admit_download(Some("203.0.113.10:5000".parse()?)),
        Err(ApiError::RateLimited)
    ));
    drop(permits);
    assert!(
        tickets
            .admit_download(Some("203.0.113.10:5000".parse()?))
            .is_ok()
    );

    Ok(())
}

#[tokio::test]
async fn temporary_download_url_is_single_use_and_path_scoped() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let state = test_state().await;
    let artifact_name = "inst_abc.postgres.sql.gz";
    let artifact = instance_export_root(&state, "inst_abc").join(artifact_name);
    tokio::fs::create_dir_all(artifact.parent().context("expected a value from parent")?).await?;
    tokio::fs::write(&artifact, b"dump").await?;
    state.instances.upsert(sample_metadata("inst_abc")).await;

    let ticket = create_download_url(
        &state,
        artifact_name,
        "inst_abc",
        CreateDownloadRequest {
            expires_in_seconds: Some(60),
            single_use: Some(true),
        },
        DownloadKind::Artifact,
    )
    .await?
    .into_body();
    let public_ticket = serde_json::to_value(&ticket)?;
    let fields = public_ticket.as_object().context("expected an object")?;
    assert_eq!(fields.len(), 3);
    assert!(fields.contains_key("url"));
    assert!(fields.contains_key("expires_at_unix"));
    assert!(fields.contains_key("single_use"));
    assert!(ticket.url.starts_with(&format!(
        "/api/instances/inst_abc/artifacts/{artifact_name}/download?token="
    )));
    assert!(!ticket.url.contains("dbe.example.com"));
    let token = ticket
        .url
        .split_once("token=")
        .expect("signed URL contains token")
        .1
        .to_string();

    let mismatch = download(
        &state,
        &token,
        "inst_other",
        artifact_name,
        DownloadKind::Artifact,
        None,
    )
    .await
    .expect_err("download should return an error");
    assert!(matches!(mismatch, ApiError::Unauthorized));

    download(
        &state,
        &token,
        "inst_abc",
        artifact_name,
        DownloadKind::Artifact,
        None,
    )
    .await?;
    let error = download(
        &state,
        &token,
        "inst_abc",
        artifact_name,
        DownloadKind::Artifact,
        None,
    )
    .await
    .expect_err("download should return an error");
    assert!(matches!(error, ApiError::Unauthorized));

    Ok(())
}

#[tokio::test]
async fn temporary_download_url_rejects_expired_token_without_leeway() -> anyhow::Result<()> {
    let state = test_state().await;
    let now = now_unix();
    let claims = DownloadClaims {
        iss: ISSUER.to_string(),
        aud: AUDIENCE.to_string(),
        sub: "panel".to_string(),
        purpose: DOWNLOAD_PURPOSE.to_string(),
        kind: DownloadKind::Artifact.as_str().to_string(),
        artifact: "inst_abc.postgres.sql.gz".to_string(),
        instance_id: "inst_abc".to_string(),
        single_use: true,
        iat: now - 10,
        nbf: now - 10,
        exp: now - 1,
        jti: Uuid::new_v4().to_string(),
    };
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(state.config.websocket_jwt_secret())?,
    )?;

    let error = validate_download_token(&state, &token)
        .expect_err("validate download token should return an error");

    assert!(matches!(error, ApiError::Unauthorized));

    Ok(())
}

#[tokio::test]
async fn artifact_must_belong_to_requested_instance() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let state = test_state().await;
    let artifact_name = "inst_abc.postgres.sql.gz";
    let artifact = instance_export_root(&state, "inst_other").join(artifact_name);
    tokio::fs::create_dir_all(artifact.parent().context("expected a value from parent")?).await?;
    tokio::fs::write(&artifact, b"dump").await?;
    state.instances.upsert(sample_metadata("inst_abc")).await;
    state.instances.upsert(sample_metadata("inst_other")).await;

    let error = create_download_url(
        &state,
        artifact_name,
        "inst_abc",
        CreateDownloadRequest {
            expires_in_seconds: Some(60),
            single_use: Some(true),
        },
        DownloadKind::Artifact,
    )
    .await
    .expect_err("create download url should return an error");

    assert!(matches!(error, ApiError::NotFound));

    Ok(())
}

#[tokio::test]
async fn one_use_export_is_hidden_forced_single_use_and_deleted_with_stream() -> anyhow::Result<()>
{
    use anyhow::Context as _;

    let state = test_state_with_policy(true, 20).await;
    let artifact_name = "one-use.mongodb.archive.gz";
    let artifact = instance_spool_root(&state, "inst_abc").join(artifact_name);
    tokio::fs::create_dir_all(artifact.parent().context("expected a value from parent")?).await?;
    tokio::fs::write(&artifact, b"dump").await?;
    state.instances.upsert(sample_metadata("inst_abc")).await;

    assert!(
        read_instance_artifacts(&state, "inst_abc")
            .await?
            .is_empty()
    );
    let ticket = create_download_url(
        &state,
        artifact_name,
        "inst_abc",
        CreateDownloadRequest {
            expires_in_seconds: Some(60),
            single_use: Some(false),
        },
        DownloadKind::Artifact,
    )
    .await?
    .into_body();
    assert!(ticket.single_use);
    let token = ticket
        .url
        .split_once("token=")
        .context("expected a value from split_once")?
        .1;
    let response = download(
        &state,
        token,
        "inst_abc",
        artifact_name,
        DownloadKind::Artifact,
        None,
    )
    .await?;
    assert!(artifact.exists());
    drop(response);
    assert!(!artifact.exists());

    Ok(())
}

#[tokio::test]
async fn per_instance_artifact_limit_counts_retained_and_one_use_outputs() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let state = test_state_with_policy(false, 2).await;
    for path in [
        instance_export_root(&state, "inst_abc").join("retained.sql"),
        instance_spool_root(&state, "inst_abc").join("pending.sql"),
    ] {
        tokio::fs::create_dir_all(path.parent().context("expected a value from parent")?).await?;
        tokio::fs::write(path, b"dump").await?;
    }

    let error = check_export_slot(&state, "inst_abc")
        .await
        .expect_err("check export slot should return an error");
    assert!(matches!(error, ApiError::Conflict(_)));

    Ok(())
}

#[tokio::test]
async fn one_use_sweeper_removes_expired_output_but_preserves_active_export() -> anyhow::Result<()>
{
    let state = test_state_with_policy(true, 20).await;
    let root = instance_spool_root(&state, "inst_abc");
    tokio::fs::create_dir_all(&root).await?;
    let stale = root.join("stale.sql");
    let active = root.join("active.sql");
    for path in [&stale, &active] {
        std::fs::write(path, b"dump")?;
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)?
            .set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH))?;
    }
    state
        .import_export_jobs
        .insert(crate::server::jobs::import_export::ImportExportJob {
            job_id: "active-export".to_string(),
            instance_id: "inst_abc".to_string(),
            action: crate::server::jobs::import_export::ImportExportAction::Export,
            status: crate::server::jobs::import_export::ImportExportStatus::Running,
            artifact_path: Some(active.display().to_string()),
            replay_options: None,
            error: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        })
        .await?;

    assert_eq!(sweep_one_use_exports(&state).await?, 1);
    assert!(!stale.exists());
    assert!(active.exists());

    Ok(())
}

#[tokio::test]
async fn verified_artifact_path_rejects_symlinks() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let state = test_state().await;
    let artifact = instance_export_root(&state, "inst_abc").join("link.sql");
    tokio::fs::create_dir_all(artifact.parent().context("expected a value from parent")?).await?;
    std::os::unix::fs::symlink("/etc/passwd", &artifact)?;

    let error = verified_artifact_path(&state, "link.sql", "inst_abc")
        .await
        .expect_err("verified artifact path should return an error");
    assert!(matches!(error, ApiError::BadRequest(_)));

    Ok(())
}

async fn test_state() -> AppState {
    test_state_with_policy(false, 20).await
}

async fn test_state_with_policy(
    stream_exports_only: bool,
    max_artifacts_per_instance: usize,
) -> AppState {
    let dir = tempfile::tempdir().expect("tempdir should succeed").keep();
    let pool = sqlite::connect(&dir).await.expect("connect should succeed");
    let store = InstanceStore::default();
    let manager = InstanceManager::new(store.clone(), InstanceRepository::new(pool.clone()));
    let config = Config {
        uuid: "node".to_string(),
        token_id: "token-id".to_string(),
        token: "secret".to_string(),
        jwt_signing_key: "test-jwt-signing-key-at-least-32-bytes".to_string(),
        remote: "https://panel.example.com".to_string(),
        artifacts: crate::config::ArtifactConfig {
            stream_exports_only,
            max_artifacts_per_instance,
            ..Default::default()
        },
        paths: PathConfig {
            data: dir.display().to_string(),
            artifacts: dir.join("artifacts").display().to_string(),
            tmp: dir.join("tmp").display().to_string(),
            ..Default::default()
        },
        ..Default::default()
    };
    api_test_support::state(
        config,
        dir.join("config.yml"),
        ApiToken::new("secret"),
        store,
        manager,
        pool,
    )
}

fn sample_metadata(instance_id: &str) -> InstanceMetadata {
    let mut metadata = test_support::metadata(instance_id, Protocol::Postgres);
    metadata.public.port = 5434;
    metadata.backend = BackendEndpoint::UnixSocket {
        socket_path: format!("/run/dbev/sockets/{instance_id}/.s.PGSQL.5432"),
    };
    metadata.database.name = "db".to_string();
    metadata.database.username = "user".to_string();
    metadata
}
