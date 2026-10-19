//! Root-only reveal of an instance's stored credentials.
//!
//! The API never returns passwords. Root on the host can already read the
//! daemon's metadata key, so the console reads the encrypted credential store
//! directly: the SQLite database is opened read-only (no migrations, no
//! creation) and the key without creating it or touching its mode, so this is
//! safe while the daemon runs.

use std::{path::Path, time::Duration};

use anyhow::{Context, anyhow, bail};
use secrecy::SecretString;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

use crate::{
    config::Config, server::placement::DeploymentMode, storage::repositories::InstanceRepository,
    storage::secrets::SecretStore,
};

pub(super) struct RevealedCredentials {
    pub username: String,
    pub password: SecretString,
    /// Engine superuser of a dedicated runtime, e.g. `MariaDB root`.
    pub admin: Option<(&'static str, SecretString)>,
}

pub(super) fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

pub(super) async fn reveal(
    config: &Config,
    instance_id: &str,
) -> anyhow::Result<RevealedCredentials> {
    if !is_root() {
        bail!("revealing stored passwords needs root; rerun the console with sudo");
    }
    read_stored(Path::new(&config.paths.metadata_root()), instance_id).await
}

async fn read_stored(
    metadata_root: &Path,
    instance_id: &str,
) -> anyhow::Result<RevealedCredentials> {
    let secrets = SecretStore::open_existing(metadata_root)
        .context("cannot open the daemon's metadata key")?;
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(crate::storage::sqlite::database_path(metadata_root))
                .read_only(true)
                .create_if_missing(false)
                .busy_timeout(Duration::from_secs(5)),
        )
        .await
        .context("cannot open the daemon metadata read-only")?;
    let repository = InstanceRepository::with_secrets(pool.clone(), secrets);
    let metadata = repository.get(instance_id).await;
    pool.close().await;
    let metadata = metadata
        .context("cannot read the stored instance")?
        .ok_or_else(|| anyhow!("instance {instance_id} is not in the daemon metadata"))?;
    let password = metadata
        .tenant_password
        .clone()
        .filter(|password| !password.is_empty())
        .ok_or_else(|| anyhow!("instance {instance_id} has no stored tenant password"))?;
    let engine = metadata.protocol.engine();
    let admin = if metadata.deployment_mode == DeploymentMode::Dedicated {
        engine
            .maintenance_secret_label()
            .zip(engine.runtime_admin_secret(&metadata))
            .map(|(label, secret)| (label, SecretString::from(secret.to_string())))
    } else {
        // A shared pool's superuser spans other tenants; never reveal it here.
        None
    };
    Ok(RevealedCredentials {
        username: metadata.database.username.clone(),
        password: SecretString::from(password),
        admin,
    })
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;
    use crate::databases::protocol::Protocol;

    #[tokio::test]
    async fn stored_credentials_are_read_without_writing_anything() {
        let root = tempfile::tempdir().unwrap();
        assert!(read_stored(root.path(), "inst_one").await.is_err());
        assert!(
            !root.path().join("metadata.key").exists(),
            "a missing key is never created"
        );

        let pool = crate::storage::sqlite::connect(root.path()).await.unwrap();
        let writer = InstanceRepository::encrypted(pool.clone(), root.path()).unwrap();
        let mut metadata = crate::server::test_support::metadata("inst_one", Protocol::Mariadb);
        metadata.tenant_password = Some("tenant-secret".to_string());
        metadata.mariadb_root_password = Some("root-secret".to_string());
        writer.upsert(&metadata).await.unwrap();
        pool.close().await;
        let database = crate::storage::sqlite::database_path(root.path());
        let before = std::fs::read(&database).unwrap();

        let revealed = read_stored(root.path(), "inst_one").await.unwrap();

        assert_eq!(revealed.username, metadata.database.username);
        assert_eq!(revealed.password.expose_secret(), "tenant-secret");
        let (label, admin) = revealed.admin.unwrap();
        assert_eq!(label, "MariaDB root");
        assert_eq!(admin.expose_secret(), "root-secret");
        assert_eq!(std::fs::read(&database).unwrap(), before);
        assert!(read_stored(root.path(), "inst_missing").await.is_err());
    }
}
