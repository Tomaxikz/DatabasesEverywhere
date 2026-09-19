use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, ensure};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

pub(crate) async fn show(
    config_path: PathBuf,
    entity_id: Option<String>,
    history: bool,
    before: Option<i64>,
    limit: u32,
) -> anyhow::Result<()> {
    let config = crate::config::load::load_config(config_path)?;
    let path = crate::storage::sqlite::database_path(Path::new(&config.paths.metadata_root()));
    let pool = open_history(&path).await?;
    let records =
        crate::storage::quarantine::list(&pool, entity_id.as_deref(), history, before, limit)
            .await?;
    println!("{}", serde_json::to_string_pretty(&records)?);
    pool.close().await;
    Ok(())
}

async fn open_history(path: &Path) -> anyhow::Result<sqlx::SqlitePool> {
    // No migrations, directory creation, daemon lock, or schema writes: this is
    // usable while the daemon runs and must not create a misleading empty DB.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(path)
                .read_only(true)
                .create_if_missing(false)
                .busy_timeout(Duration::from_secs(5)),
        )
        .await
        .context("could not open existing daemon metadata read-only")?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='quarantine_events')")
        .fetch_one(&pool).await?;
    ensure!(
        exists,
        "quarantine history is unavailable; start the upgraded daemon or run dbev migrate first"
    );
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn inspection_cannot_write_metadata_or_create_a_missing_database() {
        let dir = tempfile::tempdir().unwrap();
        let writer = crate::storage::sqlite::connect(dir.path()).await.unwrap();
        let path = crate::storage::sqlite::database_path(dir.path());
        let reader = open_history(&path).await.unwrap();
        assert!(sqlx::query("INSERT INTO quarantine_events(entity_kind,entity_id,generation,code,recovery_class,source)
            VALUES ('pool','not-written','generation','unknown','manual_review','test')")
            .execute(&reader).await.is_err());
        assert!(
            crate::storage::quarantine::list(&writer, None, true, None, 100)
                .await
                .unwrap()
                .is_empty()
        );
        let absent = dir.path().join("absent.sqlite");
        assert!(open_history(&absent).await.is_err());
        assert!(!absent.exists());
    }
}
