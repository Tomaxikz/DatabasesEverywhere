use std::path::{Path, PathBuf};

use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};

use super::migrations;

#[derive(Debug, thiserror::Error)]
pub enum SqliteStorageError {
    #[error("failed to create sqlite parent directory {path}: {source}")]
    CreateDir {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to connect sqlite database: {0}")]
    Connect(#[from] sqlx::Error),
    #[error("failed to run sqlite migrations: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

pub fn database_path(data_root: &Path) -> PathBuf {
    data_root.join("databases-everywhere.sqlite")
}

pub fn database_files(data_root: &Path) -> Vec<PathBuf> {
    let path = database_path(data_root);
    vec![
        path.clone(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ]
}

pub async fn connect(data_root: &Path) -> Result<SqlitePool, SqliteStorageError> {
    let path = database_path(data_root);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|source| {
            SqliteStorageError::CreateDir {
                path: parent.display().to_string(),
                source,
            }
        })?;
    }

    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;
    migrations::run(&pool).await?;
    Ok(pool)
}
