use std::{
    collections::{HashSet, VecDeque},
    io::{self, BufWriter, Read, Write},
    path::Path,
    time::{Duration, Instant},
};

use crate::io::files::sync_directory;

use crate::routes::http::response::ApiError;

mod bounded;
use bounded::*;
mod context;
use context::*;
mod scanner;
use scanner::*;
mod qualifiers;
use qualifiers::*;

const MAX_QUOTED_IDENTIFIER_BYTES: usize = 1024;
const MAX_QUALIFIER_GAP_BYTES: usize = 64 * 1024;
const STREAM_BUFFER_BYTES: usize = 64 * 1024;
const MYSQL_MAX_DATABASE_CHARS: usize = 64;
const CLICKHOUSE_MAX_DATABASE_CHARS: usize = 128;

/// Safely rebases MySQL/MariaDB schema-qualified object references in place.
///
/// The input is parsed as bytes so dump contents do not need to be UTF-8. Replacement is
/// performed through a private file in the same directory and committed with one durable
/// rename. The original path is never followed when it is a symlink. Both the observed input
/// length and the rewritten output are capped by `max_staged_bytes`, including file growth that
/// happens after the initial metadata check.
pub(super) async fn rewrite_mysql_schema_qualifiers(
    path: &Path,
    source_database: &str,
    target_database: &str,
    max_staged_bytes: u64,
    operation_timeout: Duration,
) -> Result<(), ApiError> {
    rewrite_schema_qualifiers(
        path,
        source_database,
        target_database,
        max_staged_bytes,
        MYSQL_MAX_DATABASE_CHARS,
        operation_timeout,
    )
    .await
}

pub(super) async fn rewrite_clickhouse_schema(
    path: &Path,
    source_database: &str,
    target_database: &str,
    max_staged_bytes: u64,
    operation_timeout: Duration,
) -> Result<(), ApiError> {
    rewrite_schema_qualifiers(
        path,
        source_database,
        target_database,
        max_staged_bytes,
        CLICKHOUSE_MAX_DATABASE_CHARS,
        operation_timeout,
    )
    .await
}

async fn rewrite_schema_qualifiers(
    path: &Path,
    source_database: &str,
    target_database: &str,
    max_staged_bytes: u64,
    max_database_chars: usize,
    operation_timeout: Duration,
) -> Result<(), ApiError> {
    validate_database_name_with_limit(source_database, "source database", max_database_chars)
        .map_err(rewrite_api_error)?;
    validate_database_name_with_limit(target_database, "target database", max_database_chars)
        .map_err(rewrite_api_error)?;
    if source_database == target_database {
        return Ok(());
    }

    let path = path.to_path_buf();
    let source_database = source_database.as_bytes().to_vec();
    let quoted_target_database = quote_identifier(target_database.as_bytes(), b'`');
    let double_quoted_target_database = quote_identifier(target_database.as_bytes(), b'"');
    let deadline = Instant::now() + operation_timeout;
    tokio::task::spawn_blocking(move || {
        rewrite_mysql_schemas(
            &path,
            &source_database,
            &quoted_target_database,
            &double_quoted_target_database,
            max_staged_bytes,
            deadline,
        )
    })
    .await
    .map_err(|error| {
        ApiError::Runtime(format!(
            "mysql schema qualifier rewrite worker failed: {error}"
        ))
    })?
    .map(|_| ())
    .map_err(rewrite_api_error)
}

fn rewrite_api_error(error: MysqlSqlRewriteError) -> ApiError {
    match error {
        MysqlSqlRewriteError::InvalidDatabaseName { .. }
        | MysqlSqlRewriteError::InputLimit { .. }
        | MysqlSqlRewriteError::OutputLimit { .. }
        | MysqlSqlRewriteError::Malformed(_) => {
            ApiError::BadRequest(format!("SQL dump cannot be safely rebased: {error}"))
        }
        MysqlSqlRewriteError::Io(error) => {
            ApiError::Runtime(format!("failed to rewrite SQL dump safely: {error}"))
        }
        MysqlSqlRewriteError::Timeout => ApiError::ServiceUnavailable(
            "SQL dump rewrite exceeded the configured operation timeout".to_string(),
        ),
    }
}

#[derive(Debug, thiserror::Error)]
enum MysqlSqlRewriteError {
    #[error("{field} is not a valid database identifier")]
    InvalidDatabaseName { field: &'static str },
    #[error("SQL dump exceeds the {limit}-byte input limit")]
    InputLimit { limit: u64 },
    #[error("rewritten SQL dump exceeds the {limit}-byte output limit")]
    OutputLimit { limit: u64 },
    #[error("malformed SQL dump: {0}")]
    Malformed(&'static str),
    #[error("SQL dump rewrite exceeded its operation timeout")]
    Timeout,
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[cfg(test)]
fn validate_database_name(database: &str, field: &'static str) -> Result<(), MysqlSqlRewriteError> {
    validate_database_name_with_limit(database, field, MYSQL_MAX_DATABASE_CHARS)
}

fn validate_database_name_with_limit(
    database: &str,
    field: &'static str,
    max_chars: usize,
) -> Result<(), MysqlSqlRewriteError> {
    if database.is_empty()
        || database.chars().count() > max_chars
        || database
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(MysqlSqlRewriteError::InvalidDatabaseName { field });
    }
    Ok(())
}

fn quote_identifier(identifier: &[u8], quote: u8) -> Vec<u8> {
    let escaped_quotes = identifier.iter().filter(|byte| **byte == quote).count();
    let mut quoted = Vec::with_capacity(identifier.len() + escaped_quotes + 2);
    quoted.push(quote);
    for byte in identifier {
        quoted.push(*byte);
        if *byte == quote {
            quoted.push(quote);
        }
    }
    quoted.push(quote);
    quoted
}

fn rewrite_mysql_schemas(
    path: &Path,
    source_database: &[u8],
    quoted_target_database: &[u8],
    double_quoted_target_database: &[u8],
    max_bytes: u64,
    deadline: Instant,
) -> Result<u64, MysqlSqlRewriteError> {
    use std::fs::File;

    use rustix::fs::{AtFlags, Mode, OFlags, RenameFlags};

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "mysql dump path has no parent directory",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "mysql dump path has no file name",
        )
    })?;
    let directory = rustix::fs::open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let source_descriptor = rustix::fs::openat(
        &directory,
        file_name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let mut source = File::from(source_descriptor);
    let source_metadata = source.metadata()?;
    if !source_metadata.is_file() {
        return Err(MysqlSqlRewriteError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mysql dump is not a regular file",
        )));
    }
    if source_metadata.len() > max_bytes {
        return Err(MysqlSqlRewriteError::InputLimit { limit: max_bytes });
    }

    let temporary_name = format!(".mysql-schema-rewrite-{}.tmp", uuid::Uuid::new_v4());
    let temporary_descriptor = rustix::fs::openat(
        &directory,
        temporary_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(io::Error::from)?;
    let mut temporary = File::from(temporary_descriptor);

    let rewrite_result = (|| {
        let replacements = {
            let mut input = BoundedInput::new(&mut source, max_bytes, deadline);
            let mut output = BoundedOutput::new(&mut temporary, max_bytes);
            let mut context = SqlContext::default();
            let identifiers = RewriteIdentifiers {
                source_database,
                quoted_target_database,
                double_quoted_target_database,
            };
            let replacements =
                rewrite_sql(&mut input, &mut output, &identifiers, &mut context, false)?;
            output.flush()?;
            replacements
        };
        rustix::fs::fchmod(&temporary, Mode::RUSR | Mode::WUSR).map_err(io::Error::from)?;
        temporary.sync_all()?;
        Ok(replacements)
    })();

    drop(source);
    drop(temporary);

    let replacements = match rewrite_result {
        Ok(replacements) => replacements,
        Err(error) => {
            let _ = rustix::fs::unlinkat(&directory, temporary_name.as_str(), AtFlags::empty());
            return Err(error);
        }
    };

    if let Err(error) = rustix::fs::renameat_with(
        &directory,
        temporary_name.as_str(),
        &directory,
        file_name,
        RenameFlags::empty(),
    ) {
        let _ = rustix::fs::unlinkat(&directory, temporary_name.as_str(), AtFlags::empty());
        return Err(MysqlSqlRewriteError::Io(io::Error::from(error)));
    }
    sync_directory(&directory)?;
    Ok(replacements)
}

#[cfg(test)]
mod tests;
