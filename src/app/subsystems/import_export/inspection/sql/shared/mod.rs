use std::{collections::BTreeSet, io::Read};

use crate::databases::engine::EngineFamily;

use super::{
    CatalogBuilder, InspectionError, Protocol, SqlComment, SqlObserver, SqlToken, Statement,
    is_any_keyword, parse_create_table, parse_insert_table, parse_namespace,
    parse_qualified_identifier, scan_sql_reader,
};

mod clickhouse;
mod errors;
pub(crate) use errors::{SharedSqlError, SharedSqlIssue, SharedSqlReport};
mod mysql_command;
pub(crate) use mysql_command::validate_shared_mysql_command;
use mysql_command::{executable_mysql_comment, is_mysqldump_sandbox_directive};
mod mysql;
mod postgres;
mod words;
use words::statement_words;

const SAFE_MYSQL_ENGINES: &[&str] = &["INNODB", "MYISAM", "MEMORY", "CSV", "ARCHIVE"];

const SAFE_CLICKHOUSE_ENGINES: &[&str] = &[
    "MERGETREE",
    "REPLACINGMERGETREE",
    "SUMMINGMERGETREE",
    "AGGREGATINGMERGETREE",
    "COLLAPSINGMERGETREE",
    "VERSIONEDCOLLAPSINGMERGETREE",
    "GRAPHITEMERGETREE",
    "COALESCINGMERGETREE",
    "TINYLOG",
    "STRIPELOG",
    "LOG",
    "MEMORY",
    "SET",
    "JOIN",
    "NULL",
];

pub(crate) fn validate_shared_sql_reader<R: Read>(
    reader: R,
    protocol: Protocol,
    target_database: &str,
) -> Result<SharedSqlReport, SharedSqlError> {
    let mut observer = SharedObserver::new(protocol, target_database);
    scan_sql_reader(reader, protocol, &mut observer)?;
    observer.catalog.validate_dialect()?;
    Ok(SharedSqlReport {
        statements_checked: observer.statements_checked,
        namespaces: observer.namespaces.into_iter().collect(),
    })
}

struct SharedObserver<'a> {
    protocol: Protocol,
    target_database: &'a str,
    catalog: CatalogBuilder,
    namespaces: BTreeSet<String>,
    statements_checked: usize,
    saw_backslash: bool,
}

impl<'a> SharedObserver<'a> {
    fn new(protocol: Protocol, target_database: &'a str) -> Self {
        Self {
            protocol,
            target_database,
            catalog: CatalogBuilder::new(protocol),
            namespaces: BTreeSet::new(),
            statements_checked: 0,
            saw_backslash: false,
        }
    }

    fn reject<T>(
        &self,
        issue: SharedSqlIssue,
        message: impl Into<String>,
    ) -> Result<T, SharedSqlError> {
        Err(SharedSqlError::Rejected {
            issue,
            message: message.into(),
        })
    }

    fn validate_statement(&mut self, statement: &Statement) -> Result<(), SharedSqlError> {
        if statement.truncated {
            return self.reject(
                SharedSqlIssue::AmbiguousStatement,
                "SQL statement exceeds the bounded syntax budget for shared-tenant validation",
            );
        }
        if self.saw_backslash {
            return self.reject(
                SharedSqlIssue::PrivilegedStatement,
                "client meta-commands are not allowed in a shared-tenant import",
            );
        }

        let words = statement_words(statement);
        if words.is_empty() {
            return Ok(());
        }
        match self.protocol.engine().family() {
            EngineFamily::Postgres => self.validate_postgres(statement, &words),
            EngineFamily::Mysql => self.validate_mysql(statement, &words),
            EngineFamily::Columnar => self.validate_clickhouse(statement, &words),
            _ => self.reject(
                SharedSqlIssue::UnsupportedStatement,
                "the target protocol does not use shared SQL dump validation",
            ),
        }
    }

    fn require_target_database(&self, database: &str) -> Result<(), SharedSqlError> {
        if database == self.target_database {
            Ok(())
        } else {
            self.reject(
                SharedSqlIssue::CrossDatabase,
                format!(
                    "shared import references database {database}; expected {}",
                    self.target_database
                ),
            )
        }
    }
}

impl SqlObserver for SharedObserver<'_> {
    type Error = SharedSqlError;

    fn comment(&mut self, comment: &SqlComment) -> Result<(), Self::Error> {
        self.catalog.observe_comment(&comment.bytes);
        if self.protocol.engine().family().is_mysql() {
            let body = executable_mysql_comment(comment).map_err(|_| SharedSqlError::Rejected {
                issue: SharedSqlIssue::AmbiguousStatement,
                message: "executable MySQL/MariaDB comment exceeds the bounded syntax budget"
                    .to_string(),
            })?;
            if let Some(body) = body {
                if is_mysqldump_sandbox_directive(body) {
                    return Ok(());
                }
                validate_shared_sql_reader(
                    std::io::Cursor::new(body),
                    self.protocol,
                    self.target_database,
                )?;
            }
        }
        Ok(())
    }

    fn token(&mut self, token: &SqlToken) -> Result<(), Self::Error> {
        if matches!(token, SqlToken::Backslash) {
            self.saw_backslash = true;
        }
        Ok(())
    }

    fn statement(&mut self, _protocol: Protocol, statement: &Statement) -> Result<(), Self::Error> {
        statement.record_catalog(&mut self.catalog)?;
        self.validate_statement(statement)?;
        self.statements_checked = self.statements_checked.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
