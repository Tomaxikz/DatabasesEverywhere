use std::{
    collections::{BTreeSet, VecDeque},
    io::Read,
};

use super::{
    CatalogBuilder, InspectionError, Protocol, SqlComment, SqlObserver, SqlToken, Statement,
    is_any_keyword, parse_create_table, parse_insert_table, parse_namespace,
    parse_qualified_identifier, scan_sql_reader,
};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SharedSqlIssue {
    CrossDatabase,
    SystemNamespace,
    PrivilegedStatement,
    ExternalAccess,
    UnsupportedStatement,
    AmbiguousStatement,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum MysqlCommandPolicyError {
    #[error("shared MySQL-family tenants cannot change database or physical storage layout")]
    StorageEscape,
    #[error("shared MySQL-family tenants cannot execute dynamically prepared SQL")]
    DynamicSql,
    #[error("the shared MySQL-family command could not be validated safely")]
    Invalid,
}

impl From<InspectionError> for MysqlCommandPolicyError {
    fn from(_: InspectionError) -> Self {
        Self::Invalid
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SharedSqlError {
    #[error(transparent)]
    Inspection(#[from] InspectionError),
    #[error("{message}")]
    Rejected {
        issue: SharedSqlIssue,
        message: String,
    },
}

impl SharedSqlError {
    #[cfg(test)]
    pub(super) fn issue(&self) -> Option<SharedSqlIssue> {
        match self {
            Self::Inspection(_) => None,
            Self::Rejected { issue, .. } => Some(*issue),
        }
    }
}

#[derive(Debug)]
pub(crate) struct SharedSqlReport {
    pub(crate) statements_checked: usize,
    pub(crate) namespaces: Vec<String>,
}

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

/// Applies only the physical-storage boundary required by a live shared
/// MySQL/MariaDB session. Unlike dump admission, this deliberately permits
/// ordinary application SQL while denying statements that can replace the
/// routed database or place table data outside its managed directory.
pub(crate) fn validate_shared_mysql_command(
    sql: &[u8],
    protocol: Protocol,
) -> Result<(), MysqlCommandPolicyError> {
    check_shared_mysql_command(sql, protocol, false)
}

fn check_shared_mysql_command(
    sql: &[u8],
    protocol: Protocol,
    executable_fragment: bool,
) -> Result<(), MysqlCommandPolicyError> {
    if !matches!(protocol, Protocol::Mariadb | Protocol::Mysql) {
        return Err(MysqlCommandPolicyError::Invalid);
    }
    let mut observer = MysqlCommandObserver {
        protocol,
        executable_fragment,
        keywords: VecDeque::with_capacity(4),
        violation: None,
    };
    scan_sql_reader(std::io::Cursor::new(sql), protocol, &mut observer)
}

struct MysqlCommandObserver {
    protocol: Protocol,
    executable_fragment: bool,
    keywords: VecDeque<String>,
    violation: Option<MysqlStorageViolation>,
}

impl SqlObserver for MysqlCommandObserver {
    type Error = MysqlCommandPolicyError;

    fn comment(&mut self, comment: &SqlComment) -> Result<(), Self::Error> {
        match executable_mysql_comment(comment)? {
            Some(body) if !is_mysqldump_sandbox_directive(body) => {
                check_shared_mysql_command(body, self.protocol, true)
            }
            _ => Ok(()),
        }
    }

    fn token(&mut self, token: &SqlToken) -> Result<(), Self::Error> {
        let SqlToken::Identifier(word) = token else {
            self.keywords.clear();
            return Ok(());
        };
        if self.keywords.len() == 4 {
            self.keywords.pop_front();
        }
        self.keywords.push_back(word.to_ascii_uppercase());
        self.violation = self
            .violation
            .or_else(|| mysql_keyword_violation(&self.keywords, self.executable_fragment));
        Ok(())
    }

    fn statement(&mut self, _protocol: Protocol, statement: &Statement) -> Result<(), Self::Error> {
        let violation = self
            .violation
            .take()
            .or_else(|| mysql_storage_policy_violation(statement, self.executable_fragment));
        self.keywords.clear();
        match violation {
            Some(MysqlStorageViolation::DynamicSql) => Err(MysqlCommandPolicyError::DynamicSql),
            Some(MysqlStorageViolation::StorageEscape) => {
                Err(MysqlCommandPolicyError::StorageEscape)
            }
            None => Ok(()),
        }
    }
}

#[derive(Clone, Copy)]
enum MysqlStorageViolation {
    StorageEscape,
    DynamicSql,
}

fn mysql_keyword_violation(
    keywords: &VecDeque<String>,
    executable_fragment: bool,
) -> Option<MysqlStorageViolation> {
    let last = |offset: usize| {
        keywords
            .len()
            .checked_sub(offset + 1)
            .and_then(|index| keywords.get(index))
            .map(String::as_str)
    };
    let current = last(0)?;
    if current == "PREPARE" || (last(1) == Some("EXECUTE") && current == "IMMEDIATE") {
        return Some(MysqlStorageViolation::DynamicSql);
    }
    if [
        "TABLESPACE",
        "DATAFILE",
        "UNDOFILE",
        "REDOFILE",
        "FILE_NAME",
        "TABLE_TYPE",
        "SECONDARY_ENGINE",
        "ENGINE_ATTRIBUTE",
        "SECONDARY_ENGINE_ATTRIBUTE",
    ]
    .contains(&current)
        || (executable_fragment && ["DATABASE", "SCHEMA", "DIRECTORY"].contains(&current))
        || matches!(
            (last(1), current),
            (
                Some("CREATE" | "ALTER" | "DROP" | "RENAME"),
                "DATABASE" | "SCHEMA"
            ) | (Some("DATA" | "INDEX"), "DIRECTORY")
                | (Some("LOGFILE"), "GROUP")
                | (Some("STORAGE"), "DISK" | "MEMORY")
                | (Some("IMPORT"), "TABLE")
        )
        || (matches!(current, "DATABASE" | "SCHEMA")
            && last(1) == Some("REPLACE")
            && last(2) == Some("OR")
            && last(3) == Some("CREATE"))
    {
        return Some(MysqlStorageViolation::StorageEscape);
    }
    None
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
        self.saw_backslash = false;

        let words = statement_words(statement);
        if words.is_empty() {
            return Ok(());
        }
        match self.protocol {
            Protocol::Postgres => self.validate_postgres(statement, &words),
            Protocol::Mariadb | Protocol::Mysql => self.validate_mysql(statement, &words),
            Protocol::Clickhouse => self.validate_clickhouse(statement, &words),
            _ => self.reject(
                SharedSqlIssue::UnsupportedStatement,
                "the target protocol does not use shared SQL dump validation",
            ),
        }
    }

    fn validate_postgres(
        &mut self,
        statement: &Statement,
        words: &[String],
    ) -> Result<(), SharedSqlError> {
        let command = words[0].as_str();
        if let Some(namespace) = parse_namespace(&statement.tokens) {
            if is_postgres_system_schema(&namespace) {
                return self.reject(
                    SharedSqlIssue::SystemNamespace,
                    "shared PostgreSQL imports cannot create or select system schemas",
                );
            }
            self.namespaces.insert(namespace);
        }
        self.reject_system_postgres_object(statement)?;
        if contains_any(words, &["SUPERUSER", "CREATEROLE", "CREATEDB", "BYPASSRLS"])
            || contains_sequence(words, &["SESSION", "AUTHORIZATION"])
            || contains_sequence(words, &["SET", "ROLE"])
            || contains_sequence(words, &["OWNER", "TO"])
            || privileged_object_command(
                command,
                words,
                &[
                    "SYSTEM",
                    "ROLE",
                    "USER",
                    "OWNED",
                    "PRIVILEGES",
                    "PUBLICATION",
                    "SUBSCRIPTION",
                    "SERVER",
                ],
            )
        {
            return self.reject(
                SharedSqlIssue::PrivilegedStatement,
                "role, ownership, or administrator changes are not allowed in a shared PostgreSQL import",
            );
        }
        if contains_any(words, &["PROGRAM", "FOREIGN"])
            || contains_sequence(words, &["FOREIGN", "DATA", "WRAPPER"])
            || contains_sequence(words, &["USER", "MAPPING"])
        {
            return self.reject(
                SharedSqlIssue::ExternalAccess,
                "PostgreSQL external programs and foreign data access are not allowed in a shared import",
            );
        }
        if contains_any(words, &["EXTENSION", "LANGUAGE", "FUNCTION", "PROCEDURE"])
            || is_any_keyword(command, &["DO", "CALL", "GRANT", "REVOKE"])
        {
            return self.reject(
                SharedSqlIssue::PrivilegedStatement,
                "executable database code, extensions, grants, and role calls are not allowed in a shared import",
            );
        }

        match command {
            value if value.eq_ignore_ascii_case("SET") => Ok(()),
            value if value.eq_ignore_ascii_case("SELECT") => {
                if words
                    .get(1)
                    .is_some_and(|word| word.eq_ignore_ascii_case("PG_CATALOG"))
                    && words
                        .get(2)
                        .is_some_and(|word| word.eq_ignore_ascii_case("SET_CONFIG"))
                {
                    Ok(())
                } else {
                    self.reject(
                        SharedSqlIssue::UnsupportedStatement,
                        "only pg_catalog.set_config setup SELECTs are accepted in shared PostgreSQL dumps",
                    )
                }
            }
            value if value.eq_ignore_ascii_case("COPY") => {
                if !statement.copy_from_stdin || contains_any(words, &["TO", "PROGRAM"]) {
                    self.reject(
                        SharedSqlIssue::ExternalAccess,
                        "shared PostgreSQL COPY is restricted to COPY ... FROM STDIN",
                    )
                } else {
                    self.reject_system_postgres_object(statement)
                }
            }
            value if value.eq_ignore_ascii_case("CREATE") => {
                let object = create_object(words);
                if !matches!(
                    object,
                    Some(
                        "SCHEMA"
                            | "TABLE"
                            | "SEQUENCE"
                            | "TYPE"
                            | "DOMAIN"
                            | "COLLATION"
                            | "INDEX"
                            | "VIEW"
                    )
                ) || contains_any(words, &["TEMP", "TEMPORARY"])
                {
                    return self.reject(
                        SharedSqlIssue::UnsupportedStatement,
                        "this PostgreSQL CREATE form is not safe for a shared-tenant import",
                    );
                }
                if object != Some("VIEW") && contains_any(words, &["SELECT"]) {
                    return self.reject(
                        SharedSqlIssue::ExternalAccess,
                        "query-backed PostgreSQL CREATE statements are not allowed in a shared import",
                    );
                }
                self.reject_system_postgres_object(statement)
            }
            value
                if is_any_keyword(
                    value,
                    &[
                        "ALTER", "DROP", "INSERT", "TRUNCATE", "COMMENT", "ANALYZE", "LOCK",
                    ],
                ) =>
            {
                if command.eq_ignore_ascii_case("INSERT") && contains_any(words, &["SELECT"]) {
                    return self.reject(
                        SharedSqlIssue::ExternalAccess,
                        "shared PostgreSQL imports accept literal INSERT records, not query-backed data sources",
                    );
                }
                self.reject_system_postgres_object(statement)
            }
            _ => self.reject(
                SharedSqlIssue::UnsupportedStatement,
                format!(
                    "PostgreSQL {command} statements are not accepted in shared-tenant imports"
                ),
            ),
        }
    }

    fn reject_system_postgres_object(&self, statement: &Statement) -> Result<(), SharedSqlError> {
        if qualified_identifiers(&statement.tokens)
            .into_iter()
            .any(|(namespace, _)| is_postgres_system_schema(namespace))
        {
            self.reject(
                SharedSqlIssue::SystemNamespace,
                "shared PostgreSQL imports cannot modify system schemas",
            )
        } else {
            Ok(())
        }
    }

    fn validate_mysql(
        &mut self,
        statement: &Statement,
        words: &[String],
    ) -> Result<(), SharedSqlError> {
        let command = words[0].as_str();
        if mysql_database_ddl(statement, words) {
            return self.reject(
                SharedSqlIssue::PrivilegedStatement,
                "shared imports cannot create, alter, drop, or rename a database",
            );
        }
        if mysql_storage_policy_violation(statement, false).is_some()
            || contains_any(
                words,
                &[
                    "OUTFILE",
                    "DUMPFILE",
                    "SONAME",
                    "LOAD_FILE",
                    "PLUGIN",
                    "COMPONENT",
                ],
            )
        {
            return self.reject(
                SharedSqlIssue::ExternalAccess,
                "filesystem, plugin, and component features are not allowed in a shared MySQL import",
            );
        }
        if contains_any(words, &["GLOBAL", "PERSIST", "PERSIST_ONLY"])
            || is_any_keyword(command, &["GRANT", "REVOKE", "INSTALL", "UNINSTALL"])
            || privileged_object_command(
                command,
                words,
                &[
                    "USER",
                    "ROLE",
                    "FUNCTION",
                    "PROCEDURE",
                    "TRIGGER",
                    "EVENT",
                    "SERVER",
                    "INSTANCE",
                ],
            )
            || contains_any(words, &["SQL_LOG_BIN"])
        {
            return self.reject(
                SharedSqlIssue::PrivilegedStatement,
                "users, grants, global settings, stored code, and server objects are not allowed in a shared MySQL import",
            );
        }
        if command.eq_ignore_ascii_case("LOAD") {
            return self.reject(
                SharedSqlIssue::ExternalAccess,
                "LOAD DATA/XML is not allowed in a shared MySQL import",
            );
        }

        if let Some(namespace) = parse_namespace(&statement.tokens) {
            if is_mysql_system_database(&namespace) {
                return self.reject(
                    SharedSqlIssue::SystemNamespace,
                    "shared MySQL imports cannot select a system database",
                );
            }
            self.require_target_database(&namespace)?;
            self.namespaces.insert(namespace);
        }
        self.require_mysql_qualifiers(statement)?;
        validate_engine(&statement.tokens, SAFE_MYSQL_ENGINES, "MySQL", self)?;

        if is_any_keyword(command, &["INSERT", "REPLACE"]) && contains_any(words, &["SELECT"]) {
            return self.reject(
                SharedSqlIssue::ExternalAccess,
                "shared MySQL imports accept INSERT/REPLACE value records, not query-backed data sources",
            );
        }

        // mysqldump represents views using executable version comments that
        // may split CREATE/ALGORITHM, DEFINER/SQL SECURITY, and VIEW across
        // adjacent fragments. Each fragment is harmless on its own and the
        // assembled statement still runs as the fenced tenant. Accept only
        // these narrow wrapper shapes; routines/triggers/events remain denied.
        let view = contains_any(words, &["VIEW"]);
        if command.eq_ignore_ascii_case("DEFINER") && contains_sequence(words, &["SQL", "SECURITY"])
        {
            return Ok(());
        }
        if command.eq_ignore_ascii_case("VIEW") {
            if !contains_any(words, &["SELECT"]) {
                return self.reject(
                    SharedSqlIssue::AmbiguousStatement,
                    "shared MySQL view definition has no SELECT body",
                );
            }
            return self.require_mysql_qualifiers(statement);
        }
        if command.eq_ignore_ascii_case("CREATE")
            && !view
            && words.len() == 3
            && words[1].eq_ignore_ascii_case("ALGORITHM")
            && is_any_keyword(&words[2], &["UNDEFINED", "MERGE", "TEMPTABLE"])
        {
            return Ok(());
        }

        match command {
            value
                if is_any_keyword(
                    value,
                    &[
                        "SET", "USE", "CREATE", "ALTER", "DROP", "INSERT", "REPLACE", "TRUNCATE",
                        "LOCK", "UNLOCK", "START", "COMMIT", "ROLLBACK", "ANALYZE", "OPTIMIZE",
                    ],
                ) =>
            {
                if command.eq_ignore_ascii_case("CREATE") {
                    let object = create_object(words);
                    if !matches!(object, Some("TABLE" | "INDEX" | "VIEW")) && !view {
                        return self.reject(
                            SharedSqlIssue::UnsupportedStatement,
                            "this MySQL CREATE form is not safe for a shared-tenant import",
                        );
                    }
                }
                Ok(())
            }
            _ => self.reject(
                SharedSqlIssue::UnsupportedStatement,
                format!(
                    "MySQL/MariaDB {command} statements are not accepted in shared-tenant imports"
                ),
            ),
        }
    }

    fn require_mysql_qualifiers(&self, statement: &Statement) -> Result<(), SharedSqlError> {
        for (database, _) in import_object_qualifiers(&statement.tokens) {
            if is_mysql_system_database(&database) {
                return self.reject(
                    SharedSqlIssue::SystemNamespace,
                    "shared MySQL imports cannot reference system databases",
                );
            }
            if database != self.target_database {
                return self.reject(
                    SharedSqlIssue::CrossDatabase,
                    format!(
                        "shared MySQL import references database {database}; expected {}",
                        self.target_database
                    ),
                );
            }
        }
        Ok(())
    }

    fn validate_clickhouse(
        &mut self,
        statement: &Statement,
        words: &[String],
    ) -> Result<(), SharedSqlError> {
        let command = words[0].as_str();
        if contains_sequence(words, &["ON", "CLUSTER"])
            || contains_any(
                words,
                &[
                    "OUTFILE",
                    "INFILE",
                    "FILE",
                    "REMOTE",
                    "REMOTESECURE",
                    "URL",
                    "S3",
                    "HDFS",
                    "JDBC",
                    "ODBC",
                    "EXECUTABLE",
                    "EXECUTABLEPOOL",
                    "DICTIONARY",
                    "DISTRIBUTED",
                    "KAFKA",
                    "RABBITMQ",
                    "MYSQL",
                    "POSTGRESQL",
                    "MONGODB",
                    "REDIS",
                ],
            )
        {
            return self.reject(
                SharedSqlIssue::ExternalAccess,
                "remote, filesystem, executable, dictionary, and distributed ClickHouse sources are not allowed in a shared import",
            );
        }
        if is_any_keyword(
            command,
            &[
                "SYSTEM", "KILL", "GRANT", "REVOKE", "ATTACH", "DETACH", "BACKUP", "RESTORE",
            ],
        ) || privileged_object_command(
            command,
            words,
            &[
                "USER",
                "ROLE",
                "QUOTA",
                "POLICY",
                "PROFILE",
                "FUNCTION",
                "WORKLOAD",
                "COLLECTION",
            ],
        ) {
            return self.reject(
                SharedSqlIssue::PrivilegedStatement,
                "cluster administration and access-control statements are not allowed in a shared ClickHouse import",
            );
        }
        if let Some(namespace) = parse_namespace(&statement.tokens) {
            if is_clickhouse_system_database(&namespace) {
                return self.reject(
                    SharedSqlIssue::SystemNamespace,
                    "shared ClickHouse imports cannot select a system database",
                );
            }
            self.require_target_database(&namespace)?;
            self.namespaces.insert(namespace);
        }
        for (database, _) in import_object_qualifiers(&statement.tokens) {
            if is_clickhouse_system_database(&database) {
                return self.reject(
                    SharedSqlIssue::SystemNamespace,
                    "shared ClickHouse imports cannot reference system databases",
                );
            }
            self.require_target_database(&database)?;
        }
        let has_engine = validate_engine(
            &statement.tokens,
            SAFE_CLICKHOUSE_ENGINES,
            "ClickHouse",
            self,
        )?;

        // ClickHouse can bind CREATE/INSERT directly to table functions such
        // as file(), url(), or remote(). Reject the syntax class instead of
        // trying to keep an ever-growing function denylist. Tenant SOURCE
        // grants are a second boundary, not a substitute for admission.
        let create_object = command
            .eq_ignore_ascii_case("CREATE")
            .then(|| create_object(words))
            .flatten();
        if contains_sequence(words, &["INTO", "FUNCTION"])
            || (create_object == Some("TABLE") && top_level_keyword(&statement.tokens, "AS"))
        {
            return self.reject(
                SharedSqlIssue::ExternalAccess,
                "ClickHouse table-function sources and sinks are not allowed in a shared import",
            );
        }

        if (command.eq_ignore_ascii_case("INSERT")
            || (command.eq_ignore_ascii_case("CREATE") && create_object != Some("VIEW")))
            && contains_any(words, &["SELECT"])
        {
            return self.reject(
                SharedSqlIssue::ExternalAccess,
                "shared ClickHouse imports accept INSERT value records, not query-backed data sources",
            );
        }

        match command {
            value
                if is_any_keyword(
                    value,
                    &[
                        "USE", "SET", "CREATE", "ALTER", "DROP", "INSERT", "TRUNCATE", "OPTIMIZE",
                    ],
                ) =>
            {
                if command.eq_ignore_ascii_case("CREATE") {
                    let object = create_object;
                    if object == Some("DATABASE") {
                        return self.reject(
                            SharedSqlIssue::PrivilegedStatement,
                            "shared imports cannot create a ClickHouse database",
                        );
                    }
                    if !matches!(object, Some("TABLE" | "INDEX" | "VIEW")) {
                        return self.reject(
                            SharedSqlIssue::UnsupportedStatement,
                            "this ClickHouse CREATE form is not safe for a shared-tenant import",
                        );
                    }
                    if object == Some("TABLE") && !has_engine {
                        return self.reject(
                            SharedSqlIssue::AmbiguousStatement,
                            "shared ClickHouse CREATE TABLE requires one explicit allowed engine",
                        );
                    }
                }
                if command.eq_ignore_ascii_case("DROP")
                    && words
                        .get(1)
                        .is_some_and(|word| word.eq_ignore_ascii_case("DATABASE"))
                {
                    return self.reject(
                        SharedSqlIssue::PrivilegedStatement,
                        "shared imports cannot drop a ClickHouse database",
                    );
                }
                if command.eq_ignore_ascii_case("ALTER")
                    && words
                        .get(1)
                        .is_some_and(|word| word.eq_ignore_ascii_case("DATABASE"))
                {
                    return self.reject(
                        SharedSqlIssue::PrivilegedStatement,
                        "shared imports cannot alter a ClickHouse database",
                    );
                }
                Ok(())
            }
            _ => self.reject(
                SharedSqlIssue::UnsupportedStatement,
                format!(
                    "ClickHouse {command} statements are not accepted in shared-tenant imports"
                ),
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
        if matches!(self.protocol, Protocol::Mariadb | Protocol::Mysql) {
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

#[derive(Debug)]
struct ExecutableCommentTooLarge;

impl From<ExecutableCommentTooLarge> for MysqlCommandPolicyError {
    fn from(_: ExecutableCommentTooLarge) -> Self {
        Self::Invalid
    }
}

fn executable_mysql_comment(
    comment: &SqlComment,
) -> Result<Option<&[u8]>, ExecutableCommentTooLarge> {
    let whitespace = comment
        .bytes
        .iter()
        .take_while(|byte| byte.is_ascii_whitespace())
        .count();
    let trimmed = &comment.bytes[whitespace..];
    let Some(body) = trimmed
        .strip_prefix(b"!")
        .or_else(|| trimmed.strip_prefix(b"M!"))
        .or_else(|| trimmed.strip_prefix(b"m!"))
    else {
        return Ok(None);
    };
    if comment.truncated {
        return Err(ExecutableCommentTooLarge);
    }
    let body = &body[body
        .iter()
        .take_while(|byte| byte.is_ascii_whitespace())
        .count()..];
    let body = &body[body.iter().take_while(|byte| byte.is_ascii_digit()).count()..];
    Ok(Some(
        &body[body
            .iter()
            .take_while(|byte| byte.is_ascii_whitespace())
            .count()..],
    ))
}

fn is_mysqldump_sandbox_directive(body: &[u8]) -> bool {
    body.starts_with(b"\\- enable the sandbox mode")
}

fn mysql_storage_policy_violation(
    statement: &Statement,
    executable_fragment: bool,
) -> Option<MysqlStorageViolation> {
    let words = statement_words(statement);
    if has_keyword(&statement.tokens, "PREPARE")
        || has_keyword_sequence(&statement.tokens, &["EXECUTE", "IMMEDIATE"])
    {
        return Some(MysqlStorageViolation::DynamicSql);
    }

    if executable_fragment
        && ["DATABASE", "SCHEMA", "TABLESPACE", "DIRECTORY"]
            .into_iter()
            .any(|keyword| has_keyword(&statement.tokens, keyword))
    {
        return Some(MysqlStorageViolation::StorageEscape);
    }

    // Database aliases are the route boundary. Match token sequences rather
    // than substrings so strings, comments, and quoted identifiers cannot
    // either trigger false positives or hide an executable statement.
    if mysql_database_ddl(statement, &words) {
        return Some(MysqlStorageViolation::StorageEscape);
    }

    if has_keyword(&statement.tokens, "TABLESPACE")
        || has_keyword_sequence(&statement.tokens, &["DATA", "DIRECTORY"])
        || has_keyword_sequence(&statement.tokens, &["INDEX", "DIRECTORY"])
        || has_keyword_sequence(&statement.tokens, &["LOGFILE", "GROUP"])
        || has_keyword_sequence(&statement.tokens, &["STORAGE", "DISK"])
        || has_keyword_sequence(&statement.tokens, &["STORAGE", "MEMORY"])
        || has_keyword_sequence(&statement.tokens, &["IMPORT", "TABLE"])
        || [
            "DATAFILE",
            "UNDOFILE",
            "REDOFILE",
            "FILE_NAME",
            "TABLE_TYPE",
            "SECONDARY_ENGINE",
            "ENGINE_ATTRIBUTE",
            "SECONDARY_ENGINE_ATTRIBUTE",
        ]
        .into_iter()
        .any(|keyword| has_keyword(&statement.tokens, keyword))
    {
        return Some(MysqlStorageViolation::StorageEscape);
    }
    None
}

fn mysql_database_ddl(statement: &Statement, words: &[String]) -> bool {
    let Some(command) = words.first() else {
        return false;
    };
    ["DATABASE", "SCHEMA"].into_iter().any(|object| {
        ["CREATE", "ALTER", "DROP", "RENAME"]
            .into_iter()
            .any(|verb| has_keyword_sequence(&statement.tokens, &[verb, object]))
            || (command.eq_ignore_ascii_case("CREATE") && create_object(words) == Some(object))
    })
}

fn has_keyword(tokens: &[SqlToken], expected: &str) -> bool {
    tokens.iter().any(
        |token| matches!(token, SqlToken::Identifier(word) if word.eq_ignore_ascii_case(expected)),
    )
}

fn has_keyword_sequence(tokens: &[SqlToken], expected: &[&str]) -> bool {
    tokens.windows(expected.len()).any(|window| {
        window.iter().zip(expected).all(|(token, expected)| {
            matches!(token, SqlToken::Identifier(word) if word.eq_ignore_ascii_case(expected))
        })
    })
}

fn statement_words(statement: &Statement) -> Vec<String> {
    statement
        .tokens
        .iter()
        .filter_map(|token| match token {
            SqlToken::Identifier(word) => Some(word.to_ascii_uppercase()),
            _ => None,
        })
        .collect()
}

fn create_object(words: &[String]) -> Option<&str> {
    let mut index = 1;
    while words.get(index).is_some_and(|word| {
        is_any_keyword(
            word,
            &[
                "OR",
                "REPLACE",
                "TEMP",
                "TEMPORARY",
                "UNLOGGED",
                "GLOBAL",
                "LOCAL",
                "UNIQUE",
            ],
        )
    }) {
        index += 1;
    }
    words.get(index).map(String::as_str)
}

fn contains_any(words: &[String], expected: &[&str]) -> bool {
    words.iter().any(|word| is_any_keyword(word, expected))
}

fn contains_sequence(words: &[String], expected: &[&str]) -> bool {
    words.windows(expected.len()).any(|window| {
        window
            .iter()
            .zip(expected)
            .all(|(word, expected)| word.eq_ignore_ascii_case(expected))
    })
}

fn privileged_object_command(command: &str, words: &[String], objects: &[&str]) -> bool {
    is_any_keyword(command, &["CREATE", "ALTER", "DROP"])
        && words
            .iter()
            .skip(1)
            .any(|word| is_any_keyword(word, objects))
}

fn qualified_identifiers(tokens: &[SqlToken]) -> Vec<(&str, &str)> {
    tokens
        .windows(3)
        .filter_map(|window| {
            if !matches!(window.get(1), Some(SqlToken::Dot)) {
                return None;
            }
            Some((
                super::identifier_at(window, 0)?,
                super::identifier_at(window, 2)?,
            ))
        })
        .collect()
}

fn import_object_qualifiers(tokens: &[SqlToken]) -> Vec<(String, String)> {
    let mut objects = Vec::new();
    if let Some((Some(database), name)) =
        parse_create_table(tokens).or_else(|| parse_insert_table(tokens))
    {
        objects.push((database, name));
    }

    for (index, token) in tokens.iter().enumerate() {
        let SqlToken::Identifier(word) = token else {
            continue;
        };
        let mut object_index = match word.to_ascii_uppercase().as_str() {
            "REFERENCES" | "UPDATE" => Some(index + 1),
            "FROM" | "INTO" | "TABLE" | "TABLES" | "ON" | "JOIN" => Some(index + 1),
            _ => None,
        };
        let Some(mut object_index) = object_index.take() else {
            continue;
        };
        while super::identifier_at(tokens, object_index)
            .is_some_and(|word| is_any_keyword(word, &["IF", "NOT", "EXISTS", "ONLY", "IGNORE"]))
        {
            object_index += 1;
        }
        if let Some((Some(database), name)) = parse_qualified_identifier(tokens, object_index) {
            objects.push((database, name));
        }
    }
    objects.sort_unstable();
    objects.dedup();
    objects
}

fn validate_engine(
    tokens: &[SqlToken],
    allowed: &[&str],
    label: &str,
    observer: &SharedObserver<'_>,
) -> Result<bool, SharedSqlError> {
    let mut depth = 0_usize;
    let mut found = false;
    for index in 0..tokens.len() {
        match tokens[index] {
            SqlToken::OpenParen => {
                depth = depth.saturating_add(1);
                continue;
            }
            SqlToken::CloseParen => {
                depth = depth.saturating_sub(1);
                continue;
            }
            _ => {}
        }
        if depth != 0 {
            continue;
        }
        if !matches!(tokens.get(index), Some(SqlToken::Identifier(word)) if word.eq_ignore_ascii_case("ENGINE"))
            || !matches!(tokens.get(index + 1), Some(SqlToken::Equal))
        {
            continue;
        }
        if found {
            return observer.reject(
                SharedSqlIssue::AmbiguousStatement,
                format!("{label} table declares more than one engine"),
            );
        }
        found = true;
        let Some(SqlToken::Identifier(engine)) = tokens.get(index + 2) else {
            return observer.reject(
                SharedSqlIssue::AmbiguousStatement,
                format!("{label} table engine could not be determined safely"),
            );
        };
        if !allowed
            .iter()
            .any(|allowed| engine.eq_ignore_ascii_case(allowed))
        {
            return observer.reject(
                SharedSqlIssue::ExternalAccess,
                format!("{label} table engine {engine} is not allowed in a shared import"),
            );
        }
    }
    Ok(found)
}

fn top_level_keyword(tokens: &[SqlToken], expected: &str) -> bool {
    let mut depth = 0_usize;
    for token in tokens {
        match token {
            SqlToken::OpenParen => depth = depth.saturating_add(1),
            SqlToken::CloseParen => depth = depth.saturating_sub(1),
            SqlToken::Identifier(word) if depth == 0 && word.eq_ignore_ascii_case(expected) => {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn is_mysql_system_database(database: &str) -> bool {
    ["mysql", "sys", "performance_schema", "information_schema"]
        .into_iter()
        .any(|system| database.eq_ignore_ascii_case(system))
}

fn is_postgres_system_schema(schema: &str) -> bool {
    schema.eq_ignore_ascii_case("information_schema")
        || schema.to_ascii_lowercase().starts_with("pg_")
}

fn is_clickhouse_system_database(database: &str) -> bool {
    ["system", "information_schema", "INFORMATION_SCHEMA"]
        .into_iter()
        .any(|system| database.eq_ignore_ascii_case(system))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn validate(protocol: Protocol, sql: &str) -> Result<SharedSqlReport, SharedSqlError> {
        validate_shared_sql_reader(Cursor::new(sql.as_bytes()), protocol, "tenant_db")
    }

    fn validate_live(protocol: Protocol, sql: &str) -> Result<(), MysqlCommandPolicyError> {
        validate_shared_mysql_command(sql.as_bytes(), protocol)
    }

    #[test]
    fn live_mysql_policy_keeps_normal_table_ddl_and_data_queries() {
        for protocol in [Protocol::Mysql, Protocol::Mariadb] {
            for sql in [
                "CREATE TABLE items(id BIGINT, note TEXT) ENGINE=InnoDB",
                "ALTER TABLE items ADD COLUMN value VARCHAR(255)",
                "DROP TABLE IF EXISTS items",
                "SELECT 'DROP DATABASE tenant_db', `tablespace` FROM items",
                "INSERT INTO items(note) VALUES ('DATA DIRECTORY=/tmp/not-syntax')",
            ] {
                validate_live(protocol, sql)
                    .unwrap_or_else(|error| panic!("{protocol} rejected {sql:?}: {error}"));
            }
        }
    }

    #[test]
    fn live_mysql_policy_rejects_database_and_storage_layout_changes() {
        for protocol in [Protocol::Mysql, Protocol::Mariadb] {
            for sql in [
                "CREATE DATABASE other",
                "CREATE OR REPLACE SCHEMA other",
                "ALTER DATABASE tenant_db CHARACTER SET utf8mb4",
                "DROP /* hidden */ DATABASE tenant_db",
                "RENAME DATABASE tenant_db TO other",
                "CREATE TABLE items(id BIGINT) TABLESPACE=innodb_system",
                "ALTER TABLE items TABLESPACE innodb_system",
                "CREATE TABLE items(id BIGINT) DATA DIRECTORY='/tmp/escape'",
                "CREATE TABLE items(id BIGINT) INDEX DIRECTORY='/tmp/escape'",
                "CREATE TABLE items(id BIGINT) ENGINE=CONNECT TABLE_TYPE=CSV FILE_NAME='/tmp/x'",
                "CREATE LOGFILE GROUP group_1 ADD UNDOFILE '/tmp/undo.dat' ENGINE=InnoDB",
                "IMPORT TABLE FROM '/tmp/table.sdi'",
                "/*!50100 DROP DATABASE tenant_db */",
                "/*! 50100 DROP DATABASE tenant_db */",
                "DROP /*!50100 DATABASE */ tenant_db",
                "CREATE TABLE items(id BIGINT) /*!50100 TABLESPACE innodb_system */",
                "CREATE TABLE items(id BIGINT) DATA /*!50100 DIRECTORY */='/tmp/escape'",
            ] {
                assert!(
                    matches!(
                        validate_live(protocol, sql),
                        Err(MysqlCommandPolicyError::StorageEscape)
                    ),
                    "{protocol} accepted {sql:?}"
                );
            }
        }
    }

    #[test]
    fn live_mysql_policy_rejects_sql_level_dynamic_execution() {
        for protocol in [Protocol::Mysql, Protocol::Mariadb] {
            for sql in [
                "PREPARE stmt FROM 'DROP DATABASE tenant_db'",
                "SET @sql='DROP DATABASE tenant_db'; PREPARE stmt FROM @sql; EXECUTE stmt",
                "EXECUTE IMMEDIATE 'DROP DATABASE tenant_db'",
                "/*!50000 PREPARE stmt FROM 'DROP DATABASE tenant_db' */",
            ] {
                assert!(
                    matches!(
                        validate_live(protocol, sql),
                        Err(MysqlCommandPolicyError::DynamicSql)
                    ),
                    "{protocol} accepted {sql:?}"
                );
            }
        }
    }

    #[test]
    fn accepts_bounded_tenant_only_dump_shapes() {
        for (protocol, sql) in [
            (
                Protocol::Postgres,
                "SET statement_timeout = 0; CREATE TABLE public.items(id bigint); CREATE VIEW public.item_view AS SELECT id FROM public.items; COPY public.items FROM STDIN;\n1\n\\.\n",
            ),
            (
                Protocol::Mysql,
                "USE tenant_db; CREATE TABLE tenant_db.items(id bigint) ENGINE=InnoDB; /*!50001 CREATE ALGORITHM=UNDEFINED */ /*!50013 DEFINER=`tenant_user`@`%` SQL SECURITY DEFINER */ /*!50001 VIEW `item_view` AS SELECT id FROM tenant_db.items */; INSERT INTO tenant_db.items VALUES (1);",
            ),
            (
                Protocol::Mariadb,
                "USE tenant_db; CREATE TABLE tenant_db.items(id bigint) ENGINE=ArChIvE; CREATE SQL SECURITY INVOKER VIEW item_view AS SELECT id FROM tenant_db.items; LOCK TABLES tenant_db.items WRITE; UNLOCK TABLES;",
            ),
            (
                Protocol::Clickhouse,
                "USE tenant_db; CREATE TABLE tenant_db.items(id UInt64) ENGINE = MergeTree ORDER BY id; CREATE VIEW tenant_db.item_view AS SELECT id FROM tenant_db.items; INSERT INTO tenant_db.items VALUES (1);",
            ),
        ] {
            let report =
                validate(protocol, sql).unwrap_or_else(|error| panic!("{protocol}: {error}"));
            assert!(report.statements_checked >= 2);
        }
    }

    #[test]
    fn rejects_engine_level_database_creation() {
        for protocol in [Protocol::Mysql, Protocol::Mariadb, Protocol::Clickhouse] {
            let error = validate(protocol, "CREATE DATABASE tenant_db;").unwrap_err();
            assert_eq!(
                error.issue(),
                Some(SharedSqlIssue::PrivilegedStatement),
                "{protocol}"
            );
        }
    }

    #[test]
    fn rejects_cross_database_and_system_namespaces() {
        for (protocol, sql, issue) in [
            (
                Protocol::Mysql,
                "INSERT INTO other.items VALUES (1);",
                SharedSqlIssue::CrossDatabase,
            ),
            (
                Protocol::Mariadb,
                "USE mysql;",
                SharedSqlIssue::SystemNamespace,
            ),
            (
                Protocol::Clickhouse,
                "CREATE TABLE system.items(id UInt8) ENGINE=Log;",
                SharedSqlIssue::SystemNamespace,
            ),
            (
                Protocol::Postgres,
                "DELETE FROM pg_catalog.pg_authid;",
                SharedSqlIssue::SystemNamespace,
            ),
            (
                Protocol::Postgres,
                "DROP TABLE pg_toast.pg_toast_123;",
                SharedSqlIssue::SystemNamespace,
            ),
            (
                Protocol::Mysql,
                "CREATE VIEW tenant_db.v AS SELECT id FROM other_db.items;",
                SharedSqlIssue::CrossDatabase,
            ),
        ] {
            assert_eq!(validate(protocol, sql).unwrap_err().issue(), Some(issue));
        }
    }

    #[test]
    fn rejects_privilege_code_and_external_access_corpus() {
        for (protocol, sql, issue) in [
            (
                Protocol::Postgres,
                "COPY public.items FROM PROGRAM 'curl bad';",
                SharedSqlIssue::ExternalAccess,
            ),
            (
                Protocol::Postgres,
                "CREATE EXTENSION file_fdw;",
                SharedSqlIssue::PrivilegedStatement,
            ),
            (
                Protocol::Postgres,
                "ALTER TABLE public.items OWNER TO postgres;",
                SharedSqlIssue::PrivilegedStatement,
            ),
            (
                Protocol::Postgres,
                "ALTER SYSTEM SET shared_preload_libraries = 'evil';",
                SharedSqlIssue::PrivilegedStatement,
            ),
            (
                Protocol::Postgres,
                "CREATE TABLE public.copy AS SELECT * FROM public.source;",
                SharedSqlIssue::ExternalAccess,
            ),
            (
                Protocol::Mysql,
                "SELECT 1 INTO OUTFILE '/tmp/pwn';",
                SharedSqlIssue::ExternalAccess,
            ),
            (
                Protocol::Mysql,
                "CREATE FUNCTION pwn RETURNS STRING SONAME 'pwn.so';",
                SharedSqlIssue::ExternalAccess,
            ),
            (
                Protocol::Mysql,
                "CREATE TRIGGER pwn BEFORE INSERT ON items FOR EACH ROW SET @x = 1;",
                SharedSqlIssue::PrivilegedStatement,
            ),
            (
                Protocol::Mariadb,
                "CREATE EVENT pwn ON SCHEDULE EVERY 1 HOUR DO DELETE FROM items;",
                SharedSqlIssue::PrivilegedStatement,
            ),
            (
                Protocol::Mariadb,
                "SET GLOBAL general_log_file='/tmp/pwn';",
                SharedSqlIssue::PrivilegedStatement,
            ),
            (
                Protocol::Mysql,
                "DROP USER tenant_admin;",
                SharedSqlIssue::PrivilegedStatement,
            ),
            (
                Protocol::Mariadb,
                "LOCK TABLES other_db.items WRITE;",
                SharedSqlIssue::CrossDatabase,
            ),
            (
                Protocol::Clickhouse,
                "CREATE TABLE tenant_db.x(v String) ENGINE=File(CSV);",
                SharedSqlIssue::ExternalAccess,
            ),
            (
                Protocol::Clickhouse,
                "INSERT INTO tenant_db.x SELECT * FROM url('http://bad');",
                SharedSqlIssue::ExternalAccess,
            ),
            (
                Protocol::Clickhouse,
                "CREATE TABLE tenant_db.x AS file('secret.csv');",
                SharedSqlIssue::ExternalAccess,
            ),
            (
                Protocol::Clickhouse,
                "INSERT INTO FUNCTION file('leak.csv', CSV) VALUES (1);",
                SharedSqlIssue::ExternalAccess,
            ),
            (
                Protocol::Clickhouse,
                "CREATE TABLE tenant_db.x(id UInt64);",
                SharedSqlIssue::AmbiguousStatement,
            ),
            (
                Protocol::Clickhouse,
                "DROP USER tenant_admin;",
                SharedSqlIssue::PrivilegedStatement,
            ),
        ] {
            assert_eq!(
                validate(protocol, sql).unwrap_err().issue(),
                Some(issue),
                "{sql}"
            );
        }
    }

    #[test]
    fn rejects_client_commands_and_executable_comments() {
        for sql in [
            "\\connect other\nCREATE TABLE public.x(id int);",
            "/*!40101 SET GLOBAL sql_mode='' */;",
        ] {
            assert!(validate(Protocol::Mysql, sql).is_err());
        }
        validate(
            Protocol::Mysql,
            "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;",
        )
        .unwrap();
    }
}
