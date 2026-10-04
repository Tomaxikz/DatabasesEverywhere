use super::{
    SAFE_MYSQL_ENGINES, SharedObserver, SharedSqlError, SharedSqlIssue, Statement, is_any_keyword,
    mysql_command::{mysql_database_ddl, mysql_storage_policy_violation, validate_engine},
    parse_namespace,
    words::{
        contains_any, contains_sequence, create_object, import_object_qualifiers,
        is_mysql_system_database, privileged_object_command,
    },
};

impl SharedObserver<'_> {
    pub(super) fn validate_mysql(
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

    pub(super) fn require_mysql_qualifiers(
        &self,
        statement: &Statement,
    ) -> Result<(), SharedSqlError> {
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
}
