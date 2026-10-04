use super::{
    SAFE_CLICKHOUSE_ENGINES, SharedObserver, SharedSqlError, SharedSqlIssue, Statement,
    is_any_keyword,
    mysql_command::validate_engine,
    parse_namespace,
    words::{
        contains_any, contains_sequence, create_object, import_object_qualifiers,
        is_clickhouse_system_database, privileged_object_command, top_level_keyword, word_at_is,
    },
};

impl SharedObserver<'_> {
    pub(super) fn validate_clickhouse(
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
                    if create_object == Some("DATABASE") {
                        return self.reject(
                            SharedSqlIssue::PrivilegedStatement,
                            "shared imports cannot create a ClickHouse database",
                        );
                    }
                    if !matches!(create_object, Some("TABLE" | "INDEX" | "VIEW")) {
                        return self.reject(
                            SharedSqlIssue::UnsupportedStatement,
                            "this ClickHouse CREATE form is not safe for a shared-tenant import",
                        );
                    }
                    if create_object == Some("TABLE") && !has_engine {
                        return self.reject(
                            SharedSqlIssue::AmbiguousStatement,
                            "shared ClickHouse CREATE TABLE requires one explicit allowed engine",
                        );
                    }
                }
                let targets_database = word_at_is(words, 1, "DATABASE");
                if command.eq_ignore_ascii_case("DROP") && targets_database {
                    return self.reject(
                        SharedSqlIssue::PrivilegedStatement,
                        "shared imports cannot drop a ClickHouse database",
                    );
                }
                if command.eq_ignore_ascii_case("ALTER") && targets_database {
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
}
