use super::{
    SharedObserver, SharedSqlError, SharedSqlIssue, SqlToken, Statement, is_any_keyword,
    parse_namespace,
    words::{
        contains_any, contains_sequence, create_object, is_postgres_system_schema,
        privileged_object_command, qualified_identifiers,
    },
};

impl SharedObserver<'_> {
    pub(super) fn validate_postgres(
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
        if is_pg_dump_search_path_reset(&statement.tokens) {
            return Ok(());
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

    pub(super) fn reject_system_postgres_object(
        &self,
        statement: &Statement,
    ) -> Result<(), SharedSqlError> {
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
}

// pg_dump clears search_path before it emits qualified object names.
fn is_pg_dump_search_path_reset(tokens: &[SqlToken]) -> bool {
    use SqlToken::{CloseParen, Comma, Dot, EmptyString, Identifier, OpenParen, SearchPathString};
    matches!(tokens, [Identifier(select), Identifier(catalog), Dot, Identifier(function), OpenParen,
        SearchPathString, Comma, EmptyString, Comma, Identifier(local), CloseParen]
        if select.eq_ignore_ascii_case("select") && catalog == "pg_catalog"
            && function == "set_config" && local.eq_ignore_ascii_case("false"))
}
