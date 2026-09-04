pub mod clickhouse;
pub mod mariadb;
pub mod mongodb;
pub mod mysql;
#[cfg(test)]
mod mysql_wire_integration;
pub mod postgres;
pub mod qdrant;
pub(crate) mod resp;

#[cfg(test)]
mod test_support;

pub(crate) fn quote_mysql_ident(identifier: &str) -> String {
    format!("`{}`", identifier.replace('`', "``"))
}

/// MySQL-family database names in database-level grants are patterns even
/// when quoted. Escape their pattern metacharacters before identifier quoting.
pub(crate) fn quote_mysql_grant_db(database: &str) -> String {
    let escaped = database
        .replace('\\', "\\\\")
        .replace('_', "\\_")
        .replace('%', "\\%");
    quote_mysql_ident(&escaped)
}

/// Replaces every existing account grant with the tenant-safe shared profile.
/// Executable schema objects stay excluded because shared logical restores do
/// not accept routines or triggers.
pub(crate) fn mysql_shared_grant_sql(database: &str, username: &str) -> String {
    let database = quote_mysql_grant_db(database);
    let username = quote_mysql_ident(username);
    format!(
        "REVOKE ALL PRIVILEGES, GRANT OPTION FROM {username}@'%';\nGRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER, INDEX, REFERENCES, LOCK TABLES, CREATE VIEW, SHOW VIEW ON {database}.* TO {username}@'%';"
    )
}

pub(crate) fn mysql_fence_sql(username: &str) -> String {
    format!(
        "ALTER USER {}@'%' ACCOUNT LOCK;",
        quote_mysql_ident(username),
    )
}

pub(crate) fn mysql_unfence_sql(username: &str) -> String {
    format!(
        "ALTER USER {}@'%' ACCOUNT UNLOCK;",
        quote_mysql_ident(username),
    )
}

pub(crate) fn mysql_session_ids_sql(username: &str) -> String {
    format!(
        "SELECT ID FROM information_schema.PROCESSLIST WHERE USER = {} AND ID <> CONNECTION_ID();",
        quote_mysql_string(username),
    )
}

pub(crate) fn mysql_kill_sql(connection_id: u64) -> String {
    format!("KILL CONNECTION {connection_id};")
}

pub(crate) fn mysql_drop_sql(database: &str, username: &str) -> String {
    format!(
        "DROP DATABASE IF EXISTS {};\nDROP USER IF EXISTS {}@'%';",
        quote_mysql_ident(database),
        quote_mysql_ident(username),
    )
}

/// Returns one allocated table-and-index byte count per schema, in input
/// order. Binary comparison keeps tenant identity matching case-sensitive.
pub(crate) fn mysql_storage_sql(databases: &[&str]) -> String {
    databases
        .iter()
        .map(|database| {
            format!(
                "SELECT COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH), 0) FROM information_schema.TABLES WHERE BINARY TABLE_SCHEMA = BINARY {};",
                quote_mysql_string(database)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Counts objects that a tenant-only MySQL-family dump cannot replay exactly.
/// Run this as the engine administrator while the tenant route is fenced.
pub(crate) fn mysql_rollback_gap_sql(database: &str, username: &str) -> String {
    let database = quote_mysql_string(database);
    let definer = quote_mysql_string(&format!("{username}@%"));
    format!(
        "SELECT \
         (SELECT COUNT(*) FROM information_schema.ROUTINES WHERE BINARY ROUTINE_SCHEMA = BINARY {database}) + \
         (SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE BINARY TRIGGER_SCHEMA = BINARY {database}) + \
         (SELECT COUNT(*) FROM information_schema.EVENTS WHERE BINARY EVENT_SCHEMA = BINARY {database}) + \
         (SELECT COUNT(*) FROM information_schema.VIEWS WHERE BINARY TABLE_SCHEMA = BINARY {database} AND BINARY DEFINER <> BINARY {definer});"
    )
}

pub(crate) fn quote_mysql_string(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_gap_query_is_schema_scoped_and_includes_every_unsupported_object() {
        let sql = mysql_rollback_gap_sql("tenant'db", "user'name");

        for catalog in ["ROUTINES", "TRIGGERS", "EVENTS", "VIEWS"] {
            assert!(sql.contains(&format!("information_schema.{catalog}")));
        }
        assert_eq!(sql.matches("BINARY 'tenant''db'").count(), 4);
        assert!(sql.contains("BINARY DEFINER <> BINARY 'user''name@%'"));
        assert!(!sql.contains("DATABASE()"));
        assert!(!sql.contains("CURRENT_USER()"));
    }

    #[test]
    fn mysql_family_tenant_sql_is_scoped_and_escaped() {
        let grant = mysql_shared_grant_sql("tenant_db", "tenant`user");
        assert!(grant.contains(r"ON `tenant\_db`.* TO `tenant``user`@'%'"));
        assert!(!grant.contains("ON *.*"));
        for privilege in [" FILE", " PROCESS", " SUPER", " EXECUTE", " TRIGGER"] {
            assert!(!grant.contains(privilege));
        }

        let username = "tenant'name";
        assert!(mysql_fence_sql(username).contains("ACCOUNT LOCK"));
        assert!(mysql_unfence_sql(username).contains("ACCOUNT UNLOCK"));
        assert!(mysql_session_ids_sql(username).contains("USER = 'tenant''name'"));
        assert_eq!(mysql_kill_sql(42), "KILL CONNECTION 42;");

        let drop = mysql_drop_sql("tenant`db", "tenant`user");
        assert_eq!(
            drop,
            "DROP DATABASE IF EXISTS `tenant``db`;\nDROP USER IF EXISTS `tenant``user`@'%';"
        );

        let storage = mysql_storage_sql(&["tenant_a", "db'name"]);
        let rows = storage.lines().collect::<Vec<_>>();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].contains("BINARY TABLE_SCHEMA = BINARY 'tenant_a'"));
        assert!(rows[1].contains("BINARY TABLE_SCHEMA = BINARY 'db''name'"));
        assert!(
            rows.iter()
                .all(|row| row.contains("DATA_LENGTH + INDEX_LENGTH"))
        );
    }
}
