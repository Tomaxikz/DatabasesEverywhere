pub fn create_role_sql(username: &str) -> String {
    format!(
        "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD $1;",
        quote_ident(username)
    )
}

pub fn create_database_sql(database: &str, owner: &str) -> String {
    format!(
        "CREATE DATABASE {} OWNER {};",
        quote_ident(database),
        quote_ident(owner)
    )
}

fn quote_ident(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_sql_uses_least_privilege_flags() {
        let sql = create_role_sql("app");

        assert!(sql.contains("NOSUPERUSER"));
        assert!(sql.contains("NOCREATEDB"));
        assert!(sql.contains("NOCREATEROLE"));
        assert!(sql.contains("NOBYPASSRLS"));
    }
}
