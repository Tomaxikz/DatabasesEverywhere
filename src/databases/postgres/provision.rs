pub fn provision_tenant_role_sql(database: &str, username: &str) -> String {
    let username_identifier = quote_ident(username);
    let database_identifier = quote_ident(database);
    let create_role_statement = quote_literal(&format!("CREATE ROLE {username_identifier} LOGIN"));
    let username_literal = quote_literal(username);

    format!(
        "BEGIN;\nSET LOCAL log_min_error_statement = PANIC;\nSELECT {create_role_statement}\nWHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {username_literal})\n\\gexec\nALTER ROLE {username_identifier} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'tenant_password';\nREVOKE ALL ON DATABASE {database_identifier} FROM PUBLIC;\nALTER DATABASE {database_identifier} OWNER TO {username_identifier};\nCOMMIT;"
    )
}

pub fn restrict_tenant_role_sql(username: &str) -> String {
    format!(
        "ALTER ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;",
        quote_ident(username),
    )
}

pub fn tenant_role_state_sql(username: &str) -> String {
    format!(
        "SELECT oid::text || ':' || (rolsuper OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication OR rolbypassrls)::int::text FROM pg_roles WHERE rolname = {};",
        quote_literal(username),
    )
}

fn quote_ident(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    format!("\"{escaped}\"")
}

fn quote_literal(value: &str) -> String {
    let escaped = value.replace('\'', "''");
    format!("'{escaped}'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_provisioning_is_atomic_and_uses_a_psql_password_variable() {
        let sql = provision_tenant_role_sql("app_db", "app_user");

        assert!(sql.starts_with("BEGIN;"));
        assert!(sql.contains("CREATE ROLE \"app_user\" LOGIN"));
        assert!(sql.contains("WHERE NOT EXISTS"));
        assert!(sql.contains("\\gexec"));
        assert!(sql.contains("\"app_user\" LOGIN NOSUPERUSER"));
        assert!(sql.contains("PASSWORD :'tenant_password'"));
        assert!(sql.contains("SET LOCAL log_min_error_statement = PANIC"));
        assert!(sql.contains("REVOKE ALL ON DATABASE \"app_db\" FROM PUBLIC"));
        assert!(sql.contains("ALTER DATABASE \"app_db\" OWNER TO \"app_user\""));
        assert!(sql.ends_with("COMMIT;"));
    }

    #[test]
    fn tenant_role_sql_uses_least_privilege_flags() {
        let sql = restrict_tenant_role_sql("app");

        assert!(sql.contains("LOGIN NOSUPERUSER"));
        assert!(sql.contains("NOCREATEDB"));
        assert!(sql.contains("NOCREATEROLE"));
        assert!(sql.contains("NOINHERIT"));
        assert!(sql.contains("NOBYPASSRLS"));
    }

    #[test]
    fn identifiers_and_literals_are_quoted() {
        let sql = provision_tenant_role_sql("db\"name", "user'name");
        let state_sql = tenant_role_state_sql("user'name");

        assert!(sql.contains("ALTER DATABASE \"db\"\"name\""));
        assert!(sql.contains("\"user'name\""));
        assert!(state_sql.contains("'user''name'"));
    }
}
