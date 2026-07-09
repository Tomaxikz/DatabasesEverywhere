pub fn create_maintenance_role_sql(username: &str) -> String {
    format!(
        "CREATE ROLE {} NOLOGIN SUPERUSER CREATEDB CREATEROLE NOINHERIT NOREPLICATION BYPASSRLS;",
        quote_ident(username),
    )
}

pub fn restrict_tenant_role_sql(username: &str) -> String {
    format!(
        "ALTER ROLE {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;",
        quote_ident(username),
    )
}

pub fn harden_tenant_role_sql(maintenance_username: &str, tenant_username: &str) -> String {
    format!(
        "BEGIN;\n{}\n{}\nCOMMIT;",
        create_maintenance_role_sql(maintenance_username),
        restrict_tenant_role_sql(tenant_username),
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
    fn tenant_role_sql_uses_least_privilege_flags() {
        let sql = restrict_tenant_role_sql("app");

        assert!(sql.contains("NOSUPERUSER"));
        assert!(sql.contains("NOCREATEDB"));
        assert!(sql.contains("NOCREATEROLE"));
        assert!(sql.contains("NOBYPASSRLS"));
    }

    #[test]
    fn maintenance_role_is_superuser_but_cannot_log_in() {
        let sql = create_maintenance_role_sql("dbe_\"admin");

        assert!(sql.contains("CREATE ROLE \"dbe_\"\"admin\" NOLOGIN SUPERUSER"));
        assert!(!sql.contains("PASSWORD"));
        assert!(!sql.contains(" LOGIN "));
    }

    #[test]
    fn maintenance_creation_and_tenant_demotion_are_one_transaction() {
        let sql = harden_tenant_role_sql("dbe_admin", "app");

        assert!(sql.starts_with("BEGIN;\nCREATE ROLE \"dbe_admin\" NOLOGIN SUPERUSER"));
        assert!(sql.contains("\nALTER ROLE \"app\" NOSUPERUSER"));
        assert!(sql.ends_with("\nCOMMIT;"));
    }
}
