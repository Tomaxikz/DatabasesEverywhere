use crate::shared::hex::encode_lower;

pub fn provision_tenant_role_sql(database: &str, username: &str) -> String {
    let username_identifier = quote_ident(username);
    let database_identifier = quote_ident(database);
    let create_role_statement = quote_literal(&format!("CREATE ROLE {username_identifier} LOGIN"));
    let username_literal = quote_literal(username);

    format!(
        "BEGIN;\nSET LOCAL log_min_error_statement = PANIC;\nSET LOCAL password_encryption = 'scram-sha-256';\nSELECT {create_role_statement}\nWHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {username_literal})\n\\gexec\nALTER ROLE {username_identifier} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'tenant_password';\nREVOKE ALL ON DATABASE {database_identifier} FROM PUBLIC;\nALTER DATABASE {database_identifier} OWNER TO {username_identifier};\nCOMMIT;"
    )
}

pub fn provision_shared_tenant_role_sql(database: &str, username: &str) -> String {
    let username_identifier = quote_ident(username);
    let database_identifier = quote_ident(database);
    let tablespace_name = tenant_tablespace_name(database);
    let tablespace_identifier = quote_ident(&tablespace_name);
    let tablespace_literal = quote_literal(&tablespace_name);
    let create_database_statement = quote_literal(&format!(
        "CREATE DATABASE {database_identifier} TABLESPACE {tablespace_identifier}"
    ));
    let database_literal = quote_literal(database);
    let create_role_statement = quote_literal(&format!("CREATE ROLE {username_identifier} LOGIN"));
    let username_literal = quote_literal(username);

    format!(
        "SELECT {create_database_statement}\nWHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = {database_literal})\n\\gexec\nBEGIN;\nSET LOCAL log_min_error_statement = PANIC;\nSET LOCAL password_encryption = 'scram-sha-256';\nSELECT {create_role_statement}\nWHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {username_literal})\n\\gexec\nALTER ROLE {username_identifier} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD :'tenant_password';\nGRANT CREATE ON TABLESPACE {tablespace_identifier} TO {username_identifier};\nALTER ROLE {username_identifier} IN DATABASE {database_identifier} SET default_tablespace TO {tablespace_literal};\nALTER ROLE {username_identifier} IN DATABASE {database_identifier} SET temp_tablespaces TO {tablespace_literal};\nREVOKE ALL ON DATABASE {database_identifier} FROM PUBLIC;\nREVOKE ALL ON DATABASE {database_identifier} FROM {username_identifier};\nALTER DATABASE {database_identifier} OWNER TO CURRENT_USER;\nGRANT CONNECT ON DATABASE {database_identifier} TO {username_identifier};\nCOMMIT;\n\\connect {database_identifier}\nBEGIN;\nREVOKE ALL ON SCHEMA public FROM PUBLIC;\nGRANT USAGE, CREATE ON SCHEMA public TO {username_identifier};\nCOMMIT;"
    )
}

/// Removes PostgreSQL's default PUBLIC access to databases that belong to the
/// shared engine itself. Tenant roles receive CONNECT only on their own
/// database, so leaving these defaults in place would bypass per-database
/// timeouts and allow unaccounted temporary files in the system catalogs.
pub fn shared_catalog_lockdown_sql() -> String {
    let databases = ["postgres", "template0", "template1", "dbe_control"];
    let revoke = databases
        .iter()
        .map(|database| {
            format!(
                "REVOKE CONNECT, TEMPORARY ON DATABASE {} FROM PUBLIC;",
                quote_ident(database)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let protected = databases
        .iter()
        .map(|database| quote_literal(database))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "REVOKE CREATE ON TABLESPACE pg_default FROM PUBLIC;\nREVOKE CREATE ON TABLESPACE pg_global FROM PUBLIC;\n{revoke}\nSELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname IN ({protected}) AND usename IS DISTINCT FROM current_user AND pid <> pg_backend_pid();"
    )
}

pub fn fence_tenant_sql(database: &str, username: &str) -> String {
    format!(
        "ALTER ROLE {} NOLOGIN;\nREVOKE CONNECT ON DATABASE {} FROM {};",
        quote_ident(username),
        quote_ident(database),
        quote_ident(username),
    )
}

pub fn unfence_tenant_sql(database: &str, username: &str) -> String {
    format!(
        "ALTER ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;\nREVOKE TEMPORARY ON DATABASE {} FROM {};\nGRANT CONNECT ON DATABASE {} TO {};",
        quote_ident(username),
        quote_ident(database),
        quote_ident(username),
        quote_ident(database),
        quote_ident(username),
    )
}

pub fn terminate_tenant_sql(database: &str, username: &str) -> String {
    format!(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = {} AND usename = {} AND pid <> pg_backend_pid();",
        quote_literal(database),
        quote_literal(username),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantDropSql {
    /// Run while connected to the tenant database, before the maintenance SQL.
    pub database_sql: String,
    /// Run from an administrator connection to a different database.
    pub maintenance_sql: String,
}

pub fn drop_tenant_sql(database: &str, username: &str) -> TenantDropSql {
    let database_identifier = quote_ident(database);
    let username_identifier = quote_ident(username);
    let username_literal = quote_literal(username);
    let tablespace_identifier = quote_ident(&tenant_tablespace_name(database));
    let reassign = quote_literal(&format!(
        "REASSIGN OWNED BY {username_identifier} TO CURRENT_USER"
    ));
    let drop_owned = quote_literal(&format!("DROP OWNED BY {username_identifier}"));
    TenantDropSql {
        database_sql: format!(
            "SELECT {reassign} WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {username_literal})\n\\gexec\nSELECT {drop_owned} WHERE EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {username_literal})\n\\gexec"
        ),
        maintenance_sql: format!(
            "{}\nDROP DATABASE IF EXISTS {database_identifier} WITH (FORCE);\nDROP TABLESPACE IF EXISTS {tablespace_identifier};\nDROP ROLE IF EXISTS {username_identifier};",
            terminate_tenant_sql(database, username),
        ),
    }
}

/// Stable, engine-local name for the daemon-owned tablespace that contains one
/// shared tenant database. The digest keeps the identifier below PostgreSQL's
/// 63-byte limit and avoids exposing the public database name as a host path.
pub fn tenant_tablespace_name(database: &str) -> String {
    use sha2::{Digest, Sha256};

    let suffix = encode_lower(&Sha256::digest(database.as_bytes())[..16]);
    format!("dbev_ts_{suffix}")
}

/// Creates the daemon-owned tablespace idempotently and returns its canonical
/// PostgreSQL-visible location as the final output row. The caller validates
/// that row against the trusted bind root before provisioning the database.
pub fn ensure_tenant_tablespace_sql(database: &str, location: &str) -> String {
    let name = tenant_tablespace_name(database);
    let name_ident = quote_ident(&name);
    let name_literal = quote_literal(&name);
    let create = quote_literal(&format!(
        "CREATE TABLESPACE {name_ident} LOCATION {}",
        quote_literal(location)
    ));
    format!(
        "SELECT {create} WHERE NOT EXISTS (SELECT 1 FROM pg_tablespace WHERE spcname = {name_literal})\n\\gexec\nSELECT pg_tablespace_location(oid) FROM pg_tablespace WHERE spcname = {name_literal};"
    )
}

/// Reports the default tablespace location for a managed database. An empty
/// row means pg_default and therefore a legacy shared layout that cannot be
/// safely relabelled as a hard per-tenant boundary in place.
pub fn tenant_tablespace_location_sql(database: &str) -> String {
    format!(
        "SELECT COALESCE(pg_tablespace_location(dattablespace), '') FROM pg_database WHERE datname = {};",
        quote_literal(database)
    )
}

pub fn tenant_database_exists_sql(database: &str) -> String {
    format!(
        "SELECT 1 FROM pg_database WHERE datname = {};",
        quote_literal(database),
    )
}

pub fn drop_tenant_identity_sql(database: &str, username: &str) -> String {
    format!(
        "DROP TABLESPACE IF EXISTS {};\nDROP ROLE IF EXISTS {};",
        quote_ident(&tenant_tablespace_name(database)),
        quote_ident(username),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantQuota {
    pub max_connections: u32,
    pub statement_timeout_ms: u64,
    pub lock_timeout_ms: u64,
    pub idle_transaction_timeout_ms: u64,
    pub temp_file_limit_kib: u64,
}

pub fn tenant_quota_sql(database: &str, username: &str, quota: TenantQuota) -> String {
    let database = quote_ident(database);
    let username = quote_ident(username);
    format!(
        "ALTER ROLE {username} CONNECTION LIMIT {};\nALTER ROLE {username} IN DATABASE {database} SET statement_timeout TO '{}ms';\nALTER ROLE {username} IN DATABASE {database} SET lock_timeout TO '{}ms';\nALTER ROLE {username} IN DATABASE {database} SET idle_in_transaction_session_timeout TO '{}ms';\nALTER ROLE {username} IN DATABASE {database} SET temp_file_limit TO '{}kB';",
        quota.max_connections,
        quota.statement_timeout_ms,
        quota.lock_timeout_ms,
        quota.idle_transaction_timeout_ms,
        quota.temp_file_limit_kib,
    )
}

pub fn restrict_tenant_role_sql(username: &str) -> String {
    format!(
        "ALTER ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;",
        quote_ident(username),
    )
}

pub fn reset_tenant_password_sql(username: &str) -> String {
    format!(
        "SET password_encryption = 'scram-sha-256';\nALTER ROLE {} PASSWORD :'tenant_password';",
        quote_ident(username),
    )
}

pub fn tenant_password_verifier_sql(username: &str) -> String {
    format!(
        "SELECT COALESCE(rolpassword, '') FROM pg_authid WHERE rolname = {};",
        quote_literal(username),
    )
}

pub fn restore_verifier_sql(username: &str) -> String {
    format!(
        "ALTER ROLE {} PASSWORD :'tenant_password_verifier';",
        quote_ident(username),
    )
}

pub fn tenant_role_state_sql(username: &str) -> String {
    format!(
        "SELECT oid::text || ':' || (rolsuper OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication OR rolbypassrls)::int::text FROM pg_roles WHERE rolname = {};",
        quote_literal(username),
    )
}

/// Returns one physical byte count per database, in input order. The control
/// administrator owns shared databases, so `pg_database_size` is the engine's
/// authoritative tenant measurement instead of a guessed host directory.
pub fn tenant_storage_sql(databases: &[&str]) -> String {
    databases
        .iter()
        .map(|database| {
            format!(
                "SELECT COALESCE(pg_database_size({}), 0)::bigint;",
                quote_literal(database)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn quote_ident(value: &str) -> String {
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
    fn shared_tenant_provisioning_creates_an_admin_owned_database() {
        let sql = provision_shared_tenant_role_sql("app_db", "app_user");

        assert!(sql.starts_with("SELECT 'CREATE DATABASE \"app_db\" TABLESPACE \"dbev_ts_"));
        assert!(sql.contains("TABLESPACE \"dbev_ts_"));
        assert!(sql.contains("FROM pg_database WHERE datname = 'app_db'"));
        assert!(sql.contains("CREATE ROLE \"app_user\" LOGIN"));
        assert!(sql.contains("WHERE NOT EXISTS"));
        assert!(sql.contains("\\gexec"));
        assert!(sql.contains("\"app_user\" LOGIN NOSUPERUSER"));
        assert!(sql.contains("PASSWORD :'tenant_password'"));
        assert!(sql.contains("GRANT CREATE ON TABLESPACE \"dbev_ts_"));
        assert!(sql.contains("SET default_tablespace TO 'dbev_ts_"));
        assert!(sql.contains("SET temp_tablespaces TO 'dbev_ts_"));
        assert!(sql.contains("SET LOCAL log_min_error_statement = PANIC"));
        assert!(sql.contains("REVOKE ALL ON DATABASE \"app_db\" FROM PUBLIC"));
        assert!(sql.contains("REVOKE ALL ON DATABASE \"app_db\" FROM \"app_user\""));
        assert!(sql.contains("ALTER DATABASE \"app_db\" OWNER TO CURRENT_USER"));
        assert!(sql.contains("\\connect \"app_db\""));
        assert!(sql.contains("GRANT CONNECT ON DATABASE \"app_db\""));
        assert!(!sql.contains("GRANT CONNECT, TEMPORARY"));
        assert!(sql.contains("REVOKE ALL ON SCHEMA public FROM PUBLIC"));
        assert!(sql.contains("GRANT USAGE, CREATE ON SCHEMA public TO \"app_user\""));
        assert!(sql.ends_with("COMMIT;"));
    }

    #[test]
    fn dedicated_tenant_keeps_ownership_of_its_existing_database() {
        let sql = provision_tenant_role_sql("app_db", "app_user");

        assert!(sql.starts_with("BEGIN;"));
        assert!(sql.contains("ALTER DATABASE \"app_db\" OWNER TO \"app_user\""));
        assert!(sql.contains("REVOKE ALL ON DATABASE \"app_db\" FROM PUBLIC"));
        assert!(!sql.contains("CREATE DATABASE"));
        assert!(!sql.contains("GRANT USAGE, CREATE ON SCHEMA public"));
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
    fn shared_catalogs_reject_public_connections_and_temp_files() {
        let sql = shared_catalog_lockdown_sql();

        assert!(sql.contains("REVOKE CREATE ON TABLESPACE pg_default FROM PUBLIC"));
        assert!(sql.contains("REVOKE CREATE ON TABLESPACE pg_global FROM PUBLIC"));

        for database in ["postgres", "template0", "template1", "dbe_control"] {
            assert!(sql.contains(&format!(
                "REVOKE CONNECT, TEMPORARY ON DATABASE \"{database}\" FROM PUBLIC"
            )));
            assert!(sql.contains(&quote_literal(database)));
        }
        assert!(sql.contains("pg_terminate_backend(pid)"));
        assert!(sql.contains("usename IS DISTINCT FROM current_user"));
        assert!(!sql.contains("ALTER DATABASE"));
        assert!(!sql.contains("DROP DATABASE"));
    }

    #[test]
    fn password_reset_uses_a_psql_variable_instead_of_interpolating_the_secret() {
        let sql = reset_tenant_password_sql("app_user");

        assert!(sql.starts_with("SET password_encryption = 'scram-sha-256';"));
        assert!(sql.ends_with("ALTER ROLE \"app_user\" PASSWORD :'tenant_password';"));
    }

    #[test]
    fn password_verifier_capture_and_restore_quote_the_role() {
        let capture = tenant_password_verifier_sql("user'name");
        let restore = restore_verifier_sql("user\"name");

        assert!(capture.contains("rolname = 'user''name'"));
        assert_eq!(
            restore,
            "ALTER ROLE \"user\"\"name\" PASSWORD :'tenant_password_verifier';"
        );
    }

    #[test]
    fn identifiers_and_literals_are_quoted() {
        let sql = provision_tenant_role_sql("db\"name", "user'name");
        let state_sql = tenant_role_state_sql("user'name");

        assert!(sql.contains("ALTER DATABASE \"db\"\"name\""));
        assert!(sql.contains("\"user'name\""));
        assert!(state_sql.contains("'user''name'"));
    }

    #[test]
    fn lifecycle_operations_target_only_one_tenant() {
        for (database, username) in [("tenant_a", "user_a"), ("db\"quoted", "user'quoted")] {
            let fence = fence_tenant_sql(database, username);
            let unfence = unfence_tenant_sql(database, username);
            let terminate = terminate_tenant_sql(database, username);
            let drop = drop_tenant_sql(database, username);

            for sql in [
                fence.as_str(),
                unfence.as_str(),
                terminate.as_str(),
                drop.database_sql.as_str(),
                drop.maintenance_sql.as_str(),
            ] {
                assert!(!sql.contains("DROP ROLE dbe_admin"));
                assert!(!sql.contains("pg_signal_backend"));
                assert!(!sql.contains("*.*"));
            }
            assert!(terminate.contains(&quote_literal(database)));
            assert!(terminate.contains(&quote_literal(username)));
            assert!(unfence.contains("REVOKE TEMPORARY ON DATABASE"));
            assert!(drop.maintenance_sql.contains("WITH (FORCE)"));
            assert!(tenant_database_exists_sql(database).contains(&quote_literal(database)));
            let identity = drop_tenant_identity_sql(database, username);
            assert!(identity.contains(&quote_ident(username)));
            assert!(identity.contains(&tenant_tablespace_name(database)));
        }
    }

    #[test]
    fn quota_is_role_and_database_scoped() {
        let sql = tenant_quota_sql(
            "tenant_db",
            "tenant_user",
            TenantQuota {
                max_connections: 8,
                statement_timeout_ms: 30_000,
                lock_timeout_ms: 5_000,
                idle_transaction_timeout_ms: 60_000,
                temp_file_limit_kib: 262_144,
            },
        );

        assert!(sql.contains("ALTER ROLE \"tenant_user\" CONNECTION LIMIT 8"));
        assert!(sql.contains("IN DATABASE \"tenant_db\""));
        assert!(sql.contains("temp_file_limit TO '262144kB'"));
        assert!(!sql.contains("ALTER SYSTEM"));
        assert!(!sql.contains("SET GLOBAL"));
    }

    #[test]
    fn storage_queries_are_ordered_and_literal_quoted() {
        let sql = tenant_storage_sql(&["tenant_a", "db'name"]);
        let rows = sql.lines().collect::<Vec<_>>();

        assert_eq!(rows.len(), 2);
        assert!(rows[0].contains("pg_database_size('tenant_a')"));
        assert!(rows[1].contains("pg_database_size('db''name')"));
    }
}
