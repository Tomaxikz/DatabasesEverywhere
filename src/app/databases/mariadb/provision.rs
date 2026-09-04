use super::super::{
    mysql_shared_grant_sql, quote_mysql_grant_db as quote_grant_db,
    quote_mysql_ident as quote_identifier,
};

#[derive(Debug, thiserror::Error)]
pub enum MariadbProvisionError {
    #[error("native password verifier must be 40 hexadecimal characters")]
    InvalidNativePasswordVerifier,
}

pub fn scoped_grant_sql(database: &str, username: &str) -> String {
    format!(
        "GRANT ALL PRIVILEGES ON {}.* TO {}@'%';",
        quote_grant_db(database),
        quote_identifier(username),
    )
}

pub fn tenant_user_sql(
    database: &str,
    username: &str,
    native_password_sha1_stage2_hex: &str,
) -> Result<String, MariadbProvisionError> {
    build_tenant_user_sql(
        database,
        username,
        native_password_sha1_stage2_hex,
        TenantAccess::Dedicated,
    )
}

pub fn shared_tenant_user_sql(
    database: &str,
    username: &str,
    native_password_sha1_stage2_hex: &str,
) -> Result<String, MariadbProvisionError> {
    build_tenant_user_sql(
        database,
        username,
        native_password_sha1_stage2_hex,
        TenantAccess::Shared,
    )
}

#[derive(Clone, Copy)]
enum TenantAccess {
    Dedicated,
    Shared,
}

fn build_tenant_user_sql(
    database: &str,
    username: &str,
    native_password_sha1_stage2_hex: &str,
    access: TenantAccess,
) -> Result<String, MariadbProvisionError> {
    if native_password_sha1_stage2_hex.len() != 40
        || !native_password_sha1_stage2_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(MariadbProvisionError::InvalidNativePasswordVerifier);
    }

    let database_ident = quote_identifier(database);
    let username_ident = quote_identifier(username);
    let native_password_hash = format!("*{}", native_password_sha1_stage2_hex.to_ascii_uppercase());
    let grants = match access {
        TenantAccess::Dedicated => scoped_grant_sql(database, username),
        TenantAccess::Shared => mysql_shared_grant_sql(database, username),
    };

    Ok(format!(
        r#"
CREATE DATABASE IF NOT EXISTS {database_ident};
CREATE USER IF NOT EXISTS {username_ident}@'%' IDENTIFIED BY PASSWORD '{native_password_hash}';
ALTER USER {username_ident}@'%' IDENTIFIED BY PASSWORD '{native_password_hash}';
{grants}
FLUSH PRIVILEGES;
"#
    ))
}

pub fn reset_tenant_password_sql(
    username: &str,
    native_password_sha1_stage2_hex: &str,
) -> Result<String, MariadbProvisionError> {
    if native_password_sha1_stage2_hex.len() != 40
        || !native_password_sha1_stage2_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(MariadbProvisionError::InvalidNativePasswordVerifier);
    }
    Ok(format!(
        "ALTER USER {}@'%' IDENTIFIED BY PASSWORD '*{}';",
        quote_identifier(username),
        native_password_sha1_stage2_hex.to_ascii_uppercase(),
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantQuota {
    pub max_queries_per_hour: u64,
    pub max_updates_per_hour: u64,
    pub max_connections_per_hour: u64,
    pub max_connections: u32,
    pub max_statement_millis: u64,
}

pub fn tenant_quota_sql(username: &str, quota: TenantQuota) -> String {
    let statement_seconds = if quota.max_statement_millis.is_multiple_of(1_000) {
        (quota.max_statement_millis / 1_000).to_string()
    } else {
        format!(
            "{}.{:03}",
            quota.max_statement_millis / 1_000,
            quota.max_statement_millis % 1_000,
        )
    };
    format!(
        "ALTER USER {}@'%' WITH MAX_QUERIES_PER_HOUR {} MAX_UPDATES_PER_HOUR {} MAX_CONNECTIONS_PER_HOUR {} MAX_USER_CONNECTIONS {} MAX_STATEMENT_TIME {};",
        quote_identifier(username),
        quota.max_queries_per_hour,
        quota.max_updates_per_hour,
        quota.max_connections_per_hour,
        quota.max_connections,
        statement_seconds,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_user_sql_accepts_only_native_password_hashes() {
        let sql = tenant_user_sql(
            "app_db",
            "app_user",
            "0123456789abcdef0123456789abcdef01234567",
        )
        .unwrap();

        assert!(sql.contains("CREATE DATABASE IF NOT EXISTS `app_db`"));
        assert!(sql.contains("ALTER USER `app_user`@'%'"));
        assert!(sql.contains("*0123456789ABCDEF0123456789ABCDEF01234567"));
        assert!(sql.contains("GRANT ALL PRIVILEGES ON `app\\_db`.* TO `app_user`@'%'"));
        assert!(!sql.contains("REVOKE ALL PRIVILEGES"));
        assert!(tenant_user_sql("db", "user", "not-a-hash").is_err());
    }

    #[test]
    fn shared_tenant_user_has_scoped_privileges() {
        let sql = shared_tenant_user_sql(
            "app_db",
            "app_user",
            "0123456789abcdef0123456789abcdef01234567",
        )
        .unwrap();

        assert!(sql.contains("REVOKE ALL PRIVILEGES, GRANT OPTION"));
        assert!(sql.contains("GRANT SELECT, INSERT, UPDATE, DELETE"));
        assert!(!sql.contains("GRANT ALL PRIVILEGES"));
        assert!(!sql.contains("CREATE TEMPORARY TABLES"));
        assert!(!sql.contains("ACCOUNT UNLOCK"));
        for executable in [" EXECUTE", " CREATE ROUTINE", " ALTER ROUTINE", " TRIGGER"] {
            assert!(!sql.contains(executable));
        }
        assert_eq!(sql.matches("REVOKE ALL PRIVILEGES").count(), 1);
        assert!(sql.contains(&mysql_shared_grant_sql("app_db", "app_user")));
    }

    #[test]
    fn quota_sql_is_account_scoped() {
        for username in ["tenant_a", "tenant`quoted", "tenant'name"] {
            let quota = tenant_quota_sql(
                username,
                TenantQuota {
                    max_queries_per_hour: 20_000,
                    max_updates_per_hour: 5_000,
                    max_connections_per_hour: 1_000,
                    max_connections: 12,
                    max_statement_millis: 30_000,
                },
            );

            assert!(quota.contains("MAX_USER_CONNECTIONS 12"));
            assert!(quota.contains("MAX_STATEMENT_TIME 30"));
            assert!(!quota.contains("mysql.user SET"));
            assert!(!quota.contains("DROP USER root"));
            assert!(!quota.contains("SET GLOBAL"));
        }
    }

    #[test]
    fn shared_grants_never_cross_schema_boundaries() {
        let create = shared_tenant_user_sql(
            "tenant_db",
            "tenant_user",
            "0123456789abcdef0123456789abcdef01234567",
        )
        .unwrap();

        assert!(create.contains("ON `tenant\\_db`.*"));
        assert!(!create.contains("ON *.*"));
        assert!(!create.contains(" FILE"));
        assert!(!create.contains(" PROCESS"));
        assert!(!create.contains(" SUPER"));
        assert!(!create.contains("GRANT OPTION TO"));
    }

    #[test]
    fn database_grants_escape_pattern_metacharacters() {
        assert_eq!(quote_grant_db("tenant_db"), r"`tenant\_db`");
        assert_eq!(quote_grant_db(r"tenant\db%"), r"`tenant\\db\%`");

        let sql = mysql_shared_grant_sql("tenant_db", "tenant_user");
        assert!(sql.contains(r"ON `tenant\_db`.*"));
        assert!(!sql.contains("CREATE TEMPORARY TABLES"));

        let dedicated = scoped_grant_sql("tenant_db", "tenant_user");
        assert!(dedicated.contains(r"ON `tenant\_db`.*"));
    }

    #[test]
    fn password_reset_is_account_scoped_and_accepts_only_a_verifier() {
        let sql = reset_tenant_password_sql("app_user", "0123456789abcdef0123456789abcdef01234567")
            .unwrap();
        assert_eq!(
            sql,
            "ALTER USER `app_user`@'%' IDENTIFIED BY PASSWORD '*0123456789ABCDEF0123456789ABCDEF01234567';"
        );
        assert!(reset_tenant_password_sql("app_user", "plaintext").is_err());
    }
}
