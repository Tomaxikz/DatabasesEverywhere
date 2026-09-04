use super::super::{
    mysql_shared_grant_sql, quote_mysql_grant_db as quote_grant_db,
    quote_mysql_ident as quote_identifier, quote_mysql_string,
};

pub const PASSWORD_B64_PLACEHOLDER: &str = "__DBEV_PASSWORD_B64__";
pub const AUTH_STRING_B64_PLACEHOLDER: &str = "__DBEV_AUTH_STRING_B64__";

#[derive(Debug, thiserror::Error)]
pub enum MysqlProvisionError {
    #[error("MySQL password SQL template is missing its protected placeholder")]
    MissingPasswordPlaceholder,
    #[error("MySQL authentication plugin name is invalid")]
    InvalidAuthenticationPlugin,
}

pub fn tenant_user_sql(database: &str, username: &str) -> String {
    build_tenant_user_sql(database, username, TenantAccess::Dedicated)
}

pub fn shared_tenant_user_sql(database: &str, username: &str) -> String {
    build_tenant_user_sql(database, username, TenantAccess::Shared)
}

#[derive(Clone, Copy)]
enum TenantAccess {
    Dedicated,
    Shared,
}

fn build_tenant_user_sql(database: &str, username: &str, access: TenantAccess) -> String {
    let database_ident = quote_identifier(database);
    let grant_database = quote_grant_db(database);
    let username_ident = quote_identifier(username);
    let account = format!("{username_ident}@'%' ");
    let create = quote_mysql_string(&format!(
        "CREATE USER IF NOT EXISTS {account}IDENTIFIED WITH caching_sha2_password BY "
    ));
    let alter = quote_mysql_string(&format!(
        "ALTER USER {account}IDENTIFIED WITH caching_sha2_password BY "
    ));
    let grants = match access {
        TenantAccess::Dedicated => {
            format!("GRANT ALL PRIVILEGES ON {grant_database}.* TO {username_ident}@'%';")
        }
        TenantAccess::Shared => mysql_shared_grant_sql(database, username),
    };

    format!(
        r#"
SET SESSION sql_log_bin = 0;
SET SESSION sql_log_off = 1;
CREATE DATABASE IF NOT EXISTS {database_ident};
SET @dbev_password = CONVERT(FROM_BASE64('{PASSWORD_B64_PLACEHOLDER}') USING utf8mb4);
SET @dbev_create = CONCAT({create}, QUOTE(@dbev_password));
PREPARE dbev_statement FROM @dbev_create;
EXECUTE dbev_statement;
DEALLOCATE PREPARE dbev_statement;
SET @dbev_alter = CONCAT({alter}, QUOTE(@dbev_password));
PREPARE dbev_statement FROM @dbev_alter;
EXECUTE dbev_statement;
DEALLOCATE PREPARE dbev_statement;
{grants}
SET @dbev_password = NULL;
SET @dbev_create = NULL;
SET @dbev_alter = NULL;
"#
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantQuota {
    pub max_queries_per_hour: u64,
    pub max_updates_per_hour: u64,
    pub max_connections_per_hour: u64,
    pub max_connections: u32,
}

pub fn tenant_quota_sql(username: &str, quota: TenantQuota) -> String {
    format!(
        "ALTER USER {}@'%' WITH MAX_QUERIES_PER_HOUR {} MAX_UPDATES_PER_HOUR {} MAX_CONNECTIONS_PER_HOUR {} MAX_USER_CONNECTIONS {};",
        quote_identifier(username),
        quota.max_queries_per_hour,
        quota.max_updates_per_hour,
        quota.max_connections_per_hour,
        quota.max_connections,
    )
}

pub fn reset_tenant_password_sql(username: &str) -> String {
    let username = quote_identifier(username);
    let alter = quote_mysql_string(&format!(
        "ALTER USER {username}@'%' IDENTIFIED WITH caching_sha2_password BY "
    ));
    format!(
        r#"
SET SESSION sql_log_bin = 0;
SET SESSION sql_log_off = 1;
SET @dbev_password = CONVERT(FROM_BASE64('{PASSWORD_B64_PLACEHOLDER}') USING utf8mb4);
SET @dbev_alter = CONCAT({alter}, QUOTE(@dbev_password));
PREPARE dbev_statement FROM @dbev_alter;
EXECUTE dbev_statement;
DEALLOCATE PREPARE dbev_statement;
SET @dbev_password = NULL;
SET @dbev_alter = NULL;
"#
    )
}

pub fn tenant_auth_state_sql(username: &str) -> String {
    format!(
        "SELECT CONCAT(plugin, CHAR(9), REPLACE(TO_BASE64(authentication_string), '\\n', '')) FROM mysql.user WHERE User = {} AND Host = '%';",
        quote_mysql_string(username),
    )
}

pub fn restore_tenant_auth_sql(
    username: &str,
    plugin: &str,
) -> Result<String, MysqlProvisionError> {
    if plugin.is_empty()
        || plugin.len() > 64
        || !plugin
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(MysqlProvisionError::InvalidAuthenticationPlugin);
    }
    let account = format!("{}@'%'", quote_identifier(username));
    let alter = quote_mysql_string(&format!(
        "ALTER USER {account} IDENTIFIED WITH {} AS ",
        quote_identifier(plugin),
    ));
    Ok(format!(
        r#"
SET SESSION sql_log_bin = 0;
SET SESSION sql_log_off = 1;
SET @dbev_auth_string = CONVERT(FROM_BASE64('{AUTH_STRING_B64_PLACEHOLDER}') USING ascii);
SET @dbev_alter = CONCAT({alter}, QUOTE(@dbev_auth_string));
PREPARE dbev_statement FROM @dbev_alter;
EXECUTE dbev_statement;
DEALLOCATE PREPARE dbev_statement;
SET @dbev_auth_string = NULL;
SET @dbev_alter = NULL;
"#
    ))
}

pub fn password_sql_fragments(sql: &str) -> Result<(&str, &str), MysqlProvisionError> {
    sql.split_once(PASSWORD_B64_PLACEHOLDER)
        .ok_or(MysqlProvisionError::MissingPasswordPlaceholder)
}

pub fn auth_string_sql_fragments(sql: &str) -> Result<(&str, &str), MysqlProvisionError> {
    sql.split_once(AUTH_STRING_B64_PLACEHOLDER)
        .ok_or(MysqlProvisionError::MissingPasswordPlaceholder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_provisioning_uses_one_protected_caching_sha2_password() {
        let sql = tenant_user_sql("app_db", "app_user");

        assert!(sql.contains("CREATE DATABASE IF NOT EXISTS `app_db`"));
        assert!(sql.contains("IDENTIFIED WITH caching_sha2_password BY"));
        assert!(sql.contains("GRANT ALL PRIVILEGES ON `app\\_db`.* TO `app_user`@'%'"));
        assert!(!sql.contains("REVOKE ALL PRIVILEGES"));
        assert!(sql.contains(PASSWORD_B64_PLACEHOLDER));
        assert!(!sql.contains("mysql_native_password"));
        let disable_binlog = sql.find("SET SESSION sql_log_bin = 0;").unwrap();
        let disable_general_log = sql.find("SET SESSION sql_log_off = 1;").unwrap();
        let password = sql.find("SET @dbev_password").unwrap();

        assert!(disable_binlog < password);
        assert!(disable_general_log < password);
        let (before, after) = password_sql_fragments(&sql).unwrap();

        assert!(!before.contains(PASSWORD_B64_PLACEHOLDER));
        assert!(!after.contains(PASSWORD_B64_PLACEHOLDER));
        assert_eq!(sql.matches(PASSWORD_B64_PLACEHOLDER).count(), 1);
    }

    #[test]
    fn shared_tenant_provisioning_uses_scoped_privileges() {
        let sql = shared_tenant_user_sql("app_db", "app_user");

        assert!(sql.contains("REVOKE ALL PRIVILEGES, GRANT OPTION"));
        assert!(sql.contains("GRANT SELECT, INSERT, UPDATE, DELETE"));
        assert!(sql.contains("ON `app\\_db`.* TO `app_user`@'%'"));
        assert!(!sql.contains("GRANT ALL PRIVILEGES"));
        assert!(!sql.contains("CREATE TEMPORARY TABLES"));
        assert!(!sql.contains("ACCOUNT UNLOCK"));
        for executable in [" EXECUTE", " CREATE ROUTINE", " ALTER ROUTINE", " TRIGGER"] {
            assert!(!sql.contains(executable));
        }
        assert_eq!(sql.matches("REVOKE ALL PRIVILEGES").count(), 1);
        assert_eq!(
            mysql_shared_grant_sql("app_db", "app_user"),
            sql.lines()
                .skip_while(|line| !line.starts_with("REVOKE ALL"))
                .take(2)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    #[test]
    fn reset_only_alters_the_existing_user() {
        let sql = reset_tenant_password_sql("app_user");

        assert!(sql.contains("IDENTIFIED WITH caching_sha2_password BY"));
        assert!(!sql.contains("CREATE DATABASE"));
        assert!(!sql.contains("CREATE USER"));
        assert!(!sql.contains("GRANT "));
    }

    #[test]
    fn captures_and_restores_existing_authentication_state_without_plaintext() {
        let capture = tenant_auth_state_sql("user'name");
        let restore = restore_tenant_auth_sql("user`name", "caching_sha2_password").unwrap();

        assert!(capture.contains("User = 'user''name'"));
        assert!(capture.contains("TO_BASE64(authentication_string)"));
        assert!(restore.contains("ALTER USER `user``name`@''%''"));
        assert!(restore.contains("`caching_sha2_password` AS"));
        assert!(restore.contains(AUTH_STRING_B64_PLACEHOLDER));
        assert!(!restore.contains("CREATE USER"));
    }

    #[test]
    fn rejects_untrusted_authentication_plugin_names() {
        assert!(restore_tenant_auth_sql("app", "plugin; DROP USER root").is_err());
    }

    #[test]
    fn quota_sql_stays_on_the_tenant_account() {
        for username in ["tenant_a", "tenant`quoted", "tenant'name"] {
            let quota = tenant_quota_sql(
                username,
                TenantQuota {
                    max_queries_per_hour: 20_000,
                    max_updates_per_hour: 5_000,
                    max_connections_per_hour: 1_000,
                    max_connections: 12,
                },
            );

            assert!(quota.contains("MAX_USER_CONNECTIONS 12"));
            assert!(!quota.contains("mysql.user SET"));
            assert!(!quota.contains("DROP USER root"));
            assert!(!quota.contains("SET GLOBAL"));
        }
    }

    #[test]
    fn shared_grants_never_cross_schema_boundaries() {
        let create = shared_tenant_user_sql("tenant_db", "tenant_user");

        assert!(create.contains("ON `tenant\\_db`.*"));
        assert!(!create.contains("ON *.*"));
        assert!(!create.contains("FILE"));
        assert!(!create.contains("PROCESS"));
        assert!(!create.contains("SUPER"));
        assert!(!create.contains("SYSTEM_USER"));
        assert!(!create.contains("GRANT OPTION TO"));
    }
}
