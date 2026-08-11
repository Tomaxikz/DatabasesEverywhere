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
    let database = quote_identifier(database);
    let username = quote_identifier(username);
    let account = format!("{username}@'%' ");
    let create = quote_sql_string(&format!(
        "CREATE USER IF NOT EXISTS {account}IDENTIFIED WITH caching_sha2_password BY "
    ));
    let alter = quote_sql_string(&format!(
        "ALTER USER {account}IDENTIFIED WITH caching_sha2_password BY "
    ));

    format!(
        r#"
SET SESSION sql_log_bin = 0;
SET SESSION sql_log_off = 1;
CREATE DATABASE IF NOT EXISTS {database};
SET @dbev_password = CONVERT(FROM_BASE64('{PASSWORD_B64_PLACEHOLDER}') USING utf8mb4);
SET @dbev_create = CONCAT({create}, QUOTE(@dbev_password));
PREPARE dbev_statement FROM @dbev_create;
EXECUTE dbev_statement;
DEALLOCATE PREPARE dbev_statement;
SET @dbev_alter = CONCAT({alter}, QUOTE(@dbev_password));
PREPARE dbev_statement FROM @dbev_alter;
EXECUTE dbev_statement;
DEALLOCATE PREPARE dbev_statement;
GRANT ALL PRIVILEGES ON {database}.* TO {username}@'%';
SET @dbev_password = NULL;
SET @dbev_create = NULL;
SET @dbev_alter = NULL;
"#
    )
}

pub fn reset_tenant_password_sql(username: &str) -> String {
    let username = quote_identifier(username);
    let alter = quote_sql_string(&format!(
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
        quote_sql_string(username),
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
    let alter = quote_sql_string(&format!(
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

fn quote_identifier(identifier: &str) -> String {
    format!("`{}`", identifier.replace('`', "``"))
}

fn quote_sql_string(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisions_with_caching_sha2_without_embedding_plaintext() {
        let sql = tenant_user_sql("app_db", "app_user");

        assert!(sql.contains("CREATE DATABASE IF NOT EXISTS `app_db`"));
        assert!(sql.contains("IDENTIFIED WITH caching_sha2_password BY"));
        assert!(sql.contains("GRANT ALL PRIVILEGES ON `app_db`.*"));
        assert!(sql.contains(PASSWORD_B64_PLACEHOLDER));
        assert!(!sql.contains("mysql_native_password"));
    }

    #[test]
    fn disables_logs_before_materializing_the_password() {
        let sql = tenant_user_sql("app_db", "app_user");
        let disable_binlog = sql.find("SET SESSION sql_log_bin = 0;").unwrap();
        let disable_general_log = sql.find("SET SESSION sql_log_off = 1;").unwrap();
        let password = sql.find("SET @dbev_password").unwrap();

        assert!(disable_binlog < password);
        assert!(disable_general_log < password);
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
    fn splits_the_single_protected_password_placeholder() {
        let sql = tenant_user_sql("app_db", "app_user");
        let (before, after) = password_sql_fragments(&sql).unwrap();

        assert!(!before.contains(PASSWORD_B64_PLACEHOLDER));
        assert!(!after.contains(PASSWORD_B64_PLACEHOLDER));
        assert_eq!(sql.matches(PASSWORD_B64_PLACEHOLDER).count(), 1);
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
}
