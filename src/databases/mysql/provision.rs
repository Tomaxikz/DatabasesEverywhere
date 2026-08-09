#[derive(Debug, thiserror::Error)]
pub enum MysqlProvisionError {
    #[error("native password verifier must be 40 hexadecimal characters")]
    InvalidNativePasswordVerifier,
}

pub fn tenant_user_sql(
    database: &str,
    username: &str,
    native_password_sha1_stage2_hex: &str,
) -> Result<String, MysqlProvisionError> {
    let database = quote_identifier(database);
    let username = quote_identifier(username);
    let native_password_hash = native_password_hash(native_password_sha1_stage2_hex)?;

    Ok(format!(
        r#"
SET SESSION sql_log_bin = 0;
CREATE DATABASE IF NOT EXISTS {database};
CREATE USER IF NOT EXISTS {username}@'%' IDENTIFIED WITH mysql_native_password AS '{native_password_hash}';
ALTER USER {username}@'%' IDENTIFIED WITH mysql_native_password AS '{native_password_hash}';
GRANT ALL PRIVILEGES ON {database}.* TO {username}@'%';
"#
    ))
}

pub fn reset_tenant_password_sql(
    username: &str,
    native_password_sha1_stage2_hex: &str,
) -> Result<String, MysqlProvisionError> {
    let username = quote_identifier(username);
    let native_password_hash = native_password_hash(native_password_sha1_stage2_hex)?;

    Ok(format!(
        r#"
SET SESSION sql_log_bin = 0;
ALTER USER {username}@'%' IDENTIFIED WITH mysql_native_password AS '{native_password_hash}';
"#
    ))
}

fn native_password_hash(
    native_password_sha1_stage2_hex: &str,
) -> Result<String, MysqlProvisionError> {
    if native_password_sha1_stage2_hex.len() != 40
        || !native_password_sha1_stage2_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(MysqlProvisionError::InvalidNativePasswordVerifier);
    }
    Ok(format!(
        "*{}",
        native_password_sha1_stage2_hex.to_ascii_uppercase()
    ))
}

fn quote_identifier(identifier: &str) -> String {
    format!("`{}`", identifier.replace('`', "``"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisions_only_the_requested_database_without_plaintext_password() {
        let sql = tenant_user_sql(
            "app_db",
            "app_user",
            "0123456789abcdef0123456789abcdef01234567",
        )
        .unwrap();

        assert!(sql.contains("CREATE DATABASE IF NOT EXISTS `app_db`"));
        assert!(sql.contains("IDENTIFIED WITH mysql_native_password AS"));
        assert!(sql.contains("GRANT ALL PRIVILEGES ON `app_db`.*"));
        assert!(sql.contains("*0123456789ABCDEF0123456789ABCDEF01234567"));
    }

    #[test]
    fn disables_binary_logging_before_account_ddl() {
        let sql = tenant_user_sql(
            "app_db",
            "app_user",
            "0123456789abcdef0123456789abcdef01234567",
        )
        .unwrap();

        let disable_binlog = sql.find("SET SESSION sql_log_bin = 0;").unwrap();
        let create_database = sql.find("CREATE DATABASE").unwrap();
        let create_user = sql.find("CREATE USER").unwrap();
        let alter_user = sql.find("ALTER USER").unwrap();
        let grant = sql.find("GRANT ALL PRIVILEGES").unwrap();

        assert!(disable_binlog < create_database);
        assert!(disable_binlog < create_user);
        assert!(disable_binlog < alter_user);
        assert!(disable_binlog < grant);
    }

    #[test]
    fn password_reset_disables_binary_logging_and_only_alters_the_existing_user() {
        let sql = reset_tenant_password_sql("app_user", "0123456789abcdef0123456789abcdef01234567")
            .unwrap();

        assert!(sql.trim_start().starts_with("SET SESSION sql_log_bin = 0;"));
        assert!(sql.contains(
            "ALTER USER `app_user`@'%' IDENTIFIED WITH mysql_native_password AS \
             '*0123456789ABCDEF0123456789ABCDEF01234567';"
        ));
        assert!(!sql.contains("CREATE DATABASE"));
        assert!(!sql.contains("CREATE USER"));
        assert!(!sql.contains("GRANT "));
    }

    #[test]
    fn rejects_invalid_native_password_verifier() {
        assert!(tenant_user_sql("db", "user", "not-a-hash").is_err());
        assert!(reset_tenant_password_sql("user", "not-a-hash").is_err());
    }
}
