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
    if native_password_sha1_stage2_hex.len() != 40
        || !native_password_sha1_stage2_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(MysqlProvisionError::InvalidNativePasswordVerifier);
    }

    let database = quote_identifier(database);
    let username = quote_identifier(username);
    let native_password_hash = format!("*{}", native_password_sha1_stage2_hex.to_ascii_uppercase());

    Ok(format!(
        r#"
CREATE DATABASE IF NOT EXISTS {database};
CREATE USER IF NOT EXISTS {username}@'%' IDENTIFIED WITH mysql_native_password AS '{native_password_hash}';
ALTER USER {username}@'%' IDENTIFIED WITH mysql_native_password AS '{native_password_hash}';
GRANT ALL PRIVILEGES ON {database}.* TO {username}@'%';
"#
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
    fn rejects_invalid_native_password_verifier() {
        assert!(tenant_user_sql("db", "user", "not-a-hash").is_err());
    }
}
