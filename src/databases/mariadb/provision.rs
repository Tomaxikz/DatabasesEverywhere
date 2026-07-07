#[derive(Debug, thiserror::Error)]
pub enum MariadbProvisionError {
    #[error("native password verifier must be 40 hexadecimal characters")]
    InvalidNativePasswordVerifier,
}

pub fn scoped_grant_sql(database: &str, username: &str) -> String {
    format!(
        "GRANT ALL PRIVILEGES ON `{}`.* TO `{}`@'%';",
        database.replace('`', "``"),
        username.replace('`', "``")
    )
}

pub fn tenant_user_sql(
    database: &str,
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

    let database = quote_identifier(database);
    let username = quote_identifier(username);
    let native_password_hash = format!("*{}", native_password_sha1_stage2_hex.to_ascii_uppercase());

    Ok(format!(
        r#"
CREATE DATABASE IF NOT EXISTS {database};
CREATE USER IF NOT EXISTS {username}@'%' IDENTIFIED BY PASSWORD '{native_password_hash}';
ALTER USER {username}@'%' IDENTIFIED BY PASSWORD '{native_password_hash}';
GRANT ALL PRIVILEGES ON {database}.* TO {username}@'%';
FLUSH PRIVILEGES;
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
    fn tenant_user_sql_uses_native_password_hash_without_plaintext() {
        let sql = tenant_user_sql(
            "app_db",
            "app_user",
            "0123456789abcdef0123456789abcdef01234567",
        )
        .unwrap();

        assert!(sql.contains("CREATE DATABASE IF NOT EXISTS `app_db`"));
        assert!(sql.contains("ALTER USER `app_user`@'%'"));
        assert!(sql.contains("*0123456789ABCDEF0123456789ABCDEF01234567"));
    }

    #[test]
    fn tenant_user_sql_rejects_invalid_hashes() {
        assert!(tenant_user_sql("db", "user", "not-a-hash").is_err());
    }
}
