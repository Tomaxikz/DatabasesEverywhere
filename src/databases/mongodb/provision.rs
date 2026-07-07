use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CreateUserCommand<'a> {
    pub create_user: &'a str,
    pub pwd: &'a str,
    pub roles: Vec<MongoRole<'a>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MongoRole<'a> {
    pub role: &'a str,
    pub db: &'a str,
}

pub fn scoped_user_command<'a>(
    database: &'a str,
    username: &'a str,
    password: &'a str,
) -> CreateUserCommand<'a> {
    CreateUserCommand {
        create_user: username,
        pwd: password,
        roles: vec![MongoRole {
            role: "readWrite",
            db: database,
        }],
    }
}

pub fn create_user_script(
    database: &str,
    username: &str,
    password: &str,
) -> Result<String, MongodbProvisionError> {
    validate_identifier("database", database)?;
    validate_identifier("username", username)?;

    Ok(format!(
        r#"
const database = {database};
const username = {username};
const password = {password};

db = db.getSiblingDB(database);
db.createUser({{
  user: username,
  pwd: password,
  roles: [{{ role: "readWrite", db: database }}]
}});
"#,
        database = serde_json::to_string(database)?,
        username = serde_json::to_string(username)?,
        password = serde_json::to_string(password)?,
    ))
}

pub fn create_root_user_script(
    username: &str,
    password: &str,
) -> Result<String, MongodbProvisionError> {
    validate_identifier("username", username)?;

    Ok(format!(
        r#"
const username = {username};
const password = {password};

db = db.getSiblingDB("admin");
db.createUser({{
  user: username,
  pwd: password,
  roles: [{{ role: "root", db: "admin" }}]
}});
"#,
        username = serde_json::to_string(username)?,
        password = serde_json::to_string(password)?,
    ))
}

fn validate_identifier(kind: &'static str, value: &str) -> Result<(), MongodbProvisionError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(MongodbProvisionError::InvalidIdentifier {
            kind,
            value: value.to_string(),
        });
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum MongodbProvisionError {
    #[error("{kind} contains unsupported characters: {value}")]
    InvalidIdentifier { kind: &'static str, value: String },
    #[error("failed to encode mongodb init script json: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoped_user_command_uses_read_write_on_database() {
        let command = scoped_user_command("mongo_1", "app_mongo_1", "secret");

        assert_eq!(command.roles[0].role, "readWrite");
        assert_eq!(command.roles[0].db, "mongo_1");
    }

    #[test]
    fn create_user_script_creates_scoped_database_user() {
        let script = create_user_script("mongo_1", "app_mongo_1", "secret").unwrap();

        assert!(!script.contains("getUser"));
        assert!(!script.contains("usersInfo"));
        assert!(script.contains("readWrite"));
        assert!(script.contains("mongo_1"));
        assert!(script.contains("app_mongo_1"));
    }

    #[test]
    fn create_root_user_script_creates_admin_root_user() {
        let script = create_root_user_script("dbe_root", "secret").unwrap();

        assert!(script.contains("getSiblingDB(\"admin\")"));
        assert!(script.contains("root"));
        assert!(script.contains("dbe_root"));
    }

    #[test]
    fn rejects_identifier_with_dot() {
        let error = validate_identifier("database", "bad.name").unwrap_err();

        assert!(matches!(
            error,
            MongodbProvisionError::InvalidIdentifier { .. }
        ));
    }
}
