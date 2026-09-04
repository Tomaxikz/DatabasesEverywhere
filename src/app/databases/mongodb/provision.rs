/// Creates or repairs one database-scoped tenant account. The password is
/// read from the managed exec environment so neither tenant nor administrator
/// credentials appear in process argv.
pub fn create_tenant_script(
    database: &str,
    username: &str,
) -> Result<String, MongodbProvisionError> {
    validate_identifier("database", database)?;
    validate_identifier("username", username)?;

    Ok(format!(
        r#"
const database = {database};
const username = {username};
const password = process.env.DBE_TENANT_PASSWORD;

if (typeof password !== "string" || password.length === 0) {{
  throw new Error("DBE_TENANT_PASSWORD is unavailable");
}}
db = db.getSiblingDB(database);
const user = db.getUser(username);
if (user === null) {{
  db.createUser({{
    user: username,
    pwd: password,
    roles: [{{ role: "readWrite", db: database }}]
  }});
}} else {{
  db.updateUser(username, {{
    pwd: password,
    roles: [{{ role: "readWrite", db: database }}]
  }});
}}
"#,
        database = serde_json::to_string(database)?,
        username = serde_json::to_string(username)?,
    ))
}

/// Runs a daemon-generated maintenance script through an authenticated local
/// connection without placing the administrator password in `mongosh` argv.
/// The caller supplies `DBE_ADMIN_PASSWORD` through the managed secret env.
pub fn admin_script(script: &str) -> String {
    format!(
        r#"
const adminPassword = process.env.DBE_ADMIN_PASSWORD;
if (typeof adminPassword !== "string" || adminPassword.length === 0) {{
  throw new Error("DBE_ADMIN_PASSWORD is unavailable");
}}
const adminUri = "mongodb://{admin_user}:" + encodeURIComponent(adminPassword)
  + "@127.0.0.1/admin?authSource=admin&directConnection=true";
const adminConnection = new Mongo(adminUri);
db = adminConnection.getDB("admin");
{script}
"#,
        admin_user = crate::databases::mongodb::docker::INTERNAL_ROOT_USERNAME,
    )
}

pub fn fence_tenant_script(
    database: &str,
    username: &str,
) -> Result<String, MongodbProvisionError> {
    tenant_roles_script(database, username, &[])
}

pub fn unfence_tenant_script(
    database: &str,
    username: &str,
) -> Result<String, MongodbProvisionError> {
    tenant_roles_script(database, username, &["readWrite"])
}

fn tenant_roles_script(
    database: &str,
    username: &str,
    roles: &[&str],
) -> Result<String, MongodbProvisionError> {
    validate_identifier("database", database)?;
    validate_identifier("username", username)?;
    let roles = roles
        .iter()
        .map(|role| serde_json::json!({ "role": role, "db": database }))
        .collect::<Vec<_>>();
    Ok(format!(
        "const database = {};\nconst username = {};\ndb = db.getSiblingDB(database);\ndb.updateUser(username, {{ roles: {} }});\n",
        serde_json::to_string(database)?,
        serde_json::to_string(username)?,
        serde_json::to_string(&roles)?,
    ))
}

pub fn terminate_tenant_script(
    database: &str,
    username: &str,
) -> Result<String, MongodbProvisionError> {
    validate_identifier("database", database)?;
    validate_identifier("username", username)?;
    Ok(format!(
        "db = db.getSiblingDB(\"admin\");\ndb.runCommand({{ killAllSessions: [{{ user: {}, db: {} }}] }});\n",
        serde_json::to_string(username)?,
        serde_json::to_string(database)?,
    ))
}

pub fn drop_tenant_script(database: &str, username: &str) -> Result<String, MongodbProvisionError> {
    validate_identifier("database", database)?;
    validate_identifier("username", username)?;
    Ok(format!(
        "const database = {};\nconst username = {};\ndb = db.getSiblingDB(database);\nif (db.getUser(username) !== null) {{ db.dropUser(username); }}\ndb.dropDatabase();\n",
        serde_json::to_string(database)?,
        serde_json::to_string(username)?,
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantQuota {
    pub max_connections: u32,
    pub max_operation_time_ms: u64,
    pub storage_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantQuotaPolicy {
    /// MongoDB Community has no native per-database CPU, memory, connection,
    /// or storage quota. These limits must be enforced by the gateway,
    /// scheduler, and logical disk scanner instead of being represented as a
    /// server-side guarantee.
    pub engine_enforced: bool,
    pub quota: TenantQuota,
}

pub fn tenant_quota_policy(quota: TenantQuota) -> TenantQuotaPolicy {
    TenantQuotaPolicy {
        engine_enforced: false,
        quota,
    }
}

/// Emits one integer byte count per database, in input order. MongoDB's
/// `totalSize` is allocated document plus index storage, including reusable
/// free space, which is the conservative tenant quota measurement.
pub fn tenant_storage_script(databases: &[&str]) -> Result<String, MongodbProvisionError> {
    for database in databases {
        validate_identifier("database", database)?;
    }
    let databases = serde_json::to_string(databases)?;
    Ok(format!(
        r#"
const tenantDatabases = {databases};
for (const database of tenantDatabases) {{
  const stats = db.getSiblingDB(database).runCommand({{ dbStats: 1, scale: 1 }});
  if (stats.ok !== 1) {{
    throw new Error("dbStats failed for a managed tenant database");
  }}
  print(Math.trunc(Number(stats.totalSize || 0)));
}}
"#,
    ))
}

/// Builds a tenant password rotation script which reads the replacement
/// password from the managed container environment. Keeping the password out
/// of generated JavaScript also keeps it out of diagnostics and test output.
pub fn password_update_script(
    database: &str,
    username: &str,
) -> Result<String, MongodbProvisionError> {
    validate_identifier("database", database)?;
    validate_identifier("username", username)?;

    Ok(format!(
        r#"
const database = {database};
const username = {username};
const password = process.env.DBE_ROTATED_PASSWORD;

if (typeof password !== "string" || password.length === 0) {{
  throw new Error("DBE_ROTATED_PASSWORD is unavailable");
}}
db = db.getSiblingDB(database);
db.updateUser(username, {{ pwd: password }});
"#,
        database = serde_json::to_string(database)?,
        username = serde_json::to_string(username)?,
    ))
}

pub fn create_root_user_script(username: &str) -> Result<String, MongodbProvisionError> {
    validate_identifier("username", username)?;

    Ok(format!(
        r#"
const username = {username};
const password = process.env.DBE_MONGO_ROOT_PASSWORD;

if (typeof password !== "string" || password.length === 0) {{
  throw new Error("DBE_MONGO_ROOT_PASSWORD is unavailable");
}}

db = db.getSiblingDB("admin");
db.createUser({{
  user: username,
  pwd: password,
  roles: [{{ role: "root", db: "admin" }}]
}});
"#,
        username = serde_json::to_string(username)?,
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
    fn generated_user_scripts_scope_roles_and_keep_passwords_out_of_commands() {
        let script = create_root_user_script("dbe_root").unwrap();

        assert!(script.contains("getSiblingDB(\"admin\")"));
        assert!(script.contains("root"));
        assert!(script.contains("dbe_root"));
        assert!(script.contains("process.env.DBE_MONGO_ROOT_PASSWORD"));
        assert!(!script.contains("secret"));

        let script = password_update_script("mongo_1", "app_mongo_1").unwrap();

        assert!(script.contains("db.updateUser"));
        assert!(script.contains("process.env.DBE_ROTATED_PASSWORD"));
        assert!(!script.contains("secret"));

        let script = create_tenant_script("mongo_1", "app_mongo_1").unwrap();

        assert!(script.contains("process.env.DBE_TENANT_PASSWORD"));
        assert!(!script.contains("process.env.DBE_ADMIN_PASSWORD"));
        assert!(script.contains("getSiblingDB(database)"));
        assert!(script.contains("readWrite"));
        assert!(script.contains("mongo_1"));
        assert!(script.contains("app_mongo_1"));
        assert!(!script.contains("secret"));
        assert!(!script.contains("readAnyDatabase"));

        let script = admin_script("db.adminCommand({ ping: 1 });");
        assert!(script.contains("process.env.DBE_ADMIN_PASSWORD"));
        assert!(script.contains("encodeURIComponent(adminPassword)"));
        assert!(script.contains("db.adminCommand({ ping: 1 });"));
    }

    #[test]
    fn rejects_identifier_with_dot() {
        let error = validate_identifier("database", "bad.name").unwrap_err();

        assert!(matches!(
            error,
            MongodbProvisionError::InvalidIdentifier { .. }
        ));
    }

    #[test]
    fn lifecycle_scripts_are_database_and_user_scoped() {
        for (database, username) in [("tenant_a", "user_a"), ("tenant-b", "user-b")] {
            let fence = fence_tenant_script(database, username).unwrap();
            let unfence = unfence_tenant_script(database, username).unwrap();
            let terminate = terminate_tenant_script(database, username).unwrap();
            let drop = drop_tenant_script(database, username).unwrap();

            assert!(fence.contains("roles: []"));
            assert!(unfence.contains("readWrite"));
            assert!(terminate.contains("killAllSessions"));
            assert!(terminate.contains(username));
            assert!(terminate.contains(database));
            assert!(drop.contains("db.dropDatabase()"));
            for script in [fence, unfence, terminate, drop] {
                assert!(!script.contains("dropAllUsers"));
                assert!(!script.contains("readAnyDatabase"));
                assert!(!script.contains("userAdmin"));
                assert!(!script.contains("clusterAdmin"));
            }
        }
    }

    #[test]
    fn quota_policy_does_not_claim_native_enforcement() {
        let policy = tenant_quota_policy(TenantQuota {
            max_connections: 8,
            max_operation_time_ms: 30_000,
            storage_bytes: 10 * 1024 * 1024 * 1024,
        });

        assert!(!policy.engine_enforced);
        assert_eq!(policy.quota.max_connections, 8);
        assert_eq!(policy.quota.max_operation_time_ms, 30_000);
    }

    #[test]
    fn storage_script_uses_database_total_size_in_input_order() {
        let script = tenant_storage_script(&["tenant_a", "tenant-b"]).unwrap();

        assert!(script.contains(r#"["tenant_a","tenant-b"]"#));
        assert!(script.contains("runCommand({ dbStats: 1, scale: 1 })"));
        assert!(script.contains("stats.totalSize"));
        assert!(!script.contains("fsUsedSize"));
        assert!(tenant_storage_script(&["bad.name"]).is_err());
    }
}
