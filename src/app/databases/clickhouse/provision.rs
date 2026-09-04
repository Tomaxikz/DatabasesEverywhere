pub const PASSWORD_SQL_PLACEHOLDER: &str = "__DBEV_CLICKHOUSE_PASSWORD_LITERAL__";

#[derive(Debug, thiserror::Error)]
pub enum ClickhouseProvisionError {
    #[error("ClickHouse password SQL template is missing its protected placeholder")]
    MissingPasswordPlaceholder,
}

pub fn create_tenant_sql(database: &str, username: &str) -> String {
    let role = tenant_role_ident(username);
    let database = quote_ident(database);
    let username = quote_ident(username);

    let grants = shared_grant_sql_quoted(&database, &role);
    format!(
        r#"CREATE DATABASE IF NOT EXISTS {database} ENGINE = Atomic;
CREATE OR REPLACE ROLE {role};
{grants}
GRANT TABLE ENGINE ON MergeTree TO {role};
GRANT TABLE ENGINE ON ReplacingMergeTree TO {role};
GRANT TABLE ENGINE ON SummingMergeTree TO {role};
GRANT TABLE ENGINE ON AggregatingMergeTree TO {role};
GRANT TABLE ENGINE ON CollapsingMergeTree TO {role};
GRANT TABLE ENGINE ON VersionedCollapsingMergeTree TO {role};
GRANT TABLE ENGINE ON Log TO {role};
GRANT TABLE ENGINE ON TinyLog TO {role};
GRANT TABLE ENGINE ON StripeLog TO {role};
CREATE USER IF NOT EXISTS {username} NOT IDENTIFIED HOST NONE;
ALTER USER {username} IDENTIFIED WITH sha256_password BY {PASSWORD_SQL_PLACEHOLDER} HOST LOCAL DEFAULT DATABASE {database};
GRANT {role} TO {username} WITH REPLACE OPTION;
ALTER USER {username} DEFAULT ROLE {role};"#,
    )
}

/// Replaces database-scoped role privileges with the import-safe profile.
/// View privileges remain part of the profile; destructive imports separately
/// prove that the generated rollback stream can replay every current view.
pub fn shared_grant_sql(database: &str, username: &str) -> String {
    shared_grant_sql_quoted(&quote_ident(database), &tenant_role_ident(username))
}

fn shared_grant_sql_quoted(database: &str, role: &str) -> String {
    format!(
        "REVOKE ALL ON {database}.* FROM {role};\nGRANT SELECT, INSERT, ALTER UPDATE, ALTER DELETE, ALTER COLUMN, ALTER INDEX, ALTER CONSTRAINT, ALTER TTL, CREATE TABLE, CREATE VIEW, DROP VIEW, TRUNCATE, OPTIMIZE ON {database}.* TO {role};"
    )
}

pub fn fence_tenant_sql(username: &str) -> String {
    format!("ALTER USER {} HOST NONE;", quote_ident(username))
}

pub fn unfence_tenant_sql(username: &str) -> String {
    format!("ALTER USER {} HOST LOCAL;", quote_ident(username))
}

pub fn reset_tenant_password_sql(username: &str) -> String {
    format!(
        "ALTER USER {} IDENTIFIED WITH sha256_password BY {PASSWORD_SQL_PLACEHOLDER};",
        quote_ident(username),
    )
}

pub fn terminate_tenant_sql(username: &str) -> String {
    format!("KILL QUERY WHERE user = {} SYNC;", quote_literal(username),)
}

/// Returns one on-disk byte count per database, in input order. Live table
/// bytes and detached MergeTree parts are both charged to their owning tenant.
/// Whole-table detach is not granted because a detached table disappears from
/// both catalogs while its files remain on disk.
pub fn tenant_storage_sql(databases: &[&str]) -> String {
    databases
        .iter()
        .map(|database| {
            format!(
                "SELECT live.bytes + detached.bytes\nFROM\n    (SELECT coalesce(sum(total_bytes), 0) AS bytes FROM system.tables WHERE database = {database}) AS live\nCROSS JOIN\n    (SELECT coalesce(sum(bytes_on_disk), 0) AS bytes FROM system.detached_parts WHERE database = {database}) AS detached\nFORMAT TSVRaw;",
                database = quote_literal(database)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn drop_tenant_sql(database: &str, username: &str) -> String {
    let database = quote_ident(database);
    let username_ident = quote_ident(username);
    let role = tenant_role_ident(username);
    let profile = tenant_profile_ident(username);
    let quota = tenant_quota_ident(username);
    format!(
        "{}\nDROP USER IF EXISTS {username_ident};\nDROP QUOTA IF EXISTS {quota};\nDROP SETTINGS PROFILE IF EXISTS {profile};\nDROP ROLE IF EXISTS {role};\nDROP DATABASE IF EXISTS {database};",
        terminate_tenant_sql(username),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantQuota {
    pub max_memory_bytes: u64,
    pub max_threads: u32,
    pub max_execution_time_seconds: u64,
    pub max_result_bytes: u64,
    pub max_temp_bytes: u64,
    pub max_queries_per_hour: u64,
    pub max_read_bytes_per_hour: u64,
    pub max_written_bytes_per_hour: u64,
}

pub fn tenant_quota_sql(username: &str, quota: TenantQuota) -> String {
    let role = tenant_role_ident(username);
    let profile = tenant_profile_ident(username);
    let quota_name = tenant_quota_ident(username);
    format!(
        r#"CREATE OR REPLACE SETTINGS PROFILE {profile} SETTINGS
    max_memory_usage = {} CONST,
    max_threads = {} CONST,
    max_execution_time = {} CONST,
    max_result_bytes = {} CONST,
    max_temporary_data_on_disk_size_for_query = {} CONST,
    allow_introspection_functions = 0 CONST,
    log_queries = 1 CONST,
    log_queries_probability = 1 CONST,
    log_queries_min_query_duration_ms = 0 CONST,
    log_queries_min_type = 'QUERY_FINISH' CONST,
    log_queries_cut_to_length = 1024 CONST,
    log_comment = '' CONST,
    log_formatted_queries = 0 CONST,
    max_query_size = 262144 CONST,
    log_profile_events = 1 CONST,
    log_query_settings = 0 CONST,
    log_query_threads = 0 CONST,
    log_query_views = 0 CONST,
    log_processors_profiles = 0 CONST
TO {role};
CREATE OR REPLACE QUOTA {quota_name} KEYED BY user_name
    FOR INTERVAL 1 hour MAX queries = {}, read_bytes = {}, written_bytes = {}
TO {role};"#,
        quota.max_memory_bytes,
        quota.max_threads,
        quota.max_execution_time_seconds,
        quota.max_result_bytes,
        quota.max_temp_bytes,
        quota.max_queries_per_hour,
        quota.max_read_bytes_per_hour,
        quota.max_written_bytes_per_hour,
    )
}

pub fn password_sql_fragments(sql: &str) -> Result<(&str, &str), ClickhouseProvisionError> {
    sql.split_once(PASSWORD_SQL_PLACEHOLDER)
        .ok_or(ClickhouseProvisionError::MissingPasswordPlaceholder)
}

/// Escapes a password for the protected stdin writer. Callers must never put
/// this value in command arguments or diagnostics.
pub fn password_literal(password: &str) -> String {
    quote_literal(password)
}

fn tenant_role_ident(username: &str) -> String {
    quote_ident(&format!("dbev_role_{username}"))
}

fn tenant_profile_ident(username: &str) -> String {
    quote_ident(&format!("dbev_profile_{username}"))
}

fn tenant_quota_ident(username: &str) -> String {
    quote_ident(&format!("dbev_quota_{username}"))
}

pub(crate) fn quote_ident(value: &str) -> String {
    format!(
        "`{}`",
        value
            .replace('\\', "\\\\")
            .replace('`', "\\`")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    )
}

fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creation_uses_one_protected_password_and_explicit_local_grants() {
        for (database, username) in [("tenant_a", "user_a"), ("db`quoted", "user`quoted")] {
            let sql = create_tenant_sql(database, username);

            assert_eq!(sql.matches(PASSWORD_SQL_PLACEHOLDER).count(), 1);
            assert!(sql.contains("HOST LOCAL"));
            assert!(sql.contains("DEFAULT DATABASE"));
            assert!(sql.contains("GRANT SELECT, INSERT, ALTER UPDATE"));
            assert!(sql.contains("ALTER DELETE"));
            assert!(sql.contains("ALTER COLUMN"));
            assert!(sql.contains("TABLE ENGINE ON MergeTree"));
            assert!(!sql.contains("GRANT ALL"));
            assert!(!sql.contains(", ALTER,"));
            assert!(!sql.contains("DROP TABLE"));
            assert!(!sql.contains("ALTER SETTINGS"));
            assert!(!sql.contains("ALTER MOVE PARTITION"));
            assert!(!sql.contains("ALTER FETCH PARTITION"));
            assert!(!sql.contains("ALTER FREEZE PARTITION"));
            assert!(!sql.contains("ACCESS MANAGEMENT"));
            assert!(!sql.contains(" ON *.* TO"));
            assert!(!sql.contains("SOURCES"));
            assert!(!sql.contains("FILE ON"));
            assert!(!sql.contains("URL ON"));
            assert!(!sql.contains("S3 ON"));
            assert!(!sql.contains("REMOTE ON"));
            assert!(!sql.contains("Executable"));
            assert!(sql.contains("CREATE VIEW"));
            assert!(sql.contains("DROP VIEW"));
            assert!(sql.contains(&shared_grant_sql(database, username)));
            let (before, after) = password_sql_fragments(&sql).unwrap();
            assert!(!before.contains(PASSWORD_SQL_PLACEHOLDER));
            assert!(!after.contains(PASSWORD_SQL_PLACEHOLDER));
        }
    }

    #[test]
    fn storage_measurement_includes_detached_parts() {
        let sql = tenant_storage_sql(&["tenant_a", "tenant'b"]);

        assert_eq!(sql.matches("FROM system.tables").count(), 2);
        assert_eq!(sql.matches("FROM system.detached_parts").count(), 2);
        assert_eq!(sql.matches("FORMAT TSVRaw").count(), 2);
        assert!(sql.contains("database = 'tenant_a'"));
        assert!(sql.contains("database = 'tenant\\'b'"));
    }

    #[test]
    fn tenant_cannot_disable_shared_pool_accounting() {
        let sql = tenant_quota_sql(
            "tenant-a",
            TenantQuota {
                max_memory_bytes: 1,
                max_threads: 1,
                max_execution_time_seconds: 1,
                max_result_bytes: 1,
                max_temp_bytes: 1,
                max_queries_per_hour: 1,
                max_read_bytes_per_hour: 1,
                max_written_bytes_per_hour: 1,
            },
        );

        for setting in [
            "log_queries = 1 CONST",
            "log_queries_probability = 1 CONST",
            "log_queries_min_query_duration_ms = 0 CONST",
            "log_queries_min_type = 'QUERY_FINISH' CONST",
            "log_queries_cut_to_length = 1024 CONST",
            "log_comment = '' CONST",
            "log_formatted_queries = 0 CONST",
            "max_query_size = 262144 CONST",
            "log_profile_events = 1 CONST",
            "log_query_settings = 0 CONST",
            "log_query_threads = 0 CONST",
            "log_query_views = 0 CONST",
            "log_processors_profiles = 0 CONST",
        ] {
            assert!(sql.contains(setting), "missing immutable {setting}");
        }
    }

    #[test]
    fn lifecycle_operations_target_only_the_tenant_access_entities() {
        for (database, username) in [("tenant_a", "user_a"), ("db`quoted", "user'quoted")] {
            let fence = fence_tenant_sql(username);
            let unfence = unfence_tenant_sql(username);
            let terminate = terminate_tenant_sql(username);
            let drop = drop_tenant_sql(database, username);

            assert!(fence.contains("HOST NONE"));
            assert!(unfence.contains("HOST LOCAL"));
            assert!(terminate.contains(&quote_literal(username)));
            assert!(drop.contains(&quote_ident(database)));
            for sql in [fence, unfence, terminate, drop] {
                assert!(!sql.contains("DROP USER default"));
                assert!(!sql.contains("DROP DATABASE system"));
                assert!(!sql.contains("KILL QUERY WHERE 1"));
                assert!(!sql.contains("ON CLUSTER"));
            }
        }
    }

    #[test]
    fn quota_profile_is_role_scoped_and_const() {
        let sql = tenant_quota_sql(
            "tenant_user",
            TenantQuota {
                max_memory_bytes: 512 * 1024 * 1024,
                max_threads: 2,
                max_execution_time_seconds: 30,
                max_result_bytes: 64 * 1024 * 1024,
                max_temp_bytes: 256 * 1024 * 1024,
                max_queries_per_hour: 20_000,
                max_read_bytes_per_hour: 100 * 1024 * 1024 * 1024,
                max_written_bytes_per_hour: 20 * 1024 * 1024 * 1024,
            },
        );

        assert!(sql.contains("max_memory_usage = 536870912 CONST"));
        assert!(sql.contains("max_threads = 2 CONST"));
        assert!(sql.contains("allow_introspection_functions = 0 CONST"));
        assert!(sql.contains("KEYED BY user_name"));
        assert!(sql.contains("TO `dbev_role_tenant_user`"));
        assert!(!sql.contains("TO ALL"));
        assert!(!sql.contains("ON CLUSTER"));
    }

    #[test]
    fn password_literal_escapes_quotes_and_backslashes() {
        assert_eq!(password_literal("a'b\\c"), "'a\\'b\\\\c'");
    }

    #[test]
    fn password_reset_changes_only_the_selected_account() {
        let sql = reset_tenant_password_sql("tenant_user");
        assert_eq!(
            sql,
            "ALTER USER `tenant_user` IDENTIFIED WITH sha256_password BY __DBEV_CLICKHOUSE_PASSWORD_LITERAL__;"
        );
        assert_eq!(
            password_sql_fragments(&sql).unwrap().0,
            "ALTER USER `tenant_user` IDENTIFIED WITH sha256_password BY "
        );
    }

    #[test]
    fn identifiers_use_clickhouse_backslash_escaping() {
        assert_eq!(quote_ident("a`b\\c\nd"), "`a\\`b\\\\c\\nd`");
    }

    #[test]
    fn storage_queries_cover_every_table_engine_per_database() {
        let sql = tenant_storage_sql(&["tenant_a", "db'name"]);
        let queries = sql
            .split(';')
            .map(str::trim)
            .filter(|query| !query.is_empty())
            .collect::<Vec<_>>();

        assert_eq!(queries.len(), 2);
        assert!(queries[0].contains("WHERE database = 'tenant_a'"));
        assert!(queries[1].contains("WHERE database = 'db\\'name'"));
        assert!(
            queries
                .iter()
                .all(|query| query.contains("sum(total_bytes)"))
        );
    }
}
