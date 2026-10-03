use std::io::Cursor;

use super::*;

fn validate(protocol: Protocol, sql: &str) -> Result<SharedSqlReport, SharedSqlError> {
    validate_shared_sql_reader(Cursor::new(sql.as_bytes()), protocol, "tenant_db")
}

fn validate_live(protocol: Protocol, sql: &str) -> Result<(), MysqlCommandPolicyError> {
    validate_shared_mysql_command(sql.as_bytes(), protocol)
}

#[test]
fn live_mysql_policy_keeps_normal_table_ddl_and_data_queries() {
    for protocol in [Protocol::Mysql, Protocol::Mariadb] {
        for sql in [
            "CREATE TABLE items(id BIGINT, note TEXT) ENGINE=InnoDB",
            "ALTER TABLE items ADD COLUMN value VARCHAR(255)",
            "DROP TABLE IF EXISTS items",
            "SELECT 'DROP DATABASE tenant_db', `tablespace` FROM items",
            "INSERT INTO items(note) VALUES ('DATA DIRECTORY=/tmp/not-syntax')",
        ] {
            validate_live(protocol, sql)
                .unwrap_or_else(|error| panic!("{protocol} rejected {sql:?}: {error}"));
        }
    }
}

#[test]
fn live_mysql_policy_rejects_database_and_storage_layout_changes() {
    for protocol in [Protocol::Mysql, Protocol::Mariadb] {
        for sql in [
            "CREATE DATABASE other",
            "CREATE OR REPLACE SCHEMA other",
            "ALTER DATABASE tenant_db CHARACTER SET utf8mb4",
            "DROP /* hidden */ DATABASE tenant_db",
            "RENAME DATABASE tenant_db TO other",
            "CREATE TABLE items(id BIGINT) TABLESPACE=innodb_system",
            "ALTER TABLE items TABLESPACE innodb_system",
            "CREATE TABLE items(id BIGINT) DATA DIRECTORY='/tmp/escape'",
            "CREATE TABLE items(id BIGINT) INDEX DIRECTORY='/tmp/escape'",
            "CREATE TABLE items(id BIGINT) ENGINE=CONNECT TABLE_TYPE=CSV FILE_NAME='/tmp/x'",
            "CREATE LOGFILE GROUP group_1 ADD UNDOFILE '/tmp/undo.dat' ENGINE=InnoDB",
            "IMPORT TABLE FROM '/tmp/table.sdi'",
            "/*!50100 DROP DATABASE tenant_db */",
            "/*! 50100 DROP DATABASE tenant_db */",
            "DROP /*!50100 DATABASE */ tenant_db",
            "CREATE TABLE items(id BIGINT) /*!50100 TABLESPACE innodb_system */",
            "CREATE TABLE items(id BIGINT) DATA /*!50100 DIRECTORY */='/tmp/escape'",
        ] {
            assert!(
                matches!(
                    validate_live(protocol, sql),
                    Err(MysqlCommandPolicyError::StorageEscape)
                ),
                "{protocol} accepted {sql:?}"
            );
        }
    }
}

#[test]
fn live_mysql_policy_rejects_sql_level_dynamic_execution() {
    for protocol in [Protocol::Mysql, Protocol::Mariadb] {
        for sql in [
            "PREPARE stmt FROM 'DROP DATABASE tenant_db'",
            "SET @sql='DROP DATABASE tenant_db'; PREPARE stmt FROM @sql; EXECUTE stmt",
            "EXECUTE IMMEDIATE 'DROP DATABASE tenant_db'",
            "/*!50000 PREPARE stmt FROM 'DROP DATABASE tenant_db' */",
        ] {
            assert!(
                matches!(
                    validate_live(protocol, sql),
                    Err(MysqlCommandPolicyError::DynamicSql)
                ),
                "{protocol} accepted {sql:?}"
            );
        }
    }
}

#[test]
fn accepts_bounded_tenant_only_dump_shapes() {
    for (protocol, sql) in [
        (
            Protocol::Postgres,
            "SET statement_timeout = 0; CREATE TABLE public.items(id bigint); CREATE VIEW public.item_view AS SELECT id FROM public.items; COPY public.items FROM STDIN;\n1\n\\.\n",
        ),
        (
            Protocol::Mysql,
            "USE tenant_db; CREATE TABLE tenant_db.items(id bigint) ENGINE=InnoDB; /*!50001 CREATE ALGORITHM=UNDEFINED */ /*!50013 DEFINER=`tenant_user`@`%` SQL SECURITY DEFINER */ /*!50001 VIEW `item_view` AS SELECT id FROM tenant_db.items */; INSERT INTO tenant_db.items VALUES (1);",
        ),
        (
            Protocol::Mariadb,
            "USE tenant_db; CREATE TABLE tenant_db.items(id bigint) ENGINE=ArChIvE; CREATE SQL SECURITY INVOKER VIEW item_view AS SELECT id FROM tenant_db.items; LOCK TABLES tenant_db.items WRITE; UNLOCK TABLES;",
        ),
        (
            Protocol::Clickhouse,
            "USE tenant_db; CREATE TABLE tenant_db.items(id UInt64) ENGINE = MergeTree ORDER BY id; CREATE VIEW tenant_db.item_view AS SELECT id FROM tenant_db.items; INSERT INTO tenant_db.items VALUES (1);",
        ),
    ] {
        let report = validate(protocol, sql).unwrap_or_else(|error| panic!("{protocol}: {error}"));
        assert!(report.statements_checked >= 2);
    }
}

#[test]
fn rejects_engine_level_database_creation() {
    for protocol in [Protocol::Mysql, Protocol::Mariadb, Protocol::Clickhouse] {
        let error = validate(protocol, "CREATE DATABASE tenant_db;").unwrap_err();
        assert_eq!(
            error.issue(),
            Some(SharedSqlIssue::PrivilegedStatement),
            "{protocol}"
        );
    }
}

#[test]
fn rejects_cross_database_and_system_namespaces() {
    for (protocol, sql, issue) in [
        (
            Protocol::Mysql,
            "INSERT INTO other.items VALUES (1);",
            SharedSqlIssue::CrossDatabase,
        ),
        (
            Protocol::Mariadb,
            "USE mysql;",
            SharedSqlIssue::SystemNamespace,
        ),
        (
            Protocol::Clickhouse,
            "CREATE TABLE system.items(id UInt8) ENGINE=Log;",
            SharedSqlIssue::SystemNamespace,
        ),
        (
            Protocol::Postgres,
            "DELETE FROM pg_catalog.pg_authid;",
            SharedSqlIssue::SystemNamespace,
        ),
        (
            Protocol::Postgres,
            "DROP TABLE pg_toast.pg_toast_123;",
            SharedSqlIssue::SystemNamespace,
        ),
        (
            Protocol::Mysql,
            "CREATE VIEW tenant_db.v AS SELECT id FROM other_db.items;",
            SharedSqlIssue::CrossDatabase,
        ),
    ] {
        assert_eq!(validate(protocol, sql).unwrap_err().issue(), Some(issue));
    }
}

#[test]
fn rejects_privilege_code_and_external_access_corpus() {
    for (protocol, sql, issue) in [
        (
            Protocol::Postgres,
            "COPY public.items FROM PROGRAM 'curl bad';",
            SharedSqlIssue::ExternalAccess,
        ),
        (
            Protocol::Postgres,
            "CREATE EXTENSION file_fdw;",
            SharedSqlIssue::PrivilegedStatement,
        ),
        (
            Protocol::Postgres,
            "ALTER TABLE public.items OWNER TO postgres;",
            SharedSqlIssue::PrivilegedStatement,
        ),
        (
            Protocol::Postgres,
            "ALTER SYSTEM SET shared_preload_libraries = 'evil';",
            SharedSqlIssue::PrivilegedStatement,
        ),
        (
            Protocol::Postgres,
            "CREATE TABLE public.copy AS SELECT * FROM public.source;",
            SharedSqlIssue::ExternalAccess,
        ),
        (
            Protocol::Mysql,
            "SELECT 1 INTO OUTFILE '/tmp/pwn';",
            SharedSqlIssue::ExternalAccess,
        ),
        (
            Protocol::Mysql,
            "CREATE FUNCTION pwn RETURNS STRING SONAME 'pwn.so';",
            SharedSqlIssue::ExternalAccess,
        ),
        (
            Protocol::Mysql,
            "CREATE TRIGGER pwn BEFORE INSERT ON items FOR EACH ROW SET @x = 1;",
            SharedSqlIssue::PrivilegedStatement,
        ),
        (
            Protocol::Mariadb,
            "CREATE EVENT pwn ON SCHEDULE EVERY 1 HOUR DO DELETE FROM items;",
            SharedSqlIssue::PrivilegedStatement,
        ),
        (
            Protocol::Mariadb,
            "SET GLOBAL general_log_file='/tmp/pwn';",
            SharedSqlIssue::PrivilegedStatement,
        ),
        (
            Protocol::Mysql,
            "DROP USER tenant_admin;",
            SharedSqlIssue::PrivilegedStatement,
        ),
        (
            Protocol::Mariadb,
            "LOCK TABLES other_db.items WRITE;",
            SharedSqlIssue::CrossDatabase,
        ),
        (
            Protocol::Clickhouse,
            "CREATE TABLE tenant_db.x(v String) ENGINE=File(CSV);",
            SharedSqlIssue::ExternalAccess,
        ),
        (
            Protocol::Clickhouse,
            "INSERT INTO tenant_db.x SELECT * FROM url('http://bad');",
            SharedSqlIssue::ExternalAccess,
        ),
        (
            Protocol::Clickhouse,
            "CREATE TABLE tenant_db.x AS file('secret.csv');",
            SharedSqlIssue::ExternalAccess,
        ),
        (
            Protocol::Clickhouse,
            "INSERT INTO FUNCTION file('leak.csv', CSV) VALUES (1);",
            SharedSqlIssue::ExternalAccess,
        ),
        (
            Protocol::Clickhouse,
            "CREATE TABLE tenant_db.x(id UInt64);",
            SharedSqlIssue::AmbiguousStatement,
        ),
        (
            Protocol::Clickhouse,
            "DROP USER tenant_admin;",
            SharedSqlIssue::PrivilegedStatement,
        ),
    ] {
        assert_eq!(
            validate(protocol, sql).unwrap_err().issue(),
            Some(issue),
            "{sql}"
        );
    }
}

#[test]
fn rejects_client_commands_and_executable_comments() {
    for sql in [
        "\\connect other\nCREATE TABLE public.x(id int);",
        "/*!40101 SET GLOBAL sql_mode='' */;",
    ] {
        assert!(validate(Protocol::Mysql, sql).is_err());
    }
    validate(
        Protocol::Mysql,
        "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;",
    )
    .unwrap();
}
