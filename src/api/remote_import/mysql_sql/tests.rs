use std::io::Cursor;

use super::*;

type RewriteCase<'a> = (&'a str, &'a [u8], &'a str, &'a str, &'a [u8]);

fn rewrite_bytes(
    input: &[u8],
    source_database: &str,
    target_database: &str,
) -> Result<Vec<u8>, MysqlSqlRewriteError> {
    rewrite_bytes_with_limit(
        input,
        source_database,
        target_database,
        u64::try_from(input.len())
            .unwrap_or(u64::MAX)
            .saturating_add(4096)
            .max(1),
    )
}

fn rewrite_bytes_with_limit(
    input: &[u8],
    source_database: &str,
    target_database: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, MysqlSqlRewriteError> {
    validate_database_name(source_database, "source database")?;
    validate_database_name(target_database, "target database")?;
    if u64::try_from(input.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(MysqlSqlRewriteError::InputLimit { limit: max_bytes });
    }
    if source_database == target_database {
        return Ok(input.to_vec());
    }
    let mut reader = BoundedInput::new(
        Cursor::new(input),
        max_bytes,
        Instant::now() + Duration::from_secs(30),
    );
    let mut rewritten = Vec::new();
    {
        let mut writer = BoundedOutput::new(&mut rewritten, max_bytes);
        let mut context = SqlContext::default();
        let quoted_target_database = quote_identifier(target_database.as_bytes(), b'`');
        let double_quoted_target_database = quote_identifier(target_database.as_bytes(), b'"');
        let identifiers = RewriteIdentifiers {
            source_database: source_database.as_bytes(),
            quoted_target_database: &quoted_target_database,
            double_quoted_target_database: &double_quoted_target_database,
        };
        rewrite_sql(&mut reader, &mut writer, &identifiers, &mut context, false)?;
        writer.flush()?;
    }
    Ok(rewritten)
}

#[test]
fn rewrites_supported_sql_contexts_without_touching_literals() {
    let cases: &[RewriteCase<'_>] = &[
        (
            "qualifiers and ordinary comments",
            br#"INSERT INTO `source_db`.`events` VALUES
  ('`source_db`.`literal`', "a ""`source_db`.`double_literal`"" b", 'it\'s intact');
-- `source_db`.`line_comment`
# `source_db`.`hash_comment`
/* `source_db`.`block_comment` */
SELECT * FROM `source_db`.`real_table`;
"#,
            "source_db",
            "target_db",
            br#"INSERT INTO `target_db`.`events` VALUES
  ('`source_db`.`literal`', "a ""`source_db`.`double_literal`"" b", 'it\'s intact');
-- `source_db`.`line_comment`
# `source_db`.`hash_comment`
/* `source_db`.`block_comment` */
SELECT * FROM `target_db`.`real_table`;
"#,
        ),
        (
            "MySQL executable comments",
            br#"/*!50003 CREATE*/ /*!50020 DEFINER=`user`@`%` SQL SECURITY DEFINER */
/*!50001 CREATE VIEW `source`.`view_name` AS
SELECT '`source`.`literal`' AS value FROM `source`.`table_name` */;
/* ordinary `source`.`untouched` */
"#,
            "source",
            "target",
            br#"/*!50003 CREATE*/ /*!50020 DEFINER=`user`@`%` SQL SECURITY DEFINER */
/*!50001 CREATE VIEW `target`.`view_name` AS
SELECT '`source`.`literal`' AS value FROM `target`.`table_name` */;
/* ordinary `source`.`untouched` */
"#,
        ),
        (
            "MariaDB executable comments",
            br#"/*M!100100 CREATE VIEW source . "view_name" AS
SELECT * FROM `source`   . table_name */;
"#,
            "source",
            "target",
            br#"/*M!100100 CREATE VIEW `target` . "view_name" AS
SELECT * FROM `target`   . table_name */;
"#,
        ),
        (
            "routine delimiters and doubled quotes",
            br#"DELIMITER ;;
CREATE PROCEDURE `source`.`refresh_data`()
BEGIN
  SET @sql = 'SELECT ''`source`.`not_code`''';
  INSERT INTO `source`.`audit` VALUES ("`source`.`also_not_code`");
END;;
DELIMITER ;
"#,
            "source",
            "target",
            br#"DELIMITER ;;
CREATE PROCEDURE `target`.`refresh_data`()
BEGIN
  SET @sql = 'SELECT ''`source`.`not_code`''';
  INSERT INTO `target`.`audit` VALUES ("`source`.`also_not_code`");
END;;
DELIMITER ;
"#,
        ),
        (
            "trigger name, target, and body",
            br#"DELIMITER ;;
CREATE TRIGGER source.trigger_name BEFORE INSERT ON `source`.`orders`
FOR EACH ROW
BEGIN
  INSERT INTO source.audit_log VALUES (NEW.id);
END;;
DELIMITER ;
"#,
            "source",
            "target",
            br#"DELIMITER ;;
CREATE TRIGGER `target`.trigger_name BEFORE INSERT ON `target`.`orders`
FOR EACH ROW
BEGIN
  INSERT INTO `target`.audit_log VALUES (NEW.id);
END;;
DELIMITER ;
"#,
        ),
        (
            "comma-separated FROM tables",
            br#"CREATE VIEW `source`.`combined` AS
SELECT a.id, b.value
FROM `source`.`first_table` AS a, `source`.`second_table` AS b
WHERE a.id = b.id;
"#,
            "source",
            "target",
            br#"CREATE VIEW `target`.`combined` AS
SELECT a.id, b.value
FROM `target`.`first_table` AS a, `target`.`second_table` AS b
WHERE a.id = b.id;
"#,
        ),
        (
            "loop and repeat bodies",
            br#"DELIMITER ;;
CREATE PROCEDURE `source`.`refresh_data`()
BEGIN
  work_loop: LOOP
INSERT INTO `source`.`audit` VALUES (1);
LEAVE work_loop;
  END LOOP;
  REPEAT
INSERT INTO source.history VALUES (2);
  UNTIL done END REPEAT;
END;;
DELIMITER ;
"#,
            "source",
            "target",
            br#"DELIMITER ;;
CREATE PROCEDURE `target`.`refresh_data`()
BEGIN
  work_loop: LOOP
INSERT INTO `target`.`audit` VALUES (1);
LEAVE work_loop;
  END LOOP;
  REPEAT
INSERT INTO `target`.history VALUES (2);
  UNTIL done END REPEAT;
END;;
DELIMITER ;
"#,
        ),
        (
            "escaped backticks",
            b"SELECT * FROM `source``database`.`table``name`, `source_database`.`other`;\n",
            "source`database",
            "target`database",
            b"SELECT * FROM `target``database`.`table``name`, `source_database`.`other`;\n",
        ),
        (
            "quoted, unquoted, whitespace, and ANSI forms",
            br#"CREATE TABLE `source`.table_name (id INT);
INSERT INTO source . `table_name` VALUES (1);
SELECT * FROM "source" . "table_name";
SELECT `source`.`table_name`.`column_name`, source.function_name();
"#,
            "source",
            "target",
            br#"CREATE TABLE `target`.table_name (id INT);
INSERT INTO `target` . `table_name` VALUES (1);
SELECT * FROM "target" . "table_name";
SELECT `target`.`table_name`.`column_name`, `target`.function_name();
"#,
        ),
    ];

    for (name, input, source, target, expected) in cases {
        assert_eq!(
            rewrite_bytes(input, source, target).unwrap(),
            *expected,
            "rewrite case failed: {name}"
        );
    }
}

#[test]
fn rebases_clickhouse_style_function_and_table_references() {
    let input = br#"CREATE TABLE `items` (`id` UInt64 DEFAULT source_db.normalize(`raw`))
ENGINE = MergeTree ORDER BY id;
INSERT INTO `items` SELECT * FROM source_db.source_items;
SELECT 'source_db.literal';
"#;
    let expected = br#"CREATE TABLE `items` (`id` UInt64 DEFAULT `target_db`.normalize(`raw`))
ENGINE = MergeTree ORDER BY id;
INSERT INTO `items` SELECT * FROM `target_db`.source_items;
SELECT 'source_db.literal';
"#;

    assert_eq!(
        rewrite_bytes(input, "source_db", "target_db").unwrap(),
        expected
    );
    assert!(validate_database_name_with_limit(&"a".repeat(128), "source database", 128).is_ok());
    assert!(validate_database_name_with_limit(&"a".repeat(129), "source database", 128).is_err());
}

#[test]
fn rejects_ambiguous_source_prefixed_alias_columns() {
    let cases: &[(&str, &[u8])] = &[
        (
            "expression comma",
            b"SELECT * FROM `other`.`orders` AS `source` WHERE id IN (1, `source`.`id`);\n",
        ),
        (
            "table expression comma",
            br#"SELECT *
FROM `other`.`orders` AS `source`
JOIN JSON_TABLE(`other`.`payload`, `source`.`path` COLUMNS (value JSON PATH '$')) AS jt;
"#,
        ),
        (
            "direct alias column",
            b"SELECT `source`.`id` FROM `other`.`orders` AS `source`;\n",
        ),
    ];

    for (name, input) in cases {
        assert!(
            matches!(
                rewrite_bytes(input, "source", "target"),
                Err(MysqlSqlRewriteError::Malformed(message))
                    if message.contains("ambiguous source-prefixed two-part")
            ),
            "ambiguous case was accepted: {name}"
        );
    }
}

#[test]
fn equal_database_names_leave_every_byte_unchanged() {
    let input = b"SELECT * FROM `same`.`table` WHERE value='`same`.`literal`';\n";

    assert_eq!(rewrite_bytes(input, "same", "same").unwrap(), input);
}

#[test]
fn rewrites_a_qualifier_split_across_stream_buffers() {
    let mut input = vec![b' '; STREAM_BUFFER_BYTES - 8];
    input.extend_from_slice(b"FROM `source`.`table`;\n");
    let mut expected = vec![b' '; STREAM_BUFFER_BYTES - 8];
    expected.extend_from_slice(b"FROM `target`.`table`;\n");

    assert_eq!(rewrite_bytes(&input, "source", "target").unwrap(), expected);
}

#[test]
fn rejects_input_and_output_size_overruns() {
    assert!(matches!(
        rewrite_bytes_with_limit(b"12345", "a", "b", 4),
        Err(MysqlSqlRewriteError::InputLimit { limit: 4 })
    ));
    let expanding = b"FROM `a`.`b`";
    let limit = u64::try_from(expanding.len()).unwrap();
    assert!(matches!(
        rewrite_bytes_with_limit(expanding, "a", "longer", limit),
        Err(MysqlSqlRewriteError::OutputLimit { limit: actual }) if actual == limit
    ));

    let mut expired = BoundedInput::new(
        Cursor::new(b"SELECT 1"),
        1024,
        Instant::now() - Duration::from_secs(1),
    );
    assert!(matches!(
        expired.next_byte(),
        Err(MysqlSqlRewriteError::Timeout)
    ));
}

#[test]
fn rejects_malformed_and_overlong_tokens() {
    for malformed in [
        b"SELECT 'unterminated".as_slice(),
        b"SELECT \"unterminated".as_slice(),
        b"SELECT `unterminated".as_slice(),
        b"SELECT /* unterminated".as_slice(),
        b"SELECT /*! `source`.`table`".as_slice(),
        b"SELECT */ 1".as_slice(),
    ] {
        assert!(
            matches!(
                rewrite_bytes(malformed, "source", "target"),
                Err(MysqlSqlRewriteError::Malformed(_))
            ),
            "accepted malformed input: {}",
            String::from_utf8_lossy(malformed)
        );
    }

    let mut overlong = Vec::from(b"SELECT `".as_slice());
    overlong.extend(std::iter::repeat_n(b'a', MAX_QUOTED_IDENTIFIER_BYTES));
    overlong.extend_from_slice(b"`");
    assert!(matches!(
        rewrite_bytes(&overlong, "source", "target"),
        Err(MysqlSqlRewriteError::Malformed(_))
    ));

    let mut overlong_gap = Vec::from(b"FROM `source`".as_slice());
    overlong_gap.extend(std::iter::repeat_n(b' ', MAX_QUALIFIER_GAP_BYTES + 1));
    overlong_gap.extend_from_slice(b".`table`");
    assert!(matches!(
        rewrite_bytes(&overlong_gap, "source", "target"),
        Err(MysqlSqlRewriteError::Malformed(_))
    ));
}

#[test]
fn rejects_invalid_database_names() {
    assert!(validate_database_name("", "source").is_err());
    assert!(validate_database_name("line\nbreak", "source").is_err());
    assert!(validate_database_name(&"a".repeat(65), "source").is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn atomically_replaces_regular_files_and_rejects_symlink_inputs() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let directory = tempfile::tempdir().unwrap();
    let dump = directory.path().join("source.mysql.sql");
    std::fs::write(&dump, b"SELECT * FROM `source`.`table`;\n").unwrap();
    std::fs::set_permissions(&dump, std::fs::Permissions::from_mode(0o640)).unwrap();

    rewrite_mysql_schema_qualifiers(
        &dump,
        "source",
        "target",
        1024 * 1024,
        Duration::from_secs(30),
    )
    .await
    .unwrap();

    assert_eq!(
        std::fs::read(&dump).unwrap(),
        b"SELECT * FROM `target`.`table`;\n"
    );
    assert_eq!(
        std::fs::symlink_metadata(&dump)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );

    let victim = directory.path().join("victim.sql");
    let linked = directory.path().join("linked.mysql.sql");
    std::fs::write(&victim, b"SELECT * FROM `source`.`victim`;\n").unwrap();
    symlink(&victim, &linked).unwrap();

    assert!(
        rewrite_mysql_schema_qualifiers(
            &linked,
            "source",
            "target",
            1024 * 1024,
            Duration::from_secs(30),
        )
        .await
        .is_err()
    );
    assert_eq!(
        std::fs::read(&victim).unwrap(),
        b"SELECT * FROM `source`.`victim`;\n"
    );

    let malformed = directory.path().join("malformed.mysql.sql");
    let malformed_contents = b"SELECT * FROM `source`.`table` WHERE value='unterminated";
    std::fs::write(&malformed, malformed_contents).unwrap();
    assert!(
        rewrite_mysql_schema_qualifiers(
            &malformed,
            "source",
            "target",
            1024 * 1024,
            Duration::from_secs(30),
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read(&malformed).unwrap(), malformed_contents);

    let ambiguous = directory.path().join("ambiguous.mysql.sql");
    let ambiguous_contents = b"SELECT `source`.`id` FROM `other`.`orders` AS `source`;\n";
    std::fs::write(&ambiguous, ambiguous_contents).unwrap();
    assert!(
        rewrite_mysql_schema_qualifiers(
            &ambiguous,
            "source",
            "target",
            1024 * 1024,
            Duration::from_secs(30),
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read(&ambiguous).unwrap(), ambiguous_contents);

    assert!(std::fs::read_dir(directory.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".mysql-schema-rewrite-")
    }));
}
