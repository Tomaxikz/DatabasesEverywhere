use std::io::Cursor;

use super::*;

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
    let mut reader = BoundedInput::new(Cursor::new(input), max_bytes);
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
fn rewrites_qualifiers_but_preserves_literals_and_ordinary_comments() {
    let input = br#"INSERT INTO `source_db`.`events` VALUES
  ('`source_db`.`literal`', "a ""`source_db`.`double_literal`"" b", 'it\'s intact');
-- `source_db`.`line_comment`
# `source_db`.`hash_comment`
/* `source_db`.`block_comment` */
SELECT * FROM `source_db`.`real_table`;
"#;
    let expected = br#"INSERT INTO `target_db`.`events` VALUES
  ('`source_db`.`literal`', "a ""`source_db`.`double_literal`"" b", 'it\'s intact');
-- `source_db`.`line_comment`
# `source_db`.`hash_comment`
/* `source_db`.`block_comment` */
SELECT * FROM `target_db`.`real_table`;
"#;

    assert_eq!(
        rewrite_bytes(input, "source_db", "target_db").unwrap(),
        expected
    );
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
fn processes_mysql_executable_comments_without_touching_strings() {
    let input = br#"/*!50003 CREATE*/ /*!50020 DEFINER=`user`@`%` SQL SECURITY DEFINER */
/*!50001 CREATE VIEW `source`.`view_name` AS
SELECT '`source`.`literal`' AS value FROM `source`.`table_name` */;
/* ordinary `source`.`untouched` */
"#;
    let expected = br#"/*!50003 CREATE*/ /*!50020 DEFINER=`user`@`%` SQL SECURITY DEFINER */
/*!50001 CREATE VIEW `target`.`view_name` AS
SELECT '`source`.`literal`' AS value FROM `target`.`table_name` */;
/* ordinary `source`.`untouched` */
"#;

    assert_eq!(rewrite_bytes(input, "source", "target").unwrap(), expected);
}

#[test]
fn processes_mariadb_executable_comments() {
    let input = br#"/*M!100100 CREATE VIEW source . "view_name" AS
SELECT * FROM `source`   . table_name */;
"#;
    let expected = br#"/*M!100100 CREATE VIEW `target` . "view_name" AS
SELECT * FROM `target`   . table_name */;
"#;

    assert_eq!(rewrite_bytes(input, "source", "target").unwrap(), expected);
}

#[test]
fn handles_routines_delimiters_and_doubled_string_quotes() {
    let input = br#"DELIMITER ;;
CREATE PROCEDURE `source`.`refresh_data`()
BEGIN
  SET @sql = 'SELECT ''`source`.`not_code`''';
  INSERT INTO `source`.`audit` VALUES ("`source`.`also_not_code`");
END;;
DELIMITER ;
"#;
    let expected = br#"DELIMITER ;;
CREATE PROCEDURE `target`.`refresh_data`()
BEGIN
  SET @sql = 'SELECT ''`source`.`not_code`''';
  INSERT INTO `target`.`audit` VALUES ("`source`.`also_not_code`");
END;;
DELIMITER ;
"#;

    assert_eq!(rewrite_bytes(input, "source", "target").unwrap(), expected);
}

#[test]
fn rewrites_trigger_name_target_and_body_table_contexts() {
    let input = br#"DELIMITER ;;
CREATE TRIGGER source.trigger_name BEFORE INSERT ON `source`.`orders`
FOR EACH ROW
BEGIN
  INSERT INTO source.audit_log VALUES (NEW.id);
END;;
DELIMITER ;
"#;
    let expected = br#"DELIMITER ;;
CREATE TRIGGER `target`.trigger_name BEFORE INSERT ON `target`.`orders`
FOR EACH ROW
BEGIN
  INSERT INTO `target`.audit_log VALUES (NEW.id);
END;;
DELIMITER ;
"#;

    assert_eq!(rewrite_bytes(input, "source", "target").unwrap(), expected);
}

#[test]
fn rewrites_comma_separated_from_table_lists() {
    let input = br#"CREATE VIEW `source`.`combined` AS
SELECT a.id, b.value
FROM `source`.`first_table` AS a, `source`.`second_table` AS b
WHERE a.id = b.id;
"#;
    let expected = br#"CREATE VIEW `target`.`combined` AS
SELECT a.id, b.value
FROM `target`.`first_table` AS a, `target`.`second_table` AS b
WHERE a.id = b.id;
"#;

    assert_eq!(rewrite_bytes(input, "source", "target").unwrap(), expected);
}

#[test]
fn from_list_context_ends_before_expression_commas() {
    let input = b"SELECT * FROM `other`.`orders` AS `source` WHERE id IN (1, `source`.`id`);\n";

    assert!(matches!(
        rewrite_bytes(input, "source", "target"),
        Err(MysqlSqlRewriteError::Malformed(message))
            if message.contains("ambiguous source-prefixed two-part")
    ));
}

#[test]
fn from_list_commas_inside_table_expressions_do_not_authorize_alias_columns() {
    let input = br#"SELECT *
FROM `other`.`orders` AS `source`
JOIN JSON_TABLE(`other`.`payload`, `source`.`path` COLUMNS (value JSON PATH '$')) AS jt;
"#;

    assert!(matches!(
        rewrite_bytes(input, "source", "target"),
        Err(MysqlSqlRewriteError::Malformed(message))
            if message.contains("ambiguous source-prefixed two-part")
    ));
}

#[test]
fn rewrites_statements_inside_loop_and_repeat_bodies() {
    let input = br#"DELIMITER ;;
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
"#;
    let expected = br#"DELIMITER ;;
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
"#;

    assert_eq!(rewrite_bytes(input, "source", "target").unwrap(), expected);
}

#[test]
fn decodes_and_reencodes_escaped_backticks_in_identifiers() {
    let input = b"SELECT * FROM `source``database`.`table``name`, `source_database`.`other`;\n";
    let expected = b"SELECT * FROM `target``database`.`table``name`, `source_database`.`other`;\n";

    assert_eq!(
        rewrite_bytes(input, "source`database", "target`database").unwrap(),
        expected
    );
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
fn handles_legal_quoted_unquoted_whitespace_and_ansi_forms() {
    let input = br#"CREATE TABLE `source`.table_name (id INT);
INSERT INTO source . `table_name` VALUES (1);
SELECT * FROM "source" . "table_name";
SELECT `source`.`table_name`.`column_name`, source.function_name();
"#;
    let expected = br#"CREATE TABLE `target`.table_name (id INT);
INSERT INTO `target` . `table_name` VALUES (1);
SELECT * FROM "target" . "table_name";
SELECT `target`.`table_name`.`column_name`, `target`.function_name();
"#;

    assert_eq!(rewrite_bytes(input, "source", "target").unwrap(), expected);
}

#[test]
fn rejects_alias_column_two_part_names() {
    let input = b"SELECT `source`.`id` FROM `other`.`orders` AS `source`;\n";

    assert!(matches!(
        rewrite_bytes(input, "source", "target"),
        Err(MysqlSqlRewriteError::Malformed(message))
            if message.contains("ambiguous source-prefixed two-part")
    ));
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

    rewrite_mysql_schema_qualifiers(&dump, "source", "target", 1024 * 1024)
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
        rewrite_mysql_schema_qualifiers(&linked, "source", "target", 1024 * 1024)
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
        rewrite_mysql_schema_qualifiers(&malformed, "source", "target", 1024 * 1024)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&malformed).unwrap(), malformed_contents);

    let ambiguous = directory.path().join("ambiguous.mysql.sql");
    let ambiguous_contents = b"SELECT `source`.`id` FROM `other`.`orders` AS `source`;\n";
    std::fs::write(&ambiguous, ambiguous_contents).unwrap();
    assert!(
        rewrite_mysql_schema_qualifiers(&ambiguous, "source", "target", 1024 * 1024)
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
