use super::*;

use std::{
    io::{self, Cursor, Write},
    path::PathBuf,
};

use bzip2::write::BzEncoder;
use flate2::{Compression, write::GzEncoder};
use tempfile::TempDir;

fn scan_sql(protocol: Protocol, sql: &[u8]) -> Result<DumpInspection, InspectionError> {
    let mut catalog = CatalogBuilder::new(protocol);
    inspect_sql_reader(Cursor::new(sql), protocol, &mut catalog)?;
    catalog.validate_dialect()?;
    Ok(catalog.finish("00".repeat(32), sql.len() as u64, DumpArchiveFormat::Plain))
}

fn write_temp_file(directory: &TempDir, name: &str, contents: &[u8]) -> PathBuf {
    let path = directory.path().join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

fn gzip(contents: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(contents).unwrap();
    encoder.finish().unwrap()
}

fn mongodb_archive(metadata: &[(&str, &str)]) -> Vec<u8> {
    let mut bytes = vec![0x6d, 0xe2, 0x99, 0x81];
    bytes.extend(
        bson::to_vec(&bson::doc! {
            "concurrent_collections": 4_i32,
            "version": "0.1",
            "server_version": "8.0.0",
            "tool_version": "100.12.2",
        })
        .unwrap(),
    );
    for (database, collection) in metadata {
        bytes.extend(
            bson::to_vec(&bson::doc! {
                "db": database,
                "collection": collection,
                "metadata": "{}",
                "size": 0_i32,
                "type": "collection",
            })
            .unwrap(),
        );
    }
    bytes.extend(u32::MAX.to_le_bytes());
    bytes
}

#[test]
fn tar_gzip_uses_the_documented_json_value() {
    assert_eq!(
        serde_json::to_string(&DumpArchiveFormat::TarGzip).unwrap(),
        r#""tar.gz""#
    );
    assert_eq!(
        serde_json::from_str::<DumpArchiveFormat>(r#""tar.gz""#).unwrap(),
        DumpArchiveFormat::TarGzip
    );
}

fn bzip2(contents: &[u8]) -> Vec<u8> {
    let mut encoder = BzEncoder::new(Vec::new(), bzip2::Compression::default());
    encoder.write_all(contents).unwrap();
    encoder.finish().unwrap()
}

fn tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut output = Vec::new();
    {
        let mut archive = tar::Builder::new(&mut output);
        for (name, contents) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o600);
            header.set_size(contents.len() as u64);
            header.set_cksum();
            archive.append_data(&mut header, *name, *contents).unwrap();
        }
        archive.finish().unwrap();
    }
    output
}

fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut output = Cursor::new(Vec::new());
    {
        let mut archive = zip::ZipWriter::new(&mut output);
        for (name, contents) in entries {
            archive
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            archive.write_all(contents).unwrap();
        }
        archive.finish().unwrap();
    }
    output.into_inner()
}

#[test]
fn postgres_catalog_handles_quotes_copy_and_ignored_sql_text() {
    let sql = br#"-- PostgreSQL database dump
CREATE SCHEMA "public";
CREATE TABLE "public"."Users" (id bigint);
INSERT INTO "audit"."events" VALUES ('CREATE TABLE fake.inside_string (id int);');
INSERT INTO "audit"."events" VALUES (E'CREATE TABLE fake.inside_escape_string (id int);');
COPY public.orders (id, note) FROM stdin;
1	CREATE TABLE fake.copy_data
\.
DO $body$ BEGIN RAISE NOTICE 'CREATE TABLE fake.body'; END $body$;
-- CREATE TABLE fake.comment (id int);
/* CREATE TABLE fake.block_comment (id int); */
/* outer /* CREATE TABLE fake.nested_comment (id int); */ still outer */
"#;
    let result = scan_sql(Protocol::Postgres, sql).unwrap();

    let keys = result
        .objects
        .iter()
        .map(|object| object.selection_key.as_str())
        .collect::<Vec<_>>();
    assert_eq!(keys, ["audit.events", "public.Users", "public.orders"]);
    assert_eq!(result.namespaces, ["audit", "public"]);
    assert!(!result.selective_supported);
    assert!(result.catalog_complete);
}

#[test]
fn mysql_and_mariadb_catalogs_parse_common_mysqldump_statements() {
    let sql = br#"-- MySQL dump 10.13
CREATE DATABASE IF NOT EXISTS `tenant`;
USE `tenant`;
CREATE TABLE IF NOT EXISTS `tenant`.`orders` (`id` bigint);
INSERT IGNORE INTO `tenant`.`customers` VALUES (1, 'INSERT INTO fake VALUES (1)');
CREATE TEMPORARY TABLE `scratch` (`id` int);
"#;
    for protocol in [Protocol::Mysql, Protocol::Mariadb] {
        let result = scan_sql(protocol, sql).unwrap();
        let keys = result
            .objects
            .iter()
            .map(|object| object.selection_key.as_str())
            .collect::<Vec<_>>();
        assert_eq!(keys, ["scratch", "tenant.customers", "tenant.orders"]);
        assert_eq!(result.namespaces, ["tenant"]);
    }
}

#[test]
fn clickhouse_catalog_deduplicates_create_and_insert() {
    let sql = br#"-- DatabasesEverywhere ClickHouse logical dump
CREATE TABLE `events` (id UInt64) ENGINE = MergeTree ORDER BY id;
INSERT INTO `events` VALUES (1);
CREATE TABLE analytics.metrics (value Float64) ENGINE = TinyLog;
"#;
    let result = scan_sql(Protocol::Clickhouse, sql).unwrap();
    assert_eq!(result.objects.len(), 2);
    assert_eq!(result.objects[0].selection_key, "events");
    assert_eq!(result.objects[1].selection_key, "metrics");
    assert_eq!(result.objects[1].namespace.as_deref(), Some("analytics"));
}

#[test]
fn sql_failures_reject_mismatches_malformed_contexts_and_binary_data() {
    let error = scan_sql(
        Protocol::Postgres,
        b"-- MySQL dump secret-marker-which-must-not-leak\nCREATE TABLE users(id int);",
    )
    .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("does not match"));
    assert!(!message.contains("secret-marker"));

    for sql in [
        b"CREATE TABLE users (value text DEFAULT 'unterminated);".as_slice(),
        b"/* unterminated CREATE TABLE users(id int);".as_slice(),
        b"DO $tag$ CREATE TABLE users(id int);".as_slice(),
        b"CREATE TABLE \"unterminated (id int);".as_slice(),
    ] {
        assert!(scan_sql(Protocol::Postgres, sql).is_err());
    }

    let error = scan_sql(
        Protocol::Postgres,
        b"CREATE TABLE users(id int);\0CREATE TABLE hidden(id int);",
    )
    .unwrap_err();
    assert!(error.to_string().contains("binary data"));
}

#[test]
fn sql_identifier_and_catalog_limits_are_bounded() {
    let sql = br#"
CREATE TABLE "public"."normal-name" (id int);
CREATE TABLE "public"."not selectable" (id int);
"#;
    let result = scan_sql(Protocol::Postgres, sql).unwrap();
    assert_eq!(result.objects.len(), 1);
    assert_eq!(result.objects[0].selection_key, "public.normal-name");
    assert_eq!(result.unselectable_object_count, 1);

    let long_name = "a".repeat(MAX_IDENTIFIER_BYTES + 1);
    let result = scan_sql(
        Protocol::Postgres,
        format!("CREATE TABLE {long_name} (id int);").as_bytes(),
    )
    .unwrap();
    assert!(result.objects.is_empty());
    assert_eq!(result.unselectable_object_count, 1);

    let mut many = String::new();
    for index in 0..=MAX_OBJECTS {
        many.push_str(&format!("CREATE TABLE table_{index} (id int);\n"));
    }
    let result = scan_sql(Protocol::Postgres, many.as_bytes()).unwrap();
    assert_eq!(result.objects.len(), MAX_OBJECTS);
    assert!(!result.catalog_complete);

    let value = "a".repeat(MAX_IDENTIFIER_BYTES * 8);
    let sql = format!(
        "-- MySQL dump\nCREATE TABLE `payloads` (`value` longblob); INSERT INTO `payloads` VALUES (0x{value});"
    );
    let result = scan_sql(Protocol::Mysql, sql.as_bytes()).unwrap();
    assert_eq!(result.objects.len(), 1);
    assert_eq!(result.objects[0].selection_key, "payloads");
}

#[tokio::test]
async fn plain_gzip_and_bzip2_are_detected_and_hashed() {
    let directory = TempDir::new().unwrap();
    let sql = b"-- PostgreSQL database dump\nCREATE TABLE public.users(id int);";
    let inputs = [
        ("dump.sql", sql.to_vec(), DumpArchiveFormat::Plain),
        ("dump.sql.gz", gzip(sql), DumpArchiveFormat::Gzip),
        ("dump.sql.bz2", bzip2(sql), DumpArchiveFormat::Bzip2),
    ];
    for (name, contents, expected_format) in inputs {
        let path = write_temp_file(&directory, name, &contents);
        let result = inspect_uploaded_dump(&path, Protocol::Postgres, None)
            .await
            .unwrap();
        assert_eq!(result.detected_archive_format, expected_format);
        assert_eq!(result.source_size_bytes, contents.len() as u64);
        assert_eq!(result.sha256, format!("{:x}", Sha256::digest(&contents)));
        assert_eq!(result.objects[0].selection_key, "public.users");
    }
}

#[tokio::test]
async fn requested_wrapper_must_match_detected_content() {
    let directory = TempDir::new().unwrap();
    let path = write_temp_file(&directory, "dump.sql", b"CREATE TABLE users(id int);");
    let error = inspect_uploaded_dump(&path, Protocol::Postgres, Some("gzip"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("does not match"));
}

#[tokio::test]
async fn tar_tar_gzip_and_zip_select_exactly_one_sql_member() {
    let directory = TempDir::new().unwrap();
    let sql = b"-- MySQL dump\nCREATE TABLE `orders` (`id` bigint);";
    let tar_bytes = tar(&[("nested/dump.mysql.sql", sql)]);
    let inputs = [
        ("dump.tar", tar_bytes.clone(), DumpArchiveFormat::Tar),
        ("dump.tar.gz", gzip(&tar_bytes), DumpArchiveFormat::TarGzip),
        (
            "dump.zip",
            zip(&[("nested/dump.mysql.sql", sql)]),
            DumpArchiveFormat::Zip,
        ),
    ];
    for (name, contents, expected_format) in inputs {
        let path = write_temp_file(&directory, name, &contents);
        let result = inspect_uploaded_dump(&path, Protocol::Mysql, None)
            .await
            .unwrap();
        assert_eq!(result.detected_archive_format, expected_format);
        assert_eq!(result.objects[0].selection_key, "orders");
    }
}

#[tokio::test]
async fn archives_reject_ambiguous_candidates_and_missing_dump() {
    let directory = TempDir::new().unwrap();
    let ambiguous = zip(&[
        ("one.sql", b"CREATE TABLE one(id int);"),
        ("two.postgres.sql", b"CREATE TABLE two(id int);"),
    ]);
    let path = write_temp_file(&directory, "ambiguous.zip", &ambiguous);
    let error = inspect_uploaded_dump(&path, Protocol::Postgres, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("multiple candidate"));

    let missing = tar(&[("README.txt", b"not a dump")]);
    let path = write_temp_file(&directory, "missing.tar", &missing);
    let error = inspect_uploaded_dump(&path, Protocol::Postgres, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("does not contain"));
}

#[tokio::test]
async fn zip_traversal_and_tar_symlink_entries_are_rejected() {
    let directory = TempDir::new().unwrap();
    let traversal = zip(&[("../escape.sql", b"CREATE TABLE escaped(id int);")]);
    let path = write_temp_file(&directory, "traversal.zip", &traversal);
    let error = inspect_uploaded_dump(&path, Protocol::Postgres, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("unsafe entry path"));

    let mut symlink_archive = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut symlink_archive);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_mode(0o777);
        header.set_size(0);
        header.set_link_name("outside.sql").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "dump.sql", io::empty())
            .unwrap();
        builder.finish().unwrap();
    }
    let path = write_temp_file(&directory, "symlink.tar", &symlink_archive);
    let error = inspect_uploaded_dump(&path, Protocol::Postgres, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("link"));
}

#[tokio::test]
async fn archive_depth_and_expansion_limits_fail_before_extraction() {
    let directory = TempDir::new().unwrap();
    let deep_name = format!(
        "{}/dump.sql",
        vec!["level"; MAX_ARCHIVE_DEPTH + 1].join("/")
    );
    let deep = zip(&[(&deep_name, b"CREATE TABLE users(id int);")]);
    let path = write_temp_file(&directory, "deep.zip", &deep);
    let error = inspect_uploaded_dump(&path, Protocol::Postgres, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("too deep"));

    let mut oversized = Vec::new();
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o600);
    header.set_path("dump.sql").unwrap();
    header.set_size(MAX_INSPECTED_BYTES + 1);
    header.set_cksum();
    oversized.extend_from_slice(header.as_bytes());
    oversized.extend_from_slice(&[0_u8; 1024]);
    let path = write_temp_file(&directory, "bomb.tar", &oversized);
    let error = inspect_uploaded_dump(&path, Protocol::Postgres, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("expansion"));
}

#[tokio::test]
async fn bounded_failure_retains_the_confirmed_wrapper_format() {
    let directory = TempDir::new().unwrap();
    let mut oversized = Vec::new();
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o600);
    header.set_path("dump.sql").unwrap();
    header.set_size(MAX_INSPECTED_BYTES + 1);
    header.set_cksum();
    oversized.extend_from_slice(header.as_bytes());
    oversized.extend_from_slice(&[0_u8; 1024]);
    let path = write_temp_file(&directory, "bounded.tar", &oversized);

    let failure = inspect_uploaded_dump_with_format(&path, Protocol::Postgres, None)
        .await
        .unwrap_err();
    assert!(matches!(failure.error, ApiError::ServiceUnavailable(_)));
    assert_eq!(
        failure.detected_archive_format,
        Some(DumpArchiveFormat::Tar)
    );
}

#[test]
fn bounded_reader_enforces_decompressed_limit_even_when_metadata_lies() {
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut reader = BoundedReader::new(Cursor::new(b"12345"), 4, deadline);
    let mut output = Vec::new();
    let error = reader.read_to_end(&mut output).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[tokio::test]
async fn malformed_archives_return_sanitized_errors() {
    let directory = TempDir::new().unwrap();
    let path = write_temp_file(
        &directory,
        "broken.zip",
        b"PK\x03\x04SECRET_DUMP_CONTENT_THAT_MUST_NOT_LEAK",
    );
    let error = inspect_uploaded_dump(&path, Protocol::Postgres, None)
        .await
        .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("malformed"));
    assert!(!message.contains("SECRET_DUMP_CONTENT"));
}

#[test]
fn prefix_reads_are_not_confused_by_short_underlying_reads() {
    struct OneByteAtATime(Cursor<Vec<u8>>);

    impl Read for OneByteAtATime {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let length = buffer.len().min(1);
            self.0.read(&mut buffer[..length])
        }
    }

    let mut reader = OneByteAtATime(Cursor::new(b"complete-prefix".to_vec()));
    let mut prefix = [0_u8; 15];
    assert_eq!(read_up_to(&mut reader, &mut prefix).unwrap(), 15);
    assert_eq!(&prefix, b"complete-prefix");
}

#[tokio::test]
async fn mongodb_and_physical_protocols_report_bounded_full_only_catalogs() {
    let directory = TempDir::new().unwrap();
    let gzip_bytes = gzip(&mongodb_archive(&[
        ("tenant", "users"),
        ("tenant", "orders"),
    ]));
    let mongo = write_temp_file(&directory, "mongo.archive.gz", &gzip_bytes);
    let mongo_result = inspect_uploaded_dump(&mongo, Protocol::Mongodb, None)
        .await
        .unwrap();
    assert_eq!(mongo_result.selection_kind, DumpSelectionKind::Collections);
    assert!(!mongo_result.selective_supported);
    assert!(mongo_result.catalog_complete);
    assert_eq!(mongo_result.namespaces, ["tenant"]);
    assert!(
        mongo_result
            .selective_unavailable_reason
            .as_deref()
            .unwrap()
            .contains("complete selected source database")
    );

    let physical_archive = tar(&[("data/dump.rdb", b"opaque")]);
    for protocol in [Protocol::Redis, Protocol::Valkey, Protocol::Qdrant] {
        let path = write_temp_file(
            &directory,
            &format!("{}.tar.gz", protocol.as_str()),
            &gzip(&physical_archive),
        );
        let result = inspect_uploaded_dump(&path, protocol, None).await.unwrap();
        assert_eq!(result.selection_kind, DumpSelectionKind::FullOnly);
        assert!(!result.selective_supported);
        assert!(result.catalog_complete);
        assert!(result.objects.is_empty());
    }
}

#[tokio::test]
async fn serializable_catalog_round_trips_for_sqlite_storage() {
    let directory = TempDir::new().unwrap();
    let path = write_temp_file(
        &directory,
        "dump.sql",
        b"CREATE TABLE public.users(id bigint);",
    );
    let original = inspect_uploaded_dump(&path, Protocol::Postgres, None)
        .await
        .unwrap();
    let json = serde_json::to_vec(&original).unwrap();
    let restored: DumpInspection = serde_json::from_slice(&json).unwrap();
    assert_eq!(restored, original);
}

#[test]
fn bounded_inspection_limits_are_retryable_not_malformed() {
    let error = InspectionError::Limit("archive contains too many entries").into_api_error();
    assert!(matches!(error, ApiError::ServiceUnavailable(_)));

    let error = InspectionError::Invalid("archive format does not match").into_api_error();
    assert!(matches!(error, ApiError::BadRequest(_)));
}

#[tokio::test]
async fn mongodb_rejects_uncompressed_native_uploads() {
    let directory = TempDir::new().unwrap();
    let path = write_temp_file(&directory, "mongo.archive", b"opaque native archive");
    let error = inspect_uploaded_dump(&path, Protocol::Mongodb, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("native gzip archives"));
}

#[tokio::test]
async fn mongodb_wrappers_require_one_valid_native_gzip_archive() {
    let directory = TempDir::new().unwrap();

    let missing = write_temp_file(
        &directory,
        "missing.tar",
        &tar(&[("readme.txt", b"not a dump")]),
    );
    assert!(
        inspect_uploaded_dump(&missing, Protocol::Mongodb, Some("tar"))
            .await
            .unwrap_err()
            .to_string()
            .contains("does not contain")
    );

    let two = write_temp_file(
        &directory,
        "two.tar",
        &tar(&[
            (
                "one.archive.gz",
                gzip(&mongodb_archive(&[("one", "users")])).as_slice(),
            ),
            (
                "two.mongodb.archive.gz",
                gzip(&mongodb_archive(&[("two", "users")])).as_slice(),
            ),
        ]),
    );
    assert!(
        inspect_uploaded_dump(&two, Protocol::Mongodb, Some("tar"))
            .await
            .unwrap_err()
            .to_string()
            .contains("multiple")
    );

    let valid_gzip = gzip(&mongodb_archive(&[("legacy", "users")]));
    let valid = write_temp_file(
        &directory,
        "valid.tar",
        &tar(&[("nested/dump.mongodb.archive.gz", &valid_gzip)]),
    );
    let result = inspect_uploaded_dump(&valid, Protocol::Mongodb, Some("tar"))
        .await
        .unwrap();
    assert_eq!(result.detected_archive_format, DumpArchiveFormat::Tar);
    assert_eq!(result.namespaces, ["legacy"]);
}

#[tokio::test]
async fn mongodb_discovery_represents_one_multiple_and_no_source_databases() {
    let directory = TempDir::new().unwrap();
    let cases = [
        (
            "one.archive.gz",
            vec![("tenant", "users"), ("tenant", "orders")],
            vec!["tenant"],
        ),
        (
            "multiple.archive.gz",
            vec![
                ("beta", "events"),
                ("alpha", "users"),
                ("admin", "system.users"),
                ("config", "settings"),
                ("local", "oplog.rs"),
            ],
            vec!["alpha", "beta"],
        ),
        (
            "none.archive.gz",
            vec![("admin", "system.users"), ("local", "oplog.rs")],
            vec![],
        ),
    ];
    for (name, metadata, expected) in cases {
        let path = write_temp_file(
            &directory,
            name,
            &gzip(&mongodb_archive(metadata.as_slice())),
        );
        let result = inspect_uploaded_dump(&path, Protocol::Mongodb, None)
            .await
            .unwrap();
        assert_eq!(result.namespaces, expected);
        assert!(result.catalog_complete);
        assert!(!result.selective_supported);
        assert!(result.objects.is_empty());
    }
}

#[tokio::test]
async fn mongodb_rejects_gzip_that_is_not_a_native_archive() {
    let directory = TempDir::new().unwrap();
    let path = write_temp_file(
        &directory,
        "fake.archive.gz",
        &gzip(b"not a mongodump archive"),
    );
    let error = inspect_uploaded_dump(&path, Protocol::Mongodb, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("native mongodump archive"));
}

#[tokio::test]
async fn mongodb_validates_every_gzip_member_and_rejects_trailing_data() {
    let directory = TempDir::new().unwrap();
    let archive = mongodb_archive(&[("tenant", "users")]);

    let split = archive.len() / 2;
    let mut multistream = gzip(&archive[..split]);
    multistream.extend(gzip(&archive[split..]));
    let valid = write_temp_file(&directory, "multi.archive.gz", &multistream);
    let result = inspect_uploaded_dump(&valid, Protocol::Mongodb, None)
        .await
        .unwrap();
    assert_eq!(result.namespaces, ["tenant"]);

    let mut trailing = gzip(&archive);
    trailing.extend(b"not another gzip member");
    let invalid = write_temp_file(&directory, "trailing.archive.gz", &trailing);
    assert!(
        inspect_uploaded_dump(&invalid, Protocol::Mongodb, None)
            .await
            .unwrap_err()
            .to_string()
            .contains("malformed native gzip archive")
    );

    let mut truncated = gzip(&archive);
    truncated.truncate(truncated.len() - 4);
    let invalid = write_temp_file(&directory, "truncated.archive.gz", &truncated);
    assert!(
        inspect_uploaded_dump(&invalid, Protocol::Mongodb, None)
            .await
            .unwrap_err()
            .to_string()
            .contains("malformed")
    );
}

#[tokio::test]
async fn mongodb_tar_gzip_wrapper_validates_its_complete_outer_stream() {
    let directory = TempDir::new().unwrap();
    let inner = gzip(&mongodb_archive(&[("tenant", "users")]));
    let mut outer = gzip(&tar(&[("dump.mongodb.archive.gz", &inner)]));
    outer.extend(b"trailing outer data");
    let path = write_temp_file(&directory, "dump.tar.gz", &outer);
    assert!(
        inspect_uploaded_dump(&path, Protocol::Mongodb, None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn mongodb_zip_tar_gzip_and_bzip2_wrappers_preserve_discovery() {
    let directory = TempDir::new().unwrap();
    let native_gzip = gzip(&mongodb_archive(&[("legacy", "users")]));
    let tar_bytes = tar(&[("nested/dump.mongodb.archive.gz", &native_gzip)]);
    let inputs = [
        (
            "dump.tar.gz",
            gzip(&tar_bytes),
            Some("tar.gz"),
            DumpArchiveFormat::TarGzip,
        ),
        (
            "dump.zip",
            zip(&[("nested/dump.mongodb.archive.gz", &native_gzip)]),
            Some("zip"),
            DumpArchiveFormat::Zip,
        ),
        (
            "dump.archive.gz.bz2",
            bzip2(&native_gzip),
            Some("bzip2"),
            DumpArchiveFormat::Bzip2,
        ),
    ];
    for (name, bytes, requested, expected_format) in inputs {
        let path = write_temp_file(&directory, name, &bytes);
        let result = inspect_uploaded_dump(&path, Protocol::Mongodb, requested)
            .await
            .unwrap();
        assert_eq!(result.namespaces, ["legacy"]);
        assert_eq!(result.detected_archive_format, expected_format);
        assert!(result.catalog_complete);
    }
}
