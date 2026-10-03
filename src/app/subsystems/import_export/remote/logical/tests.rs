use super::*;

#[test]
fn option_file_escapes_quotes_and_backslashes() {
    assert_eq!(mysql_option_value("a\"b\\c").unwrap(), "\"a\\\"b\\\\c\"");
}

#[test]
fn pgpass_escapes_field_separators() {
    assert_eq!(pgpass_value(r"a:b\c").unwrap(), r"a\:b\\c");
}

#[test]
fn pgpass_rejects_line_and_nul_injection() {
    for value in ["secret\nother", "secret\rother", "secret\0other"] {
        assert!(matches!(pgpass_value(value), Err(ApiError::BadRequest(_))));
    }
}

#[test]
fn generated_scripts_do_not_contain_passwords() {
    let source = RemoteImportSource {
        endpoint: super::super::security::ResolvedRemoteEndpoint {
            host: "db.example.com".to_string(),
            port: 5432,
            addresses: vec!["203.0.113.5:5432".parse().unwrap()],
            tls: true,
        },
        database: Some("app".to_string()),
        username: Some("operator".to_string()),
        password: Some(secrecy::SecretString::from("do-not-leak")),
        authentication_database: None,
        database_index: 0,
        api_key: None,
    };
    let dir = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let script = runtime
        .block_on(prepare_postgres(
            &source,
            &ImportExportSelection::default(),
            dir.path(),
            37,
        ))
        .unwrap();
    assert!(!script.contains("do-not-leak"));
    assert!(script.contains("sslrootcert=/etc/ssl/certs/ca-certificates.crt"));
    assert!(script.contains("--format=custom"));
    assert!(script.contains("pg_restore --list"));
    assert!(script.contains("--clean --if-exists"));
    assert!(script.contains(&sh_quote(POSTGRES_TOC_FILTER_PROGRAM)));
    assert!(script.contains("CREATE SCHEMA IF NOT EXISTS"));
    let service = std::fs::read_to_string(dir.path().join("pg_service.conf")).unwrap();
    assert!(service.contains("connect_timeout=37"));
}

#[test]
fn mysql_dump_scripts_end_options_before_database_and_tables() {
    let source = RemoteImportSource {
        endpoint: super::super::security::ResolvedRemoteEndpoint {
            host: "db.example.com".to_string(),
            port: 3306,
            addresses: vec!["203.0.113.5:3306".parse().unwrap()],
            tls: false,
        },
        database: Some("-app".to_string()),
        username: Some("operator".to_string()),
        password: Some(secrecy::SecretString::from("secret")),
        authentication_database: None,
        database_index: 0,
        api_key: None,
    };
    let selection = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["-events".to_string()],
        exclude: vec!["legacy".to_string()],
        ..ImportExportSelection::default()
    };
    let mysql_dir = tempfile::tempdir().unwrap();
    let mariadb_dir = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mysql = runtime
        .block_on(prepare_mysql(
            &source,
            &selection,
            "target_user",
            mysql_dir.path(),
            23,
        ))
        .unwrap();
    let mariadb = runtime
        .block_on(prepare_mariadb(&source, &selection, mariadb_dir.path(), 23))
        .unwrap();

    for script in [&mysql, &mariadb] {
        let ignore = script.find("--ignore-table='-app.legacy'").unwrap();
        let positionals = script.find("-- '-app' '-events'").unwrap();
        assert!(ignore < positionals);
        assert!(script.contains("--triggers"));
        assert!(!script.contains("--routines"));
        assert!(!script.contains("--events --triggers"));
        assert!(
            !script.contains("sed -E 's/DEFINER="),
            "a global DEFINER replacement can corrupt ordinary INSERT values"
        );
    }
    assert!(mysql.contains("DEFINER=`target_user`@`%`"));
    assert!(mysql.contains(&sh_quote(MYSQL_TARGET_DEFINER_AWK_PROGRAM)));
    assert!(
        mariadb.contains(&sh_quote(MYSQL_DEFINER_SED_PROGRAM)),
        "mariadb restores as its tenant and strips source definers"
    );
    for directory in [&mysql_dir, &mariadb_dir] {
        let config = std::fs::read_to_string(directory.path().join("client.cnf")).unwrap();
        assert!(config.contains("connect-timeout=23"));
    }
}

#[test]
fn full_mysql_dumps_include_database_wide_objects_but_selective_dumps_do_not() {
    let full = ImportExportSelection::default();
    let selective = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["orders".to_string()],
        ..ImportExportSelection::default()
    };

    assert_eq!(mysql_extra_args(&full), " --routines --events");
    assert_eq!(mysql_extra_args(&selective), "");
}

#[test]
fn mysql_selection_rejects_a_different_database_qualifier() {
    let mismatched = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["other.orders".to_string()],
        ..ImportExportSelection::default()
    };
    assert!(matches!(
        mysql_selection_args(&mismatched, "app", "--ignore-table"),
        Err(ApiError::BadRequest(_))
    ));

    let matched = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["app.orders".to_string()],
        exclude: vec!["app.audit".to_string()],
        ..ImportExportSelection::default()
    };
    let (filters, tables) = mysql_selection_args(&matched, "app", "--ignore-table").unwrap();
    assert!(filters.contains("--ignore-table='app.audit'"));
    assert_eq!(tables, " 'orders'");
}

#[test]
fn mariadb_definer_filter_preserves_insert_values() {
    let fixture = concat!(
        "INSERT INTO `payloads` VALUES ('DEFINER=`x`@`y` ',",
        "'/*!50017 DEFINER=`x`@`y`*/');\n",
        "/*!50003 CREATE*/ /*!50017 DEFINER=`admin`@`%`*/ ",
        "/*!50003 TRIGGER `audit` BEFORE INSERT ON `items` FOR EACH ROW ",
        "SET @x='/*!50017 DEFINER=`literal`@`value`*/' */;;\n",
        "/*M!100301 CREATE*/ /*M!100301 DEFINER=`maria_admin`@`localhost`*/ ",
        "/*M!100301 TRIGGER `maria_audit` BEFORE UPDATE ON `items` FOR EACH ROW ",
        "SET @x='/*M!100301 DEFINER=`literal`@`value`*/' */;;\n",
        "CREATE DEFINER=`admin`@`%` VIEW `items_view` AS SELECT 1;\n",
        "ALTER ALGORITHM=UNDEFINED DEFINER=`admin`@`%` VIEW `other_view` AS SELECT 2;\n",
    );
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("dump.sql");
    std::fs::write(&input, fixture).unwrap();
    let output = std::process::Command::new("sed")
        .arg("-E")
        .arg(MYSQL_DEFINER_SED_PROGRAM)
        .arg("--")
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sed failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let filtered = String::from_utf8(output.stdout).unwrap();

    assert!(filtered.contains(
        "INSERT INTO `payloads` VALUES ('DEFINER=`x`@`y` ',\
'/*!50017 DEFINER=`x`@`y`*/');"
    ));
    assert!(filtered.contains("/*!50003 CREATE*/ /*!50017 */"));
    assert!(filtered.contains("'/*!50017 DEFINER=`literal`@`value`*/'"));
    assert!(filtered.contains("/*M!100301 CREATE*/ /*M!100301 */"));
    assert!(filtered.contains("'/*M!100301 DEFINER=`literal`@`value`*/'"));
    assert!(filtered.contains("CREATE VIEW `items_view`"));
    assert!(filtered.contains("ALTER ALGORITHM=UNDEFINED VIEW `other_view`"));
}

#[test]
fn mysql_definer_filter_rewrites_every_supported_object_to_the_target_tenant() {
    let fixture = concat!(
        "INSERT INTO `payloads` VALUES ('DEFINER=`literal`@`value`');\n",
        "/*!50003 CREATE*/ /*!50017 DEFINER=`source`@`localhost`*/ ",
        "/*!50003 TRIGGER `audit` BEFORE INSERT ON `items` FOR EACH ROW SET @x=1 */;;\n",
        "CREATE DEFINER=`source`@`localhost` PROCEDURE `refresh_items`() SELECT 1;\n",
        "CREATE DEFINER=`source`@`localhost` FUNCTION `item_count`() RETURNS INT RETURN 1;\n",
        "/*!50106 CREATE*/ /*!50117 DEFINER=`source`@`localhost`*/ ",
        "/*!50106 EVENT `nightly` ON SCHEDULE EVERY 1 DAY DO SELECT 1 */;;\n",
        "CREATE ALGORITHM=UNDEFINED DEFINER=`source`@`localhost` ",
        "SQL SECURITY DEFINER VIEW `items_view` AS SELECT 1;\n",
        "ALTER ALGORITHM=UNDEFINED DEFINER=`source`@`localhost` ",
        "VIEW `other_view` AS SELECT 2;\n",
        "/*!50001 CREATE ALGORITHM=UNDEFINED */\n",
        "/*!50013 DEFINER=`source`@`localhost` SQL SECURITY DEFINER */\n",
        "/*!50001 VIEW `versioned_view` AS SELECT 3 */;\n",
    );
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("dump.sql");
    let output = directory.path().join("filtered.sql");
    std::fs::write(&input, fixture).unwrap();
    let script = mysql_definer_filter(
        input.to_str().unwrap(),
        output.to_str().unwrap(),
        "target_user",
    )
    .unwrap();
    let command = std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .output()
        .unwrap();
    assert!(
        command.status.success(),
        "filter failed: {}",
        String::from_utf8_lossy(&command.stderr)
    );
    let filtered = std::fs::read_to_string(output).unwrap();

    assert!(filtered.contains("INSERT INTO `payloads` VALUES ('DEFINER=`literal`@`value`');"));
    assert_eq!(filtered.matches("DEFINER=`target_user`@`%`").count(), 7);
    assert!(!filtered.contains("DEFINER=`source`@`localhost`"));
}

#[test]
fn mysql_definer_filter_rejects_an_object_without_an_explicit_definer() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("dump.sql");
    let output = directory.path().join("filtered.sql");
    std::fs::write(
        &input,
        "CREATE SQL SECURITY DEFINER VIEW `unsafe_view` AS SELECT 1;\n",
    )
    .unwrap();
    let script = mysql_definer_filter(
        input.to_str().unwrap(),
        output.to_str().unwrap(),
        "target_user",
    )
    .unwrap();
    let command = std::process::Command::new("sh")
        .arg("-c")
        .arg(script)
        .output()
        .unwrap();

    assert!(!command.status.success());
    assert!(
        String::from_utf8_lossy(&command.stderr).contains("unsupported or unsafe DEFINER form")
    );
}

#[test]
fn postgres_toc_filter_removes_only_structural_schema_entries() {
    let fixture = concat!(
        ";\n",
        "; Archive created at 2026-01-01\n",
        "5; 2615 2200 SCHEMA - app operator\n",
        "125; 1259 12345 TABLE app events operator\n",
        "126; 0 0 TABLE DATA app events operator\n",
        "127; 1255 456 FUNCTION app dangerous() operator\n",
    );
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("dump.toc");
    std::fs::write(&input, fixture).unwrap();
    let output = std::process::Command::new("awk")
        .arg(POSTGRES_TOC_FILTER_PROGRAM)
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "awk failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let filtered = String::from_utf8(output.stdout).unwrap();

    assert!(!filtered.contains("SCHEMA - app"));
    assert!(filtered.contains("TABLE app events"));
    assert!(filtered.contains("TABLE DATA app events"));
    assert!(filtered.contains("FUNCTION app dangerous()"));
}

#[test]
fn postgres_schema_query_scopes_selective_imports_without_sql_injection() {
    let selection = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["reporting.orders".to_string(), "events".to_string()],
        ..ImportExportSelection::default()
    };

    let query = postgres_schema_query(&selection);

    assert!(query.contains("n.nspname = 'reporting'"));
    assert!(query.contains("c.relname = 'orders'"));
    assert!(query.contains("c.relname = 'events'"));
    assert!(query.contains("CREATE SCHEMA IF NOT EXISTS %I"));
    assert_eq!(postgres_string_literal("x'y"), "'x''y'");
}

#[test]
fn selective_postgres_dump_requires_every_pattern_to_match() {
    let selection = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["public.orders".to_string()],
        ..ImportExportSelection::default()
    };

    let args = postgres_selection_args(&selection);

    assert!(args.contains("--strict-names"));
    assert!(args.contains("--table='public.orders'"));
}

#[test]
fn mongodb_output_plan_names_single_and_multiple_collection_archives() {
    let selection = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["orders".to_string(), "customers".to_string()],
        exclude: vec!["audit".to_string()],
        ..ImportExportSelection::default()
    };

    let collections = mongodb_selected_collections(&selection).unwrap();
    let names = output_names(Protocol::Mongodb, &selection).unwrap();

    assert_eq!(collections, vec![Some("orders"), Some("customers")]);
    assert_eq!(
        names,
        vec![
            "source.mongodb.0000.archive.gz",
            "source.mongodb.0001.archive.gz"
        ]
    );
    let selection = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["orders".to_string()],
        ..ImportExportSelection::default()
    };

    assert_eq!(
        output_names(Protocol::Mongodb, &selection).unwrap(),
        vec!["source.mongodb.archive.gz"]
    );
    assert_eq!(
        output_names(Protocol::Mongodb, &ImportExportSelection::default()).unwrap(),
        vec!["source.mongodb.archive.gz"]
    );
}

#[test]
fn mongodb_config_uses_the_configured_connection_deadline() {
    let source = RemoteImportSource {
        endpoint: super::super::security::ResolvedRemoteEndpoint {
            host: "mongodb.example.com".to_string(),
            port: 27017,
            addresses: vec!["203.0.113.5:27017".parse().unwrap()],
            tls: true,
        },
        database: Some("app".to_string()),
        username: Some("operator".to_string()),
        password: Some(secrecy::SecretString::from("secret")),
        authentication_database: Some("admin".to_string()),
        database_index: 0,
        api_key: None,
    };
    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let selection = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: vec!["orders".to_string(), "customers".to_string()],
        ..ImportExportSelection::default()
    };
    let planned_output_names = output_names(Protocol::Mongodb, &selection).unwrap();

    let script = runtime
        .block_on(prepare_mongodb(
            &source,
            &selection,
            directory.path(),
            &planned_output_names,
            37,
        ))
        .unwrap();

    let client_config = std::fs::read_to_string(directory.path().join("mongodump.yml")).unwrap();
    assert!(client_config.contains("directConnection=true"));
    assert!(client_config.contains("connectTimeoutMS=37000"));
    assert!(client_config.contains("serverSelectionTimeoutMS=37000"));
    assert!(client_config.contains("tls=true"));
    assert!(!script.contains("secret"));
    assert_eq!(script.matches("mongodump ").count(), 1);
    assert_eq!(script.matches("dump_collection --collection=").count(), 2);
    assert!(script.contains("--collection='orders'"));
    assert!(script.contains("--collection='customers'"));
    assert!(script.contains("/work/source.mongodb.0000.archive.gz"));
    assert!(script.contains("/work/source.mongodb.0001.archive.gz"));

    let maximum_selection = ImportExportSelection {
        mode: SelectionMode::Selective,
        include: (0..512)
            .map(|index| format!("collection_{index:04}_{}", "x".repeat(110)))
            .collect(),
        ..ImportExportSelection::default()
    };
    let maximum_output_names = output_names(Protocol::Mongodb, &maximum_selection).unwrap();
    let maximum_directory = tempfile::tempdir().unwrap();
    let maximum_script = runtime
        .block_on(prepare_mongodb(
            &source,
            &maximum_selection,
            maximum_directory.path(),
            &maximum_output_names,
            37,
        ))
        .unwrap();
    assert_eq!(
        maximum_script
            .matches("dump_collection --collection=")
            .count(),
        512
    );
    assert!(maximum_script.len() < 256 * 1024);
}

#[test]
fn clickhouse_script_uses_a_portable_engine_allowlist() {
    let source = RemoteImportSource {
        endpoint: super::super::security::ResolvedRemoteEndpoint {
            host: "clickhouse.example.com".to_string(),
            port: 9440,
            addresses: vec!["203.0.113.5:9440".parse().unwrap()],
            tls: true,
        },
        database: Some("app".to_string()),
        username: Some("operator".to_string()),
        password: Some(secrecy::SecretString::from("secret")),
        authentication_database: None,
        database_index: 0,
        api_key: None,
    };
    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let script = runtime
        .block_on(prepare_clickhouse(
            &source,
            &ImportExportSelection::default(),
            directory.path(),
            37,
        ))
        .unwrap();

    assert!(script.contains("MergeTree|ReplacingMergeTree|SummingMergeTree"));
    assert!(script.contains("|Log|TinyLog|StripeLog|Memory)"));
    assert!(script.contains("unsupported or non-portable table engine"));
    assert!(!script.contains("ENGINE[[:space:]]*=[[:space:]]*(URL|"));
    let client_config =
        std::fs::read_to_string(directory.path().join("clickhouse-client.xml")).unwrap();
    assert!(client_config.contains("<loadDefaultCAFile>true</loadDefaultCAFile>"));
    assert!(client_config.contains("<verificationMode>strict</verificationMode>"));
    assert!(client_config.contains("<name>RejectCertificateHandler</name>"));
    assert!(client_config.contains("<connect_timeout>37</connect_timeout>"));
    crate::subsystems::import_export::tests::assert_failed_clickhouse_listing(&script);
}

#[test]
fn clickhouse_engine_parser_accepts_exactly_one_line_anchored_clause() {
    let parse = |show_create: &str| {
        std::process::Command::new("awk")
            .arg(CLICKHOUSE_ENGINE_AWK_PROGRAM)
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write as _;

                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(show_create.as_bytes())?;
                child.wait_with_output()
            })
            .unwrap()
    };

    let allowed =
        parse("CREATE TABLE `events`\n(\n  `id` UInt64\n)\nENGINE = MergeTree\nORDER BY id\n");
    assert!(allowed.status.success());
    assert_eq!(
        String::from_utf8(allowed.stdout).unwrap().trim(),
        "MergeTree"
    );

    let deceptive = parse(
        "CREATE TABLE `events`\n(\n  `payload` String DEFAULT 'ENGINE = MergeTree'\n)\nCOMMENT 'ENGINE = MergeTree'\nENGINE = URL('https://example.invalid')\n",
    );
    assert!(deceptive.status.success());
    assert_eq!(String::from_utf8(deceptive.stdout).unwrap().trim(), "URL");

    assert!(
        !parse("CREATE TABLE `events` (`id` UInt64)\n")
            .status
            .success()
    );
    assert!(
        !parse("CREATE TABLE `events` (`id` UInt64)\nENGINE = MergeTree\nENGINE = Memory\n")
            .status
            .success()
    );
}

#[test]
fn clickhouse_show_create_rebases_quoted_and_unquoted_database_names() {
    for fixture in [
        "CREATE TABLE app.orders\n(\n    `id` UInt64\n)\nENGINE = MergeTree ORDER BY id",
        "CREATE TABLE `app`.`orders`\n(\n    `id` UInt64\n)\nENGINE = MergeTree ORDER BY id",
    ] {
        let command = format!(
            "set -eu\ndatabase=app\ntable=orders\ncreate=\"$CREATE_FIXTURE\"\n{}",
            CLICKHOUSE_REBASE_CREATE_SCRIPT
        );
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .env("CREATE_FIXTURE", fixture)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "rebase failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = String::from_utf8(output.stdout).unwrap();
        assert!(output.starts_with("CREATE TABLE `orders`\n("));
        assert!(!output.contains("CREATE TABLE app.orders"));
        assert!(!output.contains("CREATE TABLE `app`.`orders`"));
    }
}
