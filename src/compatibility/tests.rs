use super::*;

#[test]
fn parses_vendor_version_outputs_without_treating_suffixes_as_semantics() {
    for (raw, expected) in [
        ("8.4.6-commercial", (8, 4, 6)),
        ("Ver 9.7.0 for Linux", (9, 7, 0)),
        ("mysql  Ver 26.7.1 Innovation", (26, 7, 1)),
        ("v8.3.4", (8, 3, 4)),
        ("ClickHouse server version 26.4.4.38", (26, 4, 4)),
    ] {
        let version = parse_engine_version(raw).unwrap();
        assert_eq!((version.major, version.minor, version.patch), expected);
    }
}

#[test]
fn policy_covers_every_declared_version_family_and_rejects_neighbors() {
    let accepted = [
        (Protocol::Postgres, "14.0"),
        (Protocol::Postgres, "18.9"),
        (Protocol::Mysql, "8.0.42"),
        (Protocol::Mysql, "8.1.0"),
        (Protocol::Mysql, "8.4.6"),
        (Protocol::Mysql, "9.2.0"),
        (Protocol::Mysql, "9.7.0"),
        (Protocol::Mysql, "26.0.0"),
        (Protocol::Mysql, "26.7.1"),
        (Protocol::Mariadb, "10.11.15-MariaDB"),
        (Protocol::Mariadb, "12.3.2-MariaDB"),
        (Protocol::Mongodb, "8.3.4"),
        (Protocol::Redis, "8.8.0"),
        (Protocol::Valkey, "9.1.1"),
        (Protocol::Clickhouse, "25.8.25.37"),
        (Protocol::Qdrant, "1.18.2"),
    ];
    for (protocol, version) in accepted {
        assert!(
            compatibility_profile(protocol, version).is_ok(),
            "{protocol} {version} should be covered"
        );
    }

    for (protocol, version) in [
        (Protocol::Postgres, "13.20"),
        (Protocol::Postgres, "19.0"),
        (Protocol::Mysql, "8.0.10"),
        (Protocol::Mysql, "10.0.0"),
        (Protocol::Mysql, "25.7.0"),
        (Protocol::Mariadb, "11.7.0"),
        (Protocol::Mongodb, "6.0"),
        (Protocol::Redis, "6.0"),
        (Protocol::Qdrant, "2.0"),
    ] {
        assert!(
            matches!(
                compatibility_profile(protocol, version),
                Err(CompatibilityPolicyError::Unsupported { .. })
            ),
            "{protocol} {version} must fail closed"
        );
    }
}

#[test]
fn capabilities_are_derived_from_the_attested_engine_not_the_image_tag() {
    let postgres_16 = compatibility_profile(Protocol::Postgres, "16.9").unwrap();
    let postgres_17 = compatibility_profile(Protocol::Postgres, "17.5").unwrap();
    assert!(!postgres_16.capabilities.postgres_direct_tls);
    assert!(postgres_17.capabilities.postgres_direct_tls);
    assert!(postgres_17.capabilities.postgres_cancel_request);

    let mysql = compatibility_profile(Protocol::Mysql, "26.7.1").unwrap();
    assert!(mysql.capabilities.mysql_caching_sha2_backend);
    let mariadb = compatibility_profile(Protocol::Mariadb, "12.3.2").unwrap();
    assert!(!mariadb.capabilities.mysql_caching_sha2_backend);
}

#[test]
fn normalizers_cover_real_vendor_cli_shapes() {
    assert_eq!(
        normalize_database_version(Protocol::Postgres, "postgres (PostgreSQL) 18.4\n"),
        Some("18.4".to_string())
    );
    assert_eq!(
        normalize_database_version(
            Protocol::Mysql,
            "mysqld  Ver 9.7.0 for Linux on x86_64 (MySQL Community Server - GPL)\n"
        ),
        Some("9.7.0".to_string())
    );
    assert_eq!(
        normalize_database_version(
            Protocol::Mysql,
            "mysqld  Ver 26.7.1 for Linux on x86_64 (MySQL Community Server)\n"
        ),
        Some("26.7.1".to_string())
    );
    assert_eq!(
        normalize_database_version(
            Protocol::Mariadb,
            "mariadb  Ver 15.1 Distrib 12.3.2-MariaDB, for debian-linux-gnu\n"
        ),
        Some("12.3.2-MariaDB".to_string())
    );
}
