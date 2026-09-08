use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use secrecy::SecretString;

use super::{
    TenantEngineError, TenantTarget, create, disk, drop_tenant, fence, rotate_password,
    secure_pool, unfence, verify_password,
};
use crate::{
    api::instances::create::prepare_instance_container_user,
    config::{Config, DaemonConfig, DiskConfig, DiskLimitMode, PathConfig},
    databases,
    instances::{
        metadata::{RuntimeKind, RuntimeMetadata},
        paths::InstancePaths,
    },
    placement::{
        DeploymentMode, ENGINE_RUNTIME_SCHEMA_VERSION, EngineRuntime, EngineRuntimeStatus,
        RuntimeReservation,
    },
    runtime::docker::{CommandOutput, DockerError, DockerInstanceSpec, DockerRuntime},
    shared::{
        backend::{BackendEndpoint, backend_socket_path},
        limits::InstanceLimits,
        protocol::Protocol,
        shell::sh_quote,
    },
};

const ADMIN_PASSWORD: &str = "shared-integration-admin-password";
const PASSWORD_A: &str = "shared-integration-a-password";
const PASSWORD_A_ROTATED: &str = "shared-integration-a-rotated-password";
const PASSWORD_B: &str = "shared-integration-b-password";
const DATABASE_A: &str = "shared_integration_a";
// Without escaping database-level GRANT patterns, DATABASE_A's underscores
// match this distinct schema and give tenant A access to tenant B.
const DATABASE_B: &str = "sharedxintegrationxa";
const USER_A: &str = "shared_user_a";
const USER_B: &str = "shared_user_b";
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(120);

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a local Docker daemon and the pinned PostgreSQL image"]
async fn postgres_shared_pool_enforces_two_tenant_lifecycle_isolation() {
    exercise_two_tenant_pool(Protocol::Postgres).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a local Docker daemon and the pinned MySQL image"]
async fn mysql_shared_pool_enforces_two_tenant_lifecycle_isolation() {
    exercise_two_tenant_pool(Protocol::Mysql).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a local Docker daemon and the pinned MariaDB image"]
async fn mariadb_shared_pool_enforces_two_tenant_lifecycle_isolation() {
    exercise_two_tenant_pool(Protocol::Mariadb).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a local Docker daemon and the pinned MongoDB image"]
async fn mongodb_shared_pool_enforces_two_tenant_lifecycle_isolation() {
    exercise_two_tenant_pool(Protocol::Mongodb).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a local Docker daemon and the pinned ClickHouse image"]
async fn clickhouse_shared_pool_enforces_two_tenant_lifecycle_isolation() {
    for image in [
        "clickhouse/clickhouse-server:25.8.25.37",
        "clickhouse/clickhouse-server:26.4.4.38",
    ] {
        exercise_two_tenant_pool_with_image(Protocol::Clickhouse, image).await;
    }
}

/// Runs a real shared SQL engine with its tenant directories on a native
/// project-quota filesystem. The privileged quota workflow selects one of the
/// three hard-capable protocols through `DBE_PROJECT_QUOTA_ENGINE_PROTOCOL`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires root, Docker, and an XFS/ext4 project-quota test root"]
async fn real_shared_engine_project_quota_enforces_tenant_writes() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "the shared-engine quota test must run as root"
    );
    let protocol = match env::var("DBE_PROJECT_QUOTA_ENGINE_PROTOCOL").as_deref() {
        Ok("postgres") => Protocol::Postgres,
        Ok("mysql") => Protocol::Mysql,
        Ok("mariadb") => Protocol::Mariadb,
        Ok(other) => panic!("unsupported shared-engine quota protocol: {other}"),
        Err(_) => panic!("DBE_PROJECT_QUOTA_ENGINE_PROTOCOL must be set by the quota runner"),
    };
    let root = PathBuf::from(
        env::var("DBE_PROJECT_QUOTA_TEST_ROOT")
            .expect("DBE_PROJECT_QUOTA_TEST_ROOT must be set by the quota runner"),
    )
    .canonicalize()
    .expect("canonicalize the project-quota engine test root");
    assert_ne!(root, Path::new("/"), "refusing to use / as a test root");
    assert!(
        std::fs::read_dir(&root)
            .expect("inspect the project-quota engine test root")
            .next()
            .is_none(),
        "the project-quota engine test root must be empty"
    );

    let pool = SharedPool::start_on_project_quota(protocol, root).await;
    let limits = InstanceLimits {
        disk_mib: 48,
        ..InstanceLimits::default()
    };
    let tenant_a = TenantTarget {
        database: DATABASE_A,
        username: USER_A,
    };
    let tenant_b = TenantTarget {
        database: DATABASE_B,
        username: USER_B,
    };
    for (target, password) in [(tenant_a, PASSWORD_A), (tenant_b, PASSWORD_B)] {
        let enforcement = create_managed_tenant(&pool, target, password, &limits)
            .await
            .expect("provision a tenant with the production quota path");
        assert!(
            enforcement.enforced,
            "{protocol} unexpectedly fell back to soft tenant enforcement"
        );
    }

    assert_ok(
        run_as(
            &pool,
            tenant_a,
            PASSWORD_A,
            DATABASE_A,
            quota_table_sql(protocol),
        )
        .await,
        "create tenant A quota probe table",
    );
    let mut quota_hit = false;
    for _ in 0..96 {
        match run_as(
            &pool,
            tenant_a,
            PASSWORD_A,
            DATABASE_A,
            quota_insert_sql(protocol),
        )
        .await
        {
            Ok(_) => {}
            Err(DockerError::ExecFailed { exit_code, .. }) => {
                assert!(
                    !matches!(exit_code, 126 | 127),
                    "the tenant client command was unavailable"
                );
                quota_hit = true;
                break;
            }
            Err(error) => panic!("tenant A quota write failed outside the engine: {error}"),
        }
    }
    assert!(
        quota_hit,
        "{protocol} accepted writes beyond the 48 MiB tenant quota"
    );
    let used = disk::quota_usage_bytes(&pool.config, &pool.runtime, tenant_a)
        .await
        .expect("read the hard tenant quota counter");
    assert!(
        used >= 32 * 1024 * 1024,
        "{protocol} reported only {used} bytes when the engine hit its quota"
    );

    // A full tenant must not consume another tenant's independent project.
    assert_ok(
        run_as(
            &pool,
            tenant_b,
            PASSWORD_B,
            DATABASE_B,
            quota_table_sql(protocol),
        )
        .await,
        "create tenant B quota probe table",
    );
    assert_ok(
        run_as(
            &pool,
            tenant_b,
            PASSWORD_B,
            DATABASE_B,
            quota_insert_sql(protocol),
        )
        .await,
        "tenant B write after tenant A reached quota",
    );

    drop_managed_tenant(&pool, tenant_a)
        .await
        .expect("remove a full tenant through the production teardown path");
    assert_ok(
        run_as(
            &pool,
            tenant_b,
            PASSWORD_B,
            DATABASE_B,
            quota_insert_sql(protocol),
        )
        .await,
        "tenant B write after tenant A quota teardown",
    );
    drop_managed_tenant(&pool, tenant_b)
        .await
        .expect("remove tenant B during test cleanup");
}

async fn exercise_two_tenant_pool(protocol: Protocol) {
    let pool = SharedPool::start(protocol).await;
    exercise_started_pool(pool).await;
}

async fn exercise_two_tenant_pool_with_image(protocol: Protocol, image: &str) {
    let pool = SharedPool::start_with_image(protocol, image).await;
    exercise_started_pool(pool).await;
}

async fn exercise_started_pool(pool: SharedPool) {
    let protocol = pool.runtime.protocol;
    let limits = InstanceLimits::default();
    let tenant_a = TenantTarget {
        database: DATABASE_A,
        username: USER_A,
    };
    let tenant_b = TenantTarget {
        database: DATABASE_B,
        username: USER_B,
    };

    create_managed_tenant(&pool, tenant_a, PASSWORD_A, &limits)
        .await
        .expect("provision tenant A through the canonical shared-tenant path");
    create_managed_tenant(&pool, tenant_b, PASSWORD_B, &limits)
        .await
        .expect("provision tenant B through the canonical shared-tenant path");

    assert_ok(
        run_as(
            &pool,
            tenant_a,
            PASSWORD_A,
            DATABASE_A,
            seed_sql(protocol, "a"),
        )
        .await,
        "tenant A seed",
    );
    assert_ok(
        run_as(
            &pool,
            tenant_b,
            PASSWORD_B,
            DATABASE_B,
            seed_sql(protocol, "b"),
        )
        .await,
        "tenant B seed",
    );
    assert_tenant_b_works(&pool, tenant_b).await;

    if protocol == Protocol::Clickhouse {
        assert_clickhouse_activity_window(&pool, tenant_a).await;
    }

    assert_denied(
        run_as(&pool, tenant_a, PASSWORD_A, DATABASE_B, read_sql(protocol)).await,
        protocol,
        "tenant A reading tenant B",
    );
    assert_denied(
        run_as(
            &pool,
            tenant_a,
            PASSWORD_A,
            DATABASE_B,
            cross_tenant_write_sql(protocol),
        )
        .await,
        protocol,
        "tenant A writing tenant B",
    );

    for (operation, database, sql) in forbidden_operations(protocol, &pool.runtime.runtime_id) {
        assert_denied(
            run_as(&pool, tenant_a, PASSWORD_A, database, &sql).await,
            protocol,
            operation,
        );
    }
    assert_tenant_b_works(&pool, tenant_b).await;

    fence(&pool.docker, &pool.runtime, tenant_a)
        .await
        .expect("fence only tenant A");
    assert_auth_rejected(
        verify_password(&pool.docker, &pool.runtime, tenant_a, PASSWORD_A).await,
        "fenced tenant A authentication",
    );
    assert_tenant_b_works(&pool, tenant_b).await;

    unfence(&pool.docker, &pool.runtime, tenant_a)
        .await
        .expect("unfence only tenant A");
    verify_password(&pool.docker, &pool.runtime, tenant_a, PASSWORD_A)
        .await
        .expect("unfenced tenant A authenticates again");

    rotate_password(&pool.docker, &pool.runtime, tenant_a, PASSWORD_A_ROTATED)
        .await
        .expect("rotate only tenant A password");
    assert_auth_rejected(
        verify_password(&pool.docker, &pool.runtime, tenant_a, PASSWORD_A).await,
        "tenant A old password after rotation",
    );
    verify_password(&pool.docker, &pool.runtime, tenant_a, PASSWORD_A_ROTATED)
        .await
        .expect("tenant A replacement password authenticates");
    assert_tenant_b_works(&pool, tenant_b).await;

    drop_managed_tenant(&pool, tenant_a)
        .await
        .expect("drop only tenant A");
    assert_auth_rejected(
        verify_password(&pool.docker, &pool.runtime, tenant_a, PASSWORD_A_ROTATED).await,
        "deleted tenant A authentication",
    );
    assert_tenant_b_works(&pool, tenant_b).await;

    drop_managed_tenant(&pool, tenant_b)
        .await
        .expect("remove tenant B during test cleanup");
}

async fn assert_clickhouse_activity_window(pool: &SharedPool, tenant: TenantTarget<'_>) {
    let first = super::clickhouse_telemetry_window(
        &pool.docker,
        &pool.runtime,
        None,
        crate::monitoring::clickhouse_collect_sql(),
    )
    .await
    .expect("establish the ClickHouse telemetry checkpoint");
    let checkpoint = telemetry_checkpoint(&first.stdout);

    assert_ok(
        run_as(
            pool,
            tenant,
            PASSWORD_A,
            DATABASE_A,
            read_sql(Protocol::Clickhouse),
        )
        .await,
        "run a tenant query inside the accounting window",
    );
    let second = super::clickhouse_telemetry_window(
        &pool.docker,
        &pool.runtime,
        Some(checkpoint),
        crate::monitoring::clickhouse_collect_sql(),
    )
    .await
    .expect("collect the ClickHouse telemetry window");
    let row = second
        .stdout
        .lines()
        .find(|line| line.starts_with(&format!("{}\t", tenant.username)))
        .unwrap_or_else(|| {
            panic!(
                "ClickHouse telemetry did not attribute the tenant query: {:?}",
                second.stdout
            )
        });
    let fields = row.split('\t').collect::<Vec<_>>();
    assert_eq!(
        fields.len(),
        7,
        "unexpected ClickHouse telemetry row: {row}"
    );
    assert!(
        fields[3].parse::<u64>().is_ok_and(|reads| reads >= 1),
        "ClickHouse telemetry did not classify the completed SELECT: {row}"
    );
    assert_clickhouse_query_log_text_bounded(pool).await;
}

async fn assert_clickhouse_query_log_text_bounded(pool: &SharedPool) {
    let long_query = format!("SELECT 1 /*{}*/", "x".repeat(8 * 1024));
    assert!(long_query.len() > 1024);
    assert_ok(
        run_as(
            pool,
            TenantTarget {
                database: DATABASE_A,
                username: USER_A,
            },
            PASSWORD_A,
            DATABASE_A,
            &long_query,
        )
        .await,
        "run an oversized tenant query through the query-log text bound",
    );
    let sql = format!(
        "SELECT count(), max(length(query)), max(length(formatted_query)), max(length(log_comment)), sum(length(query) + length(formatted_query) + length(log_comment)) FROM system.query_log WHERE type = 'QueryFinish' AND user = '{}' FORMAT TabSeparatedRaw",
        USER_A
    );
    let output = super::clickhouse_telemetry_window(&pool.docker, &pool.runtime, None, &sql)
        .await
        .expect("measure the bounded ClickHouse tenant query-log text");
    let row = output
        .stdout
        .lines()
        .find(|line| !line.starts_with("__DBE_CUTOFF__\t"))
        .unwrap_or_else(|| panic!("missing ClickHouse query-log size row: {:?}", output.stdout));
    let values = row
        .split('\t')
        .map(|value| value.parse::<u64>())
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("invalid ClickHouse query-log size row {row:?}: {error}"));
    assert_eq!(values.len(), 5, "unexpected query-log size row: {row}");
    let [rows, query_max, formatted_max, comment_max, text_bytes] = values.as_slice() else {
        unreachable!("length checked above")
    };
    assert!(*rows > 0, "tenant queries were not retained for accounting");
    assert_eq!(*query_max, 1024, "retained query text was not cut to 1 KiB");
    assert_eq!(*formatted_max, 0, "formatted query text was retained");
    assert_eq!(*comment_max, 0, "tenant log comments were retained");
    assert!(
        *text_bytes <= rows.saturating_mul(1024),
        "retained tenant-controlled query-log text exceeded its per-row bound"
    );
}

fn telemetry_checkpoint(output: &str) -> u64 {
    output
        .lines()
        .find_map(|line| line.strip_prefix("__DBE_CUTOFF__\t"))
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("missing ClickHouse telemetry checkpoint: {output:?}"))
}

async fn create_managed_tenant(
    pool: &SharedPool,
    target: TenantTarget<'_>,
    password: &str,
    limits: &InstanceLimits,
) -> Result<crate::disk::DiskEnforcement, String> {
    disk::prepare(
        &pool.config,
        &pool.docker,
        &pool.runtime,
        target,
        limits.disk_mib,
    )
    .await
    .map_err(|error| error.to_string())?;
    create(&pool.docker, &pool.runtime, target, password, limits)
        .await
        .map_err(|error| error.to_string())?;
    disk::set_limit(
        &pool.config,
        &pool.docker,
        &pool.runtime,
        target,
        limits.disk_mib,
    )
    .await
    .map_err(|error| error.to_string())
}

async fn drop_managed_tenant(pool: &SharedPool, target: TenantTarget<'_>) -> Result<(), String> {
    disk::prepare_drop(&pool.config, &pool.runtime, target)
        .await
        .map_err(|error| error.to_string())?;
    drop_tenant(&pool.docker, &pool.runtime, target)
        .await
        .map_err(|error| error.to_string())?;
    disk::remove(&pool.config, &pool.runtime, target)
        .await
        .map_err(|error| error.to_string())
}

async fn assert_tenant_b_works(pool: &SharedPool, tenant_b: TenantTarget<'_>) {
    verify_password(&pool.docker, &pool.runtime, tenant_b, PASSWORD_B)
        .await
        .expect("tenant B password remains valid");
    let output = run_as(
        pool,
        tenant_b,
        PASSWORD_B,
        DATABASE_B,
        read_sql(pool.runtime.protocol),
    )
    .await;
    let output = assert_ok(output, "tenant B read after tenant A lifecycle operation");
    assert_eq!(
        output.stdout.trim(),
        "b",
        "tenant B data changed during a tenant A lifecycle operation"
    );
}

fn seed_sql(protocol: Protocol, value: &str) -> &'static str {
    match (protocol, value) {
        (Protocol::Postgres, "a") => {
            "CREATE TABLE probe (id integer PRIMARY KEY, value text); INSERT INTO probe VALUES (1, 'a');"
        }
        (Protocol::Postgres, "b") => {
            "CREATE TABLE probe (id integer PRIMARY KEY, value text); INSERT INTO probe VALUES (1, 'b');"
        }
        (Protocol::Mysql | Protocol::Mariadb, "a") => {
            "CREATE TABLE probe (id INT PRIMARY KEY, value VARCHAR(8)); INSERT INTO probe VALUES (1, 'a');"
        }
        (Protocol::Mysql | Protocol::Mariadb, "b") => {
            "CREATE TABLE probe (id INT PRIMARY KEY, value VARCHAR(8)); INSERT INTO probe VALUES (1, 'b');"
        }
        (Protocol::Mongodb, "a") => "db.probe.insertOne({_id: 1, value: 'a'}); print('seeded');",
        (Protocol::Mongodb, "b") => "db.probe.insertOne({_id: 1, value: 'b'}); print('seeded');",
        (Protocol::Clickhouse, "a") => {
            "CREATE TABLE probe (id UInt64, value String) ENGINE = MergeTree ORDER BY id; INSERT INTO probe VALUES (1, 'a');"
        }
        (Protocol::Clickhouse, "b") => {
            "CREATE TABLE probe (id UInt64, value String) ENGINE = MergeTree ORDER BY id; INSERT INTO probe VALUES (1, 'b');"
        }
        _ => panic!("unsupported shared integration seed for {protocol}"),
    }
}

fn read_sql(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Postgres | Protocol::Mysql | Protocol::Mariadb | Protocol::Clickhouse => {
            "SELECT value FROM probe WHERE id = 1"
        }
        Protocol::Mongodb => "print(db.probe.findOne({_id: 1}).value)",
        _ => panic!("unsupported shared integration read for {protocol}"),
    }
}

fn cross_tenant_write_sql(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Postgres | Protocol::Mysql | Protocol::Mariadb => {
            "INSERT INTO probe VALUES (2, 'intrusion')"
        }
        Protocol::Mongodb => "db.probe.insertOne({_id: 2, value: 'intrusion'})",
        Protocol::Clickhouse => "INSERT INTO probe VALUES (2, 'intrusion')",
        _ => panic!("unsupported shared integration write for {protocol}"),
    }
}

fn quota_table_sql(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Postgres => {
            "CREATE TABLE quota_fill (id bigserial PRIMARY KEY, payload bytea NOT NULL)"
        }
        Protocol::Mysql | Protocol::Mariadb => {
            "CREATE TABLE quota_fill (id BIGINT AUTO_INCREMENT PRIMARY KEY, payload LONGBLOB NOT NULL) ENGINE=InnoDB"
        }
        _ => panic!("{protocol} has no hard shared-tenant quota layout"),
    }
}

fn quota_insert_sql(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Postgres => {
            "INSERT INTO quota_fill (payload) SELECT decode(string_agg(md5(random()::text), ''), 'hex') FROM generate_series(1, 65536)"
        }
        Protocol::Mysql | Protocol::Mariadb => {
            "INSERT INTO quota_fill (payload) VALUES (UNHEX(REPEAT(SHA2(UUID(), 512), 32768)))"
        }
        _ => panic!("{protocol} has no hard shared-tenant quota layout"),
    }
}

fn forbidden_operations(
    protocol: Protocol,
    runtime_id: &str,
) -> Vec<(&'static str, &'static str, String)> {
    match protocol {
        Protocol::Postgres => vec![
            (
                "tenant A creating an unmetered temporary table",
                DATABASE_A,
                "CREATE TEMPORARY TABLE shared_temp_escape (value INT)".to_string(),
            ),
            (
                "tenant A placing a table in the unmetered default tablespace",
                DATABASE_A,
                "CREATE TABLE shared_default_escape (value INT) TABLESPACE pg_default"
                    .to_string(),
            ),
            (
                "tenant A placing a table in another tenant's quota tablespace",
                DATABASE_A,
                format!(
                    "CREATE TABLE shared_cross_quota_escape (value INT) TABLESPACE {}",
                    crate::databases::postgres::provision::tenant_tablespace_name(DATABASE_B)
                ),
            ),
            (
                "tenant A connecting to the postgres system database",
                "postgres",
                "SELECT 1".to_string(),
            ),
            (
                "tenant A connecting to the shared control database",
                "dbe_control",
                "SELECT 1".to_string(),
            ),
            (
                "tenant A connecting to template1",
                "template1",
                "SELECT 1".to_string(),
            ),
            (
                "tenant A creating an administrator role",
                DATABASE_A,
                "CREATE ROLE shared_escape SUPERUSER".to_string(),
            ),
            (
                "tenant A executing an operating-system program",
                DATABASE_A,
                "COPY (SELECT 1) TO PROGRAM 'true'".to_string(),
            ),
        ],
        Protocol::Mysql | Protocol::Mariadb => vec![
            (
                "tenant A creating an unmetered temporary table",
                DATABASE_A,
                "CREATE TEMPORARY TABLE shared_temp_escape (value INT)".to_string(),
            ),
            (
                "tenant A creating an administrator account",
                DATABASE_A,
                "CREATE USER 'shared_escape'@'%' IDENTIFIED BY 'x'".to_string(),
            ),
            (
                "tenant A writing a server-side file",
                DATABASE_A,
                format!(
                    "SELECT 'escape' INTO OUTFILE '/tmp/{}_escape'",
                    runtime_id.replace('-', "_")
                ),
            ),
        ],
        Protocol::Mongodb => vec![
            (
                "tenant A creating an administrator account",
                "admin",
                "db.createUser({user: 'shared_escape', pwd: 'x', roles: [{role: 'root', db: 'admin'}]})"
                    .to_string(),
            ),
            (
                "tenant A running server-side JavaScript",
                DATABASE_A,
                "db.probe.find({$where: 'function () { return true; }'}).toArray()".to_string(),
            ),
        ],
        Protocol::Clickhouse => vec![
            (
                "tenant A disabling shared query accounting",
                DATABASE_A,
                "SET log_queries = 0".to_string(),
            ),
            (
                "tenant A expanding retained query text",
                DATABASE_A,
                "SET log_queries_cut_to_length = 1000000".to_string(),
            ),
            (
                "tenant A adding retained log comments",
                DATABASE_A,
                "SET log_comment = 'tenant-controlled-log-payload'".to_string(),
            ),
            (
                "tenant A retaining formatted query text",
                DATABASE_A,
                "SET log_formatted_queries = 1".to_string(),
            ),
            (
                "tenant A expanding the query parser input bound",
                DATABASE_A,
                "SET max_query_size = 1048576".to_string(),
            ),
            (
                "tenant A enabling per-thread query logging",
                DATABASE_A,
                "SET log_query_threads = 1".to_string(),
            ),
            (
                "tenant A enabling dependent-view query logging",
                DATABASE_A,
                "SET log_query_views = 1".to_string(),
            ),
            (
                "tenant A enabling processor profile logging",
                DATABASE_A,
                "SET log_processors_profiles = 1".to_string(),
            ),
            (
                "tenant A reading raw shared query history",
                DATABASE_A,
                "SELECT count() FROM system.query_log".to_string(),
            ),
            (
                "tenant A creating an administrator account",
                DATABASE_A,
                "CREATE USER shared_escape IDENTIFIED BY 'x'".to_string(),
            ),
            (
                "tenant A creating a server-file table",
                DATABASE_A,
                "CREATE TABLE external_escape (line String) ENGINE = File(TSV, '/etc/passwd')"
                    .to_string(),
            ),
            (
                "tenant A reading a server file through a table function",
                DATABASE_A,
                "SELECT * FROM file('/etc/passwd', LineAsString)".to_string(),
            ),
            (
                "tenant A reaching an HTTP source through a table function",
                DATABASE_A,
                "SELECT * FROM url('http://127.0.0.1:8123/', 'CSV', 'value String') LIMIT 1"
                    .to_string(),
            ),
            (
                "tenant A reaching object storage through a table function",
                DATABASE_A,
                "SELECT * FROM s3('http://127.0.0.1:8123/bucket', 'CSV', 'value String') LIMIT 1"
                    .to_string(),
            ),
            (
                "tenant A reaching another ClickHouse server through a table function",
                DATABASE_A,
                "SELECT * FROM remote('127.0.0.1:9000', 'system', 'one')".to_string(),
            ),
            (
                "tenant A detaching a whole table from disk accounting",
                DATABASE_A,
                "DETACH TABLE probe".to_string(),
            ),
            (
                "tenant A creating an uncharged frozen table snapshot",
                DATABASE_A,
                "ALTER TABLE probe FREEZE".to_string(),
            ),
        ],
        _ => panic!("unsupported shared integration privilege test for {protocol}"),
    }
}

async fn run_as(
    pool: &SharedPool,
    auth: TenantTarget<'_>,
    password: &str,
    database: &str,
    statement: &str,
) -> Result<CommandOutput, DockerError> {
    let password = SecretString::from(password.to_string());
    let command = match pool.runtime.protocol {
        Protocol::Postgres => format!(
            "set -eu\nprintf %s {} | PGPASSWORD=\"$DBE_TEST_PASSWORD\" psql -X -A -t -q -h /var/run/postgresql -U {} -d {} -v ON_ERROR_STOP=1",
            sh_quote(statement),
            sh_quote(auth.username),
            sh_quote(database),
        ),
        Protocol::Mysql => format!(
            "set -eu\nprintf %s {} | MYSQL_PWD=\"$DBE_TEST_PASSWORD\" mysql --protocol=socket --socket=/var/run/mysqld/mysqld.sock --batch --skip-column-names --raw -u {} {}",
            sh_quote(statement),
            sh_quote(auth.username),
            sh_quote(database),
        ),
        Protocol::Mariadb => format!(
            "set -eu\nprintf %s {} | MYSQL_PWD=\"$DBE_TEST_PASSWORD\" mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock --batch --skip-column-names --raw -u {} {}",
            sh_quote(statement),
            sh_quote(auth.username),
            sh_quote(database),
        ),
        Protocol::Mongodb => format!(
            "mongosh --quiet --host 127.0.0.1 --username {} --password \"$DBE_TEST_PASSWORD\" --authenticationDatabase {} {} --eval {}",
            sh_quote(auth.username),
            sh_quote(auth.database),
            sh_quote(database),
            sh_quote(statement),
        ),
        Protocol::Clickhouse => format!(
            "set -eu\nprintf %s {} | CLICKHOUSE_PASSWORD=\"$DBE_TEST_PASSWORD\" clickhouse-client --host 127.0.0.1 --user {} --database {} --multiquery",
            sh_quote(statement),
            sh_quote(auth.username),
            sh_quote(database),
        ),
        protocol => panic!("unsupported shared integration command for {protocol}"),
    };
    pool.docker
        .exec_tenant_shell(
            pool.runtime.protocol,
            &pool.runtime.runtime_id,
            &command,
            &[("DBE_TEST_PASSWORD", &password)],
            OPERATION_TIMEOUT,
        )
        .await
}

fn assert_ok(output: Result<CommandOutput, DockerError>, operation: &str) -> CommandOutput {
    output.unwrap_or_else(|error| panic!("{operation} failed: {error}"))
}

fn assert_denied(output: Result<CommandOutput, DockerError>, protocol: Protocol, operation: &str) {
    match output {
        Err(DockerError::ExecFailed {
            exit_code,
            failure_output,
            ..
        }) => {
            assert!(
                !matches!(exit_code, 126 | 127),
                "{operation} did not exercise engine authorization because the client command could not run"
            );
            let output = failure_output.to_ascii_lowercase();
            let authorization_failed = match protocol {
                Protocol::Postgres => {
                    output.contains("permission denied") || output.contains("must be superuser")
                }
                Protocol::Mysql | Protocol::Mariadb => {
                    output.contains("command denied")
                        || output.contains("access denied")
                        || output.contains("not allowed")
                }
                Protocol::Mongodb => {
                    output.contains("not authorized") || output.contains("unauthorized")
                }
                Protocol::Clickhouse => {
                    output.contains("not enough privileges")
                        || output.contains("access denied")
                        || output.contains("cannot be changed")
                        || output.contains("should not be changed")
                        || output.contains("setting constraint")
                }
                _ => false,
            };
            assert!(
                authorization_failed,
                "{operation} failed for a reason other than tenant authorization: {failure_output}"
            );
        }
        Err(error) => panic!("{operation} failed for an infrastructure reason: {error}"),
        Ok(_) => panic!("{operation} unexpectedly succeeded"),
    }
}

fn assert_auth_rejected(result: Result<(), TenantEngineError>, operation: &str) {
    match result {
        Err(TenantEngineError::Docker(DockerError::ExecFailed { exit_code, .. })) => assert!(
            !matches!(exit_code, 126 | 127),
            "{operation} did not exercise engine authentication because the client command could not run"
        ),
        Err(error) => panic!("{operation} failed for an infrastructure reason: {error}"),
        Ok(()) => panic!("{operation} unexpectedly succeeded"),
    }
}

struct SharedPool {
    config: Config,
    docker: DockerRuntime,
    runtime: EngineRuntime,
    container_name: String,
    _temp_root: Option<tempfile::TempDir>,
}

impl SharedPool {
    async fn start(protocol: Protocol) -> Self {
        Self::start_with_image(protocol, test_image(protocol)).await
    }

    async fn start_with_image(protocol: Protocol, image: &str) -> Self {
        let root = tempfile::tempdir().expect("create shared-pool test directory");
        Self::start_in(
            protocol,
            image,
            root.path().to_path_buf(),
            DiskConfig {
                mode: DiskLimitMode::SoftScanner,
                ..DiskConfig::default()
            },
            Some(root),
        )
        .await
    }

    async fn start_on_project_quota(protocol: Protocol, root: PathBuf) -> Self {
        Self::start_in(
            protocol,
            test_image(protocol),
            root,
            DiskConfig {
                mode: DiskLimitMode::ProjectQuota,
                project_id_base: 4_000_000,
                ..DiskConfig::default()
            },
            None,
        )
        .await
    }

    async fn start_in(
        protocol: Protocol,
        image: &str,
        root: PathBuf,
        disk: DiskConfig,
        temp_root: Option<tempfile::TempDir>,
    ) -> Self {
        let docker = DockerRuntime::new(&DaemonConfig::default(), false)
            .expect("connect to the local Docker daemon");
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let runtime_id = format!("shared_it_{}_{}", protocol.as_str(), &suffix[..12]);
        let (paths, path_config) = test_paths(&root, &runtime_id).await;
        let config = Config {
            paths: path_config,
            disk,
            ..Config::default()
        };
        let mut spec = shared_spec(protocol, &runtime_id, image, &paths, &root).await;
        spec.user = Some(
            prepare_instance_container_user(&docker, &paths, protocol)
                .await
                .expect("prepare shared-pool bind-mount ownership"),
        );
        let container_name = docker
            .container_name(protocol, &runtime_id)
            .expect("derive the managed test container name");
        docker
            .create(&spec)
            .await
            .expect("create the production shared-runtime container spec");

        let pool = Self {
            config,
            runtime: runtime(protocol, &runtime_id, image, &container_name, &paths),
            docker,
            container_name,
            _temp_root: temp_root,
        };
        pool.docker
            .start(protocol, &runtime_id)
            .await
            .expect("start the shared-runtime test container");
        if protocol == Protocol::Mongodb {
            bootstrap_mongodb_root(&pool).await;
        }
        pool.docker
            .wait_until_ready(protocol, &runtime_id, STARTUP_TIMEOUT)
            .await
            .expect("wait for the production shared-runtime readiness probe");
        secure_pool(&pool.docker, &pool.runtime)
            .await
            .expect("reconcile production shared-pool isolation");
        pool
    }
}

impl Drop for SharedPool {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "--force", &self.container_name])
            .output();
    }
}

async fn test_paths(root: &Path, runtime_id: &str) -> (InstancePaths, PathConfig) {
    let path = |name: &str| root.join(name).display().to_string();
    let config = PathConfig {
        data: path("data"),
        metadata: path("metadata"),
        volumes: path("volumes"),
        backups: path("backups"),
        sockets: path("sockets"),
        locks: path("locks"),
        logs: path("logs"),
        artifacts: path("artifacts"),
        exports: path("exports"),
        imports: path("imports"),
        fuse: path("fuse"),
        tmp: path("tmp"),
    };
    for directory in [
        &config.data,
        &config.metadata,
        &config.volumes,
        &config.backups,
        &config.sockets,
        &config.locks,
        &config.logs,
        &config.artifacts,
        &config.exports,
        &config.imports,
        &config.fuse,
        &config.tmp,
    ] {
        std::fs::create_dir_all(directory).expect("create shared-pool test root");
    }
    let paths = InstancePaths::new(&config, runtime_id).expect("build shared-pool paths");
    paths
        .create_dirs()
        .await
        .expect("create shared-pool instance directories");
    (paths, config)
}

async fn shared_spec(
    protocol: Protocol,
    runtime_id: &str,
    image: &str,
    paths: &InstancePaths,
    root: &Path,
) -> DockerInstanceSpec {
    let admin = || SecretString::from(ADMIN_PASSWORD.to_string());
    match protocol {
        Protocol::Postgres => databases::postgres::docker::shared_spec(
            runtime_id,
            image,
            admin(),
            paths.data.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mysql => databases::mysql::docker::shared_spec(
            runtime_id,
            image,
            admin(),
            paths.data.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mariadb => databases::mariadb::docker::shared_spec(
            runtime_id,
            image,
            admin(),
            paths.data.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Mongodb => databases::mongodb::docker::shared_spec(
            runtime_id,
            image,
            admin(),
            paths.data.clone(),
            paths.sockets.clone(),
        ),
        Protocol::Clickhouse => {
            let config =
                databases::clickhouse::docker::write_shared_hosted_config(&paths.runtime_config)
                    .await
                    .expect("write the production hosted ClickHouse config");
            let bridge = crate::bins::get_socket_bridge_bin_path(&root.join("runtime"))
                .await
                .expect("install the production socket bridge helper");
            databases::clickhouse::docker::shared_spec(
                runtime_id,
                image,
                admin(),
                paths.data.clone(),
                config,
                paths.sockets.clone(),
                bridge,
            )
        }
        _ => panic!("unsupported shared integration runtime for {protocol}"),
    }
}

fn runtime(
    protocol: Protocol,
    runtime_id: &str,
    image: &str,
    container_name: &str,
    paths: &InstancePaths,
) -> EngineRuntime {
    EngineRuntime {
        pending_image: None,
        desired_state: crate::instances::metadata::DesiredInstanceState::Running,
        owner: Some(crate::placement::test_support::owner(runtime_id)),
        schema_version: ENGINE_RUNTIME_SCHEMA_VERSION,
        runtime_id: runtime_id.to_string(),
        protocol,
        deployment_mode: DeploymentMode::Shared,
        status: EngineRuntimeStatus::Running,
        backend: BackendEndpoint::UnixSocket {
            socket_path: backend_socket_path(&paths.sockets, protocol)
                .display()
                .to_string(),
        },
        runtime: RuntimeMetadata {
            kind: RuntimeKind::Docker,
            container_name: container_name.to_string(),
            network_mode: "none".to_string(),
        },
        limits: InstanceLimits::default(),
        image: image.to_string(),
        database_version: None,
        compatibility: None,

        max_tenants: 16,
        reserved: RuntimeReservation::default(),
        admin_secret: Some(ADMIN_PASSWORD.to_string()),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    }
}

async fn bootstrap_mongodb_root(pool: &SharedPool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let ready = Command::new("docker")
            .args([
                "exec",
                &pool.container_name,
                "mongosh",
                "--quiet",
                "mongodb://127.0.0.1/admin?directConnection=true",
                "--eval",
                "db.adminCommand({ ping: 1 }).ok",
            ])
            .output()
            .is_ok_and(|output| output.status.success());
        if ready {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "MongoDB localhost bootstrap did not become ready"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    let script = databases::mongodb::provision::create_root_user_script(
        databases::mongodb::docker::INTERNAL_ROOT_USERNAME,
    )
    .expect("build the canonical MongoDB root bootstrap script");
    let command = format!(
        "mongosh --quiet mongodb://127.0.0.1/admin?directConnection=true --eval {}",
        sh_quote(&script)
    );
    let password = SecretString::from(ADMIN_PASSWORD.to_string());
    pool.docker
        .exec_shell_with_secrets_timeout(
            Protocol::Mongodb,
            &pool.runtime.runtime_id,
            &command,
            &[("DBE_MONGO_ROOT_PASSWORD", &password)],
            OPERATION_TIMEOUT,
        )
        .await
        .expect("bootstrap MongoDB root with the production script");
}

fn test_image(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Postgres => "postgres:18.4",
        Protocol::Mysql => "mysql:8.4",
        Protocol::Mariadb => "mariadb:12.3.2",
        Protocol::Mongodb => "mongo:8.3.4",
        Protocol::Clickhouse => "clickhouse/clickhouse-server:26.4.4.38",
        _ => panic!("unsupported shared integration image for {protocol}"),
    }
}
