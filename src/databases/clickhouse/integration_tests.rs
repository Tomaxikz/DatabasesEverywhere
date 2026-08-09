use std::{
    process::{Command, Output},
    thread::sleep,
    time::{Duration, Instant},
};

const IMAGE: &str = "clickhouse/clickhouse-server:25.8.25.37";
const DATABASE: &str = "integration_db";
const TENANT: &str = "integration_user";
const ORIGINAL_PASSWORD: &str = "integration-original-password";
const REPLACEMENT_PASSWORD: &str = "integration-replacement-password";

#[test]
#[ignore = "requires a local Docker daemon and the pinned ClickHouse image"]
fn clickhouse_recreation_rotates_and_rolls_back_the_startup_credential() {
    let resources = TestResources::new();
    resources.start(ORIGINAL_PASSWORD);
    wait_until_ready(&resources.name, ORIGINAL_PASSWORD);
    assert_query_succeeds(
        &resources.name,
        ORIGINAL_PASSWORD,
        "CREATE TABLE IF NOT EXISTS password_reset_probe (id UInt64, value String) ENGINE = MergeTree ORDER BY id; INSERT INTO password_reset_probe VALUES (1, 'preserved')",
    );

    resources.recreate(REPLACEMENT_PASSWORD);
    wait_until_ready(&resources.name, REPLACEMENT_PASSWORD);
    assert_authentication_fails(&resources.name, ORIGINAL_PASSWORD);
    assert_eq!(
        query(
            &resources.name,
            REPLACEMENT_PASSWORD,
            "SELECT value FROM password_reset_probe WHERE id = 1"
        ),
        "preserved",
        "persistent ClickHouse data was lost during credential recreation"
    );

    resources.recreate(ORIGINAL_PASSWORD);
    wait_until_ready(&resources.name, ORIGINAL_PASSWORD);
    assert_authentication_fails(&resources.name, REPLACEMENT_PASSWORD);
    assert_eq!(
        query(
            &resources.name,
            ORIGINAL_PASSWORD,
            "SELECT value FROM password_reset_probe WHERE id = 1"
        ),
        "preserved",
        "persistent ClickHouse data was lost during credential rollback"
    );
}

struct TestResources {
    name: String,
    volume: String,
}

impl TestResources {
    fn new() -> Self {
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let resources = Self {
            name: format!("dbev-clickhouse-test-{suffix}"),
            volume: format!("dbev-clickhouse-test-{suffix}"),
        };
        let created = Command::new("docker")
            .args(["volume", "create", &resources.volume])
            .output()
            .expect("create ClickHouse integration-test volume");
        assert_success(&created, "create ClickHouse integration-test volume");
        resources
    }

    fn start(&self, password: &str) {
        let output = Command::new("docker")
            .args([
                "run",
                "--detach",
                "--name",
                &self.name,
                "--network",
                "none",
                "--volume",
                &format!("{}:/var/lib/clickhouse", self.volume),
                "--env",
                &format!("CLICKHOUSE_DB={DATABASE}"),
                "--env",
                &format!("CLICKHOUSE_USER={TENANT}"),
                "--env",
                &format!("CLICKHOUSE_PASSWORD={password}"),
                "--env",
                "CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1",
                "--env",
                "CLICKHOUSE_RUN_AS_ROOT=1",
                "--env",
                "CLICKHOUSE_DO_NOT_CHOWN=1",
                IMAGE,
            ])
            .output()
            .expect("start ClickHouse integration-test container");
        assert_success(&output, "start ClickHouse integration-test container");
    }

    fn recreate(&self, password: &str) {
        self.remove_container();
        self.start(password);
    }

    fn remove_container(&self) {
        let _ = Command::new("docker")
            .args(["rm", "--force", &self.name])
            .output();
    }
}

impl Drop for TestResources {
    fn drop(&mut self) {
        self.remove_container();
        let _ = Command::new("docker")
            .args(["volume", "rm", "--force", &self.volume])
            .output();
    }
}

fn wait_until_ready(name: &str, password: &str) {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last_output = None;
    while Instant::now() < deadline {
        let output = exec_clickhouse(name, password, "SELECT 1");
        if output.status.success() {
            return;
        }
        last_output = Some(output);
        sleep(Duration::from_millis(250));
    }
    let output = last_output.expect("at least one ClickHouse readiness attempt");
    panic!(
        "ClickHouse did not become ready: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_query_succeeds(name: &str, password: &str, sql: &str) {
    let output = exec_clickhouse(name, password, sql);
    assert_success(&output, "execute ClickHouse integration-test query");
}

fn query(name: &str, password: &str, sql: &str) -> String {
    let output = exec_clickhouse(name, password, sql);
    assert_success(&output, "execute ClickHouse integration-test query");
    String::from_utf8(output.stdout)
        .expect("ClickHouse query output is UTF-8")
        .trim()
        .to_string()
}

fn assert_authentication_fails(name: &str, password: &str) {
    let output = exec_clickhouse(name, password, "SELECT 1");
    assert!(
        !output.status.success(),
        "superseded ClickHouse credential still authenticated"
    );
}

fn exec_clickhouse(name: &str, password: &str, sql: &str) -> Output {
    Command::new("docker")
        .args([
            "exec",
            name,
            "clickhouse-client",
            "--host",
            "127.0.0.1",
            "--user",
            TENANT,
            "--password",
            password,
            "--database",
            DATABASE,
            "--multiquery",
            "--query",
            sql,
        ])
        .output()
        .expect("run clickhouse-client in integration-test container")
}

fn assert_success(output: &Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
