use std::{
    io::Write,
    process::{Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use super::provision::provision_tenant_role_sql;

const IMAGE: &str = "postgres:18.4";
const ADMIN: &str = "dbe_admin";
const ADMIN_PASSWORD: &str = "integration-admin-password";
const DATABASE: &str = "integration_db";
const TENANT: &str = "integration_user";
const TENANT_PASSWORD: &str = "integration-tenant-password";

#[test]
#[ignore = "requires a local Docker daemon and postgres:18.4 image"]
fn postgres_18_provisions_a_restricted_database_owner() {
    let name = format!("dbev-postgres-test-{}", uuid::Uuid::new_v4().simple());
    let container = TestContainer::start(&name);
    wait_until_ready(&name);

    let mut child = Command::new("docker")
        .args([
            "exec",
            "-i",
            "-e",
            &format!("PGPASSWORD={ADMIN_PASSWORD}"),
            "-e",
            &format!("DBE_TENANT_PASSWORD={TENANT_PASSWORD}"),
            &name,
            "sh",
            "-c",
            "{ printf '%s\n' '\\getenv tenant_password DBE_TENANT_PASSWORD'; cat; } | psql -X -h /var/run/postgresql -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" -At -v ON_ERROR_STOP=1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start tenant provisioning psql");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(provision_tenant_role_sql(DATABASE, TENANT).as_bytes())
        .expect("write provisioning SQL");
    let output = child.wait_with_output().expect("wait for provisioning");
    assert!(
        output.status.success(),
        "tenant provisioning failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let hardened = run_hardening(&name);
    assert!(
        hardened.status.success(),
        "PostgreSQL hardening failed: {}",
        String::from_utf8_lossy(&hardened.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&hardened.stdout).lines().last(),
        Some("already_hardened")
    );
    let repeated = run_hardening(&name);
    assert!(repeated.status.success());
    assert_eq!(
        String::from_utf8_lossy(&repeated.stdout).lines().last(),
        Some("already_hardened")
    );

    install_legacy_peer_rule(&name);
    let repaired = run_hardening(&name);
    assert!(
        repaired.status.success(),
        "PostgreSQL peer-rule repair failed: {}",
        String::from_utf8_lossy(&repaired.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&repaired.stdout).lines().last(),
        Some("hardened")
    );

    assert_eq!(
        exec_psql(
            &name,
            ADMIN,
            "SELECT rolsuper::int || ':' || rolcreatedb::int || ':' || rolcreaterole::int || ':' || rolinherit::int || ':' || rolreplication::int || ':' || rolbypassrls::int FROM pg_roles WHERE rolname = 'integration_user'",
        ),
        "0:0:0:0:0:0"
    );
    assert_eq!(
        exec_psql(
            &name,
            ADMIN,
            "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()",
        ),
        TENANT
    );

    let tenant = Command::new("docker")
        .args([
            "exec",
            "-e",
            &format!("PGPASSWORD={TENANT_PASSWORD}"),
            &name,
            "psql",
            "-X",
            "-h",
            "/var/run/postgresql",
            "-U",
            TENANT,
            "-d",
            DATABASE,
            "-Atqc",
            "SELECT current_user",
        ])
        .output()
        .expect("validate tenant connection");
    assert!(
        tenant.status.success(),
        "tenant connection failed: {}",
        String::from_utf8_lossy(&tenant.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&tenant.stdout).trim(), TENANT);
    assert_eq!(
        exec_psql(
            &name,
            ADMIN,
            "SELECT rolpassword LIKE 'SCRAM-SHA-256$%' FROM pg_authid WHERE rolname = 'integration_user'",
        ),
        "t"
    );

    let rejected = Command::new("docker")
        .args([
            "exec",
            "-e",
            "PGPASSWORD=definitely-wrong",
            &name,
            "psql",
            "-X",
            "-h",
            "/var/run/postgresql",
            "-U",
            TENANT,
            "-d",
            DATABASE,
            "-Atqc",
            "SELECT 1",
        ])
        .output()
        .expect("attempt a wrong-password tenant connection");
    assert!(
        !rejected.status.success(),
        "PostgreSQL accepted a wrong password"
    );

    drop(container);
}

struct TestContainer(String);

impl TestContainer {
    fn start(name: &str) -> Self {
        let output = Command::new("docker")
            .args([
                "run",
                "--detach",
                "--rm",
                "--name",
                name,
                "--env",
                &format!("POSTGRES_USER={ADMIN}"),
                "--env",
                &format!("POSTGRES_PASSWORD={ADMIN_PASSWORD}"),
                "--env",
                &format!("POSTGRES_DB={DATABASE}"),
                "--env",
                &format!("DBE_POSTGRES_USER={TENANT}"),
                "--env",
                "POSTGRES_INITDB_ARGS=--auth-local=scram-sha-256 --auth-host=scram-sha-256",
                IMAGE,
                "postgres",
                "-c",
                "listen_addresses=",
                "-c",
                "password_encryption=scram-sha-256",
            ])
            .output()
            .expect("start PostgreSQL test container");
        assert!(
            output.status.success(),
            "failed to start PostgreSQL test container: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self(name.to_string())
    }
}

fn run_hardening(name: &str) -> std::process::Output {
    Command::new("docker")
        .args([
            "exec",
            "-e",
            &format!("DBE_TENANT_PASSWORD={TENANT_PASSWORD}"),
            "-e",
            &format!("DBE_POSTGRES_ADMIN_PASSWORD={ADMIN_PASSWORD}"),
            "-e",
            "DBE_INVALID_PASSWORD=definitely-wrong",
            name,
            "sh",
            "-c",
            &super::hardening::hardening_script(TENANT),
        ])
        .output()
        .expect("run PostgreSQL local-auth hardening")
}

fn install_legacy_peer_rule(name: &str) {
    let output = Command::new("docker")
        .args([
            "exec",
            name,
            "sh",
            "-c",
            r#"set -eu
hba="$PGDATA/pg_hba.conf"
tmp=$(mktemp "${hba}.test.XXXXXX")
trap 'rm -f "$tmp"' EXIT
awk '$1 != "local" { print }' "$hba" >"$tmp"
printf '%s\n' 'local all dbe_admin peer map=dbev_admin' 'local all all scram-sha-256' >>"$tmp"
chmod --reference="$hba" "$tmp"
mv -f "$tmp" "$hba"
trap - EXIT
kill -HUP 1
sleep 1"#,
        ])
        .output()
        .expect("install legacy PostgreSQL peer rule");
    assert!(
        output.status.success(),
        "failed to install legacy PostgreSQL peer rule: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

impl Drop for TestContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "--force", &self.0])
            .output();
    }
}

fn wait_until_ready(name: &str) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if Command::new("docker")
            .args([
                "exec",
                "-e",
                &format!("PGPASSWORD={ADMIN_PASSWORD}"),
                name,
                "psql",
                "-X",
                "-h",
                "/var/run/postgresql",
                "-U",
                ADMIN,
                "-d",
                DATABASE,
                "-Atqc",
                "SELECT 1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run PostgreSQL readiness query")
            .success()
        {
            return;
        }
        sleep(Duration::from_millis(250));
    }
    panic!("PostgreSQL test container did not become ready");
}

fn exec_psql(name: &str, user: &str, sql: &str) -> String {
    let output = Command::new("docker")
        .args([
            "exec",
            "-e",
            &format!("PGPASSWORD={ADMIN_PASSWORD}"),
            name,
            "psql",
            "-X",
            "-h",
            "/var/run/postgresql",
            "-U",
            user,
            "-d",
            DATABASE,
            "-Atqc",
            sql,
        ])
        .output()
        .expect("run PostgreSQL query");
    assert!(
        output.status.success(),
        "PostgreSQL query failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("PostgreSQL output is utf-8")
        .trim()
        .to_string()
}
