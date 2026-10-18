use super::*;
use crate::{
    server::{metadata::DesiredInstanceState, state::InstanceStore, test_support},
    utils::backend::BackendEndpoint,
};

#[test]
fn migration_replaces_all_local_authentication_with_scram() {
    let script = hardening_script("tenant_user");

    assert!(script.contains("local all all scram-sha-256"));
    assert!(script.contains("local replication dbe_replication scram-sha-256"));
    assert!(script.contains("replication_scram == 1"));
    assert!(script.contains("$2 == \"replication\""));
    assert!(!script.contains("local replication all"));
    assert!(!script.contains("host replication"));
    assert!(!script.contains("@REPLICATION"));
    assert!(!script.contains("@LOCAL_CLIENT"));
    assert!(!script.contains("@ENSURE_"));
    assert!(!script.contains("@RESET_REPLICATION"));
    assert!(script.contains("\\getenv replication_password DBE_REPLICATION_PASSWORD"));
    assert!(script.contains(" REPLICATION "));
    assert!(script.contains("NOSUPERUSER"));
    assert!(script.contains("NOBYPASSRLS"));
    assert!(script.contains("NOINHERIT"));
    assert!(script.contains("NOCREATEDB"));
    assert!(script.contains("NOCREATEROLE"));
    assert!(script.contains("LOGIN"));
    assert!(!script.contains("hunter2"));
    assert!(script.contains("DBE_POSTGRES_ADMIN_PASSWORD"));
    assert!(script.contains("DBE_INVALID_PASSWORD"));
    assert!(script.contains("kill -HUP 1"));
    assert!(!script.contains("peer map="));
    assert!(!script.contains("-v tenant_password="));
    assert!(script.contains("admin_available"));
    assert!(script.contains("tenant_available"));
    assert!(script.contains("mv -f \"$hba_tmp\" \"$hba_file\""));
    assert!(script.contains("case \"$replication_ownership\" in"));
    assert!(script.contains("dbe-managed-replication-v1"));
    let probe = script.find("replication_ownership=$(admin_psql").unwrap();
    let decision = script.find("case \"$replication_ownership\" in").unwrap();
    let confirmed_probe = script.find("confirmed=$(admin_psql").unwrap();
    assert!(probe < decision && decision < confirmed_probe);

    let candidate = shell_case_arm(&script, "candidate");
    let begin = candidate.find("BEGIN;").unwrap();
    let create = candidate.find("CREATE ROLE").unwrap();
    let commit = candidate.find("COMMIT;").unwrap();
    assert!(begin < create && create < commit);
    assert!(candidate.contains("COMMENT ON ROLE"));
    assert!(candidate.contains("replication_password"));
    assert!(candidate.contains("ON_ERROR_STOP=1"));
    assert!(!candidate.contains("exit "));
    assert!(!candidate.contains("hunter2"));

    let foreign = shell_case_arm(&script, "foreign");
    assert!(foreign.contains("replication_capture_blocked=true"));
    assert!(foreign.contains("printf 'replication_capture_blocked\\n'"));
    assert!(!foreign.contains("exit "));
    assert!(!foreign.contains("ALTER"));
    assert!(!foreign.contains("CREATE ROLE"));
    assert!(!foreign.contains("COMMENT"));

    let unexpected = shell_case_arm(&script, "*");
    assert!(unexpected.contains("replication_role_not_owned"));
    assert!(unexpected.contains("exit 52"));
    assert!(!unexpected.contains("ALTER"));
    assert!(!unexpected.contains("CREATE ROLE"));
    assert!(!unexpected.contains("COMMENT"));

    let skipped = script
        .find("if [ \"$replication_capture_blocked\" != true ]")
        .unwrap();
    let confirmed = script.find("confirmed=$(admin_psql").unwrap();
    assert!(skipped < confirmed);
    assert!(foreign_replication_role_diagnostic().contains("rename or drop"));

    let owned = shell_case_arm(&script, "owned");
    assert!(owned.contains("replication_login_ok"));
    assert!(owned.contains("replication_auth_failed"));
    assert!(owned.contains("ALTER ROLE"));
    assert!(owned.contains("COMMENT ON ROLE"));
}

fn shell_case_arm<'a>(script: &'a str, label: &str) -> &'a str {
    let marker = format!("\n  {label})");
    let rest = script
        .split_once(&marker)
        .unwrap_or_else(|| panic!("missing {label}"))
        .1;
    rest.split_once("\n    ;;")
        .unwrap_or_else(|| panic!("unterminated {label}"))
        .0
}

#[test]
fn generated_sql_uses_psql_environment_variables_for_secrets() {
    let script = hardening_script("user-with-dash");

    assert!(script.contains("\\getenv tenant_password DBE_TENANT_PASSWORD"));
    assert!(!script.contains("-v tenant_password="));
    assert!(script.contains("ALTER ROLE \"user-with-dash\" PASSWORD"));
}

#[test]
fn privileged_hardening_queries_always_use_internal_admin() {
    let script = hardening_script("tenant_user");

    assert!(script.contains("role_state=$(admin_psql -Atq -c"));
    assert!(script.contains("shown_hba=$(admin_psql -Atqc 'SHOW hba_file')"));
    assert!(script.contains("hba_file=\"$PGDATA/pg_hba.conf\""));
    assert!(!script.contains("db_psql"));
}

#[test]
fn tenant_auth_uses_its_database_while_admin_stays_on_control_database() {
    let script = hardening_script("tenant_user");

    assert!(script.contains(
            "tenant_psql() { PGPASSWORD=\"$DBE_TENANT_PASSWORD\" psql -X -h /var/run/postgresql -U \"$DBE_POSTGRES_USER\" -d \"$DBE_POSTGRES_DATABASE\""
        ));
    assert!(script.contains(
            "admin_psql() { PGPASSWORD=\"$DBE_POSTGRES_ADMIN_PASSWORD\" psql -X -h /var/run/postgresql -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\""
        ));
    assert!(script.contains(
            "PGPASSWORD=\"$DBE_INVALID_PASSWORD\" psql -X -h /var/run/postgresql -U \"$DBE_POSTGRES_USER\" -d \"$DBE_POSTGRES_DATABASE\""
        ));
    assert!(!script.contains("-U \"$DBE_POSTGRES_USER\" -d \"$POSTGRES_DB\""));
}

#[test]
fn bootstrap_admin_is_adopted_only_when_its_scram_secret_matches() {
    let verifier = "SCRAM-SHA-256$4096:MDEyMzQ1Njc4OWFiY2RlZg==$6/GDk4+gZMX4iv8Ibw6yXOdLYz3kM7F1as2BGy/hOKo=:Oa1MbaDa29ii1LLBMeTRyDGjXTn6G2q1ZT+GhsnFa2c=";

    assert!(verify_scram_password("admin-password", verifier));
    assert!(!verify_scram_password("wrong-password", verifier));
    assert!(!verify_scram_password("admin-password", "md5deadbeef"));
    assert!(!verify_scram_password(
        "admin-password",
        &verifier.replacen("4096", "100001", 1)
    ));
    assert!(!verify_scram_password(
        "admin-password",
        &format!("SCRAM-SHA-256$4096:{}$AA==:AA==", "A".repeat(2_000))
    ));
}

#[test]
fn failed_auth_preserves_recovery_intent_and_volume_identity() {
    let metadata = test_metadata("legacy", "legacy_user", "legacy_db");

    let failed = auth_failed_metadata(&metadata);

    assert_eq!(failed.status, InstanceStatus::Failed);
    assert_eq!(failed.desired_state, DesiredInstanceState::Running);
    assert_eq!(failed.backend, metadata.backend);
    assert_eq!(
        failed.runtime.container_name,
        metadata.runtime.container_name
    );
}

#[tokio::test]
async fn one_failed_legacy_route_does_not_remove_a_healthy_route() {
    let store = InstanceStore::default();
    let failed = test_metadata("legacy", "legacy_user", "legacy_db");
    let healthy = test_metadata("healthy", "healthy_user", "healthy_db");
    store.upsert(failed.clone()).await;
    store.upsert(healthy).await;

    store.upsert(auth_failed_metadata(&failed)).await;

    assert!(matches!(
        store
            .resolve_postgres("legacy_user", Some("legacy_db"))
            .await,
        crate::server::state::DatabaseRouteResolution::NotFound
    ));
    assert!(matches!(
        store
            .resolve_postgres("healthy_user", Some("healthy_db"))
            .await,
        crate::server::state::DatabaseRouteResolution::Found { .. }
    ));
}

#[test]
fn concurrent_outcomes_are_aggregated_deterministically() {
    let summary = merge_postgres_hardening(vec![
        PostgresHardeningSummary {
            checked: 1,
            hardened: 1,
            administrator_credentials_migrated: 0,
            attestations_reused: 1,
            deferred: 0,
            failures: vec![PostgresHardeningFailure {
                instance_id: "postgres-z".to_string(),
                reason: "z failure".to_string(),
            }],
            replication_capture_blocked: vec![PostgresReplicationCaptureBlock {
                instance_id: "postgres-z".to_string(),
                reason: "z blocked".to_string(),
            }],
        },
        PostgresHardeningSummary {
            checked: 2,
            hardened: 0,
            administrator_credentials_migrated: 1,
            attestations_reused: 2,
            deferred: 1,
            failures: vec![PostgresHardeningFailure {
                instance_id: "postgres-a".to_string(),
                reason: "a failure".to_string(),
            }],
            replication_capture_blocked: vec![PostgresReplicationCaptureBlock {
                instance_id: "postgres-a".to_string(),
                reason: "a blocked".to_string(),
            }],
        },
    ]);

    assert_eq!(summary.checked, 3);
    assert_eq!(summary.hardened, 1);
    assert_eq!(summary.administrator_credentials_migrated, 1);
    assert_eq!(summary.attestations_reused, 3);
    assert_eq!(summary.deferred, 1);
    assert_eq!(summary.failures.len(), 2);
    assert_eq!(summary.failures[0].instance_id, "postgres-a");
    assert_eq!(summary.failures[1].instance_id, "postgres-z");
    assert_eq!(summary.replication_capture_blocked.len(), 2);
    assert_eq!(
        summary.replication_capture_blocked[0].instance_id,
        "postgres-a"
    );
    assert_eq!(
        summary.replication_capture_blocked[1].instance_id,
        "postgres-z"
    );
}

#[test]
fn foreign_replication_role_keeps_hardening_successful() {
    match classify_hardening_stdout("replication_capture_blocked\nhardened\n") {
        HardeningStdout::Completed(outcome) => {
            assert!(outcome.changed);
            assert!(outcome.replication_capture_blocked);
        }
        other => panic!("expected a completed hardening run, got {other:?}"),
    }
    match classify_hardening_stdout("already_hardened\n") {
        HardeningStdout::Completed(outcome) => {
            assert!(!outcome.changed);
            assert!(!outcome.replication_capture_blocked);
        }
        other => panic!("expected an unchanged hardening run, got {other:?}"),
    }
    assert!(matches!(
        classify_hardening_stdout("replication_role_not_owned\n"),
        HardeningStdout::Unexpected
    ));
    assert!(matches!(
        classify_hardening_stdout("replication_capture_blocked\n"),
        HardeningStdout::Unexpected
    ));
    assert!(foreign_replication_role_diagnostic().contains("dbe_replication"));
    assert!(foreign_replication_role_diagnostic().contains("dbe-managed-replication-v1"));
}

fn test_metadata(instance_id: &str, username: &str, database: &str) -> InstanceMetadata {
    let mut metadata = test_support::metadata(instance_id, Protocol::Postgres);
    metadata.public.host = "127.0.0.1".to_string();
    metadata.public.port = 20_020;
    metadata.backend = BackendEndpoint::UnixSocket {
        socket_path: format!("/run/dbev/sockets/{instance_id}/.s.PGSQL.5432"),
    };
    metadata.database.name = database.to_string();
    metadata.database.username = username.to_string();
    metadata.postgres_admin_password = Some("admin-password".to_string());
    metadata
}
