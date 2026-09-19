use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    process::Command,
};

use clap::CommandFactory;

use super::*;

#[test]
fn quarantine_inspection_is_bounded_and_supports_history_paging() {
    let cli = Cli::try_parse_from([
        "dbev",
        "quarantine",
        "--entity-id",
        "pool_one",
        "--history",
        "--before",
        "42",
        "--limit",
        "50",
    ])
    .unwrap();
    assert!(
        matches!(cli.command, Some(super::Command::Quarantine { entity_id: Some(id), history: true, before: Some(42), limit: 50 }) if id == "pool_one")
    );
    for limit in ["0", "1001"] {
        assert!(Cli::try_parse_from(["dbev", "quarantine", "--limit", limit]).is_err());
    }
}

#[test]
fn cli_exposes_the_package_version() {
    assert_eq!(
        Cli::command().get_version(),
        Some(env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn cli_parses_offline_protected_secret_repair() {
    let cli = Cli::try_parse_from([
        "dbev",
        "repair-protected-secret",
        "--instance-id",
        "inst_recovery",
        "--field",
        "tenant-password",
        "--confirm-legacy-plaintext",
    ])
    .unwrap();

    assert!(matches!(
        cli.command,
        Some(super::Command::RepairProtectedSecret {
            instance_id,
            field: ProtectedSecretField::TenantPassword,
            confirm_legacy_plaintext: true,
        }) if instance_id == "inst_recovery"
    ));
}

#[test]
fn process_umask_limits_new_files_to_owner_access() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "cli::tests::restrictive_umask_child",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "umask child failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "runs in an isolated child process from process_umask_limits_new_files_to_owner_access"]
fn restrictive_umask_child() {
    set_safe_umask();
    let temp = tempfile::tempdir().unwrap();
    let file_path = temp.path().join("created");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o666)
        .open(&file_path)
        .unwrap();

    let mode = fs::metadata(file_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}
