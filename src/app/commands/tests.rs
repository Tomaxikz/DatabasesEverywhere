use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    process::Command,
};

use super::*;

#[test]
fn quarantine_inspection_is_bounded_and_supports_history_paging() -> anyhow::Result<()> {
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
    ])?;
    assert!(
        matches!(cli.command, Some(super::Command::Quarantine { entity_id: Some(id), history: true, before: Some(42), limit: 50, .. }) if id == "pool_one")
    );
    for limit in ["0", "1001"] {
        assert!(Cli::try_parse_from(["dbev", "quarantine", "--limit", limit]).is_err());
    }

    Ok(())
}

#[test]
fn output_flags_are_global_and_quiet_conflicts_with_verbose() -> anyhow::Result<()> {
    let cli = Cli::try_parse_from(["dbev", "check-config", "--json", "-vv", "--color", "never"])?;
    assert!(matches!(
        cli.command,
        Some(super::Command::CheckConfig { json: true })
    ));
    assert_eq!(cli.verbose, 2);
    assert!(matches!(cli.color, ColorChoice::Never));
    assert!(Cli::try_parse_from(["dbev", "migrate", "-q", "-v"]).is_err());

    Ok(())
}

#[test]
fn process_umask_limits_new_files_to_owner_access() -> anyhow::Result<()> {
    let output = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "commands::tests::restrictive_umask_child",
        ])
        .output()?;

    assert!(
        output.status.success(),
        "umask child failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    Ok(())
}

#[test]
#[ignore = "runs in an isolated child process from process_umask_limits_new_files_to_owner_access"]
fn restrictive_umask_child() -> anyhow::Result<()> {
    set_safe_umask();
    let temp = tempfile::tempdir()?;
    let file_path = temp.path().join("created");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o666)
        .open(&file_path)?;

    let mode = fs::metadata(file_path)?.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    Ok(())
}
