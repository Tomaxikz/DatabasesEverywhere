use std::io::Cursor;
use std::io::{Read, Write};

use super::*;

#[test]
fn rejects_archive_path_traversal() {
    let error = validate_archive_path(Path::new("data/../evil.txt"), "data", 64)
        .expect_err("validate archive path should return an error");

    assert!(matches!(error, ImportExportError::InvalidArchive(_)));
}

#[test]
fn bounded_physical_extraction_accepts_exact_limit() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let archive_path = dir.path().join("data.tar.gz");
    let target = dir.path().join("target");
    write_archive(&archive_path, "data/file.txt", b"12345678");

    extract_bounded_archive_blocking(
        &archive_path,
        &target,
        "data",
        DATA_ARCHIVE_ENTRY_DISK_OVERHEAD_BYTES + 8,
    )?;

    assert_eq!(std::fs::read(target.join("data/file.txt"))?, b"12345678");

    Ok(())
}

#[test]
fn bounded_physical_extraction_rejects_before_oversized_file_is_written() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let archive_path = dir.path().join("data.tar.gz");
    let target = dir.path().join("target");
    write_archive(&archive_path, "data/file.txt", b"12345678");

    let limit = DATA_ARCHIVE_ENTRY_DISK_OVERHEAD_BYTES + 7;
    let error = extract_bounded_archive_blocking(&archive_path, &target, "data", limit)
        .expect_err("extract bounded archive blocking should return an error");

    assert!(
        error
            .to_string()
            .contains(&format!("expands beyond {limit} bytes"))
    );
    assert!(!target.join("data/file.txt").exists());

    Ok(())
}

#[test]
fn physical_backup_rejects_internal_and_escaping_source_symlinks() -> anyhow::Result<()> {
    use std::os::unix::fs::symlink;

    for (link, target) in [
        ("metadata/database/table", "../../store/ab/table"),
        ("escape", "../secret"),
    ] {
        let dir = tempfile::tempdir()?;
        let data = dir.path().join("data");
        let stored = data.join("store/ab/table");
        std::fs::create_dir_all(&stored)?;
        std::fs::create_dir_all(data.join("metadata/database"))?;
        std::fs::write(stored.join("part.bin"), b"clickhouse data")?;
        std::fs::write(dir.path().join("secret"), b"host secret")?;
        symlink(target, data.join(link))?;
        let artifact = dir.path().join("backup.tar.gz");

        let error = create_archive_blocking(&data, &artifact, DataArchiveSourcePolicy::Strict)
            .expect_err("create archive blocking should return an error");

        assert!(
            error.to_string().contains("refuses symbolic link"),
            "{link} -> {target}"
        );
        assert!(!artifact.exists(), "{link} -> {target}");
    }

    Ok(())
}

#[test]
fn mysql_physical_backup_omits_only_the_image_runtime_socket_link() -> anyhow::Result<()> {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir()?;
    let data = dir.path().join("data");
    let artifact = dir.path().join("backup.tar.gz");
    let restored = dir.path().join("restored");
    std::fs::create_dir(&data)?;
    std::fs::write(data.join("ibdata1"), b"mysql data")?;
    symlink("/var/run/mysqld/mysqld.sock", data.join("mysql.sock"))?;

    create_archive_blocking(
        &data,
        &artifact,
        DataArchiveSourcePolicy::MysqlDataDirectory,
    )?;
    extract_archive_blocking(&artifact, &restored, "data")?;

    assert_eq!(std::fs::read(restored.join("data/ibdata1"))?, b"mysql data");
    assert!(!restored.join("data/mysql.sock").exists());

    Ok(())
}

#[test]
fn mysql_physical_backup_rejects_unexpected_socket_link_targets() -> anyhow::Result<()> {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir()?;
    let data = dir.path().join("data");
    let artifact = dir.path().join("backup.tar.gz");
    std::fs::create_dir(&data)?;
    symlink("/tmp/untrusted.sock", data.join("mysql.sock"))?;

    let error = create_archive_blocking(
        &data,
        &artifact,
        DataArchiveSourcePolicy::MysqlDataDirectory,
    )
    .expect_err("create archive blocking should return an error");

    assert!(error.to_string().contains("refuses symbolic link"));
    assert!(!artifact.exists());

    Ok(())
}

#[test]
fn physical_restore_rejects_every_symlink_entry() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let escaping = dir.path().join("escaping.tar.gz");
    let target = dir.path().join("target");
    write_symlink_archive(&escaping, "data/escape", "../secret");

    let error = extract_archive_blocking(&escaping, &target, "data")
        .expect_err("extract archive blocking should return an error");
    assert!(error.to_string().contains("symbolic link"));
    assert!(std::fs::symlink_metadata(target.join("data/escape")).is_err());

    let lexically_safe = dir.path().join("lexically-safe.tar.gz");
    write_symlink_archive(&lexically_safe, "data/self", ".");

    let error =
        extract_bounded_archive_blocking(&lexically_safe, &target, "data", MAX_DATA_ARCHIVE_BYTES)
            .expect_err("extract bounded archive blocking should return an error");

    assert!(error.to_string().contains("symbolic link"));
    assert!(!target.join("data/self").exists());

    Ok(())
}

#[test]
fn physical_backup_artifact_is_owner_only() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir()?;
    let data = dir.path().join("data");
    let artifact = dir.path().join("backup.tar.gz");
    std::fs::create_dir(&data)?;
    std::fs::write(data.join("file"), b"contents")?;

    create_archive_blocking(&data, &artifact, DataArchiveSourcePolicy::Strict)?;

    assert_eq!(
        std::fs::metadata(artifact)?.permissions().mode() & 0o777,
        0o600
    );

    Ok(())
}

#[test]
fn bounded_physical_backup_removes_partial_artifact() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data = dir.path().join("data");
    let artifact = dir.path().join("backup.tar.gz");
    std::fs::create_dir(&data)?;
    std::fs::write(data.join("file"), b"contents")?;

    let error =
        create_bounded_archive_blocking(&data, &artifact, DataArchiveSourcePolicy::Strict, 1)
            .expect_err("create bounded archive blocking should return an error");

    assert!(
        error
            .to_string()
            .contains("archive output exceeds configured byte limit")
    );
    assert!(!artifact.exists());

    Ok(())
}

#[test]
fn physical_backup_reader_ignores_concurrent_file_growth() -> anyhow::Result<()> {
    use anyhow::Context as _;

    use std::fs::OpenOptions;

    let dir = tempfile::tempdir()?;
    let source = dir.path().join("source");
    std::fs::write(&source, b"ok")?;
    let file = File::open(&source)?;
    let metadata = file.metadata()?;
    OpenOptions::new()
        .append(true)
        .open(&source)?
        .write_all(b"host-secret")?;
    let mut archive_bytes = Vec::new();
    let mut builder = Builder::new(&mut archive_bytes);

    append_bounded_archive_file(
        &mut builder,
        Path::new("data/source"),
        file,
        &metadata,
        Instant::now(),
        DATA_ARCHIVE_LIMITS,
    )?;
    builder.finish()?;
    drop(builder);

    let mut archive = Archive::new(Cursor::new(archive_bytes));
    let mut entry = archive
        .entries()?
        .next()
        .context("expected a value from next")??;
    let mut contents = Vec::new();
    entry.read_to_end(&mut contents)?;
    assert_eq!(contents, b"ok");

    Ok(())
}

#[test]
fn physical_backup_reader_enforces_deadline_inside_file_copy() -> anyhow::Result<()> {
    use anyhow::Context as _;

    let mut reader = DeadlineBoundedReader {
        inner: Cursor::new(b"contents"),
        remaining: 8,
        started: Instant::now()
            .checked_sub(Duration::from_secs(2))
            .context("expected a value from checked_sub")?,
        deadline: Duration::from_secs(1),
    };
    let mut byte = [0_u8; 1];

    let error = reader
        .read(&mut byte)
        .expect_err("read should return an error");

    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);

    Ok(())
}

#[test]
fn import_export_admission_bounds_global_and_per_instance_waiters() -> anyhow::Result<()> {
    const MAX_ADMITTED_JOBS: usize = 64;
    let mut artifacts = crate::config::ArtifactConfig::default();
    artifacts.import_export_scheduler.max_queued_jobs = MAX_ADMITTED_JOBS;
    artifacts
        .import_export_scheduler
        .max_queued_jobs_per_instance = 2;
    let jobs = ImportExportJobs::new(None, &artifacts);
    let first = jobs
        .try_admit("inst-one")
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let second = jobs
        .try_admit("inst-one")
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    assert_eq!(
        jobs.try_admit("inst-one")
            .expect_err("try admit should return an error"),
        JobAdmissionError::InstanceCapacity
    );

    let mut other_permits = Vec::new();
    for index in 2..MAX_ADMITTED_JOBS {
        other_permits.push(
            jobs.try_admit(&format!("inst-{index}"))
                .map_err(|error| anyhow::anyhow!("{error:?}"))?,
        );
    }
    assert_eq!(
        jobs.try_admit("over-global-limit")
            .expect_err("try admit should return an error"),
        JobAdmissionError::GlobalCapacity
    );

    drop(first);
    assert!(jobs.try_admit("inst-one").is_ok());
    drop(second);
    drop(other_permits);

    Ok(())
}

#[test]
fn exclusive_maintenance_admission_never_queues_behind_instance_jobs() -> anyhow::Result<()> {
    let mut artifacts = crate::config::ArtifactConfig::default();
    artifacts
        .import_export_scheduler
        .max_queued_jobs_per_instance = 64;
    let jobs = ImportExportJobs::new(None, &artifacts);

    let queued_import = jobs
        .try_admit("inst-one")
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    assert_eq!(
        jobs.try_admit_exclusive("inst-one")
            .expect_err("try admit exclusive should return an error"),
        JobAdmissionError::InstanceCapacity
    );
    drop(queued_import);

    let maintenance = jobs
        .try_admit_exclusive("inst-one")
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    assert_eq!(
        jobs.try_admit_exclusive("inst-one")
            .expect_err("try admit exclusive should return an error"),
        JobAdmissionError::InstanceCapacity
    );
    assert_eq!(
        jobs.try_admit("inst-one")
            .expect_err("try admit should return an error"),
        JobAdmissionError::InstanceCapacity
    );
    drop(maintenance);
    assert!(jobs.try_admit("inst-one").is_ok());

    Ok(())
}

#[tokio::test]
async fn shutdown_closes_admission_and_waits_for_existing_jobs() -> anyhow::Result<()> {
    let jobs = ImportExportJobs::default();
    let permit = jobs
        .try_admit("inst-one")
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;

    jobs.close_admission();

    assert_eq!(
        jobs.try_admit("inst-two")
            .expect_err("try admit should return an error"),
        JobAdmissionError::ShuttingDown
    );
    assert!(!jobs.wait_for_drain(Duration::from_millis(10)).await);
    drop(permit);
    assert!(jobs.wait_for_drain(Duration::from_millis(100)).await);

    Ok(())
}

#[tokio::test]
async fn publishes_import_export_job_events() -> anyhow::Result<()> {
    let jobs = ImportExportJobs::default();
    let mut events = jobs.subscribe();
    let job = ImportExportJob {
        job_id: "job-1".to_string(),
        instance_id: "inst-1".to_string(),
        action: ImportExportAction::Export,
        status: ImportExportStatus::Queued,
        artifact_path: None,
        replay_options: None,
        error: None,
        created_at: now_rfc3339(),
        updated_at: now_rfc3339(),
    };

    jobs.insert(job).await?;

    let event = events.recv().await?;
    assert_eq!(event.job_id, "job-1");
    assert_eq!(event.status, ImportExportStatus::Queued);

    jobs.update_status(
        "job-1",
        ImportExportStatus::Succeeded,
        Some("exports/job-1.sql".to_string()),
        None,
    )
    .await?;

    let event = events.recv().await?;
    assert_eq!(event.job_id, "job-1");
    assert_eq!(event.status, ImportExportStatus::Succeeded);
    assert_eq!(event.artifact_path.as_deref(), Some("exports/job-1.sql"));

    Ok(())
}

fn write_archive(path: &Path, entry_path: &str, contents: &[u8]) {
    let file = File::create(path).expect("create should succeed");
    let encoder = GzEncoder::new(file, Compression::default());
    let mut builder = Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header
        .set_path(entry_path)
        .expect("set path should succeed");
    header.set_size(contents.len() as u64);
    header.set_cksum();
    builder
        .append(&header, Cursor::new(contents.to_vec()))
        .expect("to vec should succeed");
    builder
        .into_inner()
        .expect("into inner should succeed")
        .finish()
        .expect("finish should succeed");
}

fn write_symlink_archive(path: &Path, entry_path: &str, link_name: &str) {
    let file = File::create(path).expect("create should succeed");
    let encoder = GzEncoder::new(file, Compression::default());
    let mut builder = Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(EntryType::Symlink);
    header.set_size(0);
    builder
        .append_link(&mut header, entry_path, link_name)
        .expect("append link should succeed");
    builder
        .into_inner()
        .expect("into inner should succeed")
        .finish()
        .expect("finish should succeed");
}

fn clickhouse_layout(data: &std::path::Path) {
    use std::os::unix::fs::symlink;

    let table = data.join("store/abc/abc12345-0000-4000-8000-000000000001");
    let database = data.join("store/def/def12345-0000-4000-8000-000000000002");
    std::fs::create_dir_all(table.join("all_1_1_0")).expect("create dir all should succeed");
    std::fs::create_dir_all(&database).expect("create dir all should succeed");
    std::fs::write(table.join("all_1_1_0/data.bin"), b"clickhouse data")
        .expect("write should succeed");
    std::fs::write(database.join("events.sql"), b"ATTACH TABLE _ UUID '...'")
        .expect("write should succeed");
    std::fs::create_dir_all(data.join("metadata")).expect("create dir all should succeed");
    std::fs::write(
        data.join("metadata/default.sql"),
        b"ATTACH DATABASE _ UUID '...'",
    )
    .expect("write should succeed");
    std::fs::create_dir_all(data.join("data/default")).expect("create dir all should succeed");
    // Table links are written relative; database links absolute in the container.
    symlink(
        "../../store/abc/abc12345-0000-4000-8000-000000000001/",
        data.join("data/default/events"),
    )
    .expect("symlink should succeed");
    symlink(
        "/var/lib/clickhouse/store/def/def12345-0000-4000-8000-000000000002/",
        data.join("metadata/default"),
    )
    .expect("symlink should succeed");
}

#[test]
fn clickhouse_backups_leave_out_atomic_store_links() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data = dir.path().join("data");
    clickhouse_layout(&data);
    let artifact = dir.path().join("backup.tar.gz");
    let restored = dir.path().join("restored");

    assert!(
        create_archive_blocking(
            &data,
            &dir.path().join("strict.tar.gz"),
            DataArchiveSourcePolicy::Strict
        )
        .is_err()
    );
    create_archive_blocking(
        &data,
        &artifact,
        DataArchiveSourcePolicy::ClickhouseDataDirectory,
    )?;
    extract_archive_blocking(&artifact, &restored, "data")?;

    assert_eq!(
        std::fs::read(
            restored.join("data/store/abc/abc12345-0000-4000-8000-000000000001/all_1_1_0/data.bin")
        )?,
        b"clickhouse data"
    );
    assert!(restored.join("data/metadata/default.sql").is_file());
    assert!(restored.join("data/data/default").is_dir());
    assert!(std::fs::symlink_metadata(restored.join("data/data/default/events")).is_err());
    assert!(std::fs::symlink_metadata(restored.join("data/metadata/default")).is_err());

    Ok(())
}

#[test]
fn clickhouse_policy_still_refuses_links_outside_store() -> anyhow::Result<()> {
    use anyhow::Context as _;

    use std::os::unix::fs::symlink;

    for (relative, target) in [
        ("data/default/escape", "../../../secret"),
        ("data/default/etc", "/etc"),
        ("data/default/store_root", "../../store"),
        ("user_files/table", "../store/abc/abc12345"),
        ("metadata/default", "/var/lib/clickhouse/metadata/other"),
    ] {
        let dir = tempfile::tempdir()?;
        let data = dir.path().join("data");
        clickhouse_layout(&data);
        let link = data.join(relative);
        let _ = std::fs::remove_file(&link);
        std::fs::create_dir_all(link.parent().context("expected a value from parent")?)?;
        symlink(target, &link)?;
        let error = create_archive_blocking(
            &data,
            &dir.path().join("backup.tar.gz"),
            DataArchiveSourcePolicy::ClickhouseDataDirectory,
        )
        .expect_err("path should return an error");
        assert!(
            error.to_string().contains("refuses symbolic link"),
            "{relative} -> {target}"
        );
    }

    Ok(())
}

#[test]
fn archive_policies_follow_the_engine() {
    use crate::databases::protocol::Protocol;

    assert_eq!(
        DataArchiveSourcePolicy::for_protocol(Protocol::Clickhouse),
        DataArchiveSourcePolicy::ClickhouseDataDirectory
    );
    assert_eq!(
        DataArchiveSourcePolicy::for_protocol(Protocol::Mysql),
        DataArchiveSourcePolicy::MysqlDataDirectory
    );
    for protocol in [
        Protocol::Postgres,
        Protocol::Mongodb,
        Protocol::Qdrant,
        Protocol::Redis,
    ] {
        assert_eq!(
            DataArchiveSourcePolicy::for_protocol(protocol),
            DataArchiveSourcePolicy::Strict
        );
    }
    assert!(
        DataArchiveSourcePolicy::Strict
            .omitted_links_note()
            .is_none()
    );
}
