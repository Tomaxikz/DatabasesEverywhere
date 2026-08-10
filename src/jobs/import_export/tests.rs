use std::io::Cursor;

use super::*;

#[test]
fn rejects_archive_path_traversal() {
    let error = validate_archive_path(Path::new("data/../evil.txt"), "data", 64).unwrap_err();

    assert!(matches!(error, ImportExportError::InvalidArchive(_)));
}

#[test]
fn accepts_archive_under_expected_root() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("good.tar.gz");
    write_archive(&archive, "data/file.txt", b"ok");

    validate_archive_blocking(&archive, "data").unwrap();
}

#[test]
fn extracts_archive_entries_without_unpack() {
    let dir = tempfile::tempdir().unwrap();
    let archive_path = dir.path().join("data.tar.gz");
    let target = dir.path().join("target");
    write_archive(&archive_path, "data/file.txt", b"ok");

    extract_data_archive_blocking(&archive_path, &target, "data").unwrap();

    assert_eq!(std::fs::read(target.join("data/file.txt")).unwrap(), b"ok");
}

#[test]
fn physical_extraction_enforces_expansion_limit() {
    let dir = tempfile::tempdir().unwrap();
    let archive_path = dir.path().join("data.tar.gz");
    let target = dir.path().join("target");
    std::fs::create_dir(&target).unwrap();
    write_archive(&archive_path, "data/file.txt", b"too large");
    let file = File::open(&archive_path).unwrap();
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);
    let limits = ArchiveLimits {
        bytes: 4,
        entries: 10,
        depth: 10,
        deadline: Duration::from_secs(10),
    };

    let error = extract_archive_entries(&mut archive, &target, "data", limits).unwrap_err();

    assert!(error.to_string().contains("expands beyond"));
}

#[test]
fn bounded_physical_extraction_accepts_exact_limit() {
    let dir = tempfile::tempdir().unwrap();
    let archive_path = dir.path().join("data.tar.gz");
    let target = dir.path().join("target");
    write_archive(&archive_path, "data/file.txt", b"12345678");

    extract_data_archive_bounded_blocking(&archive_path, &target, "data", 8).unwrap();

    assert_eq!(
        std::fs::read(target.join("data/file.txt")).unwrap(),
        b"12345678"
    );
}

#[test]
fn bounded_physical_extraction_rejects_before_oversized_file_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let archive_path = dir.path().join("data.tar.gz");
    let target = dir.path().join("target");
    write_archive(&archive_path, "data/file.txt", b"12345678");

    let error =
        extract_data_archive_bounded_blocking(&archive_path, &target, "data", 7).unwrap_err();

    assert!(error.to_string().contains("expands beyond 7 bytes"));
    assert!(!target.join("data/file.txt").exists());
}

#[cfg(unix)]
#[test]
fn physical_backup_preserves_internal_source_symlinks() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let stored = data.join("store/ab/table");
    let metadata = data.join("metadata/database");
    std::fs::create_dir_all(&stored).unwrap();
    std::fs::create_dir_all(&metadata).unwrap();
    std::fs::write(stored.join("part.bin"), b"clickhouse data").unwrap();
    symlink("../../store/ab/table", metadata.join("table")).unwrap();
    let artifact = dir.path().join("backup.tar.gz");
    let restored = dir.path().join("restored");

    create_data_archive_blocking(&data, &artifact, DataArchiveSourcePolicy::Strict).unwrap();
    extract_data_archive_blocking(&artifact, &restored, "data").unwrap();

    let link = restored.join("data/metadata/database/table");
    assert_eq!(
        std::fs::read_link(&link).unwrap(),
        Path::new("../../store/ab/table")
    );
    assert_eq!(
        std::fs::read(link.join("part.bin")).unwrap(),
        b"clickhouse data"
    );
}

#[cfg(unix)]
#[test]
fn physical_backup_rejects_source_symlinks_that_escape_data_root() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    std::fs::write(dir.path().join("secret"), b"host secret").unwrap();
    symlink("../secret", data.join("escape")).unwrap();
    let artifact = dir.path().join("backup.tar.gz");

    let error = create_data_archive_blocking(&data, &artifact, DataArchiveSourcePolicy::Strict)
        .unwrap_err();

    assert!(error.to_string().contains("escapes data root"));
    assert!(!artifact.exists());
}

#[cfg(unix)]
#[test]
fn mysql_physical_backup_omits_only_the_image_runtime_socket_link() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let artifact = dir.path().join("backup.tar.gz");
    let restored = dir.path().join("restored");
    std::fs::create_dir(&data).unwrap();
    std::fs::write(data.join("ibdata1"), b"mysql data").unwrap();
    symlink("/var/run/mysqld/mysqld.sock", data.join("mysql.sock")).unwrap();

    create_data_archive_blocking(
        &data,
        &artifact,
        DataArchiveSourcePolicy::MysqlDataDirectory,
    )
    .unwrap();
    extract_data_archive_blocking(&artifact, &restored, "data").unwrap();

    assert_eq!(
        std::fs::read(restored.join("data/ibdata1")).unwrap(),
        b"mysql data"
    );
    assert!(!restored.join("data/mysql.sock").exists());
}

#[cfg(unix)]
#[test]
fn mysql_physical_backup_rejects_unexpected_socket_link_targets() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let artifact = dir.path().join("backup.tar.gz");
    std::fs::create_dir(&data).unwrap();
    symlink("/tmp/untrusted.sock", data.join("mysql.sock")).unwrap();

    let error = create_data_archive_blocking(
        &data,
        &artifact,
        DataArchiveSourcePolicy::MysqlDataDirectory,
    )
    .unwrap_err();

    assert!(error.to_string().contains("must be relative"));
    assert!(!artifact.exists());
}

#[test]
fn physical_restore_rejects_archive_symlinks_that_escape_data_root() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("malicious.tar.gz");
    write_symlink_archive(&archive, "data/escape", "../secret");

    let error = validate_archive_blocking(&archive, "data").unwrap_err();

    assert!(error.to_string().contains("escapes data root"));
}

#[cfg(unix)]
#[test]
fn physical_backup_artifact_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let artifact = dir.path().join("backup.tar.gz");
    std::fs::create_dir(&data).unwrap();
    std::fs::write(data.join("file"), b"contents").unwrap();

    create_data_archive_blocking(&data, &artifact, DataArchiveSourcePolicy::Strict).unwrap();

    assert_eq!(
        std::fs::metadata(artifact).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn bounded_physical_backup_removes_partial_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let artifact = dir.path().join("backup.tar.gz");
    std::fs::create_dir(&data).unwrap();
    std::fs::write(data.join("file"), b"contents").unwrap();

    let error =
        create_data_archive_bounded_blocking(&data, &artifact, DataArchiveSourcePolicy::Strict, 1)
            .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("archive output exceeds configured byte limit")
    );
    assert!(!artifact.exists());
}

#[test]
fn physical_backup_reader_ignores_concurrent_file_growth() {
    use std::fs::OpenOptions;

    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    std::fs::write(&source, b"ok").unwrap();
    let file = File::open(&source).unwrap();
    let metadata = file.metadata().unwrap();
    OpenOptions::new()
        .append(true)
        .open(&source)
        .unwrap()
        .write_all(b"host-secret")
        .unwrap();
    let mut archive_bytes = Vec::new();
    let mut builder = Builder::new(&mut archive_bytes);

    append_bounded_archive_file(
        &mut builder,
        Path::new("data/source"),
        file,
        &metadata,
        Instant::now(),
        DATA_ARCHIVE_LIMITS,
    )
    .unwrap();
    builder.finish().unwrap();
    drop(builder);

    let mut archive = Archive::new(Cursor::new(archive_bytes));
    let mut entry = archive.entries().unwrap().next().unwrap().unwrap();
    let mut contents = Vec::new();
    entry.read_to_end(&mut contents).unwrap();
    assert_eq!(contents, b"ok");
}

#[test]
fn physical_backup_reader_enforces_deadline_inside_file_copy() {
    let mut reader = DeadlineBoundedReader {
        inner: Cursor::new(b"contents"),
        remaining: 8,
        started: Instant::now().checked_sub(Duration::from_secs(2)).unwrap(),
        deadline: Duration::from_secs(1),
    };
    let mut byte = [0_u8; 1];

    let error = reader.read(&mut byte).unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

#[test]
fn import_export_admission_bounds_global_and_per_instance_waiters() {
    let jobs = ImportExportJobs::default();
    let first = jobs.try_admit("inst-one").unwrap();
    let second = jobs.try_admit("inst-one").unwrap();
    assert_eq!(
        jobs.try_admit("inst-one").unwrap_err(),
        JobAdmissionError::InstanceCapacity
    );

    let mut other_permits = Vec::new();
    for index in 2..MAX_ADMITTED_JOBS {
        other_permits.push(jobs.try_admit(&format!("inst-{index}")).unwrap());
    }
    assert_eq!(
        jobs.try_admit("over-global-limit").unwrap_err(),
        JobAdmissionError::GlobalCapacity
    );

    drop(first);
    assert!(jobs.try_admit("inst-one").is_ok());
    drop(second);
    drop(other_permits);
}

#[tokio::test]
async fn shutdown_closes_admission_and_waits_for_existing_jobs() {
    let jobs = ImportExportJobs::default();
    let permit = jobs.try_admit("inst-one").unwrap();

    jobs.close_admission();

    assert_eq!(
        jobs.try_admit("inst-two").unwrap_err(),
        JobAdmissionError::ShuttingDown
    );
    assert!(!jobs.wait_for_drain(Duration::from_millis(10)).await);
    drop(permit);
    assert!(jobs.wait_for_drain(Duration::from_millis(100)).await);
}

#[tokio::test]
async fn publishes_import_export_job_events() {
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

    jobs.insert(job).await.unwrap();

    let event = events.recv().await.unwrap();
    assert_eq!(event.job_id, "job-1");
    assert_eq!(event.status, ImportExportStatus::Queued);

    jobs.update_status(
        "job-1",
        ImportExportStatus::Succeeded,
        Some("exports/job-1.sql".to_string()),
        None,
    )
    .await
    .unwrap();

    let event = events.recv().await.unwrap();
    assert_eq!(event.job_id, "job-1");
    assert_eq!(event.status, ImportExportStatus::Succeeded);
    assert_eq!(event.artifact_path.as_deref(), Some("exports/job-1.sql"));
}

fn write_archive(path: &Path, entry_path: &str, contents: &[u8]) {
    let file = File::create(path).unwrap();
    let encoder = GzEncoder::new(file, Compression::default());
    let mut builder = Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_path(entry_path).unwrap();
    header.set_size(contents.len() as u64);
    header.set_cksum();
    builder
        .append(&header, Cursor::new(contents.to_vec()))
        .unwrap();
    builder.into_inner().unwrap().finish().unwrap();
}

fn write_symlink_archive(path: &Path, entry_path: &str, link_name: &str) {
    let file = File::create(path).unwrap();
    let encoder = GzEncoder::new(file, Compression::default());
    let mut builder = Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(EntryType::Symlink);
    header.set_size(0);
    builder
        .append_link(&mut header, entry_path, link_name)
        .unwrap();
    builder.into_inner().unwrap().finish().unwrap();
}
