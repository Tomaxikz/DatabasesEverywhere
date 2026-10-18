use super::*;
use bytes::Bytes;
use secrecy::SecretString;

#[test]
fn secret_environment_is_validated_without_echoing_values() {
    let secret = SecretString::from("correct horse battery staple");
    assert_eq!(
        encode_secrets(&[("PGPASSWORD", &secret)]).unwrap(),
        vec!["PGPASSWORD=correct horse battery staple"]
    );
    assert!(
        encode_secrets(&[("BAD=KEY", &secret)])
            .unwrap_err()
            .to_string()
            .contains("environment")
    );
    assert!(encode_secrets(&[("PGPASSWORD", &secret), ("PGPASSWORD", &secret)]).is_err());
    let nul = SecretString::from("secret\0tail");
    let error = encode_secrets(&[("PGPASSWORD", &nul)]).unwrap_err();
    assert!(!error.to_string().contains("secret"));
}

#[test]
fn streaming_exec_is_attached_non_tty_and_never_privileged() {
    let options = streaming_exec_options(
        vec!["database-client".to_string()],
        vec!["PASSWORD=redacted".to_string()],
        true,
    );

    assert_eq!(options.attach_stdin, Some(true));
    assert_eq!(options.attach_stdout, Some(true));
    assert_eq!(options.attach_stderr, Some(true));
    assert_eq!(options.tty, Some(false));
    assert_eq!(options.privileged, Some(false));
    assert_eq!(
        options.cmd.as_deref(),
        Some(["database-client".to_string()].as_slice())
    );
    assert!(options.env.is_some());
}

#[tokio::test]
async fn input_pump_obeys_backpressure_and_preserves_bytes() {
    let contents = vec![b'x'; EXEC_STREAM_BUFFER_BYTES * 3 + 17];
    let (writer, mut reader) = tokio::io::duplex(7);
    let expected = contents.clone();
    let consumer = tokio::spawn(async move {
        let mut received = Vec::new();
        reader.read_to_end(&mut received).await.unwrap();
        received
    });

    let transferred = pump_private_input(
        std::io::Cursor::new(contents),
        writer,
        expected.len() as u64,
        expected.len() as u64,
    )
    .await
    .unwrap();

    assert_eq!(transferred, expected.len() as u64);
    assert_eq!(consumer.await.unwrap(), expected);
}

#[tokio::test]
async fn input_pump_rejects_growth_and_truncation() {
    let growth = pump_private_input(std::io::Cursor::new(b"too long"), tokio::io::sink(), 3, 8)
        .await
        .unwrap_err();
    assert_eq!(growth.kind(), ErrorKind::InvalidData);

    let truncated = pump_private_input(std::io::Cursor::new(b"short"), tokio::io::sink(), 8, 8)
        .await
        .unwrap_err();
    assert_eq!(truncated.kind(), ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn output_drain_writes_only_stdout_and_console() {
    let output = futures::stream::iter(vec![
        Ok(LogOutput::StdOut {
            message: Bytes::from_static(b"dump"),
        }),
        Ok(LogOutput::StdErr {
            message: Bytes::from_static(b"not part of dump"),
        }),
        Ok(LogOutput::Console {
            message: Bytes::from_static(b"-tail"),
        }),
    ]);
    let (mut writer, mut reader) = tokio::io::duplex(64);
    let drain = tokio::spawn(async move {
        let result = drain_exec_output(output, &mut writer, 9, &[])
            .await
            .unwrap();
        writer.shutdown().await.unwrap();
        result
    });
    let mut contents = Vec::new();
    reader.read_to_end(&mut contents).await.unwrap();

    let result = drain.await.unwrap();
    assert_eq!(result.transferred_bytes, 9);
    assert_eq!(result.failure_output, "not part of dump");
    assert_eq!(contents, b"dump-tail");
}

#[tokio::test]
async fn stderr_diagnostics_are_bounded_and_redacted() {
    let secret = "PASSWORD=do-not-log postgres://user:secret@localhost/db\n";
    let output = futures::stream::iter(vec![Ok(LogOutput::StdErr {
        message: Bytes::from(secret.repeat(1_000)),
    })]);

    let diagnostic = drain_exec_stderr(output, &["raw-secret-value".to_string()])
        .await
        .unwrap();

    assert!(diagnostic.len() <= EXEC_STREAM_FAILURE_DIAGNOSTIC_CHARS + 3);
    assert!(diagnostic.contains("PASSWORD=[redacted]"));
    assert!(!diagnostic.contains("do-not-log"));
    assert!(!diagnostic.contains("user:secret"));

    let output = futures::stream::iter(vec![Ok(LogOutput::StdErr {
        message: Bytes::from_static(b"client echoed raw-secret-value"),
    })]);
    let diagnostic = drain_exec_stderr(output, &["raw-secret-value".to_string()])
        .await
        .unwrap();
    assert_eq!(diagnostic, "client echoed [redacted]");
}

#[tokio::test]
async fn output_drain_stops_before_writing_past_limit() {
    let output = futures::stream::iter(vec![Ok(LogOutput::StdOut {
        message: Bytes::from_static(b"oversized"),
    })]);
    let error = drain_exec_output(output, &mut tokio::io::sink(), 4, &[])
        .await
        .unwrap_err();
    assert!(matches!(error, OutputDrainError::Limit));
}

#[test]
fn private_input_rejects_symlinks_and_oversized_files() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let regular = directory.path().join("dump.sql");
    let linked = directory.path().join("linked.sql");
    std::fs::write(&regular, b"contents").unwrap();
    symlink(&regular, &linked).unwrap();

    assert_eq!(open_private_input(&regular, 8).unwrap().1, 8);
    assert!(matches!(
        open_private_input(&regular, 7).unwrap_err(),
        DockerError::ExecStreamInputTooLarge { .. }
    ));
    assert!(open_private_input(&linked, 8).is_err());
}

#[tokio::test]
async fn verified_input_stays_bound_to_the_opened_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("dump.sql");
    let moved = directory.path().join("inspected.sql");
    let inspected = b"SELECT 1;";
    std::fs::write(&path, inspected).unwrap();
    let expected: [u8; 32] = Sha256::digest(inspected).into();
    let (mut opened, size) = open_private_input(&path, 64).unwrap();

    std::fs::rename(&path, &moved).unwrap();
    std::fs::write(&path, b"SELECT malicious();").unwrap();

    verify_private_input(&mut opened, size, 64, expected)
        .await
        .unwrap();
    let mut contents = Vec::new();
    opened.read_to_end(&mut contents).await.unwrap();
    assert_eq!(contents, inspected);

    let (mut replacement, replacement_size) = open_private_input(&path, 64).unwrap();
    let error = verify_private_input(&mut replacement, replacement_size, 64, expected)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidData);
}

#[tokio::test]
async fn verified_input_rejects_same_length_content_changes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("dump.sql");
    std::fs::write(&path, b"safe").unwrap();
    let expected: [u8; 32] = Sha256::digest(b"safe").into();
    let (mut opened, size) = open_private_input(&path, 4).unwrap();
    std::fs::write(&path, b"evil").unwrap();

    let error = verify_private_input(&mut opened, size, 4, expected)
        .await
        .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InvalidData);
}

#[tokio::test]
async fn private_output_is_create_new_private_and_durable_on_commit() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let output_path = directory.path().join("dump.sql");
    let mut output = PrivateOutputFile::create(&output_path).unwrap();
    output.file_mut().write_all(b"contents").await.unwrap();
    output.commit().await.unwrap();

    assert_eq!(std::fs::read(&output_path).unwrap(), b"contents");
    assert_eq!(
        std::fs::metadata(&output_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(PrivateOutputFile::create(&output_path).is_err());
}

#[tokio::test]
async fn output_limit_removes_partial_private_file() {
    let directory = tempfile::tempdir().unwrap();
    let output_path = directory.path().join("partial.sql");
    let output = futures::stream::iter(vec![
        Ok(LogOutput::StdOut {
            message: Bytes::from_static(b"part"),
        }),
        Ok(LogOutput::StdOut {
            message: Bytes::from_static(b"too-much"),
        }),
    ]);
    let mut file = PrivateOutputFile::create(&output_path).unwrap();

    let error = drain_exec_output(output, file.file_mut(), 4, &[])
        .await
        .unwrap_err();
    assert!(matches!(error, OutputDrainError::Limit));
    drop(file);
    assert!(!output_path.exists());
}

#[test]
fn dropping_uncommitted_output_removes_only_the_created_file() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let output_path = directory.path().join("partial.sql");
    let victim = directory.path().join("victim");
    std::fs::write(&victim, b"safe").unwrap();
    drop(PrivateOutputFile::create(&output_path).unwrap());
    assert!(!output_path.exists());

    symlink(&victim, &output_path).unwrap();
    assert!(PrivateOutputFile::create(&output_path).is_err());
    assert_eq!(std::fs::read(victim).unwrap(), b"safe");
}

#[tokio::test]
async fn cancellation_signal_notifies_the_detached_worker() {
    let (sender, receiver) = oneshot::channel();
    drop(CancellationSignal(Some(sender)));
    receiver.await.unwrap();
}
